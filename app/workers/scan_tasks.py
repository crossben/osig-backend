"""
OSIG Backend - Scan Execution

Handles running OSINT modules and persisting results to the database.
Runs in a background thread (no Celery required for dev mode).

Quick scan: core lightweight modules
Deep scan:  all quick modules + extended checks + Google Dork
Both scan types: always include Google Dork module
"""
from datetime import datetime
from typing import List

from app.db.session import SessionLocal
from app.models.scan import Scan, ScanStatus, ScanModule, ScanType, TargetType, ModuleStatus
from app.models.result import Result
from app.osint.email_intel import EmailIntelModule
from app.osint.domain_intel import DomainIntelModule
from app.osint.phone_intel import PhoneIntelModule
from app.osint.username_intel import UsernameIntelModule
from app.osint.google_dork import GoogleDorkModule
from app.osint.ip_intel import IPIntelModule
from app.osint.org_intel import OrganizationIntelModule
from app.osint.base import OSINTResult
import logging

logger = logging.getLogger(__name__)


def _get_core_modules(target_type: TargetType, scan_type: ScanType):
    """
    Core synchronous modules — run together, scan completes when these finish.
    """
    deep = (scan_type == ScanType.DEEP)

    if target_type == TargetType.EMAIL:
        core = [EmailIntelModule()]
    elif target_type == TargetType.DOMAIN:
        core = [DomainIntelModule()]
    elif target_type == TargetType.PHONE:
        core = [PhoneIntelModule()]
    elif target_type == TargetType.USERNAME:
        core = [UsernameIntelModule()]
    elif target_type == TargetType.IP:
        core = [IPIntelModule()]
    elif target_type == TargetType.ORGANIZATION:
        core = [OrganizationIntelModule()]
    else:
        core = []

    return [(m, deep) for m in core]


def _get_async_modules(target_type: TargetType, scan_type: ScanType):
    """
    Async (fire-and-forget) modules — run in background daemon thread.
    Scan completes before these finish.
    """
    target_str = target_type.value
    return [(GoogleDorkModule(target_type=target_str), False)]


def _run_modules(scan_id: str, module_pairs: list, start_progress: int = 5):
    """
    Generic runner: executes a list of (module, deep) pairs for a scan,
    saves results to DB, and returns. Used for both core and async modules.
    """
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        total = len(module_pairs)
        import concurrent.futures, inspect

        for i, (module, deep) in enumerate(module_pairs):
            # Reuse a row pre-registered as PENDING (async modules), else create one
            db_module = db.query(ScanModule).filter(
                ScanModule.scan_id == scan.id, ScanModule.name == module.name
            ).first()
            if db_module is None:
                db_module = ScanModule(
                    scan_id=scan.id,
                    name=module.name,
                    display_name=module.display_name,
                )
                db.add(db_module)
            db_module.status = ModuleStatus.RUNNING
            db_module.progress = 0
            db_module.started_at = datetime.utcnow()
            db.commit()
            db.refresh(db_module)

            try:
                sig = inspect.signature(module.run)
                run_kwargs = {'deep': deep} if 'deep' in sig.parameters else {}

                # Dynamic timeout based on scan depth
                # Quick scans should be fast, Deep scans need time for Sherlock/h8mail
                scan_timeout = 300 if deep else 45
                
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                try:
                    future = executor.submit(module.run, scan.target_value, **run_kwargs)
                    try:
                        results: List[OSINTResult] = future.result(timeout=scan_timeout)
                    except concurrent.futures.TimeoutError:
                        logger.warning(f"Module {module.name} timed out after {scan_timeout}s, skipping")
                        results = []
                finally:
                    # shutdown(wait=False) so we don't hang the parent thread if a module hangs
                    executor.shutdown(wait=False)

                for osint_result in results:
                    db_result = Result(
                        scan_id=scan.id,
                        module_id=db_module.id,
                        module=module.name,
                        data_type=osint_result.data_type,
                        data=osint_result.data,
                        source=osint_result.source,
                        source_url=osint_result.source_url,
                        confidence=osint_result.confidence,
                    )
                    db.add(db_result)

                db_module.status = ModuleStatus.COMPLETED
                db_module.progress = 100
                db_module.completed_at = datetime.utcnow()
                db_module.result_count = len(results)

            except Exception as e:
                logger.error(f"Module {module.name} failed: {e}", exc_info=True)
                db_module.status = ModuleStatus.FAILED
                db_module.error = str(e)
                db_module.completed_at = datetime.utcnow()

            db.commit()

    except Exception as e:
        logger.error(f"_run_modules error for scan {scan_id}: {e}", exc_info=True)
        db.rollback()
    finally:
        db.close()


def execute_scan_sync(scan_id: str):
    """
    Execute an OSINT scan. Core modules run synchronously — scan is marked
    completed as soon as they finish. Async modules (Google Dork) run in a
    separate daemon thread so they never block the scan status.
    """
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found.")
            return

        if scan.status == ScanStatus.FAILED:
            logger.warning(f"Scan {scan_id} was already cancelled/failed.")
            return

        # Idempotent re-runs: a retried task (worker lost mid-scan) starts clean
        db.query(Result).filter(Result.scan_id == scan.id).delete(synchronize_session=False)
        db.query(ScanModule).filter(ScanModule.scan_id == scan.id).delete(synchronize_session=False)

        # Mark as running
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        scan.progress = 10
        db.commit()

        # ── Core modules (synchronous) ────────────────────────────────────
        core_pairs = _get_core_modules(scan.target_type, scan.scan_type)
        db.close()  # Close before handing off to _run_modules
        db = None

        _run_modules(scan_id, core_pairs)

        # Re-open to complete the scan status
        db = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()

        # Register async modules as PENDING in the same commit that completes the
        # scan, so clients polling the scan never see "completed, nothing running"
        # while background modules are still about to start.
        async_pairs = _get_async_modules(scan.target_type, scan.scan_type)
        for module, _ in async_pairs:
            db.add(ScanModule(
                scan_id=scan.id,
                name=module.name,
                display_name=module.display_name,
                status=ModuleStatus.PENDING,
                progress=0,
            ))

        scan.status = ScanStatus.COMPLETED
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.commit()
        logger.info(f"Scan {scan_id} core modules completed.")

        # ── Background modules (search dorks) ─────────────────────────────
        if async_pairs:
            dispatch_background_modules(str(scan_id))

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        try:
            if db:
                db.rollback()
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    scan.completed_at = datetime.utcnow()
                    db.commit()
        except Exception:
            pass
    finally:
        if db:
            db.close()



# ── Dispatch ─────────────────────────────────────────────────────────────
# SCAN_EXECUTOR=celery (default): scans run in the Celery worker, survive API
# restarts, and a worker killed mid-scan hands the task back to the queue.
# SCAN_EXECUTOR=thread: in-process threads, for local dev without Redis.
import os
import threading

from app.core.celery_app import celery_app


def _executor() -> str:
    from app.core.config import settings
    return settings.SCAN_EXECUTOR.lower()


def run_background_modules(scan_id: str):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        pairs = _get_async_modules(scan.target_type, scan.scan_type)
    finally:
        db.close()
    _run_modules(scan_id, pairs)
    _alert_watch_owner(scan_id)


def _alert_watch_owner(scan_id: str):
    from app.services.notify_service import watch_run_finished
    db = SessionLocal()
    try:
        watch_run_finished(db, scan_id)
    except Exception as e:
        db.rollback()
        logger.error(f"Watch alert for scan {scan_id} failed: {e}", exc_info=True)
    try:
        from app.services.footprint_service import on_watch_run
        on_watch_run(db, scan_id)  # "My footprint": actions + score
    except Exception as e:
        logger.error(f"Footprint recompute for scan {scan_id} failed: {e}", exc_info=True)
    finally:
        db.close()


def dispatch_scan(scan_id: str):
    if _executor() == "thread":
        threading.Thread(target=execute_scan_sync, args=(scan_id,), daemon=True, name=f"scan-{scan_id[:8]}").start()
    else:
        # task_id = scan id, so cancelling can revoke it
        run_scan_task.apply_async(args=[scan_id], task_id=scan_id)


def dispatch_background_modules(scan_id: str):
    if _executor() == "thread":
        threading.Thread(target=run_background_modules, args=(scan_id,), daemon=True, name=f"dork-{scan_id[:8]}").start()
    else:
        run_background_task.apply_async(args=[scan_id], task_id=f"{scan_id}:background")


@celery_app.task(name="osig.run_scan", acks_late=True, reject_on_worker_lost=True)
def run_scan_task(scan_id: str):
    execute_scan_sync(scan_id)


@celery_app.task(name="osig.run_background_modules", acks_late=True, reject_on_worker_lost=True)
def run_background_task(scan_id: str):
    run_background_modules(scan_id)


@celery_app.task(name="osig.run_due_watches")
def run_due_watches():
    """Beat task: start a scan for every watch that is due."""
    from datetime import timedelta
    from fastapi import HTTPException
    from app.models.investigation import Watch
    from app.models.user import User
    from app.schemas.scan import CreateScanRequest
    from app.services.scan_service import ScanService

    db = SessionLocal()
    started = 0
    try:
        now = datetime.utcnow()
        due = db.query(Watch).filter(Watch.active.is_(True), Watch.next_run_at <= now).limit(50).all()
        for w in due:
            user = db.query(User).filter(User.id == w.user_id, User.is_active.is_(True)).first()
            if not user:
                w.active = False
                continue
            try:
                ScanService.create_scan(db, user, CreateScanRequest(
                    target_type=w.target_type, target_value=w.target_value,
                    scan_type=w.scan_type, disclaimer_accepted=True,
                ), watch_id=w.id)
                w.last_run_at = now
                w.next_run_at = now + timedelta(hours=w.interval_hours)
                started += 1
            except HTTPException as e:
                if e.status_code == 402:  # no longer in the plan (e.g. deep scan after a downgrade)
                    logger.info(f"Watch {w.id} paused: {e.detail}")
                    w.active = False
                else:  # e.g. daily quota used up: try again later
                    logger.info(f"Watch {w.id} postponed: {e.detail}")
                    w.next_run_at = now + timedelta(hours=1)
        db.commit()
    finally:
        db.close()
    return started


def purge_expired_data(db) -> int:
    """Delete scans (with results and reports) older than the retention window:
    the user's own setting, capped by the server-wide DATA_RETENTION_DAYS."""
    from datetime import timedelta
    from app.core.config import settings
    from app.models.platform import MailOutbox
    from app.models.user import User

    now = datetime.utcnow()
    deleted = 0
    for user in db.query(User).all():
        from app.services.plan_limits import limit
        windows = [d for d in (user.retention_days, settings.DATA_RETENTION_DAYS,
                               limit(db, user, "max_retention_days")) if d and d > 0]
        if not windows:
            continue
        cutoff = now - timedelta(days=min(windows))
        for scan in db.query(Scan).filter(Scan.user_id == user.id, Scan.created_at < cutoff).all():
            for report in scan.reports:
                if report.file_path and os.path.exists(report.file_path):
                    os.remove(report.file_path)
            db.delete(scan)
            deleted += 1
    # Sent mail holds one-time links: keep 30 days for troubleshooting only
    db.query(MailOutbox).filter(MailOutbox.created_at < now - timedelta(days=30)).delete(synchronize_session=False)
    db.commit()
    return deleted


@celery_app.task(name="osig.purge_expired_data")
def purge_expired_data_task():
    db = SessionLocal()
    try:
        return purge_expired_data(db)
    finally:
        db.close()


@celery_app.task(name="osig.expire_plans")
def expire_plans_task():
    from app.services.billing_service import expire_plans
    db = SessionLocal()
    try:
        return expire_plans(db)
    finally:
        db.close()


@celery_app.task(name="osig.billing_reminders")
def billing_reminders_task():
    from app.services.billing_service import send_renewal_reminders
    db = SessionLocal()
    try:
        return send_renewal_reminders(db)
    finally:
        db.close()


@celery_app.task(name="osig.reconcile_payments")
def reconcile_payments_task():
    from app.services.billing_service import enabled, reconcile_pending
    if not enabled():
        return 0
    db = SessionLocal()
    try:
        return reconcile_pending(db)
    finally:
        db.close()


@celery_app.task(name="osig.weekly_digest")
def weekly_digest_task():
    from app.services.footprint_service import send_weekly_digests
    db = SessionLocal()
    try:
        return send_weekly_digests(db)
    finally:
        db.close()


@celery_app.task(name="osig.reconcile_subscriptions")
def reconcile_subscriptions_task():
    """Safety net for missed webhooks (e.g. OSIG was down): re-read Yoon subscriptions."""
    from app.models.user import User
    from app.services.billing_service import enabled
    from app.services.subscription_service import BillingError, reconcile_user
    if not enabled():
        return 0
    db = SessionLocal()
    done = 0
    try:
        for user in db.query(User).filter(User.yoon_customer_id.isnot(None)).limit(500).all():
            try:
                reconcile_user(db, user)
                done += 1
            except BillingError:
                db.rollback()
        return done
    finally:
        db.close()
