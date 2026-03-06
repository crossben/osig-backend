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
            db_module = ScanModule(
                scan_id=scan.id,
                name=module.name,
                display_name=module.display_name,
                status=ModuleStatus.RUNNING,
                progress=0,
                started_at=datetime.utcnow(),
            )
            db.add(db_module)
            db.commit()
            db.refresh(db_module)

            try:
                sig = inspect.signature(module.run)
                run_kwargs = {'deep': deep} if 'deep' in sig.parameters else {}

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(module.run, scan.target_value, **run_kwargs)
                    try:
                        results: List[OSINTResult] = future.result(timeout=25)
                    except concurrent.futures.TimeoutError:
                        logger.warning(f"Module {module.name} timed out, skipping")
                        results = []

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
        scan.status = ScanStatus.COMPLETED
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.commit()
        logger.info(f"Scan {scan_id} core modules completed.")

        # ── Async modules (fire-and-forget) ───────────────────────────────
        async_pairs = _get_async_modules(scan.target_type, scan.scan_type)
        if async_pairs:
            import threading
            t = threading.Thread(
                target=_run_modules,
                args=(str(scan_id), async_pairs),
                daemon=True,
                name=f"dork-{scan_id[:8]}",
            )
            t.start()
            logger.info(f"Dork thread started for scan {scan_id}")

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

