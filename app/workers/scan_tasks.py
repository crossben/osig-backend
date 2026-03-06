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


def _get_modules(target_type: TargetType, scan_type: ScanType):
    """
    Return the list of (module_instance, deep_flag) tuples for the given target.
    Google Dork always runs on both quick and deep.
    """
    deep = (scan_type == ScanType.DEEP)
    target_str = target_type.value  # "email", "username", "domain", "phone"

    # Core OSINT modules per target type
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

    # Google Dork runs on both quick and deep
    dork_module = GoogleDorkModule(target_type=target_str)

    # Return (module, deep_flag) pairs
    return [(m, deep) for m in core] + [(dork_module, False)]


def execute_scan_sync(scan_id: str):
    """
    Execute an OSINT scan synchronously in a background thread.
    Persists ScanModule rows and Result rows to the database.
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
        scan.progress = 5
        db.commit()

        module_pairs = _get_modules(scan.target_type, scan.scan_type)
        total_modules = len(module_pairs)
        all_results: List[OSINTResult] = []

        for i, (module, deep) in enumerate(module_pairs):
            # Create ScanModule record
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
                # Run the module — pass `deep` flag if the module accepts it
                import inspect
                sig = inspect.signature(module.run)
                if 'deep' in sig.parameters:
                    results: List[OSINTResult] = module.run(scan.target_value, deep=deep)
                else:
                    results: List[OSINTResult] = module.run(scan.target_value)

                all_results.extend(results)

                # Persist results
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

                # Update module status
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

            # Update overall progress
            scan.progress = int(((i + 1) / total_modules) * 95) + 5
            db.commit()

        # Complete scan
        scan.status = ScanStatus.COMPLETED
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.commit()
        logger.info(f"Scan {scan_id} completed. Total results: {len(all_results)}")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        db.rollback()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
