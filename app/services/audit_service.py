"""
OSIG Backend - Audit Log

Records who did what, from where: sign-ins, scans, reports, account changes.
Writes never break the request they describe.
"""
import logging
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


def client_ip(request: Optional[Request]) -> str:
    if request is None:
        return "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def record(db: Session, action: str, *, request: Optional[Request] = None,
           user_id=None, target: Optional[str] = None) -> None:
    try:
        db.add(AuditLog(
            user_id=user_id,
            action=action,
            target=target,
            ip_address=client_ip(request),
            user_agent=(request.headers.get("user-agent") if request else None),
        ))
        db.commit()
    except Exception as e:  # auditing must never fail the user's request
        db.rollback()
        logger.warning(f"Audit write failed for {action}: {e}")
