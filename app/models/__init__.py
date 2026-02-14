"""
OSIG Backend - Models Package

Imports all models for Alembic to detect.
"""
from app.db.session import Base
from app.models.user import User
from app.models.scan import Scan, ScanModule
from app.models.result import Result, Source
from app.models.report import Report
from app.models.audit_log import AuditLog

# Export all models
__all__ = [
    "Base",
    "User",
    "Scan",
    "ScanModule",
    "Result",
    "Source",
    "Report",
    "AuditLog",
]
