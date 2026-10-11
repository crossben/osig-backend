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
from app.models.investigation import Investigation, InvestigationPin, Watch
from app.models.platform import ApiKey, InvestigationMember, MailOutbox

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
    "Investigation",
    "InvestigationPin",
    "Watch",
    "ApiKey",
    "InvestigationMember",
    "MailOutbox",
]

from app.models.billing import Payment, Plan, YoonEvent  # noqa: E402,F401
from app.models.personal import ActionItem, HouseholdMember, Identity, PushSubscription, ScamCheck  # noqa: E402,F401
