"""
OSIG Backend - User Model

SQLAlchemy model for users table.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Enum, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum

from app.db.session import Base


class UserPlan(str, enum.Enum):
    """User subscription plan types."""
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class User(Base):
    """User model for authentication and authorization."""
    
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)

    # Sign-in with Google: stable Google account id ("sub" claim)
    google_sub = Column(String, unique=True, index=True, nullable=True)
    # False for accounts created through Google until they set a password
    has_password = Column(Boolean, default=True, server_default="true", nullable=False)

    # Ownership of the email address confirmed (link sent by email, or Google)
    email_verified = Column(Boolean, default=False, server_default="false", nullable=False)
    # Bumped to revoke every session at once (password change, sign out everywhere, 2FA change)
    session_version = Column(Integer, default=0, server_default="0", nullable=False)

    # Two-factor sign-in (TOTP). Secret is encrypted at rest; recovery codes are hashed.
    totp_secret_enc = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False, server_default="false", nullable=False)
    recovery_codes = Column(JSONB, default=list, server_default="[]", nullable=False)

    # Preferences
    retention_days = Column(Integer, nullable=True)  # auto-delete scans older than this
    notify_email = Column(Boolean, default=True, server_default="true", nullable=False)
    webhook_url = Column(String, nullable=True)  # Slack / Discord / generic JSON webhook
    language = Column(String(5), default="en", server_default="en", nullable=False)
    # Billing: prepaid plan periods (see app/models/billing.py)
    plan_expires_at = Column(DateTime, nullable=True)  # null on a paid plan = granted without end
    plan_source = Column(String(10), nullable=True)  # purchase | comp
    pending_plan = Column(String(20), nullable=True)  # lower plan bought while a higher one runs
    pending_plan_days = Column(Integer, nullable=True)
    renewal_reminded_at = Column(DateTime, nullable=True)
    
    # Plan and status
    plan = Column(Enum(UserPlan), default=UserPlan.FREE, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    @property
    def google_linked(self) -> bool:
        return bool(self.google_sub)

    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User {self.username} ({self.email})>"
