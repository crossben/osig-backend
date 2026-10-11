"""
OSIG Backend - Platform models: API keys, investigation sharing, mail outbox.
"""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


class ApiKey(Base):
    """Personal API key for scripts and the CLI. Only a SHA-256 of the key is stored."""
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    prefix = Column(String(16), nullable=False)  # shown in the UI to tell keys apart
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False, server_default="false", nullable=False)

    user = relationship("User")


class InvestigationMember(Base):
    """A user an investigation is shared with."""
    __tablename__ = "investigation_members"
    __table_args__ = (UniqueConstraint("investigation_id", "user_id", name="uq_investigation_member"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(10), nullable=False, default="viewer")  # viewer | editor
    added_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")
    investigation = relationship("Investigation", back_populates="members")


class MailOutbox(Base):
    """Every email OSIG sends (or would send, without SMTP configured)."""
    __tablename__ = "mail_outbox"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    to = Column(String, nullable=False, index=True)
    subject = Column(String(300), nullable=False)
    body = Column(Text, nullable=False)
    kind = Column(String(40), nullable=False)
    sent = Column(Boolean, default=False, server_default="false", nullable=False)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
