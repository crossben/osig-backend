"""
OSIG Backend - Personal protection models.

- ScamCheck: a quick "is this a scam?" verdict on a link, number, address or
  message, with a public share id (the share page shows the verdict and a
  redacted subject, never the pasted message).
- Identity: the user's OWN email / phone / username / domain, watched for
  exposure. Emails and phones must be proven (link / code) before watching.
- ActionItem: a to-do derived from findings ("change your password on X"),
  keyed so it isn't recreated after the user completes or dismisses it.
- HouseholdMember: people a Pro user protects (they accept an invitation and
  keep control of their own identities).
- PushSubscription: Web Push endpoints for alerts on phones and desktops.
"""
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


class ScamCheck(Base):
    __tablename__ = "scam_checks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    share_id = Column(String(16), nullable=False, unique=True, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    kind = Column(String(10), nullable=False)  # url | domain | email | phone | message
    subject = Column(String(300), nullable=False)  # what the share page may show (redacted)
    input_hash = Column(String(64), nullable=False, index=True)  # sha256 of the normalised input, for caching
    verdict = Column(String(12), nullable=False)  # scam | suspicious | no_red_flags | unknown
    score = Column(Integer, nullable=False, default=0)  # 0-100, higher = riskier
    reasons = Column(JSONB, nullable=False, default=list)  # [{code, severity, text, evidence?}]
    details = Column(JSONB, nullable=False, default=dict)  # per-check raw facts (owner only)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class Identity(Base):
    __tablename__ = "identities"
    __table_args__ = (UniqueConstraint("user_id", "kind", "value", name="uq_identity"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(10), nullable=False)  # email | phone | username | domain
    value = Column(String(320), nullable=False)
    label = Column(String(60), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    verify_code_hash = Column(String(64), nullable=True)  # phone/domain codes; emails use a signed link
    verify_expires_at = Column(DateTime, nullable=True)
    watch_id = Column(UUID(as_uuid=True), ForeignKey("watches.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    watch = relationship("Watch")


class ActionItem(Base):
    __tablename__ = "action_items"
    __table_args__ = (UniqueConstraint("user_id", "key", name="uq_action_item"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    identity_id = Column(UUID(as_uuid=True), ForeignKey("identities.id", ondelete="CASCADE"), nullable=True)
    key = Column(String(200), nullable=False)  # stable: e.g. "breach:linkedin:me@x.com"
    severity = Column(String(10), nullable=False, default="medium")
    title = Column(String(300), nullable=False)
    detail = Column(Text, nullable=True)
    link = Column(String(500), nullable=True)
    status = Column(String(10), nullable=False, default="open", index=True)  # open | done | dismissed
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)


class HouseholdMember(Base):
    __tablename__ = "household_members"
    __table_args__ = (UniqueConstraint("owner_id", "email", name="uq_household_email"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    member_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    email = Column(String(320), nullable=False)
    status = Column(String(10), nullable=False, default="invited")  # invited | active
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    accepted_at = Column(DateTime, nullable=True)


class PushSubscription(Base):
    __tablename__ = "push_subscriptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint = Column(Text, nullable=False, unique=True)
    p256dh = Column(String(200), nullable=False)
    auth = Column(String(100), nullable=False)
    user_agent = Column(String(300), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
