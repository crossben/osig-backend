"""
OSIG Backend - Billing models.

Plans are prepaid periods paid through Yoon (self-hosted payment gateway):
mobile money can't be debited automatically, so each period is a one-off
payment and the plan runs until users.plan_expires_at.
"""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


class Plan(Base):
    """A plan's prices and limits. The slug matches users.plan (free, pro, enterprise)."""
    __tablename__ = "plans"

    slug = Column(String(20), primary_key=True)
    name = Column(String(60), nullable=False)
    rank = Column(Integer, nullable=False, default=0)  # higher = more; drives upgrade vs downgrade
    is_active = Column(Boolean, nullable=False, default=True, server_default="true")
    self_serve = Column(Boolean, nullable=False, default=True, server_default="true")  # false: "contact us"
    # {"XOF": {"month": 5000, "year": 50000}, "USD": {"month": 900}} in minor units
    prices = Column(JSONB, nullable=False, default=dict)
    # see app/services/plan_limits.py for the keys
    limits = Column(JSONB, nullable=False, default=dict)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Payment(Base):
    """One purchase of a plan period. Only a signed Yoon event (or Yoon's own
    status, when OSIG asks) can mark it paid; the return URL proves nothing."""
    __tablename__ = "payments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    reference = Column(String(40), nullable=False, unique=True, index=True)
    yoon_payment_id = Column(String(64), nullable=True, unique=True, index=True)
    plan = Column(String(20), nullable=False)
    period = Column(String(10), nullable=False)
    amount = Column(Integer, nullable=False)  # minor units
    currency = Column(String(3), nullable=False)
    country = Column(String(2), nullable=False)
    method = Column(String(32), nullable=True)
    status = Column(String(10), nullable=False, default="pending", index=True)  # pending | paid | failed | expired
    failure_reason = Column(Text, nullable=True)
    paid_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = relationship("User")


class YoonEvent(Base):
    """Yoon webhook event ids already handled (deliveries are at-least-once)."""
    __tablename__ = "yoon_events"

    id = Column(String(80), primary_key=True)
    type = Column(String(60), nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow, nullable=False)
