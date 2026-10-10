"""
OSIG Backend - Investigations and Watches

Investigation: a named case grouping related scans (usually built by pivoting
from one scan's findings to new targets), with notes, tags and pinned findings.
Watch: a target re-scanned on a schedule so changes over time show up.
"""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.db.session import Base
from app.models.scan import ScanType, TargetType


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    notes = Column(Text, nullable=True)
    tags = Column(JSONB, default=list, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    scans = relationship("Scan", back_populates="investigation")
    pins = relationship("InvestigationPin", back_populates="investigation", cascade="all, delete-orphan",
                        order_by="InvestigationPin.created_at")


class InvestigationPin(Base):
    """A graph entity the analyst marked as important, with an optional note."""
    __tablename__ = "investigation_pins"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    entity_id = Column(String(500), nullable=False)  # graph node id, e.g. "email:a@b.com"
    kind = Column(String(50), nullable=False)
    label = Column(String(500), nullable=False)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="pins")


class Watch(Base):
    __tablename__ = "watches"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_type = Column(Enum(TargetType), nullable=False)
    target_value = Column(String, nullable=False)
    scan_type = Column(Enum(ScanType), nullable=False, default=ScanType.QUICK)
    interval_hours = Column(Integer, nullable=False, default=24)
    active = Column(Boolean, nullable=False, default=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scans = relationship("Scan", back_populates="watch", order_by="Scan.created_at")
