"""
OSIG Backend - Scan Models

SQLAlchemy models for scans and scan_modules tables.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum

from app.db.session import Base


class TargetType(str, enum.Enum):
    """Types of scan targets."""
    EMAIL = "email"
    USERNAME = "username"
    DOMAIN = "domain"
    PHONE = "phone"


class ScanType(str, enum.Enum):
    """Scan depth types."""
    QUICK = "quick"
    DEEP = "deep"


class ScanStatus(str, enum.Enum):
    """Scan execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ModuleStatus(str, enum.Enum):
    """Module execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Scan(Base):
    """Scan model for OSINT scans."""
    
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Scan configuration
    target_type = Column(Enum(TargetType), nullable=False, index=True)
    target_value = Column(String, nullable=False)
    scan_type = Column(Enum(ScanType), nullable=False)
    
    # Scan status
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    progress = Column(Integer, default=0, nullable=False)  # 0-100
    
    # Timestamps
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="scans")
    modules = relationship("ScanModule", back_populates="scan", cascade="all, delete-orphan")
    results = relationship("Result", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan {self.id} - {self.target_type.value}: {self.target_value}>"


class ScanModule(Base):
    """Scan module execution tracking."""
    
    __tablename__ = "scan_modules"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Module info
    name = Column(String, nullable=False)  # e.g., "email_intel", "sherlock"
    display_name = Column(String, nullable=False)  # e.g., "Email Intelligence", "Username Search"
    
    # Status
    status = Column(Enum(ModuleStatus), default=ModuleStatus.PENDING, nullable=False)
    progress = Column(Integer, default=0, nullable=False)  # 0-100
    
    # Timestamps
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Results
    result_count = Column(Integer, default=0, nullable=False)
    error = Column(Text, nullable=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="modules")
    results = relationship("Result", back_populates="module", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ScanModule {self.display_name} - {self.status.value}>"
