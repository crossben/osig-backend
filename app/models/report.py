"""
OSIG Backend - Report Model

SQLAlchemy model for reports table.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum

from app.db.session import Base


class ReportFormat(str, enum.Enum):
    """Report file formats."""
    PDF = "pdf"
    JSON = "json"


class ReportStatus(str, enum.Enum):
    """Report generation status."""
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"


class Report(Base):
    """Report model for generated scan reports."""
    
    __tablename__ = "reports"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Report info
    name = Column(String, nullable=False)
    format = Column(Enum(ReportFormat), nullable=False)
    status = Column(Enum(ReportStatus), default=ReportStatus.GENERATING, nullable=False)
    
    # File storage
    file_path = Column(String, nullable=True)  # Local file path
    file_size = Column(Integer, nullable=True)  # Size in bytes
    download_url = Column(String, nullable=True)  # Download URL
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=True)  # Report expiration date
    
    # Relationships
    scan = relationship("Scan", back_populates="reports")
    user = relationship("User", back_populates="reports")
    
    def __repr__(self):
        return f"<Report {self.name} ({self.format.value}) - {self.status.value}>"
