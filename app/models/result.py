"""
OSIG Backend - Result and Source Models

SQLAlchemy models for results and sources tables.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.session import Base


class Result(Base):
    """Result model for storing OSINT findings."""
    
    __tablename__ = "results"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    module_id = Column(UUID(as_uuid=True), ForeignKey("scan_modules.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Result data
    module = Column(String, nullable=False)  # Module name
    data_type = Column(String, nullable=False, index=True)  # e.g., "social_profile", "email", "subdomain"
    data = Column(JSONB, nullable=False)  # Flexible JSON storage
    
    # Source information
    source = Column(String, nullable=False)  # e.g., "GitHub", "Holehe"
    source_url = Column(String, nullable=True)  # URL to the finding
    
    # Metadata
    confidence = Column(Float, default=1.0, nullable=False)  # 0.0 - 1.0
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="results")
    module_ref = relationship("ScanModule", back_populates="results")
    
    def __repr__(self):
        return f"<Result {self.data_type} from {self.source}>"


class Source(Base):
    """Source model for tracking OSINT data sources."""
    
    __tablename__ = "sources"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Source information
    name = Column(String, unique=True, nullable=False, index=True)  # e.g., "GitHub", "Holehe"
    url = Column(String, nullable=False)
    category = Column(String, nullable=False)  # e.g., "social", "search", "dns"
    
    # Metadata
    last_checked = Column(DateTime, default=datetime.utcnow, nullable=False)
    reliability = Column(Float, default=0.8, nullable=False)  # 0.0 - 1.0
    data_types = Column(JSONB, default=list, nullable=False)  # List of data types this source provides
    
    def __repr__(self):
        return f"<Source {self.name} ({self.category})>"
