"""
OSIG Backend - AuditLog Model

SQLAlchemy model for audit_logs table.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


class AuditLog(Base):
    """Audit log model for tracking user actions."""
    
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Action information
    action = Column(String, nullable=False, index=True)  # e.g., "scan_created", "login", "report_generated"
    target = Column(String, nullable=True)  # Target of the action (e.g., scan ID, report ID)
    
    # Request metadata
    ip_address = Column(String, nullable=False)
    user_agent = Column(Text, nullable=True)
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog {self.action} by User {self.user_id} at {self.created_at}>"
