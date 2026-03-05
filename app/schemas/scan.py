"""
OSIG Backend - Scan Schemas

Pydantic schemas for scan-related requests and responses.
"""
from typing import Optional, List
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field, field_validator, ConfigDict
import re

from app.models.scan import TargetType, ScanType, ScanStatus


# Base Scan Schema
class ScanBase(BaseModel):
    """Base scan schema with common fields."""
    target_type: TargetType
    target_value: str = Field(..., min_length=1, max_length=255)
    scan_type: ScanType


# Create Scan Request
class CreateScanRequest(ScanBase):
    """Schema for creating a new scan."""
    disclaimer_accepted: bool = Field(..., description="User must accept disclaimer")
    
    @field_validator('disclaimer_accepted')
    @classmethod
    def validate_disclaimer(cls, v):
        if not v:
            raise ValueError('You must accept the disclaimer to proceed')
        return v
    
    @field_validator('target_value')
    @classmethod
    def validate_target_value(cls, v, info):
        """Validate target value based on target type."""
        target_type = info.data.get('target_type')
        
        if target_type == TargetType.EMAIL:
            # Email validation
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, v):
                raise ValueError('Invalid email format')
        
        elif target_type == TargetType.DOMAIN:
            # Domain validation
            domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            if not re.match(domain_pattern, v):
                raise ValueError('Invalid domain format')
        
        elif target_type == TargetType.PHONE:
            # Basic phone validation (digits, +, -, spaces, parentheses)
            phone_pattern = r'^[\d\s\-\+\(\)]{8,20}$'
            if not re.match(phone_pattern, v):
                raise ValueError('Invalid phone number format')
        
        elif target_type == TargetType.USERNAME:
            # Username validation (alphanumeric, underscore, hyphen)
            username_pattern = r'^[a-zA-Z0-9_-]{3,50}$'
            if not re.match(username_pattern, v):
                raise ValueError('Invalid username format (3-50 alphanumeric characters)')
        
        return v


# Scan Response
class ScanResponse(ScanBase):
    """Schema for scan response."""
    id: UUID
    user_id: UUID
    status: ScanStatus
    progress: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    error_message: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)


# Scan List Response
class ScanListResponse(BaseModel):
    """Schema for paginated scan list."""
    scans: List[ScanResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# Scan Query Parameters
class ScanQueryParams(BaseModel):
    """Query parameters for filtering scans."""
    status: Optional[ScanStatus] = None
    target_type: Optional[TargetType] = None
    scan_type: Optional[ScanType] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=10, ge=1, le=100)
