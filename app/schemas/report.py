"""
OSIG Backend - Report Schemas

Pydantic schemas for report-related requests and responses.
"""
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.models.report import ReportFormat, ReportStatus

class ReportBase(BaseModel):
    name: str
    format: ReportFormat

class CreateReportRequest(ReportBase):
    scan_id: str

class ReportResponse(ReportBase):
    id: str
    scan_id: str
    user_id: str
    status: ReportStatus
    file_size: Optional[int] = None
    download_url: Optional[str] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)

class ReportListResponse(BaseModel):
    reports: List[ReportResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
