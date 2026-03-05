"""
OSIG Backend - Reports API Endpoints

Handles report creation, listing, and downloading.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from math import ceil
import os

from app.core.deps import get_db, get_current_user
from app.schemas.report import CreateReportRequest, ReportResponse, ReportListResponse
from app.models.report import ReportStatus
from app.models.user import User
from app.services.report_service import report_service

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.post("", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
def create_report(
    report_data: CreateReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate a new report for a specific scan.
    """
    try:
        report = report_service.create_report(db, current_user, report_data)
        return ReportResponse.model_validate(report)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Report generation failed.")

@router.get("", response_model=ReportListResponse)
def list_reports(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List user's reports with pagination.
    """
    reports, total = report_service.get_user_reports(db, str(current_user.id), page, page_size)
    
    return ReportListResponse(
        reports=[ReportResponse.model_validate(r) for r in reports],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=ceil(total / page_size) if total > 0 else 0
    )


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Download a generated report file.
    """
    report = report_service.get_report(db, report_id, str(current_user.id))
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
        
    if report.status != ReportStatus.READY or not report.file_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report is not ready for download."
        )
        
    if not os.path.exists(report.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file is missing from server."
        )
        
    return FileResponse(
        path=report.file_path,
        filename=f"{report.name}.{report.format.value}",
        media_type="application/pdf" if report.format.value == "pdf" else "application/json"
    )
