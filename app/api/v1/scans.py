"""
OSIG Backend - Scan API Endpoints

Handles scan creation, listing, and management.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from math import ceil

from app.core.deps import get_db, get_current_user
from app.schemas.scan import (
    CreateScanRequest,
    ScanResponse,
    ScanListResponse,
    ScanQueryParams
)
from app.models.scan import ScanStatus, TargetType, ScanType
from app.models.user import User
from app.services.scan_service import scan_service

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    scan_data: CreateScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new OSINT scan.
    
    - **target_type**: Type of target (email, username, domain, phone)
    - **target_value**: The actual target value
    - **scan_type**: Scan depth (quick or deep)
    - **disclaimer_accepted**: Must be true
    
    Quota limits apply based on user plan:
    - Free: 5 scans/day
    - Pro: 50 scans/day
    - Enterprise: Unlimited
    """
    scan = scan_service.create_scan(db, current_user, scan_data)
    return ScanResponse.model_validate(scan)


@router.get("", response_model=ScanListResponse)
def list_scans(
    status: Optional[ScanStatus] = Query(None, description="Filter by status"),
    target_type: Optional[TargetType] = Query(None, description="Filter by target type"),
    scan_type: Optional[ScanType] = Query(None, description="Filter by scan type"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List user's scans with pagination and filtering.
    
    Returns paginated list of scans with total count.
    """
    # Build query params
    params = ScanQueryParams(
        status=status,
        target_type=target_type,
        scan_type=scan_type,
        page=page,
        page_size=page_size
    )
    
    # Get scans
    scans, total = scan_service.get_user_scans(db, str(current_user.id), params)
    
    # Build response
    return ScanListResponse(
        scans=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=ceil(total / page_size) if total > 0 else 0
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get scan details by ID.
    
    User must own the scan.
    """
    scan = scan_service.get_scan(db, scan_id, str(current_user.id))
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return ScanResponse.model_validate(scan)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Cancel a running scan.
    
    Only pending or running scans can be cancelled.
    """
    scan = scan_service.get_scan(db, scan_id, str(current_user.id))
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    scan = scan_service.cancel_scan(db, scan)
    return ScanResponse.model_validate(scan)


@router.get("/quota/status")
def get_quota_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get user's current scan quota status.
    
    Returns used scans today and daily limit.
    """
    has_quota, used_today, daily_limit = scan_service.check_scan_quota(db, current_user)
    
    return {
        "plan": current_user.plan.value,
        "daily_limit": daily_limit,
        "used_today": used_today,
        "remaining": daily_limit - used_today,
        "has_quota": has_quota
    }
