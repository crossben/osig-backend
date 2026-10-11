"""
OSIG Backend - Scan API Endpoints

Handles scan creation, listing, and management.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy.orm import Session
from math import ceil

from app.services.graph_service import build_entity_graph
from app.services.risk_service import assess
from app.core.deps import get_db, get_current_user, get_verified_user
from app.schemas.scan import (
    CreateScanRequest,
    ScanResponse,
    ScanListResponse,
    ScanQueryParams
)
from app.models.scan import ScanStatus, TargetType, ScanType
from app.models.user import User
from app.services.scan_service import scan_service
from app.services import audit_service
from app.core.rate_limit import limiter
from app.core.config import settings

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_SCANS)
def create_scan(
    request: Request,
    scan_data: CreateScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_verified_user)
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
    audit_service.record(db, "scan_created", request=request, user_id=current_user.id,
                         target=f"{scan.id} {scan.target_type.value}:{scan.target_value}")
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
    scan = scan_service.get_scan(db, scan_id, str(current_user.id), allow_shared=True)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/details")
def get_scan_details(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get full scan details including modules, results, sources.
    """
    from app.models.scan import ScanModule
    from app.models.result import Result

    scan = scan_service.get_scan(db, scan_id, str(current_user.id), allow_shared=True)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    scan_data = ScanResponse.model_validate(scan)

    # Load modules and results from actual DB rows
    db_modules = db.query(ScanModule).filter(ScanModule.scan_id == scan.id).all()
    db_results = db.query(Result).filter(Result.scan_id == scan.id).all()

    modules_out = [
        {
            "id": str(m.id),
            "scan_id": str(m.scan_id),
            "name": m.name,
            "display_name": m.display_name,
            "status": m.status,
            "progress": m.progress,
            "started_at": m.started_at.isoformat() if m.started_at else None,
            "completed_at": m.completed_at.isoformat() if m.completed_at else None,
            "result_count": m.result_count,
            "error": m.error,
        }
        for m in db_modules
    ]

    results_out = [
        {
            "id": str(r.id),
            "scan_id": str(r.scan_id),
            "module_id": str(r.module_id),
            "module": r.module,
            "data_type": r.data_type,
            "data": r.data,
            "source": r.source,
            "source_url": r.source_url,
            "confidence": r.confidence,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in db_results
    ]

    total_results = len(db_results)
    unique_sources = list({r.source for r in db_results})

    status_label = scan.status.value
    risk = assess(scan, db_results)
    if status_label in ("pending", "running") and not risk["findings"]:
        top_findings = []
    else:
        top_findings = risk["findings"]

    return {
        "scan": scan_data,
        "modules": modules_out,
        "results": results_out,
        "sources": [
            {"id": s, "name": s, "url": "", "category": "osint", "last_checked": None, "reliability": 0.8, "data_types": []}
            for s in unique_sources
        ],
        "risk_flags": risk["flags"],
        "summary": {
            "total_results": total_results,
            "total_sources": len(unique_sources),
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "data_categories": list({r.data_type for r in db_results}),
            "top_findings": top_findings,
        }
    }

@router.get("/{scan_id}/graph")
def get_scan_graph(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Entity graph of everything the scan found: one node per distinct entity
    (IP, host, email, account, ...), linked to the sources that reported it
    and to related entities. See app/services/graph_service.py.
    """
    from app.models.result import Result

    scan = scan_service.get_scan(db, scan_id, str(current_user.id), allow_shared=True)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    db_results = db.query(Result).filter(Result.scan_id == scan.id).all()
    return build_entity_graph(scan, db_results)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    request: Request,
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
    audit_service.record(db, "scan_cancelled", request=request, user_id=current_user.id, target=str(scan.id))
    return ScanResponse.model_validate(scan)
