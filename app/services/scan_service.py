"""
OSIG Backend - Scan Service

Business logic for scan management.
"""
from typing import Optional, List, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from fastapi import HTTPException, status

from app.models.scan import Scan, ScanStatus, TargetType, ScanType
from app.models.user import User, UserPlan
from app.schemas.scan import CreateScanRequest, ScanQueryParams
from app.core.config import settings


class ScanService:
    """Service for scan operations."""
    
    @staticmethod
    def get_daily_scan_limit(user: User) -> int:
        """Get daily scan limit based on user plan."""
        limits = {
            UserPlan.FREE: settings.FREE_DAILY_SCANS,
            UserPlan.PRO: settings.PRO_DAILY_SCANS,
            UserPlan.ENTERPRISE: settings.ENTERPRISE_DAILY_SCANS,
        }
        return limits.get(user.plan, settings.FREE_DAILY_SCANS)
    
    @staticmethod
    def get_user_scans_today(db: Session, user_id: str) -> int:
        """Count scans created by user today."""
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        
        count = db.query(func.count(Scan.id)).filter(
            and_(
                Scan.user_id == user_id,
                Scan.created_at >= today_start
            )
        ).scalar()
        
        return count or 0
    
    @staticmethod
    def check_scan_quota(db: Session, user: User) -> Tuple[bool, int, int]:
        """
        Check if user has remaining scan quota.
        
        Returns:
            Tuple of (has_quota, used_today, daily_limit)
        """
        daily_limit = ScanService.get_daily_scan_limit(user)
        used_today = ScanService.get_user_scans_today(db, str(user.id))
        
        has_quota = used_today < daily_limit
        return has_quota, used_today, daily_limit
    
    @staticmethod
    def create_scan(db: Session, user: User, scan_data: CreateScanRequest, *,
                    investigation_id=None, parent_scan_id=None, pivot_entity: Optional[str] = None,
                    watch_id=None) -> Scan:
        """
        Create a new scan.
        
        Args:
            db: Database session
            user: User creating the scan
            scan_data: Scan creation data
            
        Returns:
            Created scan object
            
        Raises:
            HTTPException: If user has exceeded quota
        """
        # Check quota
        has_quota, used_today, daily_limit = ScanService.check_scan_quota(db, user)
        
        if not has_quota:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Daily scan limit exceeded. You have used {used_today}/{daily_limit} scans today."
            )
        
        # Create scan
        db_scan = Scan(
            user_id=user.id,
            target_type=scan_data.target_type,
            target_value=scan_data.target_value,
            scan_type=scan_data.scan_type,
            status=ScanStatus.PENDING,
            progress=0,
            investigation_id=investigation_id,
            parent_scan_id=parent_scan_id,
            pivot_entity=pivot_entity,
            watch_id=watch_id,
        )
        
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        
        # Hand off to the worker (or a thread when SCAN_EXECUTOR=thread)
        from app.workers.scan_tasks import dispatch_scan
        dispatch_scan(str(db_scan.id))
        
        return db_scan
    
    @staticmethod
    def get_user_scans(
        db: Session,
        user_id: str,
        params: ScanQueryParams
    ) -> Tuple[List[Scan], int]:
        """
        Get user's scans with pagination and filtering.
        
        Returns:
            Tuple of (scans_list, total_count)
        """
        query = db.query(Scan).filter(Scan.user_id == user_id)
        
        # Apply filters
        if params.status:
            query = query.filter(Scan.status == params.status)
        
        if params.target_type:
            query = query.filter(Scan.target_type == params.target_type)
        
        if params.scan_type:
            query = query.filter(Scan.scan_type == params.scan_type)
        
        # Get total count before pagination
        total = query.count()
        
        # Apply pagination
        scans = query.order_by(Scan.created_at.desc())\
            .offset((params.page - 1) * params.page_size)\
            .limit(params.page_size)\
            .all()
        
        return scans, total
    
    @staticmethod
    def get_scan(db: Session, scan_id: str, user_id: str) -> Optional[Scan]:
        """Get scan by ID (user must own the scan)."""
        return db.query(Scan).filter(
            and_(
                Scan.id == scan_id,
                Scan.user_id == user_id
            )
        ).first()
    
    @staticmethod
    def cancel_scan(db: Session, scan: Scan) -> Scan:
        """Cancel a running scan."""
        if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel scan with status: {scan.status.value}"
            )
        
        scan.status = ScanStatus.FAILED
        scan.error_message = "Scan cancelled by user"
        scan.completed_at = datetime.utcnow()
        
        db.commit()
        db.refresh(scan)
        
        # Stop the worker task if one is running (no-op in thread mode)
        try:
            from app.core.celery_app import celery_app
            celery_app.control.revoke(str(scan.id), terminate=True)
            celery_app.control.revoke(f"{scan.id}:background", terminate=True)
        except Exception:
            pass
        
        return scan



# Service instance
scan_service = ScanService()
