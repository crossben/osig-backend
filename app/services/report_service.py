"""
OSIG Backend - Report Service

Business logic for generating and managing reports.
"""
import os
import json
from uuid import UUID
from datetime import datetime, timedelta
from typing import Tuple, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.report import Report, ReportFormat, ReportStatus
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.schemas.report import CreateReportRequest
from app.core.config import settings

class ReportService:
    def get_user_reports(self, db: Session, user_id: str, page: int = 1, page_size: int = 10) -> Tuple[List[Report], int]:
        query = db.query(Report).filter(Report.user_id == user_id)
        
        total = query.count()
        reports = query.order_by(desc(Report.created_at)).offset((page - 1) * page_size).limit(page_size).all()
        
        return reports, total

    def create_report(self, db: Session, current_user: User, report_data: CreateReportRequest) -> Report:
        scan = db.query(Scan).filter(Scan.id == report_data.scan_id, Scan.user_id == current_user.id).first()
        if not scan:
            raise ValueError("Scan not found or access denied")
        if scan.status != ScanStatus.COMPLETED:
            raise ValueError("Scan must be completed to generate a report")
            
        report = Report(
            user_id=current_user.id,
            scan_id=scan.id,
            name=report_data.name or f"Report_{scan.target_value}_{datetime.now().strftime('%Y%m%d')}",
            format=report_data.format,
            status=ReportStatus.GENERATING,
            expires_at=datetime.utcnow() + timedelta(days=30)
        )
        
        db.add(report)
        db.commit()
        db.refresh(report)
        
        # We would typically dispatch to a celery task here.
        # For now, we simulate synchronous generation for JSON.
        try:
            self._generate_report_sync(db, report, scan)
        except Exception as e:
            report.status = ReportStatus.FAILED
            db.commit()
        
        return report
        
    def _generate_report_sync(self, db: Session, report: Report, scan: Scan):
        # Determine paths
        # Ensure a directory exists for storing reports
        reports_dir = os.path.join(os.getcwd(), "storage", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        file_path = os.path.join(reports_dir, f"{report.id}.{report.format.value}")
        
        # Build payload
        payload = {
            "report_name": report.name,
            "scan_id": str(scan.id),
            "target_type": scan.target_type.value,
            "target_value": scan.target_value,
            "generated_at": datetime.utcnow().isoformat(),
            "results": [{"module": mod.name, "result_count": mod.result_count} for mod in scan.modules]
        }
        
        if report.format == ReportFormat.JSON:
            with open(file_path, "w") as f:
                json.dump(payload, f, indent=4)
        elif report.format == ReportFormat.PDF:
            # Requires ReportLab or WeasyPrint
            try:
                from reportlab.pdfgen import canvas
                c = canvas.Canvas(file_path)
                c.drawString(100, 800, f"OSIG Report: {report.name}")
                c.drawString(100, 780, f"Target: {scan.target_value} ({scan.target_type.value})")
                c.drawString(100, 760, f"Date: {datetime.utcnow().isoformat()}")
                y = 720
                for mod in scan.modules:
                    c.drawString(100, y, f"- {mod.name}: {mod.result_count} results")
                    y -= 20
                c.drawString(100, y-20, "Disclaimer: Public info only.")
                c.save()
            except ImportError:
                raise Exception("ReportLab is not installed.")
                
        # Update db record
        report.file_path = file_path
        report.file_size = os.path.getsize(file_path)
        report.status = ReportStatus.READY
        # URL would be handled via a static route or S3. Providing a default local URL base pattern:
        report.download_url = f"{settings.API_V1_PREFIX}/reports/{report.id}/download"
        db.commit()

    def get_report(self, db: Session, report_id: str, user_id: str) -> Optional[Report]:
        return db.query(Report).filter(Report.id == report_id, Report.user_id == user_id).first()

report_service = ReportService()
