"""
OSIG Backend - Watches API

A watch re-scans a target on a schedule; /changes diffs the entities found by
the two most recent completed runs (new subdomain, new breach, DNS change...).
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db
from app.models.investigation import Watch
from app.models.result import Result
from app.models.scan import Scan, ScanStatus, ScanType, TargetType
from app.models.user import User
from app.schemas.scan import CreateScanRequest
from app.services import audit_service
from app.services.graph_service import build_entity_graph

router = APIRouter(prefix="/watches", tags=["Watches"])

MAX_WATCHES = 20


class WatchIn(BaseModel):
    target_type: TargetType
    target_value: str = Field(..., min_length=1, max_length=320)
    scan_type: ScanType = ScanType.QUICK
    interval_hours: int = Field(24, ge=6, le=24 * 30)

    @field_validator("target_value")
    @classmethod
    def strip(cls, v: str) -> str:
        return v.strip()


class WatchPatch(BaseModel):
    interval_hours: Optional[int] = Field(None, ge=6, le=24 * 30)
    active: Optional[bool] = None


class WatchOut(BaseModel):
    id: UUID
    target_type: TargetType
    target_value: str
    scan_type: ScanType
    interval_hours: int
    active: bool
    last_run_at: Optional[datetime]
    next_run_at: datetime
    created_at: datetime
    run_count: int = 0
    latest_scan_id: Optional[UUID] = None
    model_config = ConfigDict(from_attributes=True)


def _out(w: Watch) -> WatchOut:
    out = WatchOut.model_validate(w)
    out.run_count = len(w.scans)
    out.latest_scan_id = w.scans[-1].id if w.scans else None
    return out


def _get(db: Session, user: User, watch_id: UUID) -> Watch:
    w = db.query(Watch).filter(Watch.id == watch_id, Watch.user_id == user.id).first()
    if not w:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Watch not found")
    return w


@router.get("", response_model=List[WatchOut])
def list_watches(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return [_out(w) for w in db.query(Watch).filter(Watch.user_id == user.id).order_by(Watch.created_at.desc()).all()]


@router.post("", response_model=WatchOut, status_code=status.HTTP_201_CREATED)
def create_watch(body: WatchIn, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # Validate the target with the same rules as a manual scan
    CreateScanRequest(target_type=body.target_type, target_value=body.target_value,
                      scan_type=body.scan_type, disclaimer_accepted=True)
    if db.query(Watch).filter(Watch.user_id == user.id).count() >= MAX_WATCHES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"You can watch up to {MAX_WATCHES} targets")
    w = Watch(user_id=user.id, target_type=body.target_type, target_value=body.target_value,
              scan_type=body.scan_type, interval_hours=body.interval_hours, next_run_at=datetime.utcnow())
    db.add(w)
    db.commit()
    db.refresh(w)
    audit_service.record(db, "watch_created", request=request, user_id=user.id,
                         target=f"{w.id} {w.target_type.value}:{w.target_value}")
    return _out(w)


@router.patch("/{watch_id}", response_model=WatchOut)
def update_watch(watch_id: UUID, body: WatchPatch, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    w = _get(db, user, watch_id)
    if body.interval_hours is not None:
        w.interval_hours = body.interval_hours
        if w.last_run_at:
            w.next_run_at = w.last_run_at + timedelta(hours=w.interval_hours)
    if body.active is not None:
        w.active = body.active
        if body.active and w.next_run_at < datetime.utcnow():
            w.next_run_at = datetime.utcnow()
    db.commit()
    db.refresh(w)
    return _out(w)


@router.delete("/{watch_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_watch(watch_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Stops watching; scans already run stay in history."""
    db.delete(_get(db, user, watch_id))
    db.commit()


def _entities(db: Session, scan: Scan, include_search: bool) -> Dict[str, dict]:
    results = db.query(Result).filter(Result.scan_id == scan.id).all()
    if not include_search:
        # Search-engine hits reshuffle between runs; they'd drown real changes
        results = [r for r in results if r.data_type != "dork_result"]
    graph = build_entity_graph(scan, results)
    return {n["id"]: {"id": n["id"], "kind": n["kind"], "label": n["label"]}
            for n in graph["nodes"] if n["kind"] not in ("target", "source")}


def _finished(scan: Scan) -> bool:
    """Completed AND every module (incl. background ones) has answered."""
    return scan.status == ScanStatus.COMPLETED and all(
        m.status.value not in ("pending", "running") for m in scan.modules)


@router.get("/{watch_id}/changes")
def watch_changes(watch_id: UUID, include_search: bool = False, db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    """What appeared and disappeared between the two most recent finished runs."""
    w = _get(db, user, watch_id)
    runs = [s for s in w.scans if _finished(s)]
    if len(runs) < 2:
        return {"compared": None, "added": [], "removed": [], "runs": len(runs)}
    prev, latest = runs[-2], runs[-1]
    before, after = _entities(db, prev, include_search), _entities(db, latest, include_search)
    added = sorted((after[k] for k in after.keys() - before.keys()), key=lambda e: (e["kind"], e["label"]))
    removed = sorted((before[k] for k in before.keys() - after.keys()), key=lambda e: (e["kind"], e["label"]))
    return {
        "compared": {"previous_scan_id": str(prev.id), "previous_at": prev.created_at,
                     "latest_scan_id": str(latest.id), "latest_at": latest.created_at},
        "added": added, "removed": removed, "runs": len(runs),
    }
