"""
OSIG Backend - Analysis API

Map, timeline, STIX 2.1 / MISP exports for one scan or a whole investigation,
and comparing any two scans you can read.
"""
import io
import json
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.v1.investigations import _get as get_investigation, _scans_with_results
from app.core.deps import get_current_user, get_db
from app.models.result import Result
from app.models.user import User
from app.services import analysis_service, audit_service
from app.services.diff_service import diff
from app.services.scan_service import scan_service

router = APIRouter(tags=["Analysis"])


def _scan_pairs(db: Session, user: User, scan_id: UUID) -> List[tuple]:
    scan = scan_service.get_scan(db, str(scan_id), str(user.id), allow_shared=True)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return [(scan, db.query(Result).filter(Result.scan_id == scan.id).all())]


def _inv_pairs(db: Session, user: User, investigation_id: UUID):
    inv = get_investigation(db, user, investigation_id, "viewer")
    return inv, _scans_with_results(db, inv)


def _download(payload: dict, filename: str) -> StreamingResponse:
    body = io.BytesIO(json.dumps(payload, indent=2, default=str).encode())
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in filename)[:80]
    return StreamingResponse(body, media_type="application/json",
                             headers={"Content-Disposition": f'attachment; filename="{safe}"'})


def _require_exports(db: Session, user: User) -> None:
    from app.services import plan_limits
    plan_limits.require(db, user, "exports", "STIX and MISP exports aren't included in your plan.")


def _export(pairs, name: str, fmt: str) -> StreamingResponse:
    if fmt == "stix":
        return _download(analysis_service.stix_bundle(pairs, name), f"{name}.stix.json")
    return _download(analysis_service.misp_event(pairs, name), f"{name}.misp.json")


# ── one scan ─────────────────────────────────────────────────────
@router.get("/scans/{scan_id}/map")
def scan_map(scan_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return {"points": analysis_service.map_points(_scan_pairs(db, user, scan_id))}


@router.get("/scans/{scan_id}/timeline")
def scan_timeline(scan_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return {"events": analysis_service.timeline(_scan_pairs(db, user, scan_id))}


@router.get("/scans/{scan_id}/export")
def scan_export(scan_id: UUID, request: Request, format: str = Query(..., pattern="^(stix|misp)$"),
                db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _require_exports(db, user)
    pairs = _scan_pairs(db, user, scan_id)
    audit_service.record(db, "scan_export", request=request, user_id=user.id, target=f"{scan_id} {format}")
    return _export(pairs, pairs[0][0].target_value, format)


@router.get("/scans/{scan_id}/compare/{other_id}")
def compare_scans(scan_id: UUID, other_id: UUID, include_search: bool = False,
                  db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """What `other` (usually the newer scan) has that `scan` doesn't, and the reverse."""
    (a, _), (b, _) = _scan_pairs(db, user, scan_id)[0], _scan_pairs(db, user, other_id)[0]
    d = diff(db, a, b, include_search)
    side = lambda s: {"id": str(s.id), "target_type": s.target_type.value, "target_value": s.target_value,  # noqa: E731
                      "scan_type": s.scan_type.value, "created_at": s.created_at}
    return {"before": side(a), "after": side(b), **d}


# ── investigations ───────────────────────────────────────────────
@router.get("/investigations/{investigation_id}/map")
def investigation_map(investigation_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _inv, pairs = _inv_pairs(db, user, investigation_id)
    return {"points": analysis_service.map_points(pairs)}


@router.get("/investigations/{investigation_id}/timeline")
def investigation_timeline(investigation_id: UUID, db: Session = Depends(get_db),
                           user: User = Depends(get_current_user)):
    _inv, pairs = _inv_pairs(db, user, investigation_id)
    return {"events": analysis_service.timeline(pairs)}


@router.get("/investigations/{investigation_id}/export")
def investigation_export(investigation_id: UUID, request: Request, format: str = Query(..., pattern="^(stix|misp)$"),
                         db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _require_exports(db, user)
    inv, pairs = _inv_pairs(db, user, investigation_id)
    audit_service.record(db, "investigation_export", request=request, user_id=user.id, target=f"{inv.id} {format}")
    return _export(pairs, inv.name, format)
