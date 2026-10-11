"""
OSIG Backend - Investigations API

A case groups scans (typically grown by pivoting from one scan's findings to
new targets) with notes, tags and pinned findings, and exposes one merged
entity graph and one combined report across all of them.
"""
import io
import json
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps import get_current_user, get_db, get_verified_user
from app.core.rate_limit import limiter
from app.models.investigation import Investigation, InvestigationPin
from app.models.platform import InvestigationMember
from app.models.result import Result
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import CreateScanRequest, PivotRequest, ScanResponse
from app.services import audit_service
from app.services.graph_service import build_graph
from app.services.scan_service import scan_service

router = APIRouter(tags=["Investigations"])


# ── schemas ──────────────────────────────────────────────────────
class InvestigationIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    notes: Optional[str] = Field(None, max_length=20000)
    tags: List[str] = Field(default_factory=list, max_length=20)
    scan_ids: List[UUID] = Field(default_factory=list)


class InvestigationPatch(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    notes: Optional[str] = Field(None, max_length=20000)
    tags: Optional[List[str]] = Field(None, max_length=20)


class PinIn(BaseModel):
    entity_id: str = Field(..., max_length=500)
    kind: str = Field(..., max_length=50)
    label: str = Field(..., max_length=500)
    note: Optional[str] = Field(None, max_length=5000)


class PinOut(BaseModel):
    id: UUID
    entity_id: str
    kind: str
    label: str
    note: Optional[str]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class InvestigationSummary(BaseModel):
    id: UUID
    name: str
    tags: List[str]
    scan_count: int
    created_at: datetime
    updated_at: datetime
    role: str = "owner"
    owner: Optional[str] = None


class MemberOut(BaseModel):
    user_id: UUID
    email: str
    username: str
    role: str
    added_at: datetime


class MemberIn(BaseModel):
    email: str = Field(..., max_length=320)
    role: str = Field("viewer", pattern="^(viewer|editor)$")


class InvestigationOut(BaseModel):
    id: UUID
    name: str
    notes: Optional[str]
    tags: List[str]
    created_at: datetime
    updated_at: datetime
    scans: List[ScanResponse]
    pins: List[PinOut]
    role: str = "owner"
    owner: Optional[str] = None
    members: List[MemberOut] = []


# ── helpers ──────────────────────────────────────────────────────
ROLE_RANK = {"viewer": 1, "editor": 2, "owner": 3}


def role_of(db: Session, user: User, inv: Investigation) -> Optional[str]:
    if inv.user_id == user.id:
        return "owner"
    m = db.query(InvestigationMember).filter(InvestigationMember.investigation_id == inv.id,
                                             InvestigationMember.user_id == user.id).first()
    return m.role if m else None


def _get(db: Session, user: User, investigation_id: UUID, need: str = "owner") -> Investigation:
    """The investigation, if the user's role on it is at least `need` (viewer < editor < owner)."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    role = role_of(db, user, inv) if inv else None
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    if ROLE_RANK[role] < ROLE_RANK[need]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You can view this investigation but not change it" if role == "viewer"
                            else "Only the owner can do that")
    inv._role = role
    return inv


def _clean_tags(tags: List[str]) -> List[str]:
    return list(dict.fromkeys(t.strip().lower()[:40] for t in tags if t and t.strip()))


def _members(inv: Investigation) -> List[MemberOut]:
    return [MemberOut(user_id=m.user_id, email=m.user.email, username=m.user.username, role=m.role,
                      added_at=m.added_at) for m in sorted(inv.members, key=lambda m: m.added_at)]


def _out(inv: Investigation) -> InvestigationOut:
    scans = sorted(inv.scans, key=lambda s: s.created_at)
    role = getattr(inv, "_role", "owner")
    return InvestigationOut(
        id=inv.id, name=inv.name, notes=inv.notes, tags=inv.tags or [],
        created_at=inv.created_at, updated_at=inv.updated_at,
        scans=[ScanResponse.model_validate(s) for s in scans],
        pins=[PinOut.model_validate(p) for p in inv.pins],
        role=role, owner=inv.user.username if inv.user else None,
        members=_members(inv) if role == "owner" else [],
    )


def _scans_with_results(db: Session, inv: Investigation):
    scans = sorted(inv.scans, key=lambda s: s.created_at)
    if not scans:
        return []
    results = db.query(Result).filter(Result.scan_id.in_([s.id for s in scans])).all()
    by_scan = {}
    for r in results:
        by_scan.setdefault(r.scan_id, []).append(r)
    return [(s, by_scan.get(s.id, [])) for s in scans]


# ── investigations ───────────────────────────────────────────────
@router.get("/investigations", response_model=List[InvestigationSummary])
def list_investigations(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    shared = {m.investigation_id: m.role for m in
              db.query(InvestigationMember).filter(InvestigationMember.user_id == user.id).all()}
    rows = (
        db.query(Investigation, func.count(Scan.id))
        .outerjoin(Scan, Scan.investigation_id == Investigation.id)
        .filter(or_(Investigation.user_id == user.id, Investigation.id.in_(list(shared) or [None])))
        .group_by(Investigation.id)
        .order_by(Investigation.updated_at.desc())
        .all()
    )
    return [InvestigationSummary(id=i.id, name=i.name, tags=i.tags or [], scan_count=n,
                                 created_at=i.created_at, updated_at=i.updated_at,
                                 role="owner" if i.user_id == user.id else shared[i.id],
                                 owner=None if i.user_id == user.id else (i.user.username if i.user else None))
            for i, n in rows]


@router.post("/investigations", response_model=InvestigationOut, status_code=status.HTTP_201_CREATED)
def create_investigation(body: InvestigationIn, request: Request, db: Session = Depends(get_db),
                         user: User = Depends(get_current_user)):
    inv = Investigation(user_id=user.id, name=body.name.strip(), notes=body.notes, tags=_clean_tags(body.tags))
    db.add(inv)
    db.flush()
    if body.scan_ids:
        db.query(Scan).filter(Scan.id.in_(body.scan_ids), Scan.user_id == user.id) \
            .update({Scan.investigation_id: inv.id}, synchronize_session=False)
    db.commit()
    db.refresh(inv)
    audit_service.record(db, "investigation_created", request=request, user_id=user.id, target=str(inv.id))
    return _out(inv)


@router.get("/investigations/{investigation_id}", response_model=InvestigationOut)
def get_investigation(investigation_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return _out(_get(db, user, investigation_id, "viewer"))


@router.patch("/investigations/{investigation_id}", response_model=InvestigationOut)
def update_investigation(investigation_id: UUID, body: InvestigationPatch, db: Session = Depends(get_db),
                         user: User = Depends(get_current_user)):
    inv = _get(db, user, investigation_id, "editor")
    changes = body.model_dump(exclude_unset=True)
    if "name" in changes:
        inv.name = changes["name"].strip()
    if "notes" in changes:
        inv.notes = changes["notes"]
    if "tags" in changes:
        inv.tags = _clean_tags(changes["tags"] or [])
    inv.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(inv)
    return _out(inv)


@router.delete("/investigations/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_investigation(investigation_id: UUID, request: Request, db: Session = Depends(get_db),
                         user: User = Depends(get_current_user)):
    """Deletes the case only; its scans stay in scan history."""
    inv = _get(db, user, investigation_id)
    db.delete(inv)
    db.commit()
    audit_service.record(db, "investigation_deleted", request=request, user_id=user.id, target=str(investigation_id))


@router.post("/investigations/{investigation_id}/scans/{scan_id}", response_model=InvestigationOut)
def add_scan(investigation_id: UUID, scan_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    inv = _get(db, user, investigation_id, "editor")
    scan = scan_service.get_scan(db, str(scan_id), str(user.id))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    scan.investigation_id = inv.id
    inv.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(inv)
    return _out(inv)


@router.delete("/investigations/{investigation_id}/scans/{scan_id}", response_model=InvestigationOut)
def remove_scan(investigation_id: UUID, scan_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    inv = _get(db, user, investigation_id, "editor")
    db.query(Scan).filter(Scan.id == scan_id, Scan.investigation_id == inv.id) \
        .update({Scan.investigation_id: None}, synchronize_session=False)
    db.commit()
    db.refresh(inv)
    return _out(inv)


@router.get("/investigations/{investigation_id}/graph")
def investigation_graph(investigation_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    inv = _get(db, user, investigation_id, "viewer")
    pairs = _scans_with_results(db, inv)
    if not pairs:
        return {"nodes": [], "edges": [], "kinds": [], "counts": {}}
    graph = build_graph(pairs)
    pinned = {p.entity_id for p in inv.pins}
    for n in graph["nodes"]:
        n["pinned"] = n["id"] in pinned
    return graph


# ── pins ─────────────────────────────────────────────────────────
@router.post("/investigations/{investigation_id}/pins", response_model=PinOut, status_code=status.HTTP_201_CREATED)
def add_pin(investigation_id: UUID, body: PinIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    inv = _get(db, user, investigation_id, "editor")
    existing = next((p for p in inv.pins if p.entity_id == body.entity_id), None)
    if existing:
        existing.note = body.note if body.note is not None else existing.note
        pin = existing
    else:
        pin = InvestigationPin(investigation_id=inv.id, **body.model_dump())
        db.add(pin)
    inv.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(pin)
    return PinOut.model_validate(pin)


@router.delete("/investigations/{investigation_id}/pins/{pin_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_pin(investigation_id: UUID, pin_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    inv = _get(db, user, investigation_id, "editor")
    db.query(InvestigationPin).filter(InvestigationPin.id == pin_id, InvestigationPin.investigation_id == inv.id).delete()
    db.commit()


# ── combined report ──────────────────────────────────────────────
@router.get("/investigations/{investigation_id}/report")
def investigation_report(investigation_id: UUID, request: Request, format: str = Query("pdf", pattern="^(pdf|json)$"),
                         db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    inv = _get(db, user, investigation_id, "viewer")
    pairs = _scans_with_results(db, inv)
    audit_service.record(db, "investigation_report", request=request, user_id=user.id, target=f"{inv.id} {format}")
    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in inv.name)[:60] or "investigation"
    if format == "json":
        payload = {
            "investigation": {"id": str(inv.id), "name": inv.name, "notes": inv.notes, "tags": inv.tags},
            "pins": [{"entity": p.entity_id, "kind": p.kind, "label": p.label, "note": p.note} for p in inv.pins],
            "scans": [{
                "id": str(s.id), "target_type": s.target_type.value, "target_value": s.target_value,
                "scan_type": s.scan_type.value, "status": s.status.value, "pivot_from": s.pivot_entity,
                "created_at": s.created_at.isoformat(),
                "results": [{"module": r.module, "source": r.source, "data_type": r.data_type,
                             "confidence": r.confidence, "source_url": r.source_url, "data": r.data} for r in rs],
            } for s, rs in pairs],
        }
        body = io.BytesIO(json.dumps(payload, indent=2, default=str).encode())
        return StreamingResponse(body, media_type="application/json",
                                 headers={"Content-Disposition": f'attachment; filename="{safe_name}.json"'})
    from app.services.report_pdf import render_investigation_pdf
    buf = io.BytesIO()
    render_investigation_pdf(buf, inv, pairs)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f'attachment; filename="{safe_name}.pdf"'})


# ── pivot ────────────────────────────────────────────────────────
@router.post("/scans/{scan_id}/pivot", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_SCANS)
def pivot(scan_id: UUID, body: PivotRequest, request: Request, db: Session = Depends(get_db),
          user: User = Depends(get_verified_user)):
    """
    Scan an entity found by another scan. Both scans land in the same
    investigation (created on first pivot), so their graphs merge.
    """
    parent = scan_service.get_scan(db, str(scan_id), str(user.id), allow_shared=True)
    if not parent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if parent.user_id != user.id:
        _get(db, user, parent.investigation_id, "editor")
    if not parent.investigation_id:
        inv = Investigation(user_id=user.id, name=parent.target_value, tags=[])
        db.add(inv)
        db.flush()
        parent.investigation_id = inv.id
        db.commit()
    data = CreateScanRequest(target_type=body.target_type, target_value=body.target_value,
                             scan_type=body.scan_type, disclaimer_accepted=True)
    scan = scan_service.create_scan(db, user, data, investigation_id=parent.investigation_id,
                                    parent_scan_id=parent.id, pivot_entity=body.entity_id)
    db.query(Investigation).filter(Investigation.id == parent.investigation_id) \
        .update({Investigation.updated_at: datetime.utcnow()}, synchronize_session=False)
    db.commit()
    audit_service.record(db, "scan_pivoted", request=request, user_id=user.id,
                         target=f"{scan.id} from {parent.id} via {body.entity_id}")
    return ScanResponse.model_validate(scan)


# ── sharing ──────────────────────────────────────────────────────
@router.get("/investigations/{investigation_id}/members", response_model=List[MemberOut])
def list_members(investigation_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return _members(_get(db, user, investigation_id, "owner"))


@router.post("/investigations/{investigation_id}/members", response_model=List[MemberOut])
def add_member(investigation_id: UUID, body: MemberIn, request: Request, db: Session = Depends(get_db),
               user: User = Depends(get_verified_user)):
    """Share with another OSIG user by email. Viewers read; editors also pin, note and pivot."""
    inv = _get(db, user, investigation_id, "owner")
    from app.services import plan_limits
    plan_limits.require(db, user, "sharing", "Sharing investigations isn't included in your plan.")
    other = db.query(User).filter(User.email == body.email.strip().lower(), User.is_active.is_(True)).first()
    if not other:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="No OSIG account uses that email. Ask them to sign up first.")
    if other.id == user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You already own this investigation")
    member = next((m for m in inv.members if m.user_id == other.id), None)
    if member:
        member.role = body.role
    else:
        if len(inv.members) >= 25:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Share with at most 25 people")
        db.add(InvestigationMember(investigation_id=inv.id, user_id=other.id, role=body.role))
    db.commit()
    db.refresh(inv)
    audit_service.record(db, "investigation_shared", request=request, user_id=user.id,
                         target=f"{inv.id} {other.id} {body.role}")
    return _members(inv)


@router.delete("/investigations/{investigation_id}/members/{member_user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(investigation_id: UUID, member_user_id: UUID, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    """The owner removes anyone; a member can remove themselves (leave)."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv or (inv.user_id != user.id and member_user_id != user.id) or not role_of(db, user, inv):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    db.query(InvestigationMember).filter(InvestigationMember.investigation_id == inv.id,
                                         InvestigationMember.user_id == member_user_id).delete()
    db.commit()
    audit_service.record(db, "investigation_unshared", request=request, user_id=user.id,
                         target=f"{inv.id} {member_user_id}")


# ── bulk scans ───────────────────────────────────────────────────
MAX_BULK = 50


class BulkIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    csv: str = Field(..., max_length=100_000)
    scan_type: str = Field("quick", pattern="^(quick|deep)$")
    disclaimer_accepted: bool


def parse_bulk_csv(text: str):
    """Rows of `type,value` (a header row is optional). Returns (targets, errors)."""
    import csv as _csv
    targets, errors, seen = [], [], set()
    for n, row in enumerate(_csv.reader(io.StringIO(text)), start=1):
        cells = [c.strip() for c in row if c.strip()]
        if not cells or cells[0].startswith("#"):
            continue
        if n == 1 and cells[0].lower() in ("type", "target_type"):
            continue
        if len(cells) < 2:
            errors.append({"line": n, "error": "Expected type,value"})
            continue
        kind, value = cells[0].lower(), cells[1]
        try:
            req = CreateScanRequest(target_type=kind, target_value=value, scan_type="quick", disclaimer_accepted=True)
        except ValidationError as e:
            msg = e.errors()[0]["msg"].removeprefix("Value error, ")
            errors.append({"line": n, "error": f"{value}: {msg}"})
            continue
        key = (req.target_type.value, req.target_value.lower())
        if key not in seen:
            seen.add(key)
            targets.append(req)
    return targets, errors


@router.post("/investigations/bulk", status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_SCANS)
def bulk_scan(body: BulkIn, request: Request, db: Session = Depends(get_db), user: User = Depends(get_verified_user)):
    """Start one scan per CSV row, all inside a new investigation."""
    if not body.disclaimer_accepted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Accept the terms of use first")
    from app.services import plan_limits
    bulk_max = plan_limits.limit(db, user, "bulk_max") or 0
    if not bulk_max:
        raise plan_limits.PlanLimitReached("Bulk scans aren't included in your plan.")
    targets, errors = parse_bulk_csv(body.csv)
    if not targets:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail={"message": "No valid rows to scan", "errors": errors})
    if len(targets) > min(MAX_BULK, bulk_max):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"At most {min(MAX_BULK, bulk_max)} targets per batch")
    has_quota, used, limit = scan_service.check_scan_quota(db, user)
    if used + len(targets) > limit:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail=f"That would use {len(targets)} scans; you have {max(limit - used, 0)} left today")
    inv = Investigation(user_id=user.id, name=body.name.strip(), tags=["bulk"])
    db.add(inv)
    db.commit()
    started = []
    for t in targets:
        t.scan_type = body.scan_type
        scan = scan_service.create_scan(db, user, t, investigation_id=inv.id)
        started.append(str(scan.id))
    audit_service.record(db, "bulk_scan", request=request, user_id=user.id, target=f"{inv.id} {len(started)} scans")
    return {"investigation_id": str(inv.id), "started": len(started), "scan_ids": started, "errors": errors}
