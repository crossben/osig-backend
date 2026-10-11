"""
OSIG Backend - API keys and the admin console.

API keys ("osig_" + 40 random chars) authenticate scripts and the CLI with the
same rights as the user, except managing keys and admin actions. Only a
SHA-256 of each key is stored; the key itself is shown once.

Admin endpoints need is_superuser and an interactive session.
"""
import secrets
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.crypto import sha256
from app.core.deps import get_admin_user, get_db, get_session_user
from app.models.audit_log import AuditLog
from app.models.platform import ApiKey, MailOutbox
from app.models.scan import Scan
from app.models.user import User, UserPlan
from app.services import audit_service

router = APIRouter(tags=["Platform"])
MAX_KEYS = 10


# ── API keys ─────────────────────────────────────────────────────
class ApiKeyIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class ApiKeyOut(BaseModel):
    id: UUID
    name: str
    prefix: str
    created_at: datetime
    last_used_at: Optional[datetime]
    model_config = ConfigDict(from_attributes=True)


class ApiKeyCreated(ApiKeyOut):
    key: str


@router.get("/api-keys", response_model=List[ApiKeyOut])
def list_keys(db: Session = Depends(get_db), user: User = Depends(get_session_user)):
    return db.query(ApiKey).filter(ApiKey.user_id == user.id, ApiKey.revoked.is_(False)) \
        .order_by(ApiKey.created_at.desc()).all()


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_key(body: ApiKeyIn, request: Request, db: Session = Depends(get_db), user: User = Depends(get_session_user)):
    if not user.email_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Confirm your email address first. Check your inbox for the link.")
    from app.services import plan_limits
    active = db.query(ApiKey).filter(ApiKey.user_id == user.id, ApiKey.revoked.is_(False)).count()
    if active >= MAX_KEYS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"You can have up to {MAX_KEYS} keys")
    if not plan_limits.limit(db, user, "api_keys"):
        raise plan_limits.PlanLimitReached("API keys aren't included in your plan.")
    plan_limits.require_below(db, user, "api_keys", active, "Your plan allows {limit} API keys.")
    raw = "osig_" + secrets.token_urlsafe(30)
    key = ApiKey(user_id=user.id, name=body.name.strip(), prefix=raw[:12], key_hash=sha256(raw))
    db.add(key)
    db.commit()
    db.refresh(key)
    audit_service.record(db, "api_key_created", request=request, user_id=user.id, target=f"{key.id} {key.prefix}")
    return ApiKeyCreated(**ApiKeyOut.model_validate(key).model_dump(), key=raw)


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_key(key_id: UUID, request: Request, db: Session = Depends(get_db), user: User = Depends(get_session_user)):
    key = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.user_id == user.id).first()
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")
    key.revoked = True
    db.commit()
    audit_service.record(db, "api_key_revoked", request=request, user_id=user.id, target=str(key.id))


# ── admin ────────────────────────────────────────────────────────
class AdminUserOut(BaseModel):
    id: UUID
    email: str
    username: str
    plan: UserPlan
    is_active: bool
    is_superuser: bool
    email_verified: bool
    totp_enabled: bool
    google_linked: bool
    created_at: datetime
    scan_count: int = 0
    last_login: Optional[datetime] = None


class AdminUserPatch(BaseModel):
    plan: Optional[UserPlan] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    email_verified: Optional[bool] = None


@router.get("/admin/stats")
def admin_stats(db: Session = Depends(get_db), _admin: User = Depends(get_admin_user)):
    day = datetime.utcnow() - timedelta(days=1)
    week = datetime.utcnow() - timedelta(days=7)
    by_status = dict(db.query(Scan.status, func.count(Scan.id)).group_by(Scan.status).all())
    by_type = dict(db.query(Scan.target_type, func.count(Scan.id)).group_by(Scan.target_type).all())
    return {
        "users": db.query(User).count(),
        "users_7d": db.query(User).filter(User.created_at >= week).count(),
        "scans": db.query(Scan).count(),
        "scans_24h": db.query(Scan).filter(Scan.created_at >= day).count(),
        "scans_by_status": {k.value: v for k, v in by_status.items()},
        "scans_by_type": {k.value: v for k, v in by_type.items()},
        "failed_logins_24h": db.query(AuditLog).filter(AuditLog.action.in_(["login_failed", "mfa_failed"]),
                                                       AuditLog.created_at >= day).count(),
        "mail_pending": db.query(MailOutbox).filter(MailOutbox.sent.is_(False)).count(),
    }


@router.get("/admin/users", response_model=List[AdminUserOut])
def admin_users(q: str = "", limit: int = Query(50, le=200), offset: int = 0,
                db: Session = Depends(get_db), _admin: User = Depends(get_admin_user)):
    query = db.query(User)
    if q.strip():
        like = f"%{q.strip().lower()}%"
        query = query.filter(or_(func.lower(User.email).like(like), func.lower(User.username).like(like)))
    users = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    ids = [u.id for u in users]
    counts = dict(db.query(Scan.user_id, func.count(Scan.id)).filter(Scan.user_id.in_(ids)).group_by(Scan.user_id).all())
    logins = dict(db.query(AuditLog.user_id, func.max(AuditLog.created_at))
                  .filter(AuditLog.user_id.in_(ids), AuditLog.action.like("login%")).group_by(AuditLog.user_id).all())
    return [AdminUserOut(id=u.id, email=u.email, username=u.username, plan=u.plan, is_active=u.is_active,
                         is_superuser=u.is_superuser, email_verified=bool(u.email_verified),
                         totp_enabled=bool(u.totp_enabled), google_linked=u.google_linked,
                         created_at=u.created_at, scan_count=counts.get(u.id, 0), last_login=logins.get(u.id))
            for u in users]


@router.patch("/admin/users/{user_id}", response_model=AdminUserOut)
def admin_update_user(user_id: UUID, body: AdminUserPatch, request: Request, db: Session = Depends(get_db),
                      admin: User = Depends(get_admin_user)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    if u.id == admin.id and (changes.get("is_active") is False or changes.get("is_superuser") is False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You can't lock yourself out")
    for k, v in changes.items():
        setattr(u, k, v)
    if changes.get("is_active") is False:
        u.session_version = (u.session_version or 0) + 1  # sign them out now
    db.commit()
    db.refresh(u)
    audit_service.record(db, "admin_user_updated", request=request, user_id=admin.id,
                         target=f"{u.id} " + ",".join(f"{k}={getattr(v, 'value', v)}" for k, v in changes.items()))
    return admin_users(q=u.email, limit=1, offset=0, db=db, _admin=admin)[0]


@router.get("/admin/audit")
def admin_audit(action: str = "", user_id: Optional[UUID] = None, limit: int = Query(100, le=500), offset: int = 0,
                db: Session = Depends(get_db), _admin: User = Depends(get_admin_user)):
    query = db.query(AuditLog, User.email).outerjoin(User, User.id == AuditLog.user_id)
    if action:
        query = query.filter(AuditLog.action.like(f"{action}%"))
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    rows = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return [{"id": str(a.id), "action": a.action, "target": a.target, "user_id": str(a.user_id) if a.user_id else None,
             "email": email, "ip_address": a.ip_address, "user_agent": a.user_agent, "created_at": a.created_at}
            for a, email in rows]


@router.get("/admin/mail")
def admin_mail(limit: int = Query(50, le=200), db: Session = Depends(get_db), _admin: User = Depends(get_admin_user)):
    """Recent outgoing mail. Bodies are omitted: they hold one-time sign-in links."""
    rows = db.query(MailOutbox).order_by(MailOutbox.created_at.desc()).limit(limit).all()
    return [{"id": str(m.id), "to": m.to, "subject": m.subject, "kind": m.kind, "sent": m.sent,
             "error": m.error, "created_at": m.created_at} for m in rows]
