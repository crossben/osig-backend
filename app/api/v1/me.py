"""
OSIG Backend - "My footprint" (personal protection) API

The user's own identifiers, the actions derived from their findings, the
exposure score, household protection, Web Push subscriptions and opt-out /
deletion request letters. See app/services/footprint_service.py.
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import List, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps import get_current_user, get_db, get_verified_user
from app.core.rate_limit import limiter
from app.core.security import create_purpose_token, decode_token
from app.models.personal import ActionItem, HouseholdMember, Identity, PushSubscription
from app.models.platform import MailOutbox
from app.models.scan import ScanType, TargetType
from app.models.user import User
from app.schemas.scan import CreateScanRequest
from app.services import audit_service, footprint_service, mail_service, plan_limits, push_service

router = APIRouter(prefix="/me", tags=["My footprint"])

IDENTITY_TOKEN_MINUTES = 48 * 60
INVITE_TOKEN_MINUTES = 7 * 24 * 60
CODE_MINUTES = 15


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ── identities ──────────────────────────────────────────────────────────

class IdentityIn(BaseModel):
    kind: Literal["email", "phone", "username", "domain"]
    value: str = Field(..., min_length=1, max_length=320)
    label: Optional[str] = Field(None, max_length=60)


class VerifyIn(BaseModel):
    code: Optional[str] = Field(None, max_length=20)


class TokenIn(BaseModel):
    token: str


def _identity_out(db: Session, ident: Identity) -> dict:
    verified = ident.verified_at is not None
    out = {
        "id": str(ident.id), "kind": ident.kind, "value": ident.value, "label": ident.label,
        "verified": verified, "watching": bool(ident.watch_id),
        "last_checked_at": ident.watch.last_run_at if ident.watch else None,
        "findings": db.query(ActionItem).filter(ActionItem.identity_id == ident.id,
                                                ActionItem.status == "open").count(),
        "created_at": ident.created_at, "verification": None,
    }
    if not verified:
        if ident.kind == "domain":
            out["verification"] = {"method": "dns_txt", "record": f"osig-verify={footprint_service.domain_code(ident)}",
                                   "host": ident.value}
        elif ident.kind == "email":
            out["verification"] = {"method": "email_link"}
        elif ident.kind == "phone":
            out["verification"] = ({"method": "sms_code"} if settings.SMS_ENABLED else
                                   {"method": "unavailable", "message": "SMS verification coming soon"})
        elif ident.kind == "username":
            out["verification"] = {"method": "none"}
    return out


def _get_identity(db: Session, user: User, identity_id: UUID) -> Identity:
    ident = db.query(Identity).filter(Identity.id == identity_id, Identity.user_id == user.id).first()
    if not ident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
    return ident


def _send_identity_link(db: Session, user: User, ident: Identity) -> None:
    token = create_purpose_token("verify_identity", str(user.id), IDENTITY_TOKEN_MINUTES,
                                 iid=str(ident.id), value=ident.value)
    mail_service.send(
        db, ident.value, "Confirm this address for OSIG",
        f"Hi,\n\n{user.email} asked OSIG to watch {ident.value} for leaks and breaches.\n"
        "If this address is yours, confirm it here:\n\n"
        f"{mail_service.link('/verify-identity?token=' + token)}\n\n"
        "The link works for 48 hours. If you don't know this request, ignore this email: nothing will be watched.\n",
        kind="verify_identity")


def _send_phone_code(db: Session, ident: Identity) -> None:
    code = f"{secrets.randbelow(1_000_000):06d}"
    ident.verify_code_hash = _sha(f"{ident.id}:{code}")
    ident.verify_expires_at = datetime.utcnow() + timedelta(minutes=CODE_MINUTES)
    db.commit()
    # No SMS provider yet: the outbox is the (dev) sender
    mail_service.send(db, ident.value, "OSIG code", f"Your OSIG verification code: {code}", kind="sms_code")


def _mark_verified(db: Session, user: User, ident: Identity) -> None:
    ident.verified_at = datetime.utcnow()
    ident.verify_code_hash = None
    ident.verify_expires_at = None
    footprint_service.ensure_watch(db, user, ident)
    db.commit()


@router.get("/identities")
def list_identities(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.query(Identity).filter(Identity.user_id == user.id).order_by(Identity.created_at).all()
    return [_identity_out(db, i) for i in rows]


@router.post("/identities", status_code=status.HTTP_201_CREATED)
def add_identity(body: IdentityIn, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(get_verified_user)):
    value = body.value.strip()
    if body.kind in ("email", "domain"):
        value = value.lower()
    try:  # same rules as a scan target
        value = CreateScanRequest(target_type=TargetType(body.kind), target_value=value,
                                  scan_type=ScanType.QUICK, disclaimer_accepted=True).target_value
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail=str(e.errors()[0].get("msg", "Invalid value")).removeprefix("Value error, "))
    if db.query(Identity).filter(Identity.user_id == user.id, Identity.kind == body.kind,
                                 Identity.value == value).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="You already added this identity.")
    plan_limits.require_below(db, user, "identities", db.query(Identity).filter(Identity.user_id == user.id).count(),
                              "Your plan protects up to {limit} identities.")
    ident = Identity(user_id=user.id, kind=body.kind, value=value, label=body.label)
    db.add(ident)
    db.flush()
    if body.kind == "email" and value == user.email.lower() and user.email_verified:
        ident.verified_at = datetime.utcnow()
    elif body.kind == "domain":
        ident.verify_code_hash = _sha(footprint_service.domain_code(ident))
    footprint_service.ensure_watch(db, user, ident)
    db.commit()
    db.refresh(ident)
    if body.kind == "email" and not ident.verified_at:
        _send_identity_link(db, user, ident)
    elif body.kind == "phone" and settings.SMS_ENABLED:
        _send_phone_code(db, ident)
    audit_service.record(db, "identity_added", request=request, user_id=user.id, target=f"{ident.id} {ident.kind}")
    return _identity_out(db, ident)


@router.delete("/identities/{identity_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_identity(identity_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    footprint_service.delete_identity(db, _get_identity(db, user, identity_id))
    footprint_service.recompute(db, user, notify=False)


@router.post("/identities/{identity_id}/verify")
def verify_identity(identity_id: UUID, body: VerifyIn, db: Session = Depends(get_db),
                    user: User = Depends(get_verified_user)):
    """email: resend the link. phone: check the code (or send one when no code given). domain: check DNS TXT."""
    ident = _get_identity(db, user, identity_id)
    if ident.verified_at or ident.kind == "username":
        return _identity_out(db, ident)
    if ident.kind == "email":
        recent = db.query(MailOutbox).filter(MailOutbox.to == ident.value, MailOutbox.kind == "verify_identity",
                                             MailOutbox.created_at >= datetime.utcnow() - timedelta(minutes=2)).first()
        if not recent:
            _send_identity_link(db, user, ident)
        return _identity_out(db, ident)
    if ident.kind == "phone":
        if not settings.SMS_ENABLED:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED,
                                detail="Phone verification by SMS is coming soon. Your number is saved but not watched yet.")
        if not body.code:
            _send_phone_code(db, ident)
            return _identity_out(db, ident)
        ok = (ident.verify_code_hash and ident.verify_expires_at and ident.verify_expires_at > datetime.utcnow()
              and secrets.compare_digest(ident.verify_code_hash, _sha(f"{ident.id}:{body.code.strip()}")))
        if not ok:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Wrong or expired code.")
        _mark_verified(db, user, ident)
        return _identity_out(db, ident)
    # domain
    expected = f"osig-verify={footprint_service.domain_code(ident)}"
    if expected not in txt_records(ident.value):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"TXT record {expected} not found on {ident.value} yet. DNS changes can take a while.")
    _mark_verified(db, user, ident)
    return _identity_out(db, ident)


def txt_records(domain: str) -> List[str]:
    import dns.resolver
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=8)
    except Exception:
        return []
    return [b"".join(r.strings).decode(errors="replace").strip() for r in answers]


@router.post("/identities/verify-email")
def confirm_identity_email(body: TokenIn, db: Session = Depends(get_db)):
    """Target of the emailed link (works without being signed in, like /auth/verify-email)."""
    payload = decode_token(body.token, "verify_identity")
    ident = (db.query(Identity).filter(Identity.id == payload.get("iid"), Identity.user_id == payload.get("sub")).first()
             if payload else None)
    if not ident or ident.value != payload.get("value"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This link is invalid or has expired.")
    if not ident.verified_at:
        user = db.query(User).filter(User.id == ident.user_id).first()
        _mark_verified(db, user, ident)
    return {"verified": True, "value": ident.value}


# ── footprint and actions ───────────────────────────────────────────────

def _action_out(a: ActionItem) -> dict:
    return {"id": str(a.id), "identity_id": str(a.identity_id) if a.identity_id else None, "key": a.key,
            "severity": a.severity, "title": a.title, "detail": a.detail, "link": a.link, "status": a.status,
            "created_at": a.created_at, "resolved_at": a.resolved_at}


@router.get("/footprint")
def footprint(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    identities = db.query(Identity).filter(Identity.user_id == user.id).order_by(Identity.created_at).all()
    order = footprint_service.SEVERITY_ORDER
    open_items = db.query(ActionItem).filter(ActionItem.user_id == user.id, ActionItem.status == "open").all()
    open_items.sort(key=lambda a: (order.get(a.severity, 9), a.created_at))
    done = (db.query(ActionItem).filter(ActionItem.user_id == user.id, ActionItem.status != "open")
            .order_by(ActionItem.resolved_at.desc().nullslast()).limit(20).all())
    return {
        "score": user.exposure_score, "score_updated_at": user.score_updated_at,
        "identities": [_identity_out(db, i) for i in identities],
        "actions": {"open": [_action_out(a) for a in open_items], "done": [_action_out(a) for a in done]},
        "trend": footprint_service.trend(db, user.id),
    }


class ActionPatch(BaseModel):
    status: Literal["done", "dismissed", "open"]


@router.post("/actions/{action_id}")
def update_action(action_id: UUID, body: ActionPatch, db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    item = db.query(ActionItem).filter(ActionItem.id == action_id, ActionItem.user_id == user.id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
    item.status = body.status
    item.resolved_at = None if body.status == "open" else datetime.utcnow()
    db.commit()
    previous = user.exposure_score
    user.exposure_score = footprint_service.compute_score(db, user.id)
    user.score_updated_at = datetime.utcnow()
    db.commit()
    if previous != user.exposure_score:
        audit_service.record(db, "footprint_score", user_id=user.id, target=str(user.exposure_score))
    return {**_action_out(item), "score": user.exposure_score}


@router.post("/footprint/refresh", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(lambda: settings.RATE_LIMIT_FOOTPRINT_REFRESH)
def refresh_footprint(request: Request, db: Session = Depends(get_db), user: User = Depends(get_verified_user)):
    """Re-scan every watched identity now (daily scan quota applies), then recompute."""
    from app.services.scan_service import ScanService
    started, skipped = [], []
    now = datetime.utcnow()
    for ident in db.query(Identity).filter(Identity.user_id == user.id, Identity.watch_id.isnot(None)).all():
        w = ident.watch
        try:
            scan = ScanService.create_scan(db, user, CreateScanRequest(
                target_type=w.target_type, target_value=w.target_value, scan_type=w.scan_type,
                disclaimer_accepted=True), watch_id=w.id)
            w.last_run_at = now
            w.next_run_at = now + timedelta(hours=w.interval_hours)
            db.commit()
            started.append(str(scan.id))
        except HTTPException as e:
            db.rollback()
            skipped.append({"identity_id": str(ident.id), "reason": e.detail})
            if e.status_code == 429:  # daily quota: the rest would fail too
                break
    result = footprint_service.recompute(db, user, notify=False)
    return {"started": started, "skipped": skipped, "score": result["score"]}


# ── household ───────────────────────────────────────────────────────────

class InviteIn(BaseModel):
    email: str = Field(..., min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@router.get("/household")
def household(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    members = db.query(HouseholdMember).filter(HouseholdMember.owner_id == user.id).order_by(HouseholdMember.created_at).all()
    out = []
    for m in members:
        row = {"id": str(m.id), "email": m.email, "status": m.status, "created_at": m.created_at,
               "accepted_at": m.accepted_at}
        if m.status == "active" and m.member_user_id:
            row.update(footprint_service.member_summary(db, m.member_user_id))
        out.append(row)
    memberships = []
    for m in db.query(HouseholdMember).filter(HouseholdMember.member_user_id == user.id).all():
        owner = db.query(User).filter(User.id == m.owner_id).first()
        memberships.append({"id": str(m.id), "owner_name": owner.full_name or owner.username if owner else None,
                            "owner_email": owner.email if owner else None, "status": m.status})
    return {"limit": plan_limits.limit(db, user, "household") or 0, "members": out, "member_of": memberships}


@router.post("/household", status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_EMAIL)
def invite_member(request: Request, body: InviteIn, db: Session = Depends(get_db),
                  user: User = Depends(get_verified_user)):
    email = body.email.strip().lower()
    if email == user.email.lower():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You can't invite yourself.")
    if db.query(HouseholdMember).filter(HouseholdMember.owner_id == user.id, HouseholdMember.email == email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This person is already invited.")
    count = db.query(HouseholdMember).filter(HouseholdMember.owner_id == user.id).count()
    plan_limits.require_below(db, user, "household", count, "Your plan protects up to {limit} household members.")
    m = HouseholdMember(owner_id=user.id, email=email, status="invited")
    db.add(m)
    db.commit()
    token = create_purpose_token("household_invite", str(m.id), INVITE_TOKEN_MINUTES, email=email)
    name = user.full_name or user.username
    mail_service.send(
        db, email, f"{name} invites you to OSIG household protection",
        f"Hi,\n\n{name} ({user.email}) wants to help protect your online accounts with OSIG.\n\n"
        "If you accept, they will see your protection score and how many actions are open, never the addresses, "
        "numbers or findings themselves. You keep full control and can leave at any time.\n\n"
        f"Accept (sign in or create an account with this address first):\n{mail_service.link('/household/accept?token=' + token)}\n\n"
        "The invitation works for 7 days.\n", kind="household_invite")
    audit_service.record(db, "household_invited", request=request, user_id=user.id, target=str(m.id))
    return {"id": str(m.id), "email": m.email, "status": m.status, "created_at": m.created_at}


@router.post("/household/accept")
def accept_invite(body: TokenIn, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(get_verified_user)):
    payload = decode_token(body.token, "household_invite")
    m = db.query(HouseholdMember).filter(HouseholdMember.id == payload.get("sub")).first() if payload else None
    if not m or m.email != payload.get("email"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This invitation is invalid or has expired.")
    if m.email != user.email.lower():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="This invitation was sent to another address. Sign in with that address.")
    if m.owner_id == user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You can't join your own household.")
    if m.status != "active":
        m.status, m.member_user_id, m.accepted_at = "active", user.id, datetime.utcnow()
        db.commit()
        audit_service.record(db, "household_joined", request=request, user_id=user.id, target=str(m.id))
    return {"id": str(m.id), "status": m.status}


@router.delete("/household/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(member_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """The owner removes someone, or a member leaves (with their own membership id)."""
    m = db.query(HouseholdMember).filter(HouseholdMember.id == member_id).first()
    if not m or user.id not in (m.owner_id, m.member_user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Household member not found")
    db.delete(m)
    db.commit()


# ── web push ────────────────────────────────────────────────────────────

class PushKeys(BaseModel):
    p256dh: str = Field(..., min_length=10, max_length=200)
    auth: str = Field(..., min_length=8, max_length=100)


class PushSubscribeIn(BaseModel):
    endpoint: str = Field(..., max_length=2000)
    keys: PushKeys


class PushUnsubscribeIn(BaseModel):
    endpoint: str = Field(..., max_length=2000)


@router.get("/push/key")
def push_key():
    return {"enabled": push_service.enabled(), "public_key": settings.VAPID_PUBLIC_KEY or None}


@router.post("/push/subscribe", status_code=status.HTTP_201_CREATED)
def push_subscribe(body: PushSubscribeIn, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    if not push_service.allowed_endpoint(body.endpoint):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail="This push endpoint isn't from a supported browser push service.")
    sub = db.query(PushSubscription).filter(PushSubscription.endpoint == body.endpoint).first()
    if sub:  # same browser, maybe another account now
        sub.user_id, sub.p256dh, sub.auth = user.id, body.keys.p256dh, body.keys.auth
    else:
        sub = PushSubscription(user_id=user.id, endpoint=body.endpoint, p256dh=body.keys.p256dh,
                               auth=body.keys.auth, user_agent=(request.headers.get("user-agent") or "")[:300] or None)
        db.add(sub)
    db.commit()
    return {"subscribed": True}


@router.delete("/push/subscribe", status_code=status.HTTP_204_NO_CONTENT)
def push_unsubscribe(body: PushUnsubscribeIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    db.query(PushSubscription).filter(PushSubscription.endpoint == body.endpoint,
                                      PushSubscription.user_id == user.id).delete(synchronize_session=False)
    db.commit()


# ── opt-out / deletion request letters ──────────────────────────────────

class LetterIn(BaseModel):
    template_id: str
    company: str = Field(..., min_length=1, max_length=120)
    recipient_email: Optional[str] = Field(None, max_length=320)
    identities: List[UUID] = Field(default_factory=list, max_length=25)


@router.get("/requests/templates")
def letter_templates():
    return [{"id": k, "title": t["title"], "law": t["law"], "applies_to": t["applies_to"]}
            for k, t in footprint_service.TEMPLATES.items()]


@router.post("/requests/letter")
def request_letter(body: LetterIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if body.template_id not in footprint_service.TEMPLATES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown template")
    company = " ".join(body.company.split())
    idents = (db.query(Identity).filter(Identity.user_id == user.id, Identity.id.in_(body.identities)).all()
              if body.identities else [])
    out = footprint_service.letter(body.template_id, company, user, idents)
    key = f"request:{body.template_id}:{footprint_service._slug(company)}"
    item = db.query(ActionItem).filter(ActionItem.user_id == user.id, ActionItem.key == key).first()
    if not item:
        t = footprint_service.TEMPLATES[body.template_id]
        item = ActionItem(user_id=user.id, key=key, severity="low", status="open",
                          title=f"Send your {t['title'].split(' (')[0].lower()} to {company}",
                          detail=("To: " + body.recipient_email + "\n" if body.recipient_email else "")
                          + f"Subject: {out['subject']}\nMark it done once sent; companies usually have one month to answer.")
        db.add(item)
        db.commit()
    return {**out, "recipient_email": body.recipient_email, "action_id": str(item.id)}
