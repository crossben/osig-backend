"""
OSIG Backend - Billing API (prepaid plans paid through Yoon).

GET  /billing/plans                 public: plans, prices, limits
GET  /billing/me                    your plan, expiry, usage, recent payments
POST /billing/checkout              start paying a plan period -> Yoon hosted checkout URL
GET  /billing/payments/{reference}  status (asks Yoon when still pending)
POST /billing/yoon/webhook          signed Yoon events; the only push that grants a plan
"""
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps import get_admin_user, get_db, get_session_user, get_verified_user
from app.core.rate_limit import limiter
from app.models.billing import Payment, Plan, YoonEvent
from app.models.user import User
from app.services import audit_service, billing_service, plan_limits

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/billing", tags=["Billing"])


def _payment_out(p: Payment) -> dict:
    return {"reference": p.reference, "plan": p.plan, "period": p.period, "amount": p.amount,
            "currency": p.currency, "country": p.country, "method": p.method, "status": p.status,
            "paid_at": p.paid_at, "created_at": p.created_at}


@router.get("/plans")
def list_plans(db: Session = Depends(get_db)):
    rows = {p.slug: p for p in db.query(Plan).all()}
    slugs = sorted(set(rows) | set(plan_limits.DEFAULT_PLANS), key=lambda s: plan_limits.plan_info(db, s)["rank"])
    out = []
    for slug in slugs:
        info = plan_limits.plan_info(db, slug)
        if info["is_active"]:
            out.append({k: info[k] for k in ("slug", "name", "rank", "self_serve", "prices", "limits")})
    return {"plans": out, "periods": {k: v[0] for k, v in plan_limits.PERIODS.items()},
            "enabled": billing_service.enabled(), "xof_countries": sorted(billing_service.XOF_COUNTRIES)}


@router.get("/me")
def my_billing(db: Session = Depends(get_db), user: User = Depends(get_session_user)):
    from app.models.investigation import Watch
    from app.models.platform import ApiKey
    from app.services.scan_service import scan_service
    _has, used, daily = scan_service.check_scan_quota(db, user)
    info = plan_limits.plan_info(db, user.plan.value)
    payments = db.query(Payment).filter(Payment.user_id == user.id).order_by(Payment.created_at.desc()).limit(20).all()
    return {
        "plan": user.plan.value, "plan_name": info["name"], "expires_at": user.plan_expires_at,
        "source": user.plan_source, "pending_plan": user.pending_plan, "pending_plan_days": user.pending_plan_days,
        "subscription": bool(user.yoon_subscription_id),
        "cancel_at_period_end": bool(user.yoon_cancel_at_period_end),
        "country": user.country,
        "grace_days": settings.BILLING_GRACE_DAYS, "limits": info["limits"],
        "usage": {
            "scans_today": used, "daily_scans": daily,
            "watches": db.query(Watch).filter(Watch.user_id == user.id).count(),
            "api_keys": db.query(ApiKey).filter(ApiKey.user_id == user.id, ApiKey.revoked.is_(False)).count(),
        },
        "payments": [_payment_out(p) for p in payments],
    }


class CheckoutIn(BaseModel):
    plan: str = Field(..., max_length=20)
    period: str = Field(..., pattern="^(month|quarter|half|year)$")
    country: str = Field(..., pattern="^[A-Za-z]{2}$")


@router.post("/subscribe")
@limiter.limit(settings.RATE_LIMIT_AUTH)
def subscribe(body: CheckoutIn, request: Request, db: Session = Depends(get_db),
              user: User = Depends(get_verified_user)):
    """Buy, renew or change plan through a Yoon subscription. Returns {checkoutUrl} to open, or
    {scheduled: true} for a cheaper plan that starts at the end of the current period.
    Access is granted later, only by Yoon's signed subscription events."""
    from app.services import subscription_service
    if getattr(user, "via_api_key", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sign in to buy a plan")
    if not billing_service.enabled():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Payments aren't set up on this server yet.")
    try:
        out = subscription_service.subscribe(db, user, body.plan, body.period, body.country)
    except subscription_service.BillingError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    audit_service.record(db, "subscribe_started", request=request, user_id=user.id,
                         target=f"{body.plan}/{body.period} {body.country.upper()} {'scheduled' if out.get('scheduled') else 'checkout'}")
    return out


class CancelIn(BaseModel):
    at_period_end: bool = True


@router.post("/subscription/cancel")
def cancel_subscription(body: CancelIn, request: Request, db: Session = Depends(get_db),
                        user: User = Depends(get_session_user)):
    """Stop renewing: the plan keeps running until the end of the paid period (no refund)."""
    from app.services import subscription_service
    try:
        subscription_service.cancel(db, user, at_period_end=body.at_period_end)
    except subscription_service.BillingError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    audit_service.record(db, "subscription_canceled", request=request, user_id=user.id,
                         target="period_end" if body.at_period_end else "now")
    return {"cancel_at_period_end": user.yoon_cancel_at_period_end, "plan": user.plan.value,
            "expires_at": user.plan_expires_at}


@router.post("/subscription/resume")
def resume_subscription(request: Request, db: Session = Depends(get_db), user: User = Depends(get_session_user)):
    """Undo a cancellation that hasn't taken effect yet."""
    from app.services import subscription_service
    try:
        subscription_service.resume(db, user)
    except subscription_service.BillingError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    audit_service.record(db, "subscription_resumed", request=request, user_id=user.id)
    return {"cancel_at_period_end": user.yoon_cancel_at_period_end, "plan": user.plan.value,
            "expires_at": user.plan_expires_at}


@router.post("/subscription/sync")
@limiter.limit("20/minute")
def sync_subscription(request: Request, db: Session = Depends(get_db), user: User = Depends(get_session_user)):
    """Re-read the user's subscription from Yoon (after returning from checkout, or after an outage)."""
    from app.services import subscription_service
    try:
        subscription_service.reconcile_user(db, user)
    except subscription_service.BillingError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    db.refresh(user)
    return {"plan": user.plan.value, "expires_at": user.plan_expires_at, "source": user.plan_source,
            "pending_plan": user.pending_plan}


@router.post("/yoon/webhook")
async def yoon_webhook(request: Request, db: Session = Depends(get_db)):
    """Verifies Yoon-Signature over the raw body (and its age), drops replays by event id."""
    from yoonpay import Event, verify_signature
    raw = await request.body()
    if not settings.YOON_WEBHOOK_SECRET or not verify_signature(
            settings.YOON_WEBHOOK_SECRET, request.headers.get("Yoon-Signature"), raw):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bad signature")
    try:
        event = Event.from_json(raw)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Not a Yoon event")
    if db.get(YoonEvent, event.id):
        return Response(status_code=200)
    obj = event.object or {}
    from app.services import subscription_service
    if subscription_service.handle_event(db, event.type, obj):  # Yoon 0.3.0 subscriptions
        audit_service.record(db, f"billing_{event.type.replace('.', '_')}", target=str(obj.get("id")))
    # Remember the id only after handling succeeded: if we raised, Yoon retries
    try:
        db.add(YoonEvent(id=event.id, type=event.type, received_at=datetime.utcnow()))
        db.commit()
    except IntegrityError:
        db.rollback()
    return Response(status_code=200)


# ── admin ────────────────────────────────────────────────────────
class GrantIn(BaseModel):
    plan: str = Field(..., pattern="^(free|pro|enterprise)$")
    days: Optional[int] = Field(None, ge=1, le=3650)


class PlanPatch(BaseModel):
    name: Optional[str] = Field(None, max_length=60)
    is_active: Optional[bool] = None
    self_serve: Optional[bool] = None
    prices: Optional[dict] = None
    limits: Optional[dict] = None


@router.post("/admin/users/{user_id}/grant")
def admin_grant(user_id: str, body: GrantIn, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(get_admin_user)):
    """Give a plan without payment through a Yoon comp (Enterprise deals, support gestures).
    No days = no end date; "free" cancels the subscription now."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    from app.services import subscription_service
    try:
        subscription_service.admin_grant(db, user, body.plan, body.days)
    except subscription_service.BillingError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    db.refresh(user)
    audit_service.record(db, "admin_plan_granted", request=request, user_id=admin.id,
                         target=f"{user.id} {body.plan} {body.days or 'no end'}")
    return {"plan": user.plan.value, "expires_at": user.plan_expires_at, "source": user.plan_source}


@router.get("/admin/payments")
def admin_payments(limit: int = 100, db: Session = Depends(get_db), _a: User = Depends(get_admin_user)):
    rows = db.query(Payment, User.email).join(User, User.id == Payment.user_id) \
        .order_by(Payment.created_at.desc()).limit(min(limit, 500)).all()
    return [{**_payment_out(p), "email": email, "failure_reason": p.failure_reason} for p, email in rows]


@router.patch("/admin/plans/{slug}")
def admin_update_plan(slug: str, body: PlanPatch, request: Request, db: Session = Depends(get_db),
                      admin: User = Depends(get_admin_user)):
    if slug not in plan_limits.DEFAULT_PLANS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown plan")
    row = db.query(Plan).filter(Plan.slug == slug).first()
    if not row:
        d = plan_limits.DEFAULT_PLANS[slug]
        row = Plan(slug=slug, name=d["name"], rank=d["rank"], self_serve=d["self_serve"],
                   prices=d["prices"], limits=d["limits"])
        db.add(row)
    changes = body.model_dump(exclude_unset=True)
    if "prices" in changes:
        for cur, periods in (changes["prices"] or {}).items():
            if len(cur) != 3 or not isinstance(periods, dict) or any(
                    k not in plan_limits.PERIODS or not isinstance(v, int) or v < 1 for k, v in periods.items()):
                raise HTTPException(status_code=422, detail="Prices: {CUR: {month|quarter|half|year: positive integer}}")
    if "limits" in changes:
        changes["limits"] = {**plan_limits.DEFAULT_PLANS[slug]["limits"], **(row.limits or {}), **changes["limits"]}
    for k, v in changes.items():
        setattr(row, k, v)
    db.commit()
    audit_service.record(db, "admin_plan_updated", request=request, user_id=admin.id, target=slug)
    return plan_limits.plan_info(db, slug)
