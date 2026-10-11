"""
Billing: prepaid plan periods paid through Yoon (self-hosted payment gateway).

- checkout(): price is always read from the plans table, never from the request;
  a pending Payment row is created, then a Yoon hosted checkout (the customer
  picks Wave, Orange Money, card... on Yoon's page).
- settle(): the only way a payment becomes paid. Called from the signed Yoon
  webhook, or after asking Yoon itself for the payment's status. Row-locked and
  idempotent; the amount and currency must match what was charged.
- activate(): paying the same plan early extends from the current expiry
  (stacking); an upgrade starts now; a downgrade bought while a higher plan
  runs waits for it to end (pending_plan).
- expire_plans() / send_renewal_reminders(): Celery beat tasks.
"""
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.billing import Payment
from app.models.user import User, UserPlan
from app.services import mail_service
from app.services.plan_limits import PERIODS, plan_info, price_for

logger = logging.getLogger(__name__)

# Countries Yoon's providers collect in; anything else pays by card (Stripe) in USD
XOF_COUNTRIES = {"SN", "CI", "BJ", "BF", "ML", "TG", "NE", "GW"}


def enabled() -> bool:
    return bool(settings.YOON_API_URL and settings.YOON_API_KEY and settings.YOON_WEBHOOK_SECRET)


def yoon_client():
    from yoonpay import Yoon
    return Yoon(settings.YOON_API_URL, settings.YOON_API_KEY)


def _plan_value(user: User) -> str:
    return user.plan.value if hasattr(user.plan, "value") else str(user.plan)


def _rank(db: Session, slug: str) -> int:
    return plan_info(db, slug)["rank"]


def plan_is_running(user: User, now: Optional[datetime] = None) -> bool:
    """A paid plan with time left (or granted without end)."""
    if _plan_value(user) == "free":
        return False
    return user.plan_expires_at is None or user.plan_expires_at > (now or datetime.utcnow())


# ── checkout ─────────────────────────────────────────────────────
def checkout(db: Session, user: User, plan: str, period: str, country: str) -> Payment:
    if not enabled():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Payments aren't set up on this server yet.")
    info = plan_info(db, plan)
    if not info["is_active"] or not info["self_serve"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This plan can't be bought online. Contact us to get it.")
    if period not in PERIODS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose month, quarter, half or year.")
    country = country.upper()
    currency = "XOF" if country in XOF_COUNTRIES else "USD"
    amount = price_for(info, currency, period)
    if not amount:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"{info['name']} has no {currency} price for this period.")

    payment = Payment(user_id=user.id, reference=f"osig_{secrets.token_hex(8)}", plan=plan, period=period,
                      amount=amount, currency=currency, country=country, status="pending")
    db.add(payment)
    db.commit()
    db.refresh(payment)

    from yoonpay import YoonException
    days = PERIODS[period][0]
    try:
        created = yoon_client().create_payment(
            {
                "amount": amount, "currency": currency, "country": country, "checkout": "hosted",
                "reference": payment.reference,
                "description": f"OSIG {info['name']}, {days} days",
                "return_url": mail_service.link(f"/billing?ref={payment.reference}"),
            },
            idempotency_key=f"osig-{payment.id}",
        )
    except YoonException as e:
        payment.status = "failed"
        payment.failure_reason = f"{e.problem_code or 'unreachable'}"
        db.commit()
        logger.warning(f"Yoon refused checkout {payment.reference}: {e.problem_code}")
        detail = ("No payment method is available for your country yet. Try another country or pay by card."
                  if e.problem_code in ("no_provider_for_method", "all_providers_unavailable", "provider_not_configured")
                  else "The payment service didn't answer. Try again in a minute.")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail)
    payment.yoon_payment_id = created.id
    db.commit()
    payment.checkout_url = created.checkout_url  # transient, returned to the browser
    return payment


# ── settle & activate ────────────────────────────────────────────
def settle(db: Session, payment_id, yoon_status: str, amount: Optional[int], currency: Optional[str],
           method: Optional[str] = None) -> Optional[Payment]:
    """Apply a confirmed Yoon status to our payment. Safe to call any number of times."""
    payment = db.query(Payment).filter(Payment.id == payment_id).with_for_update().first()
    if not payment or payment.status == "paid":
        db.commit()
        return payment
    if yoon_status == "succeeded":
        if amount != payment.amount or (currency or "").upper() != payment.currency:
            payment.status = "failed"
            payment.failure_reason = f"amount mismatch: got {amount} {currency}, expected {payment.amount} {payment.currency}"
            db.commit()
            logger.error(f"Payment {payment.reference}: {payment.failure_reason}")
            return payment
        payment.status = "paid"
        payment.paid_at = datetime.utcnow()
        payment.method = method
        user = db.query(User).filter(User.id == payment.user_id).with_for_update().first()
        if user:
            activate(db, user, payment.plan, PERIODS[payment.period][0])
        db.commit()
        if user:
            _receipt(db, user, payment)
        return payment
    if yoon_status in ("failed", "expired") and payment.status == "pending":
        payment.status = yoon_status
        db.commit()
    else:
        db.commit()
    return payment


def activate(db: Session, user: User, plan: str, days: int, source: str = "purchase") -> None:
    now = datetime.utcnow()
    current = _plan_value(user)
    running = plan_is_running(user, now)
    if running and plan != current and _rank(db, plan) < _rank(db, current):
        # Downgrade while a higher plan runs: queue it (stacking repeat purchases)
        if user.pending_plan == plan:
            user.pending_plan_days = (user.pending_plan_days or 0) + days
        else:
            user.pending_plan, user.pending_plan_days = plan, days
        return
    if running and plan == current and user.plan_expires_at is None:
        return  # already granted without end
    start = user.plan_expires_at if (running and plan == current and user.plan_expires_at) else now
    user.plan = UserPlan(plan)
    user.plan_expires_at = start + timedelta(days=days)
    user.plan_source = source
    user.renewal_reminded_at = None
    if user.pending_plan == plan:
        user.pending_plan, user.pending_plan_days = None, None


def grant(db: Session, user: User, plan: str, days: Optional[int]) -> None:
    """Admin grant ("comp"): days=None means no end date."""
    if plan == "free":
        user.plan, user.plan_expires_at, user.plan_source = UserPlan.FREE, None, None
    elif days is None:
        user.plan, user.plan_expires_at, user.plan_source = UserPlan(plan), None, "comp"
    else:
        activate(db, user, plan, days, source="comp")
        if user.pending_plan == plan:  # grant overrides instead of queueing
            user.pending_plan = user.pending_plan_days = None
            user.plan, user.plan_expires_at, user.plan_source = UserPlan(plan), datetime.utcnow() + timedelta(days=days), "comp"
    db.commit()


def refresh_from_yoon(db: Session, payment: Payment) -> Payment:
    """Ask Yoon for the truth (when the webhook hasn't arrived yet)."""
    if payment.status != "pending" or not payment.yoon_payment_id or not enabled():
        return payment
    try:
        p = yoon_client().get_payment(payment.yoon_payment_id)
    except Exception as e:  # Yoon down: keep showing "waiting"
        logger.info(f"Yoon status check failed for {payment.reference}: {e}")
        return payment
    status_ = getattr(p.status, "value", p.status)
    if status_ in ("succeeded", "failed", "expired"):
        return settle(db, payment.id, status_, p.amount, p.currency, getattr(p, "method", None)) or payment
    return payment


# ── emails ───────────────────────────────────────────────────────
def _plan_name(db: Session, slug: str) -> str:
    return plan_info(db, slug)["name"]


def _receipt(db: Session, user: User, payment: Payment) -> None:
    amount = f"{payment.amount:,} XOF" if payment.currency == "XOF" else f"{payment.amount / 100:.2f} {payment.currency}"
    queued = user.pending_plan == payment.plan and _plan_value(user) != payment.plan
    until = ("after your current plan ends" if queued else
             f"until {user.plan_expires_at:%d %B %Y}" if user.plan_expires_at else "")
    mail_service.send(db, user.email, f"OSIG receipt: {_plan_name(db, payment.plan)}",
                      f"Thanks. We received {amount} for OSIG {_plan_name(db, payment.plan)} "
                      f"({PERIODS[payment.period][0]} days), {until}.\n\nReference: {payment.reference}\n"
                      f"See your plan: {mail_service.link('/billing')}\n", kind="billing_receipt")


# ── beat tasks ───────────────────────────────────────────────────
def expire_plans(db: Session) -> int:
    """Plans past expiry + grace: switch to the queued plan, else to Free."""
    now = datetime.utcnow()
    cutoff = now - timedelta(days=settings.BILLING_GRACE_DAYS)
    lapsed = db.query(User).filter(User.plan != UserPlan.FREE, User.plan_expires_at.isnot(None),
                                   User.plan_expires_at < cutoff,
                                   User.yoon_subscription_id.is_(None)).with_for_update().all()  # Yoon expires its own
    for user in lapsed:
        old = _plan_name(db, _plan_value(user))
        if user.pending_plan:
            user.plan = UserPlan(user.pending_plan)
            user.plan_expires_at = now + timedelta(days=user.pending_plan_days or 0)
            user.pending_plan = user.pending_plan_days = None
            note = f"Your {_plan_name(db, _plan_value(user))} plan has started."
        else:
            user.plan, user.plan_expires_at, user.plan_source = UserPlan.FREE, None, None
            note = "You're on the Free plan now; your data is kept."
        user.renewal_reminded_at = None
        mail_service.send(db, user.email, f"Your OSIG {old} plan has ended",
                          f"{note}\n\nRenew any time: {mail_service.link('/billing')}\n", kind="billing_expired")
    db.commit()
    return len(lapsed)


def send_renewal_reminders(db: Session) -> int:
    now = datetime.utcnow()
    soon = now + timedelta(days=settings.BILLING_REMINDER_DAYS)
    users = db.query(User).filter(User.plan != UserPlan.FREE, User.plan_expires_at.isnot(None),
                                  User.plan_expires_at > now, User.plan_expires_at <= soon,
                                  User.renewal_reminded_at.is_(None), User.pending_plan.is_(None),
                                  User.yoon_subscription_id.is_(None)).all()  # Yoon sends renewal_upcoming
    for user in users:
        mail_service.send(db, user.email, f"Your OSIG {_plan_name(db, _plan_value(user))} plan ends soon",
                          f"Your plan ends on {user.plan_expires_at:%d %B %Y}. Renew before then to keep it; "
                          f"renewing early adds to the time you have left.\n\n{mail_service.link('/billing')}\n",
                          kind="billing_reminder")
        user.renewal_reminded_at = now
    db.commit()
    return len(users)


def reconcile_pending(db: Session) -> int:
    """Settle payments whose webhook never arrived (unreachable app, lost delivery) by asking Yoon."""
    now = datetime.utcnow()
    pending = db.query(Payment).filter(Payment.status == "pending", Payment.yoon_payment_id.isnot(None),
                                       Payment.created_at < now - timedelta(minutes=2),
                                       Payment.created_at > now - timedelta(days=3)).limit(200).all()
    changed = 0
    for p in pending:
        if refresh_from_yoon(db, p).status != "pending":
            changed += 1
    return changed
