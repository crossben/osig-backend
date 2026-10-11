"""
Yoon 0.3.0 subscriptions -> OSIG access.

Access changes ONLY from signed Yoon events whose object is a subscription
(subscription.activated|renewed|changed|past_due|expired|canceled), through
yoonpay's Entitlement.from_subscription(): active and past_due (grace) are
entitled; expired, canceled, incomplete and any unknown status are not.
The return URL never grants anything.

- The user is found by the customer's external_id (= OSIG user id).
- Events are unordered: an event whose subscription is older than the last one
  applied for that user is ignored (yoon_subscription_updated_at).
- Losing entitlement only downgrades the user if it concerns their current
  subscription, so an old canceled subscription can't remove a newer one.
- subscription.renewal_upcoming -> reminder e-mail; invoice.paid -> receipt
  e-mail linking Yoon's printable receipt (a payment receipt, not a tax invoice).
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from sqlalchemy.orm import Session

from app.models.user import User, UserPlan
from app.services import mail_service
from app.services.plan_limits import plan_info

logger = logging.getLogger(__name__)

PAID_PLANS = {p.value for p in UserPlan} - {"free"}


def _naive_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def _parse(value: Any) -> Optional[datetime]:
    if isinstance(value, str):
        try:
            return _naive_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return _naive_utc(value) if isinstance(value, datetime) else None


def _user_by_external_id(db: Session, external_id: Optional[str]) -> Optional[User]:
    try:
        uid = uuid.UUID(str(external_id))
    except (TypeError, ValueError):
        return None
    return db.query(User).filter(User.id == uid).with_for_update().first()


def apply_subscription(db: Session, subscription: Mapping[str, Any]) -> Optional[User]:
    """Recompute the user's access from a subscription object. Idempotent."""
    from yoonpay.billing import Entitlement

    e = Entitlement.from_subscription(subscription)
    user = _user_by_external_id(db, e.external_id)
    if not user:
        logger.warning("Yoon subscription %s for unknown customer", e.subscription_id)
        return None
    updated_at = _parse(subscription.get("updated_at"))
    if (user.yoon_subscription_updated_at and updated_at and user.yoon_subscription_id == e.subscription_id
            and updated_at < user.yoon_subscription_updated_at):
        return user  # an older state of the same subscription arriving late

    if e.customer_id and not user.yoon_customer_id:
        user.yoon_customer_id = e.customer_id

    if e.entitled:
        if e.plan not in PAID_PLANS:
            logger.error("Yoon subscription %s is for unknown plan %r: access unchanged", e.subscription_id, e.plan)
            return user
        user.plan = UserPlan(e.plan)
        user.plan_expires_at = _naive_utc(e.until)  # None = open-ended comp
        user.plan_source = "comp" if e.comp else "purchase"
        pending = (subscription.get("pending_change") or {}).get("price") or {}
        pending_slug = (pending.get("plan") or {}).get("slug") if isinstance(pending, Mapping) else None
        user.pending_plan = pending_slug if pending_slug in PAID_PLANS else None
        user.pending_plan_days = None  # Yoon owns the schedule
        user.yoon_subscription_id = e.subscription_id
        user.yoon_subscription_updated_at = updated_at
        user.renewal_reminded_at = None
    elif user.yoon_subscription_id in (None, e.subscription_id):
        user.plan, user.plan_expires_at, user.plan_source = UserPlan.FREE, None, None
        user.pending_plan = user.pending_plan_days = None
        user.yoon_subscription_id = e.subscription_id
        user.yoon_subscription_updated_at = updated_at
    db.commit()
    return user


def send_renewal_reminder(db: Session, subscription: Mapping[str, Any]) -> None:
    from yoonpay.billing import Entitlement
    e = Entitlement.from_subscription(subscription)
    user = _user_by_external_id(db, e.external_id)
    if not user or not e.until:
        db.commit()
        return
    name = plan_info(db, e.plan or "pro")["name"]
    fr = (user.language or "en") == "fr"
    when = _naive_utc(e.until)
    subject = (f"Votre forfait OSIG {name} se termine bientôt" if fr else f"Your OSIG {name} plan ends soon")
    body = (f"Votre forfait se termine le {when:%d/%m/%Y}. Renouvelez avant cette date pour le garder ; "
            f"payer en avance s’ajoute au temps restant.\n\n{mail_service.link('/billing')}\n"
            if fr else
            f"Your plan ends on {when:%d %B %Y}. Renew before then to keep it; paying early adds to the time "
            f"you have left.\n\n{mail_service.link('/billing')}\n")
    mail_service.send(db, user.email, subject, body, kind="billing_reminder")
    user.renewal_reminded_at = datetime.utcnow()
    db.commit()


def _user_for_customer(db: Session, customer_id: Optional[str]) -> Optional[User]:
    if not customer_id:
        return None
    user = db.query(User).filter(User.yoon_customer_id == customer_id).first()
    if user:
        return user
    from app.services.billing_service import yoon_client
    try:  # not linked yet (e.g. invoice.paid before subscription.activated): ask Yoon
        yoon = yoon_client()
        customer = yoon.call(lambda: yoon.customers().get_customer(customer_id))
    except Exception as exc:
        logger.info("Couldn't look up Yoon customer %s: %s", customer_id, type(exc).__name__)
        return None
    user = _user_by_external_id(db, getattr(customer, "external_id", None))
    if user and not user.yoon_customer_id:
        user.yoon_customer_id = customer_id
    return user


def _money(amount: int, currency: str) -> str:
    return f"{amount:,} {currency}".replace(",", " ") if currency == "XOF" else f"{amount / 100:.2f} {currency}"


def send_receipt(db: Session, invoice: Mapping[str, Any]) -> None:
    user = _user_for_customer(db, invoice.get("customer"))
    if not user:
        db.commit()
        return
    fr = (user.language or "en") == "fr"
    amount = _money(int(invoice.get("amount_due") or 0), str(invoice.get("currency") or ""))
    number = invoice.get("number") or ""
    end = _parse(invoice.get("period_end"))
    receipt = invoice.get("receipt_url")
    if fr:
        subject = f"Reçu OSIG {number}"
        body = (f"Merci. Nous avons reçu {amount}." + (f" Votre forfait court jusqu’au {end:%d/%m/%Y}." if end else "")
                + (f"\n\nReçu de paiement : {receipt}" if receipt else "")
                + "\n(Reçu de paiement, pas une facture fiscale.)\n\n" + mail_service.link("/billing") + "\n")
    else:
        subject = f"OSIG receipt {number}"
        body = (f"Thanks. We received {amount}." + (f" Your plan runs until {end:%d %B %Y}." if end else "")
                + (f"\n\nPayment receipt: {receipt}" if receipt else "")
                + "\n(A payment receipt, not a tax invoice.)\n\n" + mail_service.link("/billing") + "\n")
    mail_service.send(db, user.email, subject, body, kind="billing_receipt")
    db.commit()


def handle_event(db: Session, event_type: str, obj: Mapping[str, Any]) -> bool:
    """Returns True when the event was a billing (0.3.0) event."""
    from yoonpay.billing import changes_entitlement
    if changes_entitlement(event_type):
        apply_subscription(db, obj)
        return True
    if event_type == "subscription.renewal_upcoming":
        send_renewal_reminder(db, obj)
        return True
    if event_type == "invoice.paid":
        send_receipt(db, obj)
        return True
    return event_type.startswith(("subscription.", "invoice."))  # informational: nothing to do


# ── buying / renewing (Yoon subscriptions) ──────────────────────────────

class BillingError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _yoon():
    from app.services.billing_service import yoon_client
    return yoon_client()


def _billing_error(e, what: str) -> "BillingError":
    logger.warning("Yoon refused %s: %s (HTTP %s)", what, e.problem_code, e.http_status)
    if e.problem_code in ("no_provider_for_method", "all_providers_unavailable", "provider_not_configured"):
        return BillingError(502, "No payment method is available for your country yet. Try another country "
                                 "or pay by card.")
    if e.problem_code and "currency" in e.problem_code:
        return BillingError(409, "Your plan is billed in another currency. Choose the country you first "
                                 "paid from, or contact us to switch.")
    if e.http_status and 400 <= e.http_status < 500:
        return BillingError(409, "The payment service refused this change. Refresh the page and try again.")
    return BillingError(502, "The payment service didn't answer. Try again in a minute.")


def _call(fn, what: str):
    from yoonpay import YoonException
    try:
        return fn()
    except YoonException as e:
        raise _billing_error(e, what) from None


def price_for(plan: str, period: str, currency: str) -> str:
    """The active Yoon price id for an OSIG plan/period/currency (from Yoon's catalog)."""
    from app.services.yoon_catalog import PERIODS, fetch_existing
    interval, count = PERIODS[period]
    for p in fetch_existing(_yoon()):
        if p.slug != plan or not p.active:
            continue
        for price in p.prices:
            if (price.active and price.currency == currency and getattr(price.interval, "value", price.interval) == interval
                    and price.interval_count == count):
                return price.id
    raise BillingError(400, f"This plan has no {currency} price for that period.")


def ensure_customer(db: Session, user: User, country: str) -> str:
    if user.yoon_customer_id:
        return user.yoon_customer_id
    from yoonpay import YoonException
    from yoonpay.generated import CreateCustomerRequest
    yoon = _yoon()
    try:
        customer = yoon.call(lambda: yoon.customers().create_customer(
            f"osig-customer-{user.id}",
            CreateCustomerRequest(external_id=str(user.id), email=user.email, country=country)))
        customer_id = customer.id
    except YoonException as e:
        if e.problem_code != "customer_exists":
            raise _billing_error(e, "create customer") from None
        page = _call(lambda: yoon.customers().list_customers(external_id=str(user.id)), "find customer")
        customer_id = page.data[0].id
    user.yoon_customer_id = customer_id
    db.commit()
    return customer_id


def _checkout_or_renew(sub, return_url: str, period_key: str):
    """The checkout URL of the subscription's open invoice; NoCheckout (paid, void, expired checkout) -> renew."""
    from yoonpay.fastapi import NoCheckout, redirect_to_checkout
    from yoonpay.generated import RenewSubscriptionRequest
    try:
        return redirect_to_checkout(sub).headers["location"]
    except NoCheckout:
        yoon = _yoon()
        renewed = _call(lambda: yoon.subscriptions().renew_subscription(
            sub.id, f"osig-renew-{sub.id}-{period_key}", RenewSubscriptionRequest(return_url=return_url)), "renew")
        try:
            return redirect_to_checkout(renewed).headers["location"]
        except NoCheckout:
            raise BillingError(409, "There's nothing to pay right now. Refresh the page.")


def subscribe(db: Session, user: User, plan: str, period: str, country: str) -> dict:
    """Buy, renew, upgrade or schedule a downgrade. Returns {checkout_url} or {scheduled: True}."""
    from app.services import billing_service
    from yoonpay.generated import ChangeSubscriptionRequest, CreateSubscriptionRequest

    info = plan_info(db, plan)
    if not info["is_active"] or not info["self_serve"]:
        raise BillingError(400, "This plan can't be bought online. Contact us to get it.")
    country = country.upper()
    currency = "XOF" if country in billing_service.XOF_COUNTRIES else "USD"
    price_id = price_for(plan, period, currency)
    return_url = mail_service.link("/billing?subscribed=1")
    customer_id = ensure_customer(db, user, country)
    yoon = _yoon()
    today = datetime.utcnow().strftime("%Y%m%d")

    sub = None
    if user.yoon_subscription_id:
        sub = _call(lambda: yoon.subscriptions().get_subscription(user.yoon_subscription_id), "get subscription")
        if getattr(sub.status, "value", sub.status) in ("canceled", "incomplete") and sub.price.id != price_id:
            sub = None  # start over with the chosen price
    if sub is None:
        created = _call(lambda: yoon.subscriptions().create_subscription(
            f"osig-subscribe-{user.id}-{price_id}-{today}",
            CreateSubscriptionRequest(customer=customer_id, price=price_id, return_url=return_url)), "subscribe")
        user.yoon_subscription_id = created.id
        db.commit()
        return {"checkout_url": _checkout_or_renew(created, return_url, today)}

    period_key = (sub.current_period_end.strftime("%Y%m%d") if sub.current_period_end else today)
    if sub.price.id == price_id:  # same plan and period: renew (stacks after the current period)
        from yoonpay.generated import RenewSubscriptionRequest
        renewed = _call(lambda: yoon.subscriptions().renew_subscription(
            sub.id, f"osig-renew-{sub.id}-{period_key}", RenewSubscriptionRequest(return_url=return_url)), "renew")
        return {"checkout_url": _checkout_or_renew(renewed, return_url, period_key)}
    changed = _call(lambda: yoon.subscriptions().change_subscription(
        sub.id, f"osig-change-{sub.id}-{price_id}-{period_key}",
        ChangeSubscriptionRequest(price=price_id, return_url=return_url)), "change plan")
    from yoonpay.billing import checkout_url
    invoice = changed.latest_invoice
    kind = getattr(getattr(invoice, "kind", None), "value", getattr(invoice, "kind", None))
    url = checkout_url(changed) if kind == "upgrade" else None
    if url:
        return {"checkout_url": url}  # upgrade: invoiced now for a full period of the new price
    return {"scheduled": True}  # cheaper per day: Yoon applies it at the period end


def reconcile_user(db: Session, user: User) -> Optional[User]:
    """After an outage on our side: re-read the customer's subscriptions and apply the latest one."""
    if not user.yoon_customer_id:
        return user
    yoon = _yoon()
    page = _call(lambda: yoon.subscriptions().list_subscriptions(customer=user.yoon_customer_id, limit=20),
                 "list subscriptions")
    subs = [s.to_dict() for s in page.data]
    if not subs:
        return user
    entitled = [s for s in subs if s.get("entitled")]
    pick = max(entitled or subs, key=lambda s: str(s.get("updated_at") or ""))
    for key in ("updated_at", "current_period_end", "current_period_start", "created_at"):
        if isinstance(pick.get(key), datetime):
            pick[key] = pick[key].isoformat()
    return apply_subscription(db, pick)
