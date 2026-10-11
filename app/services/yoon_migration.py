"""
Move users with a running paid OSIG plan onto Yoon 0.3.0 subscriptions.

For each user with a paid plan that is still running (or granted without end)
and no Yoon subscription yet:
  1. create the Yoon customer (external_id = OSIG user id); `409 customer_exists`
     means it already exists: look it up with ?external_id=;
  2. grant the remaining time without payment: an operator comp on the plan's
     price, `until` = the user's plan_expires_at, or `open` for open-ended grants
     (POST /admin/v1/applications/{app}/customers/{id}/comp, Idempotency-Key per user);
  3. store yoon_customer_id / yoon_subscription_id on the user.
From their next renewal on they pay through the subscription.

Which price: the plan's price in the currency and period of the user's last paid
OSIG payment; otherwise XOF monthly. Country: that payment's, otherwise SN.

plan_migration() only reads (dry run); migrate() performs one user's steps.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.billing import Payment
from app.models.user import User, UserPlan
from app.services.yoon_catalog import PERIODS


@dataclass
class UserMigration:
    user_id: str
    email: str
    plan: str
    until: Optional[datetime]  # None = open-ended
    currency: str
    period: str
    country: str
    price_id: Optional[str]
    action: str  # migrate | skip
    reason: str = ""

    @property
    def until_text(self) -> str:
        return "open" if self.until is None else self.until.strftime("%Y-%m-%dT%H:%M:%SZ")


def _mask(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:2]}***@{domain}"


def _price_index(catalog: List[Any]) -> Dict[Tuple[str, str, str, int], str]:
    """(plan slug, currency, interval, count) -> active price id."""
    out = {}
    for plan in catalog:
        slug = plan["slug"] if isinstance(plan, dict) else plan.slug
        prices = plan["prices"] if isinstance(plan, dict) else plan.prices
        for p in prices:
            get = (lambda k: p[k]) if isinstance(p, dict) else (lambda k: getattr(p, k))
            if get("active"):
                interval = getattr(get("interval"), "value", get("interval"))
                out[(slug, get("currency"), interval, get("interval_count"))] = get("id")
    return out


def plan_migration(db: Session, catalog: List[Any], now: Optional[datetime] = None) -> List[UserMigration]:
    now = now or datetime.utcnow()
    prices = _price_index(catalog)
    users = db.query(User).filter(User.plan != UserPlan.FREE).order_by(User.created_at).all()
    out: List[UserMigration] = []
    for u in users:
        plan = u.plan.value
        last = (db.query(Payment).filter(Payment.user_id == u.id, Payment.status == "paid")
                .order_by(Payment.paid_at.desc()).first())
        currency = last.currency if last else "XOF"
        period = last.period if last and last.period in PERIODS else "month"
        country = (last.country if last else "SN") or "SN"
        interval, count = PERIODS[period]
        price_id = prices.get((plan, currency, interval, count)) or prices.get((plan, currency, "month", 1))
        m = UserMigration(str(u.id), _mask(u.email), plan, u.plan_expires_at, currency, period, country,
                          price_id, "migrate")
        if u.yoon_subscription_id:
            m.action, m.reason = "skip", "already on a Yoon subscription"
        elif u.plan_expires_at is not None and u.plan_expires_at <= now:
            m.action, m.reason = "skip", "plan already ended (in grace): renews through Yoon or drops to Free"
        elif not price_id:
            m.action, m.reason = "skip", f"no active {currency} price for plan {plan} in Yoon (run yoon_sync_catalog)"
        out.append(m)
    return out


class YoonAdmin:
    """The few calls the migration needs. Never logs the tokens."""

    def __init__(self, base_url: str, api_key: str, admin_token: str, application_id: str):
        import httpx
        self.app = application_id
        self.api = httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {api_key}"}, timeout=30)
        self.admin = httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {admin_token}"}, timeout=30)

    @staticmethod
    def _check(resp, what: str):
        if resp.status_code >= 400:
            try:
                problem = resp.json()
            except ValueError:
                problem = {"status": resp.status_code}
            raise RuntimeError(f"{what}: HTTP {resp.status_code} {problem.get('code', '')} {problem.get('detail', '')}")
        return resp.json()

    def ensure_customer(self, m: UserMigration, email: str) -> str:
        resp = self.api.post("/v1/customers", headers={"Idempotency-Key": f"osig-migrate-customer-{m.user_id}"},
                             json={"external_id": m.user_id, "email": email, "country": m.country})
        if resp.status_code == 409 and resp.json().get("code") == "customer_exists":
            found = self._check(self.api.get("/v1/customers", params={"external_id": m.user_id}), "find customer")
            return found["data"][0]["id"]
        return self._check(resp, "create customer")["id"]

    def comp(self, customer_id: str, m: UserMigration) -> dict:
        body: Dict[str, Any] = {"price": m.price_id, "note": "migration from OSIG one-off billing"}
        if m.until is None:
            body["open"] = True
        else:
            body["until"] = m.until_text
        resp = self.admin.post(f"/admin/v1/applications/{self.app}/customers/{customer_id}/comp",
                               headers={"Idempotency-Key": f"osig-migrate-comp-{m.user_id}"}, json=body)
        return self._check(resp, "comp")


def migrate(db: Session, admin: YoonAdmin, m: UserMigration) -> str:
    user = db.query(User).filter(User.id == m.user_id).with_for_update().one()
    if user.yoon_subscription_id:
        db.commit()
        return user.yoon_subscription_id
    customer_id = admin.ensure_customer(m, user.email)
    sub = admin.comp(customer_id, m)
    user.yoon_customer_id = customer_id
    user.yoon_subscription_id = sub["id"]
    db.commit()
    return sub["id"]
