"""Buying through Yoon subscriptions: subscribe, renew (NoCheckout -> renew), change, sync, old path retired."""
import uuid
from types import SimpleNamespace

import pytest
from yoonpay import YoonException

from app.core.config import settings
from app.models.user import User, UserPlan
from app.services import billing_service, yoon_catalog


class Obj(SimpleNamespace):
    """Attribute access like a generated model, plus to_dict() for yoonpay's helpers."""

    def to_dict(self):
        def conv(v):
            if isinstance(v, Obj):
                return v.to_dict()
            if isinstance(v, list):
                return [conv(x) for x in v]
            return v
        return {k: conv(v) for k, v in vars(self).items()}


def _price(pid, currency, interval, count):
    return Obj(id=pid, currency=currency, interval=interval, interval_count=count, active=True)


CATALOG = [
    Obj(slug="pro", active=True, prices=[_price("price_pro_m", "XOF", "month", 1), _price("price_pro_y", "XOF", "year", 1),
                                          _price("price_pro_usd_m", "USD", "month", 1)]),
    Obj(slug="enterprise", active=True, prices=[_price("price_ent_m", "XOF", "month", 1)]),
]


def _invoice(kind="first", url="http://yoon.test/checkout/pay_1?t=x"):
    return Obj(id=f"in_{uuid.uuid4().hex[:6]}", object="invoice", kind=kind, status="open" if url else "paid",
               checkout_url=url)


class FakeCustomers:
    def __init__(self, fake):
        self.fake = fake

    def create_customer(self, key, req):
        self.fake.calls.append(("create_customer", key, req.country))
        if req.external_id in self.fake.cust_ids:
            raise YoonException("exists", http_status=409, problem_code="customer_exists")
        self.fake.cust_ids[req.external_id] = f"cus_{uuid.uuid4().hex[:12]}"
        return Obj(id=self.fake.cust_ids[req.external_id])

    def list_customers(self, external_id=None, **kw):
        return Obj(data=[Obj(id=self.fake.cust_ids[external_id])])


class FakeSubscriptions:
    def __init__(self, fake):
        self.fake = fake

    def create_subscription(self, key, req):
        self.fake.calls.append(("create_subscription", key, req.price))
        sub = Obj(id=f"sub_{uuid.uuid4().hex[:12]}", object="subscription", status="incomplete",
                  price=Obj(id=req.price), current_period_end=None, latest_invoice=_invoice(url=self.fake.first_url))
        self.fake.subs[sub.id] = sub
        return sub

    def get_subscription(self, sid):
        return self.fake.subs[sid]

    def renew_subscription(self, sid, key, req):
        self.fake.calls.append(("renew", key))
        sub = self.fake.subs[sid]
        sub.latest_invoice = _invoice("renewal", url="http://yoon.test/checkout/renew")
        return sub

    def change_subscription(self, sid, key, req):
        self.fake.calls.append(("change", req.price))
        sub = self.fake.subs[sid]
        cheaper = req.price == "price_pro_y"
        sub.latest_invoice = _invoice("renewal" if cheaper else "upgrade",
                                      url="http://yoon.test/checkout/old-renewal" if cheaper else "http://yoon.test/checkout/up")
        return sub

    def list_subscriptions(self, customer=None, **kw):
        return Obj(data=self.fake.listed)


class FakeYoon:
    def __init__(self):
        self.calls, self.subs, self.cust_ids, self.listed = [], {}, {}, []
        self.first_url = "http://yoon.test/checkout/first"

    def call(self, fn):
        return fn()

    def customers(self):
        return FakeCustomers(self)

    def subscriptions(self):
        return FakeSubscriptions(self)


@pytest.fixture
def yoon(monkeypatch):
    fake = FakeYoon()
    monkeypatch.setattr(settings, "YOON_API_URL", "http://yoon.test")
    monkeypatch.setattr(settings, "YOON_API_KEY", "yk")
    monkeypatch.setattr(settings, "YOON_WEBHOOK_SECRET", "x" * 40)
    monkeypatch.setattr(billing_service, "yoon_client", lambda: fake)
    monkeypatch.setattr(yoon_catalog, "fetch_existing", lambda y: CATALOG)
    return fake


@pytest.fixture
def buyer(client, db):
    tag = uuid.uuid4().hex[:8]
    r = client.post("/api/v1/auth/register", json={"email": f"buy{tag}@gmail.com", "username": f"buy{tag}",
                                                   "password": "Passw0rd!x"}).json()
    db.query(User).filter(User.id == r["user"]["id"]).update({"email_verified": True})
    db.commit()
    return {"Authorization": f"Bearer {r['access_token']}"}, r["user"]["id"]


def _buy(client, headers, plan="pro", period="month", country="SN"):
    return client.post("/api/v1/billing/subscribe", headers=headers,
                       json={"plan": plan, "period": period, "country": country})


def _user(db, uid):
    db.expire_all()
    return db.query(User).filter(User.id == uid).one()


def test_first_purchase_creates_customer_and_subscription(client, db, yoon, buyer):
    headers, uid = buyer
    r = _buy(client, headers)
    assert r.status_code == 200 and r.json()["checkout_url"] == "http://yoon.test/checkout/first"
    assert ("create_customer", f"osig-customer-{uid}", "SN") in yoon.calls
    create = next(c for c in yoon.calls if c[0] == "create_subscription")
    assert create[2] == "price_pro_m" and create[1].startswith(f"osig-subscribe-{uid}-price_pro_m-")
    u = _user(db, uid)
    assert u.yoon_customer_id == yoon.cust_ids[uid] and u.yoon_subscription_id in yoon.subs
    assert u.plan == UserPlan.FREE  # nothing granted until Yoon's signed event


def test_card_country_uses_usd_price(client, yoon, buyer):
    headers, _ = buyer
    _buy(client, headers, country="FR")
    assert next(c for c in yoon.calls if c[0] == "create_subscription")[2] == "price_pro_usd_m"
    assert ("create_customer", yoon.calls[0][1], "FR") in yoon.calls


def test_existing_customer_is_found_by_external_id(client, db, yoon, buyer):
    headers, uid = buyer
    yoon.cust_ids[uid] = "cus_existing"
    assert _buy(client, headers).status_code == 200
    assert _user(db, uid).yoon_customer_id == "cus_existing"


def test_renewing_same_price_and_no_checkout_falls_back_to_renew(client, db, yoon, buyer):
    headers, uid = buyer
    _buy(client, headers)
    sub = next(iter(yoon.subs.values()))
    sub.status = "active"
    sub.latest_invoice = _invoice(url=None)  # paid: NoCheckout
    r = _buy(client, headers)
    assert r.json()["checkout_url"] == "http://yoon.test/checkout/renew"
    assert [c[0] for c in yoon.calls].count("renew") == 1


def test_expired_first_checkout_is_renewed(client, yoon, buyer):
    headers, _ = buyer
    yoon.first_url = None  # the new subscription's invoice has no usable checkout
    r = _buy(client, headers)
    assert r.json()["checkout_url"] == "http://yoon.test/checkout/renew"


def test_upgrade_goes_to_checkout_downgrade_is_scheduled(client, db, yoon, buyer, monkeypatch):
    from app.services import plan_limits
    headers, uid = buyer
    _buy(client, headers)
    next(iter(yoon.subs.values())).status = "active"
    r = _buy(client, headers, period="year")  # cheaper per day: waits for the period end
    assert r.json() == {"scheduled": True}
    # Enterprise isn't sold online
    assert _buy(client, headers, plan="enterprise").status_code == 400
    # if it were, an upgrade would be invoiced now
    real = plan_limits.plan_info
    monkeypatch.setattr("app.services.subscription_service.plan_info",
                        lambda db, slug: {**real(db, slug), "self_serve": True})
    r = _buy(client, headers, plan="enterprise")
    assert r.json()["checkout_url"] == "http://yoon.test/checkout/up"


def test_sync_applies_latest_entitled_subscription(client, db, yoon, buyer):
    headers, uid = buyer
    _buy(client, headers)
    sub_id = next(iter(yoon.subs))
    yoon.listed = [Obj(id=sub_id, object="subscription", status="active", entitled=True, comp=False,
                       customer=Obj(id=yoon.cust_ids[uid], external_id=uid),
                       price=Obj(id="price_pro_m", plan=Obj(slug="pro")),
                       current_period_end="2031-01-01T00:00:00Z", updated_at="2030-12-01T00:00:00Z",
                       pending_change=None, features={})]
    r = client.post("/api/v1/billing/subscription/sync", headers=headers)
    assert r.status_code == 200 and r.json()["plan"] == "pro"
    assert _user(db, uid).plan_expires_at.year == 2031


def test_old_checkout_is_retired_and_needs_verified_email(client, yoon, buyer, unverified_user):
    headers, _ = buyer
    assert client.post("/api/v1/billing/checkout", headers=headers,
                       json={"plan": "pro", "period": "month", "country": "SN"}).status_code == 410
    uh, _ = unverified_user
    assert _buy(client, uh).status_code == 403


def test_yoon_errors_become_readable_messages(client, yoon, buyer, monkeypatch):
    headers, _ = buyer

    def refuse(self, key, req):
        raise YoonException("no provider", http_status=422, problem_code="no_provider_for_method")
    monkeypatch.setattr(FakeSubscriptions, "create_subscription", refuse)
    r = _buy(client, headers)
    assert r.status_code == 502 and "country" in r.json()["detail"]
