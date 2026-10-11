"""Moving paid OSIG users to Yoon subscriptions: dry-run plan, comp requests, idempotency."""
import json
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest

from app.models.billing import Payment
from app.models.user import User, UserPlan
from app.services import yoon_migration

CATALOG = [
    {"slug": "pro", "prices": [
        {"id": "price_pro_xof_m", "currency": "XOF", "interval": "month", "interval_count": 1, "active": True},
        {"id": "price_pro_xof_y", "currency": "XOF", "interval": "year", "interval_count": 1, "active": True},
        {"id": "price_pro_usd_m", "currency": "USD", "interval": "month", "interval_count": 1, "active": True},
        {"id": "price_old", "currency": "XOF", "interval": "month", "interval_count": 3, "active": False}]},
    {"slug": "enterprise", "prices": [
        {"id": "price_ent_xof_m", "currency": "XOF", "interval": "month", "interval_count": 1, "active": True}]},
]


@pytest.fixture
def clean(db):
    db.query(User).filter(User.plan != UserPlan.FREE).update({"plan": UserPlan.FREE, "plan_expires_at": None},
                                                             synchronize_session=False)
    db.commit()


def _user(db, plan, until=None, sub=None, paid=None):
    tag = uuid.uuid4().hex[:8]
    u = User(email=f"mig{tag}@example.com", username=f"mig{tag}", hashed_password="x", email_verified=True,
             plan=plan, plan_expires_at=until, yoon_subscription_id=sub)
    db.add(u)
    db.flush()
    if paid:
        currency, period, country = paid
        db.add(Payment(user_id=u.id, reference=f"osig_{tag}", plan=plan.value, period=period, amount=1,
                       currency=currency, country=country, status="paid", paid_at=datetime.utcnow()))
    db.commit()
    return u


def test_dry_run_lists_every_paid_user_with_price_and_end(db, clean):
    later = datetime.utcnow() + timedelta(days=40)
    pro_year = _user(db, UserPlan.PRO, later, paid=("XOF", "year", "SN"))
    pro_usd = _user(db, UserPlan.PRO, later, paid=("USD", "quarter", "FR"))  # no USD 3-month price: monthly
    ent_open = _user(db, UserPlan.ENTERPRISE, None)
    done = _user(db, UserPlan.PRO, later, sub="sub_existing")
    lapsed = _user(db, UserPlan.PRO, datetime.utcnow() - timedelta(days=1))
    rows = {r.user_id: r for r in yoon_migration.plan_migration(db, CATALOG)}
    assert rows[str(pro_year.id)].price_id == "price_pro_xof_y" and rows[str(pro_year.id)].action == "migrate"
    assert rows[str(pro_usd.id)].price_id == "price_pro_usd_m" and rows[str(pro_usd.id)].country == "FR"
    assert rows[str(ent_open.id)].until_text == "open" and rows[str(ent_open.id)].price_id == "price_ent_xof_m"
    assert rows[str(done.id)].action == "skip" and rows[str(lapsed.id)].action == "skip"
    assert rows[str(pro_year.id)].email.startswith("mi***@")  # masked in output


class FakeYoon:
    def __init__(self):
        self.customers, self.comps, self.keys = {}, {}, []

    def handler(self, request: httpx.Request):
        body = json.loads(request.content or b"{}")
        self.keys.append(request.headers.get("Idempotency-Key"))
        if request.method == "POST" and request.url.path == "/v1/customers":
            if body["external_id"] in self.customers:
                return httpx.Response(409, json={"code": "customer_exists"})
            self.customers[body["external_id"]] = f"cus_{len(self.customers)}"
            return httpx.Response(201, json={"id": self.customers[body["external_id"]]})
        if request.method == "GET" and request.url.path == "/v1/customers":
            return httpx.Response(200, json={"data": [{"id": self.customers[request.url.params["external_id"]]}]})
        if request.url.path.endswith("/comp"):
            key = request.headers["Idempotency-Key"]
            self.comps.setdefault(key, (body, f"sub_{len(self.comps)}"))
            return httpx.Response(200, json={"id": self.comps[key][1], "status": "active", "comp": True})
        return httpx.Response(404, json={})


def _admin(fake):
    admin = yoon_migration.YoonAdmin("http://yoon.test", "yk", "admintoken", "app-1")
    transport = httpx.MockTransport(fake.handler)
    admin.api = httpx.Client(base_url="http://yoon.test", transport=transport)
    admin.admin = httpx.Client(base_url="http://yoon.test", transport=transport)
    return admin


def test_migrate_creates_customer_comps_until_end_and_is_idempotent(db, clean):
    until = (datetime.utcnow() + timedelta(days=20)).replace(microsecond=0)
    u = _user(db, UserPlan.PRO, until)
    open_u = _user(db, UserPlan.ENTERPRISE, None)
    fake = FakeYoon()
    admin = _admin(fake)
    rows = {r.user_id: r for r in yoon_migration.plan_migration(db, CATALOG)}
    sub = yoon_migration.migrate(db, admin, rows[str(u.id)])
    body, _ = fake.comps[f"osig-migrate-comp-{u.id}"]
    assert body["until"] == until.strftime("%Y-%m-%dT%H:%M:%SZ") and body["price"] == "price_pro_xof_m"
    yoon_migration.migrate(db, admin, rows[str(open_u.id)])
    assert fake.comps[f"osig-migrate-comp-{open_u.id}"][0]["open"] is True

    db.expire_all()
    stored = db.query(User).filter(User.id == u.id).one()
    assert stored.yoon_subscription_id == sub and stored.yoon_customer_id == fake.customers[str(u.id)]
    # second run: nothing new (already linked); a lost link recovers the customer through ?external_id=
    assert yoon_migration.migrate(db, admin, rows[str(u.id)]) == sub
    stored.yoon_subscription_id = None
    db.commit()
    assert yoon_migration.migrate(db, admin, rows[str(u.id)]) == sub
    assert len(fake.customers) == 2 and len(fake.comps) == 2


def test_script_dry_run_changes_nothing_and_hides_secrets(monkeypatch, capsys, db, clean):
    import scripts.yoon_migrate_users as script
    from app.core.config import settings
    from app.services import billing_service, yoon_catalog
    u = _user(db, UserPlan.PRO, datetime.utcnow() + timedelta(days=5))
    monkeypatch.setattr(settings, "YOON_API_URL", "http://yoon.test")
    monkeypatch.setattr(settings, "YOON_API_KEY", "yk_secret_value")
    monkeypatch.setattr(settings, "YOON_ADMIN_TOKEN", "admin_secret_value")
    monkeypatch.setattr(billing_service, "yoon_client", lambda: SimpleNamespace())
    monkeypatch.setattr(yoon_catalog, "fetch_existing", lambda yoon: CATALOG)
    called = []
    monkeypatch.setattr(yoon_migration, "migrate", lambda *a: called.append(a))
    assert script.main([]) == 0
    out = capsys.readouterr().out
    assert "to migrate" in out and "price_pro_xof_m" in out and "Dry run" in out
    assert "secret_value" not in out and u.email not in out and "mi***@example.com" in out
    assert called == []
