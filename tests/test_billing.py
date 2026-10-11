"""Billing through Yoon: checkout, signed webhooks, settling once, plan periods, limits."""
import json
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from yoonpay import sign_signature

from app.core.config import settings
from app.models.billing import Payment
from app.models.platform import MailOutbox
from app.models.user import User, UserPlan
from app.services import billing_service

SECRET = "test-webhook-secret-of-at-least-32-chars!"


class FakeYoon:
    def __init__(self):
        self.created = []
        self.status = {}

    def create_payment(self, body, idempotency_key):
        pid = f"pay_{uuid.uuid4().hex}"
        self.created.append((body, idempotency_key, pid))
        self.status[pid] = SimpleNamespace(id=pid, status="pending", amount=body["amount"],
                                           currency=body["currency"], method="any")
        return SimpleNamespace(id=pid, checkout_url=f"http://yoon.test/checkout/{pid}?t=x")

    def get_payment(self, pid):
        return self.status[pid]


@pytest.fixture
def yoon(monkeypatch):
    fake = FakeYoon()
    monkeypatch.setattr(settings, "YOON_API_URL", "http://yoon.test")
    monkeypatch.setattr(settings, "YOON_API_KEY", "yk_test")
    monkeypatch.setattr(settings, "YOON_WEBHOOK_SECRET", SECRET)
    monkeypatch.setattr(billing_service, "yoon_client", lambda: fake)
    return fake


@pytest.fixture
def free_user(client, db):
    tag = uuid.uuid4().hex[:8]
    r = client.post("/api/v1/auth/register", json={"email": f"b{tag}@gmail.com", "username": f"b{tag}",
                                                   "password": "Passw0rd!x"}).json()
    db.query(User).filter(User.id == r["user"]["id"]).update({"email_verified": True})
    db.commit()
    return {"Authorization": f"Bearer {r['access_token']}"}, r["user"]["id"]


def _event(type_, obj, event_id=None):
    body = json.dumps({"id": event_id or f"evt_{uuid.uuid4().hex}", "type": type_, "data": {"object": obj},
                       "created_at": datetime.utcnow().isoformat() + "Z"}).encode()
    return body, {"Yoon-Signature": sign_signature(SECRET, body), "Content-Type": "application/json"}


def _paid_event(client, pid, amount, currency="XOF", event_id=None):
    body, headers = _event("payment.succeeded", {"id": pid, "object": "payment", "status": "succeeded",
                                                 "amount": amount, "currency": currency, "method": "wave"}, event_id)
    return client.post("/api/v1/billing/yoon/webhook", content=body, headers=headers)


def _user(db, uid):
    db.expire_all()
    return db.query(User).filter(User.id == uid).one()


def _checkout(client, headers, period="month", country="SN", plan="pro"):
    r = client.post("/api/v1/billing/checkout", headers=headers, json={"plan": plan, "period": period, "country": country})
    assert r.status_code == 201, r.text
    return r.json()


# ── plans & checkout ─────────────────────────────────────────────
def test_plans_are_public_and_prices_come_from_the_server(client, yoon, free_user):
    plans = client.get("/api/v1/billing/plans").json()
    assert [p["slug"] for p in plans["plans"]] == ["free", "pro", "enterprise"]
    headers, _ = free_user
    out = _checkout(client, headers, "year", "SN")
    body, key, _pid = yoon.created[-1]
    assert out["amount"] == 50000 and body["amount"] == 50000 and body["currency"] == "XOF"
    assert body["checkout"] == "hosted" and key.startswith("osig-") and "#/billing?ref=" in body["return_url"]
    # outside the XOF zone: card in USD
    _checkout(client, headers, "month", "FR")
    assert yoon.created[-1][0]["currency"] == "USD" and yoon.created[-1][0]["amount"] == 900


def test_enterprise_and_free_cant_be_bought(client, yoon, free_user):
    headers, _ = free_user
    for plan in ("enterprise", "free"):
        r = client.post("/api/v1/billing/checkout", headers=headers, json={"plan": plan, "period": "month", "country": "SN"})
        assert r.status_code == 400


def test_checkout_needs_verified_email_and_configured_gateway(client, unverified_user, monkeypatch):
    headers, _ = unverified_user
    assert client.post("/api/v1/billing/checkout", headers=headers,
                       json={"plan": "pro", "period": "month", "country": "SN"}).status_code == 403
    monkeypatch.setattr(settings, "YOON_API_KEY", "")
    assert client.get("/api/v1/billing/plans").json()["enabled"] is False


# ── webhook ──────────────────────────────────────────────────────
def test_signed_webhook_activates_once(client, db, yoon, free_user):
    headers, uid = free_user
    out = _checkout(client, headers)
    pid = yoon.created[-1][2]

    bad = client.post("/api/v1/billing/yoon/webhook", content=b'{"id":"x"}', headers={"Yoon-Signature": "t=1,v1=00"})
    assert bad.status_code == 401
    assert _user(db, uid).plan == UserPlan.FREE   # returning from checkout grants nothing

    assert _paid_event(client, pid, 5000, event_id="evt_same").status_code == 200
    u = _user(db, uid)
    assert u.plan == UserPlan.PRO and u.plan_source == "purchase"
    first_expiry = u.plan_expires_at
    assert timedelta(days=29) < first_expiry - datetime.utcnow() <= timedelta(days=30)

    # replayed event and a second delivery with a new id change nothing
    _paid_event(client, pid, 5000, event_id="evt_same")
    _paid_event(client, pid, 5000)
    assert _user(db, uid).plan_expires_at == first_expiry
    status = client.get(f"/api/v1/billing/payments/{out['reference']}", headers=headers).json()
    assert status["status"] == "paid"
    receipts = db.query(MailOutbox).filter(MailOutbox.kind == "billing_receipt", MailOutbox.to == u.email).count()
    assert receipts == 1


def test_amount_mismatch_never_activates(client, db, yoon, free_user):
    headers, uid = free_user
    out = _checkout(client, headers)
    _paid_event(client, yoon.created[-1][2], 100)
    assert _user(db, uid).plan == UserPlan.FREE
    p = db.query(Payment).filter(Payment.reference == out["reference"]).one()
    assert p.status == "failed" and "mismatch" in p.failure_reason


def test_status_poll_asks_yoon_when_webhook_is_late(client, db, yoon, free_user):
    headers, uid = free_user
    out = _checkout(client, headers)
    pid = yoon.created[-1][2]
    assert client.get(f"/api/v1/billing/payments/{out['reference']}", headers=headers).json()["status"] == "pending"
    yoon.status[pid].status = "succeeded"
    assert client.get(f"/api/v1/billing/payments/{out['reference']}", headers=headers).json()["status"] == "paid"
    assert _user(db, uid).plan == UserPlan.PRO


def test_failed_payment_and_other_users_reference(client, db, yoon, free_user, user):
    headers, uid = free_user
    out = _checkout(client, headers)
    body, h = _event("payment.failed", {"id": yoon.created[-1][2], "status": "failed", "amount": 5000, "currency": "XOF"})
    client.post("/api/v1/billing/yoon/webhook", content=body, headers=h)
    assert client.get(f"/api/v1/billing/payments/{out['reference']}", headers=headers).json()["status"] == "failed"
    other_headers, _ = user
    assert client.get(f"/api/v1/billing/payments/{out['reference']}", headers=other_headers).status_code == 404


# ── periods ──────────────────────────────────────────────────────
def test_early_renewal_stacks_and_downgrade_waits(db, free_user, client):
    _h, uid = free_user
    u = _user(db, uid)
    billing_service.activate(db, u, "pro", 30)
    db.commit()
    first = _user(db, uid).plan_expires_at
    billing_service.activate(db, _user(db, uid), "pro", 30)
    db.commit()
    assert _user(db, uid).plan_expires_at - first == timedelta(days=30)

    # upgrade starts now; a later Pro purchase waits until Enterprise ends
    billing_service.grant(db, _user(db, uid), "enterprise", 10)
    billing_service.activate(db, _user(db, uid), "pro", 30)
    db.commit()
    u = _user(db, uid)
    assert u.plan == UserPlan.ENTERPRISE and u.pending_plan == "pro" and u.pending_plan_days == 30

    # Enterprise lapses past the grace period: the queued Pro starts
    u.plan_expires_at = datetime.utcnow() - timedelta(days=settings.BILLING_GRACE_DAYS + 1)
    db.commit()
    assert billing_service.expire_plans(db) >= 1
    u = _user(db, uid)
    assert u.plan == UserPlan.PRO and u.pending_plan is None
    assert timedelta(days=29) < u.plan_expires_at - datetime.utcnow() <= timedelta(days=30)


def test_grace_period_then_free_and_reminder(db, free_user):
    _h, uid = free_user
    billing_service.activate(db, _user(db, uid), "pro", 30)
    db.commit()
    u = _user(db, uid)
    u.plan_expires_at = datetime.utcnow() + timedelta(days=3)
    db.commit()
    assert billing_service.send_renewal_reminders(db) >= 1
    assert billing_service.send_renewal_reminders(db) == 0 or _user(db, uid).renewal_reminded_at  # once only

    u = _user(db, uid)
    u.plan_expires_at = datetime.utcnow() - timedelta(days=1)  # inside grace
    db.commit()
    billing_service.expire_plans(db)
    assert _user(db, uid).plan == UserPlan.PRO
    u.plan_expires_at = datetime.utcnow() - timedelta(days=settings.BILLING_GRACE_DAYS + 1)
    db.commit()
    billing_service.expire_plans(db)
    u = _user(db, uid)
    assert u.plan == UserPlan.FREE and u.plan_expires_at is None


# ── limits ───────────────────────────────────────────────────────
def test_free_plan_limits(client, free_user):
    headers, _ = free_user
    deep = client.post("/api/v1/scans", headers=headers, json={"target_type": "domain", "target_value": "example.com",
                                                              "scan_type": "deep", "disclaimer_accepted": True})
    assert deep.status_code == 402 and "Billing" in deep.json()["detail"]
    assert client.post("/api/v1/api-keys", headers=headers, json={"name": "x"}).status_code == 402
    bulk = client.post("/api/v1/investigations/bulk", headers=headers,
                       json={"name": "b", "csv": "domain,example.com", "disclaimer_accepted": True})
    assert bulk.status_code == 402
    w = {"target_type": "domain", "target_value": "example.com", "scan_type": "quick"}
    assert client.post("/api/v1/watches", headers=headers, json={**w, "interval_hours": 6}).status_code == 402
    for i in range(2):
        assert client.post("/api/v1/watches", headers=headers,
                           json={**w, "target_value": f"ex{i}.com", "interval_hours": 24}).status_code == 201
    assert client.post("/api/v1/watches", headers=headers, json={**w, "interval_hours": 24}).status_code == 402
    me = client.get("/api/v1/billing/me", headers=headers).json()
    assert me["plan"] == "free" and me["limits"]["daily_scans"] == 10 and me["usage"]["watches"] == 2


def test_daily_quota_follows_plan(client, db, free_user):
    headers, uid = free_user
    for i in range(10):
        assert client.post("/api/v1/scans", headers=headers, json={
            "target_type": "domain", "target_value": f"q{i}.example.com", "scan_type": "quick",
            "disclaimer_accepted": True}).status_code == 201
    over = client.post("/api/v1/scans", headers=headers, json={
        "target_type": "domain", "target_value": "q.example.com", "scan_type": "quick", "disclaimer_accepted": True})
    assert over.status_code == 429


def test_admin_grant_and_plan_edit(client, db, user, free_user):
    admin_headers, admin = user
    db.query(User).filter(User.id == admin["user"]["id"]).update({"is_superuser": True})
    db.commit()
    _h, uid = free_user
    r = client.post(f"/api/v1/billing/admin/users/{uid}/grant", headers=admin_headers, json={"plan": "enterprise"})
    assert r.status_code == 200 and r.json()["source"] == "comp" and r.json()["expires_at"] is None
    r = client.patch("/api/v1/billing/admin/plans/pro", headers=admin_headers,
                     json={"prices": {"XOF": {"month": 7000}}, "limits": {"daily_scans": 300}})
    assert r.status_code == 200 and r.json()["limits"]["daily_scans"] == 300 and r.json()["limits"]["deep_scans"] is True
    bad = client.patch("/api/v1/billing/admin/plans/pro", headers=admin_headers, json={"prices": {"XOF": {"month": 1.5}}})
    assert bad.status_code == 422
    assert client.post(f"/api/v1/billing/admin/users/{uid}/grant", headers=_h,
                       json={"plan": "pro"}).status_code == 403


def test_reconcile_settles_payments_whose_webhook_was_lost(client, db, yoon, free_user):
    headers, uid = free_user
    out = _checkout(client, headers)
    pid = yoon.created[-1][2]
    db.query(Payment).filter(Payment.reference == out["reference"]).update(
        {"created_at": datetime.utcnow() - timedelta(minutes=5)})
    db.commit()
    yoon.status[pid].status = "succeeded"
    assert billing_service.reconcile_pending(db) == 1
    assert _user(db, uid).plan == UserPlan.PRO
    assert billing_service.reconcile_pending(db) == 0
