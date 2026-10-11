"""Billing through Yoon: checkout, signed webhooks, settling once, plan periods, limits."""
import json
import uuid
from datetime import datetime
from types import SimpleNamespace

import pytest
from yoonpay import sign_signature

from app.core.config import settings
from app.models.user import User
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



# ── plans & checkout ─────────────────────────────────────────────
def test_plans_are_public_and_prices_come_from_the_server(client, yoon, free_user):
    plans = client.get("/api/v1/billing/plans").json()
    assert [p["slug"] for p in plans["plans"]] == ["free", "pro", "enterprise"]
    pro = next(p for p in plans["plans"] if p["slug"] == "pro")
    assert pro["prices"]["XOF"]["year"] == 50000 and pro["prices"]["USD"]["month"] == 900
    assert pro["self_serve"] is True


def test_enterprise_and_free_cant_be_bought(client, yoon, free_user):
    headers, _ = free_user
    for plan in ("enterprise", "free"):
        r = client.post("/api/v1/billing/subscribe", headers=headers, json={"plan": plan, "period": "month", "country": "SN"})
        assert r.status_code == 400


def test_checkout_needs_verified_email_and_configured_gateway(client, unverified_user, monkeypatch):
    headers, _ = unverified_user
    assert client.post("/api/v1/billing/subscribe", headers=headers,
                       json={"plan": "pro", "period": "month", "country": "SN"}).status_code == 403
    monkeypatch.setattr(settings, "YOON_API_KEY", "")
    assert client.get("/api/v1/billing/plans").json()["enabled"] is False


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


def test_admin_plan_edit(client, db, user, free_user):
    admin_headers, admin = user
    db.query(User).filter(User.id == admin["user"]["id"]).update({"is_superuser": True})
    db.commit()
    _h, uid = free_user
    r = client.patch("/api/v1/billing/admin/plans/pro", headers=admin_headers,
                     json={"prices": {"XOF": {"month": 7000}}, "limits": {"daily_scans": 300}})
    assert r.status_code == 200 and r.json()["limits"]["daily_scans"] == 300 and r.json()["limits"]["deep_scans"] is True
    bad = client.patch("/api/v1/billing/admin/plans/pro", headers=admin_headers, json={"prices": {"XOF": {"month": 1.5}}})
    assert bad.status_code == 422
    assert client.post(f"/api/v1/billing/admin/users/{uid}/grant", headers=_h,
                       json={"plan": "pro"}).status_code == 403
