"""Yoon 0.3.0 subscription webhooks: signed test events drive access; nothing else does."""
import json
import uuid
from datetime import datetime, timedelta

import pytest
from yoonpay import sign_signature

from app.core.config import settings
from app.models.platform import MailOutbox
from app.models.user import User, UserPlan

SECRET = "test-webhook-secret-of-at-least-32-chars!"


@pytest.fixture(autouse=True)
def webhook_secret(monkeypatch):
    monkeypatch.setattr(settings, "YOON_WEBHOOK_SECRET", SECRET)


@pytest.fixture
def member(client, db):
    tag = uuid.uuid4().hex[:8]
    r = client.post("/api/v1/auth/register", json={"email": f"s{tag}@gmail.com", "username": f"s{tag}",
                                                   "password": "Passw0rd!x"}).json()
    db.query(User).filter(User.id == r["user"]["id"]).update({"email_verified": True})
    db.commit()
    return r["user"]["id"]


def _cus(user_id):
    return f"cus_{str(user_id).replace('-', '')[:12]}"


def _iso(dt):
    return dt.replace(microsecond=0).isoformat() + "Z"


def _sub(user_id, status="active", plan="pro", sub_id="sub_1", end=None, updated=None, comp=False, pending=None):
    end = end if end is not None else datetime.utcnow() + timedelta(days=31)
    return {
        "id": sub_id, "object": "subscription", "status": status, "comp": comp,
        "entitled": status in ("active", "past_due"),
        "customer": {"id": _cus(user_id), "external_id": str(user_id)},
        "price": {"id": "price_1", "currency": "XOF", "amount": 5000, "interval": "month", "interval_count": 1,
                  "plan": {"id": "plan_1", "slug": plan, "name": plan.title()}},
        "current_period_start": _iso(datetime.utcnow()),
        "current_period_end": _iso(end) if end != "open" else None,
        "grace_period_days": 2, "cancel_at_period_end": False, "features": {"daily_scans": 200},
        "pending_change": pending, "metadata": {},
        "created_at": _iso(datetime.utcnow() - timedelta(days=1)),
        "updated_at": _iso(updated or datetime.utcnow()),
    }


def _send(client, type_, obj, event_id=None):
    body = json.dumps({"id": event_id or f"evt_{uuid.uuid4().hex}", "object": "event", "type": type_,
                       "created_at": _iso(datetime.utcnow()), "data": {"object": obj}}).encode()
    return client.post("/api/v1/billing/yoon/webhook", content=body,
                       headers={"Yoon-Signature": sign_signature(SECRET, body), "Content-Type": "application/json"})


def _user(db, uid):
    db.expire_all()
    return db.query(User).filter(User.id == uid).one()


def test_activated_grants_plan_until_period_end(client, db, member):
    end = datetime.utcnow() + timedelta(days=31)
    assert _send(client, "subscription.activated", _sub(member, end=end)).status_code == 200
    u = _user(db, member)
    assert u.plan == UserPlan.PRO and u.plan_source == "purchase"
    assert abs((u.plan_expires_at - end).total_seconds()) < 2
    assert u.yoon_subscription_id == "sub_1" and u.yoon_customer_id == _cus(member)


def test_unsigned_or_forged_events_change_nothing(client, db, member):
    body = json.dumps({"id": "evt_x", "type": "subscription.activated", "data": {"object": _sub(member)}}).encode()
    assert client.post("/api/v1/billing/yoon/webhook", content=body,
                       headers={"Yoon-Signature": sign_signature("another-secret-another-secret-123", body)}).status_code == 401
    assert client.post("/api/v1/billing/yoon/webhook", content=body).status_code == 401
    assert _user(db, member).plan == UserPlan.FREE


def test_past_due_keeps_access_then_expired_removes_it(client, db, member):
    t0 = datetime.utcnow()
    _send(client, "subscription.activated", _sub(member, updated=t0))
    _send(client, "subscription.past_due", _sub(member, status="past_due", end=t0, updated=t0 + timedelta(seconds=5)))
    assert _user(db, member).plan == UserPlan.PRO  # grace: still entitled
    _send(client, "subscription.expired", _sub(member, status="expired", end=t0, updated=t0 + timedelta(seconds=9)))
    u = _user(db, member)
    assert u.plan == UserPlan.FREE and u.plan_expires_at is None


def test_late_older_event_is_ignored(client, db, member):
    t0 = datetime.utcnow()
    _send(client, "subscription.canceled", _sub(member, status="canceled", updated=t0 + timedelta(seconds=10)))
    _send(client, "subscription.activated", _sub(member, updated=t0))  # arrives after, but older
    assert _user(db, member).plan == UserPlan.FREE


def test_unknown_status_and_unknown_plan_are_not_entitlements(client, db, member):
    _send(client, "subscription.changed", _sub(member, status="paused_by_future_version"))
    assert _user(db, member).plan == UserPlan.FREE
    _send(client, "subscription.activated", _sub(member, plan="platinum"))
    assert _user(db, member).plan == UserPlan.FREE


def test_old_subscription_ending_does_not_remove_the_current_one(client, db, member):
    _send(client, "subscription.activated", _sub(member, sub_id="sub_new", plan="enterprise"))
    _send(client, "subscription.canceled", _sub(member, sub_id="sub_old", status="canceled"))
    assert _user(db, member).plan == UserPlan.ENTERPRISE


def test_open_ended_comp_and_pending_downgrade(client, db, member):
    pending = {"price": {"id": "price_2", "plan": {"slug": "pro"}}, "effective_at": None}
    _send(client, "subscription.activated", _sub(member, plan="enterprise", end="open", comp=True, pending=pending))
    u = _user(db, member)
    assert u.plan == UserPlan.ENTERPRISE and u.plan_expires_at is None and u.plan_source == "comp"
    assert u.pending_plan == "pro"


def test_duplicate_event_is_handled_once(client, db, member):
    obj = _sub(member, end=datetime.utcnow() + timedelta(days=10))
    _send(client, "subscription.renewal_upcoming", obj, event_id="evt_dup")
    _send(client, "subscription.renewal_upcoming", obj, event_id="evt_dup")
    email = _user(db, member).email
    assert db.query(MailOutbox).filter(MailOutbox.to == email, MailOutbox.kind == "billing_reminder").count() == 1


def test_renewal_reminder_and_receipt_emails(client, db, member):
    _send(client, "subscription.activated", _sub(member))
    _send(client, "subscription.renewal_upcoming", _sub(member))
    invoice = {"id": "in_1", "object": "invoice", "number": "OSIG-2026-000001", "customer": _cus(member),
               "subscription": "sub_1", "kind": "first", "status": "paid", "amount_due": 5000, "currency": "XOF",
               "lines": [], "period_end": _iso(datetime.utcnow() + timedelta(days=31)),
               "receipt_url": "http://localhost:8080/checkout/receipts/in_1?t=abc", "created_at": _iso(datetime.utcnow())}
    _send(client, "invoice.paid", invoice)
    email = _user(db, member).email
    mails = {m.kind: m for m in db.query(MailOutbox).filter(MailOutbox.to == email).all()}
    assert "ends on" in mails["billing_reminder"].body
    r = mails["billing_receipt"]
    assert "OSIG-2026-000001" in r.subject and "5 000 XOF" in r.body
    assert "receipts/in_1" in r.body and "not a tax invoice" in r.body
    assert _user(db, member).plan == UserPlan.PRO  # e-mails never change access


def test_informational_events_never_grant(client, db, member):
    _send(client, "subscription.created", _sub(member, status="incomplete"))
    _send(client, "invoice.created", {"id": "in_2", "object": "invoice", "customer": _cus(member), "status": "open"})
    assert _user(db, member).plan == UserPlan.FREE
