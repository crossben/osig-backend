"""My footprint: identities, actions + score, digest, household, push, request letters."""
import uuid
from datetime import datetime, timedelta

import pytest

from app.models.investigation import Watch
from app.models.personal import ActionItem, Identity, PushSubscription
from app.models.platform import MailOutbox
from app.models.result import Result
from app.models.scan import ModuleStatus, Scan, ScanModule, ScanStatus, ScanType
from app.models.user import User
from app.services import footprint_service, push_service

API = "/api/v1/me"


def _user(client, db, plan="ENTERPRISE", verified=True, language="en"):
    tag = uuid.uuid4().hex[:8]
    r = client.post("/api/v1/auth/register", json={
        "email": f"fp{tag}@gmail.com", "username": f"fp{tag}", "password": "Passw0rd!x"})
    assert r.status_code == 201, r.text
    body = r.json()
    db.query(User).filter(User.id == body["user"]["id"]).update(
        {"email_verified": verified, "plan": plan, "language": language})
    db.commit()
    return {"Authorization": f"Bearer {body['access_token']}"}, body["user"]


def _add(client, h, kind, value, expect=201):
    r = client.post(f"{API}/identities", headers=h, json={"kind": kind, "value": value})
    assert r.status_code == expect, r.text
    return r.json()


def _finish_watch_run(db, ident_id, results):
    """A finished scan for the identity's watch, with the given (data_type, data) results."""
    db.expire_all()
    ident = db.query(Identity).filter(Identity.id == ident_id).one()
    w = db.query(Watch).filter(Watch.id == ident.watch_id).one()
    scan = Scan(user_id=ident.user_id, target_type=w.target_type, target_value=w.target_value,
                scan_type=ScanType.QUICK, status=ScanStatus.COMPLETED, progress=100, watch_id=w.id)
    db.add(scan)
    db.flush()
    mod = ScanModule(scan_id=scan.id, name="m", display_name="M", status=ModuleStatus.COMPLETED)
    db.add(mod)
    db.flush()
    for data_type, data in results:
        db.add(Result(scan_id=scan.id, module_id=mod.id, module="m", data_type=data_type, data=data,
                      source="test", confidence=0.9))
    db.commit()
    return scan


def _recompute(db, user_id):
    db.expire_all()
    return footprint_service.recompute(db, db.query(User).filter(User.id == user_id).one())


BREACHES = [("breach", {"name": "LinkedIn", "breach_date": "2012-05-05", "data_classes": ["Passwords", "Emails"]}),
            ("breach", {"name": "Canva", "breach_date": "2019-05-24", "data_classes": ["Passwords"]})]


# ── identities ──────────────────────────────────────────────────────────

def test_identity_limits_per_plan(client, db):
    h, _ = _user(client, db, plan="FREE")
    for i in range(3):
        _add(client, h, "username", f"handle{i}{uuid.uuid4().hex[:4]}")
    r = client.post(f"{API}/identities", headers=h, json={"kind": "username", "value": "onemore"})
    assert r.status_code == 402
    assert "3 identities" in r.json()["detail"]


def test_account_email_auto_verified_and_watched(client, db):
    h, u = _user(client, db)
    ident = _add(client, h, "email", u["email"].upper())
    assert ident["verified"] and ident["watching"]
    w = db.query(Watch).join(Identity, Identity.watch_id == Watch.id).filter(Identity.id == ident["id"]).one()
    assert w.interval_hours == 24 and w.scan_type == ScanType.QUICK


def test_free_plan_watches_weekly(client, db):
    h, _ = _user(client, db, plan="FREE")
    ident = _add(client, h, "username", f"weekly{uuid.uuid4().hex[:6]}")
    assert ident["watching"] and not ident["verified"]
    assert db.query(Watch).join(Identity, Identity.watch_id == Watch.id).filter(
        Identity.id == ident["id"]).one().interval_hours == 168


def test_email_identity_link_flow(client, db):
    h, _ = _user(client, db)
    other = f"alt{uuid.uuid4().hex[:8]}@gmail.com"
    ident = _add(client, h, "email", other)
    assert not ident["verified"] and not ident["watching"]
    mail = db.query(MailOutbox).filter(MailOutbox.to == other, MailOutbox.kind == "verify_identity").one()
    token = mail.body.split("token=")[1].split()[0]
    assert client.post(f"{API}/identities/verify-email", json={"token": "bad"}).status_code == 400
    r = client.post(f"{API}/identities/verify-email", json={"token": token})
    assert r.status_code == 200, r.text
    listed = {i["id"]: i for i in client.get(f"{API}/identities", headers=h).json()}
    assert listed[ident["id"]]["verified"] and listed[ident["id"]]["watching"]


def test_phone_not_watched_without_sms(client, db):
    h, _ = _user(client, db)
    ident = _add(client, h, "phone", "+221771234567")
    assert not ident["watching"] and ident["verification"]["method"] == "unavailable"
    r = client.post(f"{API}/identities/{ident['id']}/verify", headers=h, json={})
    assert r.status_code == 501


def test_domain_txt_verification(client, db, monkeypatch):
    h, _ = _user(client, db)
    ident = _add(client, h, "domain", f"d{uuid.uuid4().hex[:6]}.com")
    record = ident["verification"]["record"]
    assert record.startswith("osig-verify=") and not ident["watching"]
    monkeypatch.setattr("app.api.v1.me.txt_records", lambda d: ["v=spf1 -all"])
    assert client.post(f"{API}/identities/{ident['id']}/verify", headers=h, json={}).status_code == 400
    monkeypatch.setattr("app.api.v1.me.txt_records", lambda d: ["v=spf1 -all", record])
    r = client.post(f"{API}/identities/{ident['id']}/verify", headers=h, json={})
    assert r.status_code == 200 and r.json()["verified"] and r.json()["watching"]


def test_identity_watch_not_counted_and_deleted_with_identity(client, db):
    h, _ = _user(client, db, plan="FREE")  # free: 2 watches
    ident = _add(client, h, "username", f"own{uuid.uuid4().hex[:6]}")
    for v in ("example.com", "example.org"):
        r = client.post("/api/v1/watches", headers=h, json={"target_type": "domain", "target_value": v,
                                                             "interval_hours": 24})
        assert r.status_code == 201, r.text
    assert client.post("/api/v1/watches", headers=h, json={"target_type": "domain", "target_value": "example.net",
                                                            "interval_hours": 24}).status_code == 402
    watch_id = db.query(Identity).filter(Identity.id == ident["id"]).one().watch_id
    assert client.delete(f"{API}/identities/{ident['id']}", headers=h).status_code == 204
    db.expire_all()
    assert db.query(Watch).filter(Watch.id == watch_id).first() is None


# ── actions and score ───────────────────────────────────────────────────

def test_recompute_actions_score_done_and_auto_resolve(client, db):
    h, u = _user(client, db)
    ident = _add(client, h, "email", u["email"])
    _finish_watch_run(db, ident["id"], BREACHES + [("infostealer", {"infection_count": 1})])
    res = _recompute(db, u["id"])
    items = {a.key: a for a in db.query(ActionItem).filter(ActionItem.user_id == u["id"])}
    li = items[f"breach:linkedin:{ident['id']}"]
    assert "Change your password for LinkedIn" in li.title and li.link.startswith("https://www.linkedin.com")
    info = items[f"infostealer:{ident['id']}"]
    assert info.severity == "critical" and "password-stealing malware" in info.title
    assert res["score"] == 100 - 15 - 15 - 30 == 40

    fp = client.get(f"{API}/footprint", headers=h).json()
    assert fp["score"] == 40 and len(fp["actions"]["open"]) == 3
    assert fp["identities"][0]["findings"] == 3 and fp["trend"]

    # done -> score up, never recreated
    r = client.post(f"{API}/actions/{li.id}", headers=h, json={"status": "done"})
    assert r.json()["score"] == 55
    _finish_watch_run(db, ident["id"], BREACHES)
    res = _recompute(db, u["id"])
    db.expire_all()
    keys = [a.key for a in db.query(ActionItem).filter(ActionItem.user_id == u["id"])]
    assert keys.count(f"breach:linkedin:{ident['id']}") == 1
    assert db.query(ActionItem).filter(ActionItem.key == f"breach:linkedin:{ident['id']}").one().status == "done"
    # infostealer vanished from the latest run -> auto-resolved
    gone = db.query(ActionItem).filter(ActionItem.key == f"infostealer:{ident['id']}").one()
    assert gone.status == "done" and gone.resolved_at and res["resolved"] == 1
    assert res["score"] == 85


def test_score_floor_and_weights(client, db):
    h, u = _user(client, db)
    for i in range(5):
        db.add(ActionItem(user_id=u["id"], key=f"x{i}", severity="critical", title="t"))
    db.add(ActionItem(user_id=u["id"], key="request:gdpr_erasure:acme", severity="low", title="t"))
    db.commit()
    assert footprint_service.compute_score(db, u["id"]) == 0
    db.query(ActionItem).filter(ActionItem.user_id == u["id"], ActionItem.key.like("x%")).delete(
        synchronize_session=False)
    for sev in ("high", "medium", "low"):
        db.add(ActionItem(user_id=u["id"], key=f"s{sev}", severity=sev, title="t"))
    db.commit()
    assert footprint_service.compute_score(db, u["id"]) == 100 - 15 - 7 - 3


def test_watch_run_hook_recomputes(client, db):
    h, u = _user(client, db)
    ident = _add(client, h, "email", u["email"])
    scan = _finish_watch_run(db, ident["id"], BREACHES[:1])
    footprint_service.on_watch_run(db, str(scan.id))
    db.expire_all()
    assert db.query(User).filter(User.id == u["id"]).one().exposure_score == 85


def test_refresh_starts_scans(client, db, no_real_scans):
    h, u = _user(client, db)
    _add(client, h, "email", u["email"])
    r = client.post(f"{API}/footprint/refresh", headers=h)
    assert r.status_code == 202, r.text
    assert len(r.json()["started"]) == 1 and r.json()["started"][0] in no_real_scans


# ── digest ──────────────────────────────────────────────────────────────

def test_weekly_digest(client, db):
    h, u = _user(client, db)
    ident = _add(client, h, "email", u["email"])
    _finish_watch_run(db, ident["id"], BREACHES)
    _recompute(db, u["id"])
    _, off = _user(client, db)
    db.query(User).filter(User.id == off["id"]).update({"digest_enabled": False})
    db.add(Identity(user_id=off["id"], kind="username", value="someone"))
    db.commit()

    now = datetime.utcnow()
    footprint_service.send_weekly_digests(db, now)
    mails = db.query(MailOutbox).filter(MailOutbox.to == u["email"], MailOutbox.kind == "weekly_digest").all()
    assert len(mails) == 1
    body = mails[0].body
    assert mails[0].subject == "Your week on OSIG"
    assert "Protection score: 70/100" in body and "Open actions: 2" in body and "New findings this week: 2" in body
    assert "Change your password for LinkedIn" in body and footprint_service.tip_for(now) in body
    assert "#/footprint" in body and "#/profile" in body
    assert not db.query(MailOutbox).filter(MailOutbox.to == off["email"], MailOutbox.kind == "weekly_digest").first()

    footprint_service.send_weekly_digests(db, now + timedelta(days=2))  # once per week
    assert db.query(MailOutbox).filter(MailOutbox.to == u["email"], MailOutbox.kind == "weekly_digest").count() == 1


def test_weekly_digest_french(client, db):
    h, u = _user(client, db, language="fr")
    _add(client, h, "username", f"fr{uuid.uuid4().hex[:6]}")
    now = datetime.utcnow()
    footprint_service.send_weekly_digests(db, now)
    mail = db.query(MailOutbox).filter(MailOutbox.to == u["email"], MailOutbox.kind == "weekly_digest").one()
    assert mail.subject == "Votre semaine sur OSIG"
    assert footprint_service.tip_for(now, "fr") in mail.body and footprint_service.tip_for(now, "fr") in \
        footprint_service.TIPS_FR


def test_digest_enabled_in_profile(client, db):
    h, _ = _user(client, db)
    r = client.patch("/api/v1/auth/me", headers=h, json={"digest_enabled": False})
    assert r.status_code == 200 and r.json()["digest_enabled"] is False


# ── household ───────────────────────────────────────────────────────────

def test_household_limits_invite_accept_privacy(client, db):
    hf, _ = _user(client, db, plan="FREE")
    assert client.post(f"{API}/household", headers=hf, json={"email": "a@gmail.com"}).status_code == 402

    ho, owner = _user(client, db, plan="PRO")
    hm, member = _user(client, db, plan="FREE")
    secret = f"secret{uuid.uuid4().hex[:6]}"
    _add(client, hm, "username", secret)
    db.add(ActionItem(user_id=member["id"], key=f"breach:x:{uuid.uuid4()}", severity="high", title="t"))
    db.commit()

    r = client.post(f"{API}/household", headers=ho, json={"email": member["email"]})
    assert r.status_code == 201, r.text
    mail = db.query(MailOutbox).filter(MailOutbox.to == member["email"], MailOutbox.kind == "household_invite").one()
    token = mail.body.split("token=")[1].split()[0]

    hx, _ = _user(client, db)  # wrong account
    assert client.post(f"{API}/household/accept", headers=hx, json={"token": token}).status_code == 403
    assert client.post(f"{API}/household/accept", headers=hm, json={"token": token}).status_code == 200

    data = client.get(f"{API}/household", headers=ho).json()
    m = data["members"][0]
    assert m["status"] == "active" and m["open_actions"] == 1 and m["identities"] == 1
    assert secret not in str(data)
    assert client.get(f"{API}/household", headers=hm).json()["member_of"][0]["owner_email"] == owner["email"]

    # owner digest summarises the member
    footprint_service.send_weekly_digests(db, datetime.utcnow())
    digest = db.query(MailOutbox).filter(MailOutbox.to == owner["email"], MailOutbox.kind == "weekly_digest").one()
    assert "1 new breach" in digest.body and secret not in digest.body

    # member leaves
    assert client.delete(f"{API}/household/{m['id']}", headers=hx).status_code == 404
    assert client.delete(f"{API}/household/{m['id']}", headers=hm).status_code == 204
    assert client.get(f"{API}/household", headers=ho).json()["members"] == []


def test_household_limit_counts(client, db):
    h, _ = _user(client, db, plan="PRO")
    for i in range(5):
        assert client.post(f"{API}/household", headers=h, json={"email": f"m{i}{uuid.uuid4().hex[:4]}@gmail.com"}
                           ).status_code == 201
    assert client.post(f"{API}/household", headers=h, json={"email": "six@gmail.com"}).status_code == 402


# ── push ────────────────────────────────────────────────────────────────

KEYS = {"p256dh": "B" * 87, "auth": "A" * 22}


@pytest.mark.parametrize("endpoint", [
    "http://fcm.googleapis.com/fcm/send/x", "https://localhost/push", "https://169.254.169.254/latest",
    "https://evil.com/fcm.googleapis.com", "https://fcm.googleapis.com.evil.com/x", "https://u:p@fcm.googleapis.com/x",
    "https://fcm.googleapis.com:8443/x",
])
def test_push_rejects_non_push_hosts(client, db, endpoint):
    h, _ = _user(client, db)
    r = client.post(f"{API}/push/subscribe", headers=h, json={"endpoint": endpoint, "keys": KEYS})
    assert r.status_code == 422


def test_push_subscribe_send_and_cleanup(client, db, monkeypatch):
    h, u = _user(client, db)
    ok = f"https://fcm.googleapis.com/fcm/send/{uuid.uuid4().hex}"
    gone = f"https://wns2-par02p.notify.windows.com/w/?token={uuid.uuid4().hex}"
    for ep in (ok, gone):
        assert client.post(f"{API}/push/subscribe", headers=h, json={"endpoint": ep, "keys": KEYS}).status_code == 201
    assert client.get(f"{API}/push/key").status_code == 200

    class Gone(Exception):
        response = type("R", (), {"status_code": 410})()

    sent = []

    def fake(sub, payload):
        if sub.endpoint == gone:
            raise Gone("gone")
        sent.append(payload)

    monkeypatch.setattr(push_service, "_webpush", fake)
    monkeypatch.setattr(push_service, "enabled", lambda: True)
    assert push_service.send(db, u["id"], "t", "b") == 1
    db.expire_all()
    assert [s.endpoint for s in db.query(PushSubscription).filter(PushSubscription.user_id == u["id"])] == [ok]
    assert client.request("DELETE", f"{API}/push/subscribe", headers=h, json={"endpoint": ok}).status_code == 204


def test_new_urgent_action_pushes(client, db, monkeypatch):
    h, u = _user(client, db)
    ident = _add(client, h, "email", u["email"])
    pushed = []
    monkeypatch.setattr(push_service, "send", lambda db, uid, title, body, url="": pushed.append(title))
    _finish_watch_run(db, ident["id"], BREACHES)
    _recompute(db, u["id"])
    assert pushed and "2 new urgent actions" in pushed[0]


# ── request letters ─────────────────────────────────────────────────────

def test_letter_generation_tracked(client, db):
    h, u = _user(client, db)
    ident = _add(client, h, "username", f"letter{uuid.uuid4().hex[:6]}")
    templates = {t["id"] for t in client.get(f"{API}/requests/templates", headers=h).json()}
    assert {"gdpr_erasure", "gdpr_access", "senegal_cdp", "broker_optout"} <= templates
    r = client.post(f"{API}/requests/letter", headers=h, json={
        "template_id": "senegal_cdp", "company": "Acme  Data", "identities": [ident["id"]]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "Acme Data" in body["body"] and ident["value"] in body["body"] and "2008-12" in body["body"]
    item = db.query(ActionItem).filter(ActionItem.id == body["action_id"]).one()
    assert item.key == "request:senegal_cdp:acme-data" and item.status == "open"
    again = client.post(f"{API}/requests/letter", headers=h, json={"template_id": "senegal_cdp", "company": "Acme Data"})
    assert again.json()["action_id"] == body["action_id"]
    assert client.post(f"{API}/requests/letter", headers=h, json={"template_id": "nope", "company": "x"}).status_code == 404


def test_letter_french(client, db):
    h, u = _user(client, db, language="fr")
    r = client.post(f"{API}/requests/letter", headers=h, json={"template_id": "gdpr_erasure", "company": "Acme"})
    assert "Madame, Monsieur" in r.json()["body"] and u["email"] in r.json()["body"]


def test_actions_follow_user_language():
    from types import SimpleNamespace
    from app.services import footprint_service, risk_service
    ident = SimpleNamespace(value="me@example.com", id="i1", kind="email")
    flags = [{"id": "breach:passwords", "severity": "high", "evidence": ["LinkedIn"], "description": "x"}]
    orig = risk_service.assess
    risk_service.assess = lambda scan, results: {"flags": flags}
    try:
        en = footprint_service.actions_for_scan(ident, None, [], "en")[0]
        fr = footprint_service.actions_for_scan(ident, None, [], "fr")[0]
    finally:
        risk_service.assess = orig
    assert en["key"] == fr["key"]
    assert en["title"].startswith("Change your password for LinkedIn")
    assert fr["title"].startswith("Changez votre mot de passe LinkedIn")
