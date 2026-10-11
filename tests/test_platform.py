"""Sharing, bulk scans, API keys, admin, analysis views, exports, alerts, retention."""
import uuid
from datetime import datetime, timedelta

from app.models.investigation import Watch
from app.models.platform import MailOutbox
from app.models.result import Result
from app.models.scan import ModuleStatus, Scan, ScanModule, ScanStatus
from app.models.user import User
from app.services import analysis_service, notify_service


def _scan(client, headers, value="example.com", kind="domain"):
    r = client.post("/api/v1/scans", headers=headers, json={
        "target_type": kind, "target_value": value, "scan_type": "quick", "disclaimer_accepted": True})
    assert r.status_code == 201, r.text
    return r.json()


def _finish(db, scan_id, results):
    """Mark a scan completed with the given (data_type, data) results."""
    scan = db.query(Scan).filter(Scan.id == scan_id).one()
    mod = ScanModule(scan_id=scan.id, name="domain_intel", display_name="Domain", status=ModuleStatus.COMPLETED)
    db.add(mod)
    db.flush()
    for data_type, data in results:
        db.add(Result(scan_id=scan.id, module_id=mod.id, module="domain_intel", data_type=data_type,
                      data=data, source="test", confidence=0.9))
    scan.status = ScanStatus.COMPLETED
    db.commit()
    return scan


# ── sharing ──────────────────────────────────────────────────────
def test_share_investigation_viewer_then_editor(client, user, db):
    (owner_h, _owner), (other_h, other) = user, _another(client, db)
    scan = _scan(client, owner_h)
    inv = client.post("/api/v1/investigations", headers=owner_h, json={"name": "Case", "scan_ids": [scan["id"]]}).json()
    base = f"/api/v1/investigations/{inv['id']}"

    assert client.get(base, headers=other_h).status_code == 404
    assert client.post(f"{base}/members", headers=owner_h, json={"email": "nobody@x.io"}).status_code == 404
    members = client.post(f"{base}/members", headers=owner_h, json={"email": other["user"]["email"]}).json()
    assert members[0]["role"] == "viewer"

    listed = client.get("/api/v1/investigations", headers=other_h).json()
    assert any(i["id"] == inv["id"] and i["role"] == "viewer" for i in listed)
    assert client.get(base, headers=other_h).json()["role"] == "viewer"
    assert client.get(f"/api/v1/scans/{scan['id']}/details", headers=other_h).status_code == 200
    # viewers can't change anything, nor cancel the owner's scan
    assert client.patch(base, headers=other_h, json={"notes": "x"}).status_code == 403
    assert client.post(f"/api/v1/scans/{scan['id']}/cancel", headers=other_h).status_code == 404

    client.post(f"{base}/members", headers=owner_h, json={"email": other["user"]["email"], "role": "editor"})
    assert client.patch(base, headers=other_h, json={"notes": "found it"}).status_code == 200
    assert client.delete(base, headers=other_h).status_code == 403   # owner only
    assert client.get(f"{base}/members", headers=other_h).status_code == 403

    # leaving
    assert client.delete(f"{base}/members/{other['user']['id']}", headers=other_h).status_code == 204
    assert client.get(base, headers=other_h).status_code == 404


def _another(client, db):
    tag = uuid.uuid4().hex[:8]
    r = client.post("/api/v1/auth/register", json={"email": f"o{tag}@gmail.com", "username": f"o{tag}",
                                                   "password": "Passw0rd!x"}).json()
    db.query(User).filter(User.id == r["user"]["id"]).update({"email_verified": True})
    db.commit()
    return {"Authorization": f"Bearer {r['access_token']}"}, r


# ── bulk ─────────────────────────────────────────────────────────
def test_bulk_csv_creates_investigation_and_reports_bad_rows(client, user):
    headers, _ = user
    csv = "type,value\ndomain,example.com\nemail,someone@gmail.com\nip,10.0.0.1\ndomain,EXAMPLE.com\nbogus\n"
    r = client.post("/api/v1/investigations/bulk", headers=headers,
                    json={"name": "Batch", "csv": csv, "disclaimer_accepted": True})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["started"] == 2  # duplicate collapsed; private IP and malformed row rejected
    assert {e["line"] for e in body["errors"]} == {4, 6}
    inv = client.get(f"/api/v1/investigations/{body['investigation_id']}", headers=headers).json()
    assert len(inv["scans"]) == 2


def test_bulk_needs_verified_email(client, unverified_user):
    headers, _ = unverified_user
    r = client.post("/api/v1/investigations/bulk", headers=headers,
                    json={"name": "B", "csv": "domain,example.com", "disclaimer_accepted": True})
    assert r.status_code == 403


# ── API keys ─────────────────────────────────────────────────────
def test_api_key_lifecycle(client, user):
    headers, _ = user
    created = client.post("/api/v1/api-keys", headers=headers, json={"name": "ci"}).json()
    key = created["key"]
    assert key.startswith("osig_") and created["prefix"] == key[:12]
    kh = {"Authorization": f"Bearer {key}"}
    assert client.get("/api/v1/auth/me", headers=kh).status_code == 200
    assert client.post("/api/v1/scans", headers=kh, json={"target_type": "domain", "target_value": "example.com",
                                                         "scan_type": "quick", "disclaimer_accepted": True}).status_code == 201
    # a key can't mint keys or touch account security
    assert client.post("/api/v1/api-keys", headers=kh, json={"name": "x"}).status_code == 403
    assert client.post("/api/v1/auth/logout-all", headers=kh).status_code == 403
    listed = client.get("/api/v1/api-keys", headers=headers).json()
    assert "key" not in listed[0] and listed[0]["last_used_at"]
    assert client.delete(f"/api/v1/api-keys/{created['id']}", headers=headers).status_code == 204
    assert client.get("/api/v1/auth/me", headers=kh).status_code == 401


# ── admin ────────────────────────────────────────────────────────
def test_admin_requires_superuser_and_can_disable(client, db, user):
    headers, body = user
    victim_h, victim = _another(client, db)
    assert client.get("/api/v1/admin/stats", headers=headers).status_code == 403
    db.query(User).filter(User.id == body["user"]["id"]).update({"is_superuser": True})
    db.commit()
    assert client.get("/api/v1/admin/stats", headers=headers).json()["users"] >= 2
    found = client.get(f"/api/v1/admin/users?q={victim['user']['email']}", headers=headers).json()
    assert found[0]["email"] == victim["user"]["email"]
    r = client.patch(f"/api/v1/admin/users/{victim['user']['id']}", headers=headers,
                     json={"is_active": False, "plan": "pro"})
    assert r.status_code == 200 and r.json()["plan"] == "pro"
    assert client.get("/api/v1/auth/me", headers=victim_h).status_code == 401
    assert client.patch(f"/api/v1/admin/users/{body['user']['id']}", headers=headers,
                        json={"is_active": False}).status_code == 400
    audit = client.get("/api/v1/admin/audit?action=admin_", headers=headers).json()
    assert audit and audit[0]["action"] == "admin_user_updated"
    mail = client.get("/api/v1/admin/mail", headers=headers).json()
    assert mail and "body" not in mail[0]


# ── analysis ─────────────────────────────────────────────────────
def test_parse_date_formats():
    p = analysis_service.parse_date
    assert str(p("2019-03-04T10:00:00Z")) == "2019-03-04"
    assert str(p("20150102030405")) == "2015-01-02"
    assert str(p(1420070400)) == "2015-01-01"
    assert str(p("+1998-09-04T00:00:00Z")) == "1998-09-04"
    assert str(p(["2001-01-01", "2002-02-02"])) == "2001-01-01"
    assert p("not a date") is None and p(True) is None and p(42) is None


def test_map_timeline_compare_and_exports(client, db, user):
    headers, _ = user
    a = _finish(db, _scan(client, headers)["id"], [
        ("domain_registration", {"domain": "example.com", "creation_date": "1995-08-14", "expiration_date": "2030-08-13"}),
        ("ip_info", {"ip": "93.184.216.34", "lat": 34.05, "lon": -118.24, "city": "Los Angeles", "country": "US"}),
        ("breach", {"name": "Adobe", "breach_date": "2013-10-04"}),
    ])
    b = _finish(db, _scan(client, headers)["id"], [
        ("ip_info", {"ip": "93.184.216.35", "lat": 34.05, "lon": -118.24, "country": "US"}),
        ("subdomain", {"subdomain": "dev.example.com"}),
    ])

    points = client.get(f"/api/v1/scans/{a.id}/map", headers=headers).json()["points"]
    assert len(points) == 1 and points[0]["place"].startswith("Los Angeles")
    assert any("93.184.216.34" in p["labels"] for p in points)

    events = client.get(f"/api/v1/scans/{a.id}/timeline", headers=headers).json()["events"]
    titles = [e["title"] for e in events]
    assert [e["date"] for e in events] == sorted(e["date"] for e in events)
    assert any(t.startswith("Appeared in a breach: Adobe") for t in titles)
    assert any(e["future"] for e in events)  # registration expiry

    diff = client.get(f"/api/v1/scans/{a.id}/compare/{b.id}", headers=headers).json()
    added = {e["label"] for e in diff["added"]}
    removed = {e["label"] for e in diff["removed"]}
    assert "93.184.216.35" in added and "93.184.216.34" in removed

    stix = client.get(f"/api/v1/scans/{a.id}/export?format=stix", headers=headers)
    bundle = stix.json()
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert {"identity", "report", "ipv4-addr"} <= types
    assert all(o["id"].startswith(o["type"] + "--") for o in bundle["objects"])
    misp = client.get(f"/api/v1/scans/{a.id}/export?format=misp", headers=headers).json()
    assert any(at["type"] == "ip-dst" and at["value"] == "93.184.216.34" for at in misp["Event"]["Attribute"])

    inv = client.post("/api/v1/investigations", headers=headers, json={"name": "Two", "scan_ids": [str(a.id), str(b.id)]}).json()
    assert client.get(f"/api/v1/investigations/{inv['id']}/timeline", headers=headers).json()["events"]
    assert client.get(f"/api/v1/investigations/{inv['id']}/export?format=misp", headers=headers).status_code == 200


# ── watch alerts ─────────────────────────────────────────────────
def test_webhook_payload_shapes():
    assert "text" in notify_service.webhook_payload("https://hooks.slack.com/services/x", "t", ["+ a"], "l")
    assert "content" in notify_service.webhook_payload("https://discord.com/api/webhooks/1/x", "t", ["+ a"], "l")
    assert notify_service.webhook_payload("https://example.com/hook", "t", ["+ a"], "l")["changes"] == ["+ a"]


def test_watch_alert_emails_only_when_something_changed(client, db, user, monkeypatch):
    headers, body = user
    sent = []
    monkeypatch.setattr("app.osint.safe_http.safe_post_json", lambda url, payload: sent.append((url, payload)))
    client.patch("/api/v1/auth/me", headers=headers, json={"webhook_url": "https://hooks.slack.com/services/T/B/x"})
    w = Watch(user_id=body["user"]["id"], target_type="domain", target_value="example.com",
              scan_type="quick", interval_hours=24, next_run_at=datetime.utcnow())
    db.add(w)
    db.commit()

    def run(results):
        s = _finish(db, _scan(client, headers)["id"], results)
        s.watch_id = w.id
        db.commit()
        return notify_service.watch_run_finished(db, str(s.id))

    assert run([("subdomain", {"subdomain": "a.example.com"})]) is None          # first run: nothing to compare
    assert run([("subdomain", {"subdomain": "a.example.com"})]) is None          # no change: silent
    changes = run([("subdomain", {"subdomain": "b.example.com"})])
    assert changes and changes["added"]
    db.expire_all()
    mails = db.query(MailOutbox).filter(MailOutbox.to == body["user"]["email"], MailOutbox.kind == "watch_alert").all()
    assert len(mails) == 1 and "b.example.com" in mails[0].body
    assert len(sent) == 1 and "b.example.com" in sent[0][1]["text"]


# ── retention ────────────────────────────────────────────────────
def test_retention_purges_old_scans_only(client, db, user):
    from app.workers.scan_tasks import purge_expired_data
    headers, body = user
    old, new = _scan(client, headers), _scan(client, headers)
    db.query(Scan).filter(Scan.id == old["id"]).update({"created_at": datetime.utcnow() - timedelta(days=40)})
    db.query(User).filter(User.id == body["user"]["id"]).update({"retention_days": 30})
    db.commit()
    assert purge_expired_data(db) >= 1
    ids = {s["id"] for s in client.get("/api/v1/scans", headers=headers).json()["scans"]}
    assert new["id"] in ids and old["id"] not in ids
