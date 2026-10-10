"""Investigations, pivoting, pins, merged graph, watches diff."""
from datetime import datetime, timedelta

from app.models.result import Result
from app.models.scan import Scan, ScanModule, ScanStatus, ModuleStatus


def make_scan(client, headers, value="acme.io"):
    r = client.post("/api/v1/scans", headers=headers, json={
        "target_type": "domain", "target_value": value, "scan_type": "quick", "disclaimer_accepted": True})
    assert r.status_code == 201, r.text
    return r.json()


def complete_with(db, scan_id, results, created=None):
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    s.status = ScanStatus.COMPLETED
    if created:
        s.created_at = created
    m = ScanModule(scan_id=s.id, name="domain_intel", display_name="Domain", status=ModuleStatus.COMPLETED, progress=100)
    db.add(m)
    db.flush()
    for source, dt, data in results:
        db.add(Result(scan_id=s.id, module_id=m.id, module="domain_intel", data_type=dt, data=data, source=source, confidence=0.9))
    db.commit()


def test_pivot_creates_investigation_and_merged_graph(client, user, db, no_real_scans):
    headers, _ = user
    parent = make_scan(client, headers)
    complete_with(db, parent["id"], [("DNS", "dns_record", {"record_type": "MX", "records": [{"exchange": "mx.acme-mail.com"}]})])
    r = client.post(f"/api/v1/scans/{parent['id']}/pivot", headers=headers, json={
        "entity_id": "mailserver:mx.acme-mail.com", "target_type": "domain", "target_value": "mx.acme-mail.com"})
    assert r.status_code == 201, r.text
    child = r.json()
    assert child["investigation_id"] and child["parent_scan_id"] == parent["id"]
    assert child["id"] in no_real_scans  # dispatched to the worker

    inv_id = child["investigation_id"]
    inv = client.get(f"/api/v1/investigations/{inv_id}", headers=headers).json()
    assert {s["id"] for s in inv["scans"]} == {parent["id"], child["id"]}

    pin = client.post(f"/api/v1/investigations/{inv_id}/pins", headers=headers,
                      json={"entity_id": "target:mx.acme-mail.com", "kind": "target", "label": "mx.acme-mail.com", "note": "MX host"})
    assert pin.status_code == 201
    g = client.get(f"/api/v1/investigations/{inv_id}/graph", headers=headers).json()
    assert len([n for n in g["nodes"] if n["kind"] == "target"]) == 2
    assert any(n.get("pinned") for n in g["nodes"])

    pdf = client.get(f"/api/v1/investigations/{inv_id}/report?format=pdf", headers=headers)
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"


def test_investigations_are_private(client, user, db):
    headers, _ = user
    inv = client.post("/api/v1/investigations", headers=headers, json={"name": "Mine"}).json()
    other = client.post("/api/v1/auth/register", json={"email": "someone.else@gmail.com", "username": "someoneelse",
                                                       "password": "Passw0rd!x"}).json()
    other_headers = {"Authorization": f"Bearer {other['access_token']}"}
    assert client.get(f"/api/v1/investigations/{inv['id']}", headers=other_headers).status_code == 404


def test_watch_changes_between_runs(client, user, db):
    headers, _ = user
    w = client.post("/api/v1/watches", headers=headers, json={"target_type": "domain", "target_value": "acme.io"}).json()
    now = datetime.utcnow()
    for i, subs in enumerate((["www.acme.io"], ["www.acme.io", "vpn.acme.io"])):
        s = make_scan(client, headers)
        db.query(Scan).filter(Scan.id == s["id"]).update({Scan.watch_id: w["id"]})
        db.commit()
        complete_with(db, s["id"], [("Subdomains", "subdomain", {"full_domain": d, "ip_addresses": [], "exists": True}) for d in subs],
                      created=now + timedelta(minutes=i))
    ch = client.get(f"/api/v1/watches/{w['id']}/changes", headers=headers).json()
    assert [a["label"] for a in ch["added"]] == ["vpn.acme.io"] and ch["removed"] == []


def test_ip_targets_must_be_public(client, user):
    headers, _ = user
    for bad in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "not-an-ip"):
        r = client.post("/api/v1/scans", headers=headers, json={"target_type": "ip", "target_value": bad,
                                                                "scan_type": "quick", "disclaimer_accepted": True})
        assert r.status_code == 422, bad
    ok = client.post("/api/v1/scans", headers=headers, json={"target_type": "ip", "target_value": "8.8.8.8",
                                                             "scan_type": "quick", "disclaimer_accepted": True})
    assert ok.status_code == 201


def test_organization_target_accepted(client, user):
    headers, _ = user
    r = client.post("/api/v1/scans", headers=headers, json={"target_type": "organization", "target_value": "Python Software Foundation",
                                                            "scan_type": "quick", "disclaimer_accepted": True})
    assert r.status_code == 201
