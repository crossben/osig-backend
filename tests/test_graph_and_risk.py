"""Entity graph building and risk assessment, on hand-built results."""
import uuid
from types import SimpleNamespace as NS

from app.models.scan import ScanType, TargetType
from app.services.graph_service import build_entity_graph, build_graph
from app.services.risk_service import assess


def scan(value, ttype=TargetType.DOMAIN, parent=None):
    return NS(id=uuid.uuid4(), target_value=value, target_type=ttype, scan_type=ScanType.QUICK,
              parent_scan_id=parent, modules=[])


def res(source, data_type, data):
    return NS(source=source, data_type=data_type, data=data, module="m", confidence=0.9, source_url=None)


def node(g, nid):
    return next((n for n in g["nodes"] if n["id"] == nid), None)


def test_same_ip_from_three_sources_is_one_node():
    s = scan("acme.io")
    g = build_entity_graph(s, [
        res("DNS", "dns_record", {"record_type": "A", "records": ["1.2.3.4"]}),
        res("Subdomains", "subdomain", {"full_domain": "www.acme.io", "ip_addresses": ["1.2.3.4"], "exists": True}),
        res("IP Intel", "ip_intel", {"ip": "1.2.3.4", "asn": "64500", "geo": {"city": "Paris", "country": "France"}}),
    ])
    ip = node(g, "ip:1.2.3.4")
    assert ip and sorted(ip["sources"]) == ["DNS", "IP Intel", "Subdomains"]
    labels = {(e["source"], e["target"]): e["label"] for e in g["edges"]}
    assert labels.get(("subdomain:www.acme.io", "ip:1.2.3.4")) == "resolves to"
    assert labels.get(("ip:1.2.3.4", "location:paris, france")) == "located in"


def test_entity_equal_to_target_collapses_onto_root():
    s = scan("acme.io")
    g = build_entity_graph(s, [res("WHOIS", "domain_registration", {"name_servers": ["ns1.acme.io"], "registrar": "R"}),
                               res("Dork", "dork_result", {"url": "https://acme.io/", "title": "acme"}),
                               res("Web", "web_server", {"final_url": "https://acme.io/"})])
    assert not node(g, "domain:acme.io")
    assert node(g, "target:acme.io")


def test_search_hit_merges_into_matching_account():
    s = scan("torvalds", TargetType.USERNAME)
    g = build_entity_graph(s, [
        res("Username Check", "social_profile", {"platform": "GitHub", "url": "https://github.com/torvalds", "exists": True, "profile": {}}),
        res("Dork", "dork_result", {"url": "https://github.com/torvalds", "title": "torvalds"}),
    ])
    assert node(g, "account:https://github.com/torvalds")
    assert not node(g, "url:https://github.com/torvalds")


def test_pivoted_scans_join_through_shared_entity():
    parent = scan("acme.io")
    child = scan("mail.acme-mx.com", parent=parent.id)
    g = build_graph([
        (parent, [res("DNS", "dns_record", {"record_type": "MX", "records": [{"exchange": "mail.acme-mx.com"}]})]),
        (child, [res("DNS", "dns_record", {"record_type": "A", "records": ["5.6.7.8"]})]),
    ])
    roots = [n for n in g["nodes"] if n["kind"] == "target"]
    assert len(roots) == 2
    assert not node(g, "mailserver:mail.acme-mx.com")  # it IS the child's root
    assert any(e["label"] == "pivoted to" for e in g["edges"])


def test_password_breaches_are_critical_and_explained():
    s = scan("a@b.com", TargetType.EMAIL)
    r = assess(s, [res("XposedOrNot", "breach", {"name": n, "data_classes": ["Email addresses", "Passwords"]}) for n in "ABC"])
    assert r["flags"][0]["severity"] == "critical"
    assert set(r["flags"][0]["evidence"]) == {"A", "B", "C"}
    assert r["score"] == 40


def test_missing_dmarc_and_exposed_database():
    s = scan("acme.io")
    r = assess(s, [
        res("DNS TXT", "email_infrastructure", {"record": "v=spf1 -all"}),
        res("Shodan InternetDB", "host_exposure", {"ip": "1.2.3.4", "ports": [443, 6379], "vulns": [], "hostnames": []}),
    ])
    ids = {f["id"] for f in r["flags"]}
    assert "mail:no_dmarc" in ids and "ports:1.2.3.4" in ids
    assert r["score"] == 35 and r["level"] == "high"


def test_clean_target_scores_zero():
    s = scan("acme.io")
    r = assess(s, [res("DMARC", "email_address", {"type": "DMARC Policy", "record": "v=DMARC1; p=reject"}),
                   res("DNS TXT", "email_infrastructure", {"record": "v=spf1 -all"})])
    assert r["score"] == 0 and r["flags"] == []


def test_infostealer_is_critical_and_drops_credentials():
    s = scan("a@b.com", TargetType.EMAIL)
    r = assess(s, [res("Hudson Rock", "infostealer", {"email": "a@b.com", "infection_count": 2, "latest": "2026-10-01",
                                                      "infections": [{"date_compromised": "2026-10-01", "operating_system": "Windows 11"}]})])
    assert r["flags"][0]["id"] == "infostealer:device" and r["flags"][0]["severity"] == "critical"


def test_lookalikes_with_mail_are_flagged_and_graphed():
    s = scan("acme.io")
    results = [res("dnstwist", "lookalike_domain", {"domain": f"acme{i}.io", "technique": "addition",
                                                    "ip_addresses": ["9.9.9.9"], "mail_servers": ["mx.bad.example"],
                                                    "can_receive_mail": True}) for i in range(3)]
    r = assess(s, results)
    assert any(f["id"] == "lookalikes:mail" and f["severity"] == "medium" for f in r["flags"])
    g = build_entity_graph(s, results)
    assert node(g, "lookalike:acme1.io") and node(g, "ip:9.9.9.9")["sources"] == ["dnstwist"]


def test_organization_profile_becomes_pivotable_entities():
    s = scan("Mailgun", TargetType.ORGANIZATION)
    g = build_entity_graph(s, [res("Wikidata", "org_profile", {
        "name": "Mailgun", "website": "https://www.mailgun.com/", "parent_organization": "Sinch",
        "headquarters": "San Antonio", "ceo": "Jane Doe", "github": "mailgun"})])
    assert node(g, "domain:mailgun.com")
    assert node(g, "organization:sinch") and node(g, "person:jane doe")
    assert node(g, "account:https://github.com/mailgun")


def test_malicious_ip_is_high():
    s = scan("203.0.113.9", TargetType.IP)
    r = assess(s, [res("GreyNoise", "ip_reputation", {"ip": "203.0.113.9", "scanning_internet": True, "classification": "malicious"})])
    assert r["flags"][0]["id"] == "ip:malicious"
