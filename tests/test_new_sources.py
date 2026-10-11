"""New public-data sources: mocked HTTP, no secrets stored, possible-match wording, graph/risk/diff wiring."""
import io
import json
import zipfile
from types import SimpleNamespace

import httpx

from app.core.config import settings
from app.osint import code_leaks, compliance_intel, darkweb, doc_metadata, page_snapshot, reputation_feeds
from app.services import footprint_service, risk_service
from app.services.graph_service import build_entity_graph
from app.services.notify_service import _lines


class FakeResponse:
    def __init__(self, status, body, headers=None):
        self.status_code = status
        self._body = body
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.headers = headers or {}

    def json(self):
        return self._body


def _scan(target_type="domain", value="acme.com"):
    return SimpleNamespace(id="s1", target_value=value, target_type=SimpleNamespace(value=target_type),
                           parent_scan_id=None)


def _res(data_type, data, source="Test"):
    return SimpleNamespace(data_type=data_type, data=data, source=source)


def _as_rows(results):
    return [_res(r.data_type, r.data, r.source) for r in results]


# ── compliance ─────────────────────────────────────────────

def test_collect_names_skips_privacy_placeholders():
    results = [
        _res("domain_registration", {"org": "Domains By Proxy, LLC"}),
        _res("legal_entity", {"name": "Acme Holdings Ltd"}),
        _res("org_profile", {"ceo": "Jane Doe", "founders": ["Jane Doe", "John Roe"]}),
        _res("social_profile", {"exists": True, "profile": {"name": "Jo Smith"}}),
    ]
    names = compliance_intel.collect_names("organization", "Acme", results)
    assert ("Acme Holdings Ltd", "Company") in names and ("Jane Doe", "Person") in names
    assert not any("Proxy" in n for n, _ in names)
    assert len({n for n, _ in names}) == len(names)


def test_opensanctions_keeps_strong_matches_as_possible(monkeypatch):
    body = {"responses": {"q0": {"results": [
        {"id": "NK-1", "caption": "ACME Trading", "schema": "Company", "score": 0.93, "datasets": ["us_ofac_sdn"],
         "properties": {"topics": ["sanction"], "country": ["ir"]}},
        {"id": "NK-2", "caption": "Acme Bakery", "schema": "Company", "score": 0.4, "properties": {}},
    ]}}}
    seen = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        seen.update(headers=headers, timeout=timeout)
        return FakeResponse(200, body)
    monkeypatch.setattr(httpx, "post", fake_post)
    [hit] = compliance_intel.opensanctions([("Acme Trading", "Company")], "k")
    assert seen["headers"]["Authorization"] == "ApiKey k" and seen["timeout"]
    assert hit.data["category"] == "sanctions" and hit.data["possible_match"] and "Possible match" in hit.data["note"]
    assert compliance_intel.opensanctions([("Acme", "Company")], "") == []  # no key: skipped


def test_icij_requires_close_name(monkeypatch):
    body = {"q0": {"result": [{"id": "10001", "name": "ACME TRADING LIMITED", "score": 30,
                               "types": [{"id": "x/entity", "name": "Entity"}]},
                              {"id": "10002", "name": "Totally Different SA", "score": 25}]}}
    monkeypatch.setattr(httpx, "post", lambda *a, **k: FakeResponse(201, body))
    [hit] = compliance_intel.icij_offshore([("Acme Trading Limited", "Company")])
    assert hit.data_type == "offshore_match" and "ICIJ" in hit.data["attribution"]
    assert hit.source_url.endswith("/nodes/10001") and hit.data["node_type"] == "Entity"


def test_screening_risk_and_graph():
    rows = [_res("sanctions_match", {"name_queried": "Acme Trading", "matched_name": "ACME Trading", "score": 0.95,
                                     "category": "sanctions", "datasets": ["us_ofac_sdn"], "entity_id": "NK-1"},
                 "OpenSanctions"),
            _res("sanctions_match", {"name_queried": "Jane Doe", "matched_name": "Jane DOE", "score": 0.8,
                                     "category": "pep", "schema": "Person", "entity_id": "Q1"}, "OpenSanctions"),
            _res("offshore_match", {"name_queried": "Acme Trading", "matched_name": "ACME TRADING LTD",
                                    "node_id": "10001", "similarity": 95}, "ICIJ Offshore Leaks")]
    flags = {f["id"]: f["severity"] for f in risk_service.assess(_scan("organization", "Acme Trading"), rows)["flags"]}
    assert flags == {"watchlist:sanctions": "critical", "watchlist:pep": "medium", "watchlist:offshore": "medium"}
    graph = build_entity_graph(_scan("organization", "Acme Trading"), rows)
    watch = [n for n in graph["nodes"] if n["kind"] == "watchlist"]
    assert len(watch) == 3 and all(n["label"].startswith("Possible match") for n in watch)
    assert any(e["source"] == "target:acme trading" and e["label"] == "possible match" for e in graph["edges"])


# ── code leaks ─────────────────────────────────────────────

def test_code_leak_classify_redacts_and_ignores_placeholders():
    info = code_leaks.classify('SMTP_HOST=mail.acme.com\nSMTP_PASSWORD="hunter2secret"', ".env")
    assert info["likely_credential"] and info["preview"] == "SMTP_PASSWORD=hunt…"
    assert "hunter2secret" not in json.dumps(info)
    assert not code_leaks.classify("password = os.environ['X'] # acme.com", "app.py")["likely_credential"]
    assert code_leaks.classify("-----BEGIN RSA PRIVATE KEY-----\nMIIEow", "id_rsa")["preview"].startswith("-----BEGIN …")
    assert code_leaks.classify("see acme.com docs", "config.php")["kind"] == "config_file"


def test_code_leaks_needs_token_and_stops_on_rate_limit(monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_TOKEN", "")
    assert code_leaks.CodeLeaksModule("domain").run("acme.com") == []

    monkeypatch.setattr(settings, "GITHUB_TOKEN", "t")
    calls = []
    item = {"html_url": "https://github.com/x/y/blob/main/.env", "path": ".env",
            "repository": {"full_name": "x/y"},
            "text_matches": [{"fragment": "DB_HOST=db.acme.com\nDB_PASSWORD=SuperSecret123"}]}

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append(params["q"])
        return FakeResponse(200, {"items": [item]}) if len(calls) == 1 else FakeResponse(403, {})
    monkeypatch.setattr(httpx, "get", fake_get)
    [r] = code_leaks.CodeLeaksModule("domain").run("acme.com")
    assert len(calls) == 2  # stopped at the 403
    assert "SuperSecret123" not in json.dumps(r.data) and r.data["preview"] == "DB_PASSWORD=Supe…"
    assert r.data["exposed_config"] and r.data["likely_credential"]
    flags = risk_service.assess(_scan(), _as_rows([r]))["flags"]
    assert flags[0]["id"] == "code:secrets" and flags[0]["severity"] == "high"


# ── document metadata ──────────────────────────────────────

def _docx(core: str, app: str = "") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("docProps/core.xml", core)
        if app:
            zf.writestr("docProps/app.xml", app)
    return buf.getvalue()


CORE = ('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
        '<dc:creator>Jane Doe</dc:creator><cp:lastModifiedBy>jdoe</cp:lastModifiedBy>'
        '<dcterms:created>2021-03-04T10:00:00Z</dcterms:created></cp:coreProperties>')
APP = ('<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
       '<Application>Microsoft Office Word</Application><Company>Acme</Company></Properties>')


def test_office_metadata_and_xxe_rejected():
    meta = doc_metadata.extract(_docx(CORE, APP), "docx")
    assert meta["author"] == "Jane Doe" and meta["last_modified_by"] == "jdoe"
    assert meta["creator"] == "Microsoft Office Word" and meta["company"] == "Acme"
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'
    try:
        doc_metadata.extract(_docx(evil), "docx")
        raised = False
    except Exception:
        raised = True
    assert raised


def test_pdf_metadata():
    from pypdf import PdfWriter
    w = PdfWriter()
    w.add_blank_page(10, 10)
    w.add_metadata({"/Author": "Jane Doe", "/Producer": "LibreOffice 7", "/CreationDate": "D:20200102030405+01'00'"})
    buf = io.BytesIO()
    w.write(buf)
    meta = doc_metadata.extract(buf.getvalue(), "pdf")
    assert meta["author"] == "Jane Doe" and meta["document_created"] == "2020-01-02T03:04:05"


def test_doc_module_uses_safe_get_and_summarises(monkeypatch):
    import app.osint.safe_http as safe_http
    monkeypatch.setattr(doc_metadata, "find_documents", lambda d, k: ["https://acme.com/a.docx"])
    fetched = []

    def fake_safe_get(url, **kw):
        fetched.append(url)
        return SimpleNamespace(status_code=200, content=_docx(CORE, APP))
    monkeypatch.setattr(safe_http, "safe_get", fake_safe_get)
    results = doc_metadata.DocMetadataModule().run("acme.com")
    assert fetched == ["https://acme.com/a.docx"]
    summary = results[-1].data
    assert summary["people"] == ["Jane Doe", "jdoe"] and summary["documents"] == 1
    rows = _as_rows(results)
    flag = next(f for f in risk_service.assess(_scan(), rows)["flags"] if f["id"] == "docs:metadata")
    assert flag["severity"] == "medium"  # 'jdoe' looks like an internal username
    graph = build_entity_graph(_scan(), rows)
    assert {"person:jane doe", "person:jdoe", "document:https://acme.com/a.docx"} <= {n["id"] for n in graph["nodes"]}


def test_find_documents_filters_off_domain():
    assert doc_metadata._ext("https://acme.com/x/Report.PDF") == "pdf"
    assert not doc_metadata._on_domain("https://evil.com/acme.com.pdf", "acme.com")


# ── dark web ───────────────────────────────────────────────

def test_ransomware_live_gated_and_matches_exactly(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_RANSOMWARE_LIVE", False)
    assert darkweb.DarkWebModule("domain").run("acme.com") == []
    monkeypatch.setattr(settings, "ENABLE_RANSOMWARE_LIVE", True)
    victims = [{"victim": "Acme Corp", "domain": "acme.com", "group": "lockbit3", "attackdate": "2026-01-02T00:00:00",
                "claim_url": "http://abcdefghijklmnop.onion/post/1", "description": "We have 200GB"},
               {"victim": "Acmetools", "domain": "acmetools.de", "group": "x"}]
    seen = []
    monkeypatch.setattr(httpx, "get", lambda url, **k: seen.append(url) or FakeResponse(200, victims))
    [hit] = darkweb.DarkWebModule("domain").run("acme.com")
    assert seen[0].endswith("/searchvictims/acme")
    assert hit.data["onion_host"] == "abcdefghijklmnop.onion" and "claim_url" not in hit.data
    assert risk_service.assess(_scan(), _as_rows([hit]))["flags"][0]["id"] == "darkweb:ransomware"


# ── reputation feeds ───────────────────────────────────────

def test_otx_parses_pulses_and_needs_key(monkeypatch):
    assert reputation_feeds.otx("domain", "acme.com", "") is None
    body = {"pulse_info": {"count": 2, "pulses": [
        {"name": "Emotet C2", "tags": ["c2"], "malware_families": [{"display_name": "Emotet"}]},
        {"name": "Phishing kit", "tags": ["phishing"]}]}, "validation": []}
    monkeypatch.setattr(httpx, "get", lambda url, **k: FakeResponse(200, body))
    r = reputation_feeds.otx("ip", "203.0.113.5", "k")
    assert r.data["pulse_count"] == 2 and r.data["malware_families"] == ["Emotet"]
    flag = risk_service.assess(_scan("ip", "203.0.113.5"), _as_rows([r]))["flags"][0]
    assert flag["id"] == "intel:otx" and flag["severity"] == "high"


def test_otx_allowlisted_is_not_flagged():
    row = _res("threat_intel", {"indicator": "google.com", "pulse_count": 40, "allowlisted": ["Majestic"]})
    out = risk_service.assess(_scan("ip", "203.0.113.5"), [row])
    assert not out["flags"] and any("allow-lists" in f for f in out["findings"])


def test_greynoise_sends_key_when_set(monkeypatch):
    monkeypatch.setattr(settings, "GREYNOISE_API_KEY", "gk")
    seen = {}
    monkeypatch.setattr(httpx, "get", lambda url, headers=None, timeout=None:
                        seen.update(headers=headers) or FakeResponse(200, {"riot": True, "name": "Cloudflare"}))
    r = reputation_feeds.greynoise("1.1.1.1")
    assert seen["headers"]["key"] == "gk" and r.data["known_benign_service"]


# ── homepage snapshot / watch diff ─────────────────────────

def test_fingerprint_ignores_scripts_numbers_and_dates():
    a = "<html><title>Acme</title><script>var t=1</script><p>Visitors: 1234 — Updated 3 March 2026</p></html>"
    b = "<html><title>Acme</title><script>var t=99</script><p>Visitors:   98765 — Updated 9 April 2027</p></html>"
    c = "<html><title>Acme</title><p>We have been acquired</p></html>"
    assert page_snapshot.fingerprint(a) == page_snapshot.fingerprint(b) != page_snapshot.fingerprint(c)


def test_snapshot_change_reads_as_homepage_changed():
    def graph_ids(fp):
        g = build_entity_graph(_scan(), [_res("page_snapshot", {"fingerprint": fp, "title": "Acme"}, "Homepage Snapshot")])
        return {n["id"]: n for n in g["nodes"] if n["kind"] == "snapshot"}
    before, after = graph_ids("aaaa1111bbbb2222"), graph_ids("cccc3333dddd4444")
    assert before.keys() != after.keys()
    changes = {"added": [{"kind": "snapshot", "label": "x"}], "removed": [{"kind": "snapshot", "label": "y"}]}
    assert _lines(changes) == ["~ Homepage content changed"]


def test_footprint_actions_for_code_leaks_in_french():
    ident = SimpleNamespace(value="me@acme.com", id="i1", kind="email")
    rows = [_res("code_leak", {"repo": "me/site", "path": ".env", "html_url": "https://github.com/me/site/.env",
                               "likely_credential": True, "preview": "PASS=abcd…"}, "GitHub Code Search")]
    [act] = [a for a in footprint_service.actions_for_scan(ident, _scan("email", "me@acme.com"), rows, "fr")
             if a["key"].startswith("code:")]
    assert "historique" in act["detail"] and act["severity"] == "high"
