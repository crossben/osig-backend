"""Third-party sources parse their APIs correctly and fail quietly (httpx mocked), and PDFs render."""
import io
import json
from types import SimpleNamespace

import httpx
import pytest

from app.core.config import settings
from app.osint.domain_intel import DomainIntelModule
from app.osint.phone_intel import PhoneIntelModule


class FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


def _route(monkeypatch, routes):
    """routes: {url-substring: (status, body) | Exception}"""
    def fake_get(url, *a, **k):
        for needle, answer in routes.items():
            if needle in url:
                if isinstance(answer, Exception):
                    raise answer
                return FakeResponse(*answer)
        return FakeResponse(404, {})
    monkeypatch.setattr(httpx, "get", fake_get)


def test_internetdb_keeps_exposed_hosts_only(monkeypatch):
    _route(monkeypatch, {
        "1.1.1.1": (200, {"ports": [53, 443], "hostnames": ["one.one.one.one"], "cpes": ["cpe:/a:cloudflare:dns"],
                          "vulns": ["CVE-2023-0001"], "tags": ["cdn"]}),
        "8.8.8.8": (200, {"ports": []}),
        "9.9.9.9": (404, {"detail": "No information available"}),
    })
    results = DomainIntelModule()._internetdb(["1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700::1111"])
    assert len(results) == 1
    assert results[0].data["ports"] == [53, 443] and results[0].data["vulns"] == ["CVE-2023-0001"]
    assert results[0].data["software"] == ["a cloudflare dns"]


def test_urlscan_parses_hits_and_survives_outage(monkeypatch):
    _route(monkeypatch, {"urlscan.io": (200, {"results": [{
        "page": {"url": "https://example.com/", "domain": "example.com", "ip": "93.184.216.34", "server": "ECS",
                 "country": "US"},
        "task": {"time": "2026-01-02T03:04:05Z"},
        "result": "https://urlscan.io/api/v1/result/abc/", "screenshot": "https://urlscan.io/screenshots/abc.png"}]})})
    [r] = DomainIntelModule()._urlscan("example.com")
    assert r.source_url == "https://urlscan.io/result/abc/" and r.data["ip"] == "93.184.216.34"
    _route(monkeypatch, {"urlscan.io": httpx.ConnectTimeout("down")})
    assert DomainIntelModule()._urlscan("example.com") == []


def test_virustotal_needs_a_key(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")
    assert DomainIntelModule()._virustotal("example.com") is None
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "k")
    _route(monkeypatch, {"virustotal.com": (200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 60},
        "reputation": -5, "categories": {"a": "phishing", "b": "phishing", "c": "business"}}}})})
    r = DomainIntelModule()._virustotal("example.com")
    assert r.data["malicious"] == 2 and r.data["categories"] == ["business", "phishing"]


def test_numverify(monkeypatch):
    monkeypatch.setattr(settings, "NUMVERIFY_API_KEY", "k")
    _route(monkeypatch, {"apilayer.net": (200, {"valid": True, "carrier": "Orange", "line_type": "mobile",
                                               "location": "", "country_name": "Senegal"})})
    r = PhoneIntelModule()._numverify("+221771234567")
    assert r.data == {"valid": True, "carrier": "Orange", "line_type": "mobile", "location": None, "country": "Senegal"}
    _route(monkeypatch, {"apilayer.net": (200, {"success": False, "error": {"code": 101}})})
    assert PhoneIntelModule()._numverify("+221771234567") is None


# ── PDF rendering ────────────────────────────────────────────────
def _fake_scan():
    from datetime import datetime
    enum = lambda v: SimpleNamespace(value=v)  # noqa: E731
    return SimpleNamespace(id="00000000-0000-0000-0000-000000000001", target_type=enum("domain"),
                           target_value="example.com", scan_type=enum("quick"), status=enum("completed"),
                           created_at=datetime(2026, 1, 1), completed_at=datetime(2026, 1, 1),
                           started_at=datetime(2026, 1, 1), pivot_entity=None, modules=[], investigation_id=None)


def _results():
    R = lambda t, d, s="test": SimpleNamespace(data_type=t, data=d, source=s, source_url="https://example.com",  # noqa: E731
                                               confidence=0.9, module="domain_intel", timestamp=None)
    return [R("domain_registration", {"domain": "example.com", "registrar": "IANA <script>", "creation_date": "1995-08-14"}),
            R("breach", {"name": "Adobe & Co", "breach_date": "2013-10-04"}),
            R("subdomain", {"subdomain": "dev.example.com"})]


def test_scan_pdf_renders(tmp_path):
    from app.services.report_pdf import render_pdf_report
    out = tmp_path / "r.pdf"
    render_pdf_report(str(out), "Example report", _fake_scan(), _results())
    data = out.read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 2000


def test_investigation_pdf_renders():
    from app.services.report_pdf import render_investigation_pdf
    inv = SimpleNamespace(name="Case <1>", notes="Notes & more", tags=["a"], pins=[], id="x",
                          created_at=_fake_scan().created_at, updated_at=_fake_scan().created_at)
    buf = io.BytesIO()
    render_investigation_pdf(buf, inv, [(_fake_scan(), _results())])
    assert buf.getvalue().startswith(b"%PDF")


@pytest.mark.parametrize("value", ["", None, [], {}])
def test_pdf_value_formatting_never_crashes(value):
    from app.services.report_pdf import _format_value
    assert isinstance(_format_value(value), str)
