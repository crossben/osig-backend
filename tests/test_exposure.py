"""Exposure lookups keep exposure facts and never store credential fragments."""
import json

import httpx

from app.osint import exposure


class FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body) if isinstance(body, dict) else body

    def json(self):
        return self._body


def test_hudson_rock_drops_passwords_logins_and_ip(monkeypatch):
    body = {"stealers": [{
        "date_compromised": "2026-10-09T02:12:36.000Z", "operating_system": "Windows 11",
        "total_user_services": 12, "total_corporate_services": 1, "ip": "81.28.**.***",
        "top_passwords": ["1****6"], "top_logins": ["t***@gmail.com"], "computer_name": "Not Found",
    }]}
    monkeypatch.setattr(httpx, "get", lambda *a, **k: FakeResponse(200, body))
    [result] = exposure.hudson_rock("email", "victim@gmail.com")
    serialized = json.dumps(result.data)
    for forbidden in ("1****6", "t***@gmail.com", "81.28", "top_passwords", "top_logins"):
        assert forbidden not in serialized
    assert result.data["infections"][0] == {"date_compromised": "2026-10-09", "operating_system": "Windows 11",
                                            "user_services": 12, "corporate_services": 1}


def test_hudson_rock_clean_address_returns_nothing(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: FakeResponse(200, {"stealers": []}))
    assert exposure.hudson_rock("email", "clean@gmail.com") == []


def test_whatsmyname_classification_needs_explicit_signals():
    from app.osint.whatsmyname import classify
    site = {"e_code": 200, "e_string": "profile-header", "m_code": 404, "m_string": "Not found"}
    assert classify(site, 200, "<div class=profile-header>") == "found"
    assert classify(site, 404, "Not found") == "missing"
    # 200 without the exists marker (e.g. a login wall) must not count as found
    assert classify(site, 200, "<html>Please log in</html>") == "unknown"
