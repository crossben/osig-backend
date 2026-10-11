"""'Is this a scam?' checker: detection, signals, redaction, sharing, limits, SSRF. No network."""
import uuid
from datetime import datetime, timedelta

import pytest

from app.api.v1 import check as check_api
from app.models.personal import ScamCheck
from app.osint import safe_http
from app.services import scam_check as sc

OLD = datetime.utcnow() - timedelta(days=4000)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """Every network primitive mocked; per-test rate-limit bucket."""
    calls = {"fetch": [], "whois": [], "resolve": []}
    ages = {}

    def resolve(host):
        calls["resolve"].append(host)
        return ["93.184.216.34"]

    def whois_created(domain):
        calls["whois"].append(domain)
        return ages.get(domain, OLD)

    def fetch(url):
        calls["fetch"].append(url)
        return {"final_url": url, "status": 200}

    monkeypatch.setattr(sc, "_resolve", resolve)
    monkeypatch.setattr(sc, "_whois_created", whois_created)
    monkeypatch.setattr(sc, "_fetch", fetch)
    monkeypatch.setattr(sc, "_tls_info", lambda host: None)
    monkeypatch.setattr(sc, "_virustotal", lambda d: None)
    monkeypatch.setattr(sc, "_urlscan", lambda d: None)
    monkeypatch.setattr(sc, "_mail_records", lambda d: {"mx": True, "spf": True, "dmarc": True})
    monkeypatch.setattr(check_api, "_KEY_SALT", uuid.uuid4().hex[:8])
    monkeypatch.setattr(check_api, "ANON_LIMIT", "1000/hour")
    calls["ages"] = ages
    return calls


def codes(res):
    return {r["code"] for r in res["reasons"]}


def post(client, text, headers=None, **extra):
    # unique suffix-free input would hit the 6 h cache across runs; tests that care use uuid
    r = client.post("/api/v1/check", json={"input": text, **extra}, headers=headers or {})
    assert r.status_code == 200, r.text
    return r.json()


def test_lookalike_domain():
    res = sc.run_check("wave-senegal-pay.com")
    assert res["kind"] == "domain"
    assert "brand_lookalike" in codes(res)
    assert res["verdict"] in ("scam", "suspicious")


def test_lookalike_new_domain_is_scam(offline):
    offline["ages"]["wave-senegal-pay.com"] = datetime.utcnow() - timedelta(days=5)
    res = sc.run_check("https://wave-senegal-pay.com/login")
    assert {"brand_lookalike", "new_domain"} <= codes(res)
    assert res["verdict"] == "scam"


def test_brand_in_subdomain():
    res = sc.run_check("http://wave.com.secure-login.xyz/verify?id=1")
    assert "brand_in_subdomain" in codes(res)
    assert {"suspicious_tld", "no_https"} <= codes(res)
    assert res["verdict"] == "scam"
    assert res["subject"] == "secure-login.xyz/verify"


def test_young_domain(offline):
    offline["ages"]["randomshop.net"] = datetime.utcnow() - timedelta(days=90)
    res = sc.run_check("randomshop.net")
    assert "young_domain" in codes(res)


def test_typosquat_and_homoglyph():
    assert "brand_typosquat" in codes(sc.run_check("paypai.com"))
    assert "brand_homoglyph" in codes(sc.run_check("paypa1.com"))


def test_legit_wave(offline):
    res = sc.run_check("https://wave.com")
    assert res["reasons"] == []
    assert res["verdict"] == "no_red_flags"
    assert offline["whois"] == []  # official brand: no WHOIS needed


def test_shortener_chain_resolved(monkeypatch, offline):
    offline["ages"]["orange-bonus.top"] = datetime.utcnow() - timedelta(days=3)
    monkeypatch.setattr(sc, "_fetch", lambda url: {"final_url": "https://orange-bonus.top/gift", "status": 200})
    res = sc.run_check("https://bit.ly/3abcd")
    c = codes(res)
    assert {"url_shortener", "redirects_elsewhere", "brand_lookalike", "new_domain"} <= c
    assert res["details"]["checks"][0]["final_host"] == "orange-bonus.top"
    assert res["verdict"] == "scam"


def test_french_scam_sms(offline):
    offline["ages"]["wave-senegal-pay.com"] = datetime.utcnow() - timedelta(days=5)
    msg = ("WAVE: votre compte sera bloqué dans 24h. Cliquez sur https://wave-senegal-pay.com/verif "
           "et envoyez le code reçu par SMS au 77 123 45 67.")
    res = sc.run_check(msg)
    assert res["kind"] == "message"
    assert {"msg_code_request", "msg_urgency", "msg_impersonation_request", "brand_lookalike"} <= codes(res)
    assert res["verdict"] == "scam"
    assert res["subject"] == "Message mentioning wave-senegal-pay.com"


def test_plain_message_no_flags():
    res = sc.run_check("Salut, on se voit demain à la plage ?")
    assert res["verdict"] == "no_red_flags"
    assert res["subject"] == "Message mentioning no links"


def test_freemail_brand_impersonation():
    res = sc.run_check("wave.support.sn@gmail.com")
    assert res["kind"] == "email"
    assert "freemail_brand" in codes(res)
    assert res["verdict"] in ("suspicious", "scam")
    assert res["subject"] == "w***@gmail.com"


def test_email_domain_without_mail(monkeypatch):
    monkeypatch.setattr(sc, "_mail_records", lambda d: {"mx": False, "spf": False, "dmarc": False})
    res = sc.run_check("support@ecobank-secure.com")
    assert {"brand_lookalike", "no_mx", "no_spf_dmarc"} <= codes(res)


def test_invalid_phone_and_masking():
    res = sc.run_check("+221 12 345", country="SN")
    assert res["kind"] == "phone"
    assert "invalid_phone" in codes(res)
    ok = sc.run_check("+221 77 123 45 67")
    assert "invalid_phone" not in codes(ok)
    assert ok["subject"].startswith("+221") and ok["subject"].endswith("67") and "*" in ok["subject"]


def test_ssrf_ip_literal_not_fetched(offline):
    res = sc.run_check("http://127.0.0.1/admin")
    assert "private_address" in codes(res)
    assert offline["fetch"] == []


def test_ssrf_domain_resolving_private(monkeypatch, offline):
    # real public_addresses check, with DNS answering 10.x
    monkeypatch.setattr(sc, "_resolve", safe_http.public_addresses)
    monkeypatch.setattr(safe_http.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("10.1.2.3", 443))])
    res = sc.run_check("https://internal.example.com/x")
    assert "private_address" in codes(res)
    assert offline["fetch"] == []


def test_api_redaction_share_and_history(client, user, db):
    headers, _ = user
    tag = uuid.uuid4().hex[:6]
    msg = f"Félicitations {tag}! Vous avez gagné 500000 FCFA. Envoyez le code de retrait à jean.dupont@gmail.com"
    body = post(client, msg, headers)
    assert body["verdict"] == "scam"
    assert "details" in body
    row = db.query(ScamCheck).filter(ScamCheck.share_id == body["shareId"]).one()
    assert row.user_id is not None
    stored = f"{row.subject} {row.details} {row.reasons}"
    assert tag not in stored and "Félicitations" not in stored  # raw message never stored
    assert row.subject == "Message mentioning gmail.com"

    pub = client.get(f"/api/v1/check/{body['shareId']}").json()
    assert pub["verdict"] == "scam" and "details" not in pub and "userId" not in pub and "user_id" not in pub

    hist = client.get("/api/v1/check/history", headers=headers).json()
    assert hist[0]["shareId"] == body["shareId"]
    assert client.get("/api/v1/check/history").status_code in (401, 403)
    assert client.get("/api/v1/check/nope").status_code == 404


def test_api_email_masked_and_cache(client, offline):
    addr = f"orange.money.{uuid.uuid4().hex[:6]}@gmail.com"
    a = post(client, addr)
    assert a["subject"].startswith("o***@gmail.com")
    b = post(client, addr)
    assert b["shareId"] != a["shareId"] and b["verdict"] == a["verdict"]
    assert b["details"].get("cached") is True


def test_anonymous_rate_limit(client, monkeypatch):
    monkeypatch.setattr(check_api, "ANON_LIMIT", "2/hour")
    for _ in range(2):
        post(client, f"hello {uuid.uuid4().hex}")
    r = client.post("/api/v1/check", json={"input": "hello again"})
    assert r.status_code == 429


def test_input_too_long(client):
    assert client.post("/api/v1/check", json={"input": "a" * 5001}).status_code == 422


def test_made_up_api_key_gets_the_anonymous_bucket():
    from starlette.requests import Request
    from app.api.v1 import check
    scope = {"type": "http", "headers": [(b"authorization", b"Bearer osig_madeup123")], "client": ("1.2.3.4", 1)}
    key = check._rate_key(Request(scope))
    assert key.endswith("ip:1.2.3.4") and check._limit_for(key) == check.ANON_LIMIT
