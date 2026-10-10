"""Username platform rules: verified against real/fake handles, mocked here."""
import httpx

from app.osint.username_intel import PLATFORMS, UsernameIntelModule

by_name = {p["name"]: p for p in PLATFORMS}


def client_returning(status: int, body: str = "", json_body=None):
    def handler(request):
        if json_body is not None:
            return httpx.Response(status, json=json_body)
        return httpx.Response(status, text=body)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_github_found_extracts_profile():
    c = client_returning(200, json_body={"name": "Linus", "location": "Portland", "blog": "", "followers": 9})
    state, profile = UsernameIntelModule()._check_one(c, "torvalds", by_name["GitHub"])
    assert state == "found" and profile["name"] == "Linus" and "website" not in profile


def test_github_404_is_missing():
    state, _ = UsernameIntelModule()._check_one(client_returning(404), "nobody", by_name["GitHub"])
    assert state == "missing"


def test_gitlab_empty_list_is_missing():
    state, _ = UsernameIntelModule()._check_one(client_returning(200, json_body=[]), "nobody", by_name["GitLab"])
    assert state == "missing"


def test_hackernews_null_is_missing():
    state, _ = UsernameIntelModule()._check_one(client_returning(200, "null"), "nobody", by_name["Hacker News"])
    assert state == "missing"


def test_telegram_needs_profile_marker():
    p = by_name["Telegram"]
    assert UsernameIntelModule()._check_one(client_returning(200, "<div>generic page</div>"), "x", p)[0] == "missing"
    assert UsernameIntelModule()._check_one(client_returning(200, '<div class="tgme_page_title">X</div>'), "x", p)[0] == "found"


def test_rate_limit_is_unknown_not_missing():
    state, _ = UsernameIntelModule()._check_one(client_returning(429), "x", by_name["GitHub"])
    assert state == "unknown"


def test_keybase_proofs_become_linked_accounts():
    body = {"them": [{"basics": {}, "profile": {"full_name": "C"}, "proofs_summary": {"all": [
        {"proof_type": "github", "nametag": "c", "service_url": "https://github.com/c"}]}}]}
    state, profile = UsernameIntelModule()._check_one(client_returning(200, json_body=body), "c", by_name["Keybase"])
    assert state == "found" and profile["linked_accounts"][0]["service"] == "github"
