"""Sign in with Google: everything except Google itself (verification mocked)."""
import uuid
from urllib.parse import parse_qs, urlparse

import pytest

from app.core.config import settings
from app.services import google_oauth


@pytest.fixture
def google(monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "test-client.apps.googleusercontent.com")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "test-secret")
    claims = {}
    monkeypatch.setattr(google_oauth, "verify_callback", lambda code, state, cookie: dict(claims))
    return claims


def oauth_code(response) -> dict:
    assert response.status_code == 302
    fragment_query = response.headers["location"].split("#/oauth?", 1)[1]
    return {k: v[0] for k, v in parse_qs(fragment_query).items()}


def test_providers_reports_google_off_without_credentials(client, monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "")
    assert client.get("/api/v1/auth/providers").json() == {"google": False}
    assert client.get("/api/v1/auth/google/start", follow_redirects=False).status_code == 404


def test_start_redirects_with_pkce_and_sets_cookie(client, google):
    r = client.get("/api/v1/auth/google/start", follow_redirects=False)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["state"] and q["code_challenge"]
    assert q["redirect_uri"] == [settings.GOOGLE_REDIRECT_URI]
    cookie = r.headers["set-cookie"]
    assert google_oauth.COOKIE in cookie and "HttpOnly" in cookie


def test_new_google_user_is_created_and_code_is_single_use(client, google):
    sub = uuid.uuid4().hex
    google.update({"sub": sub, "email": f"g.{sub[:8]}@gmail.com", "email_verified": True, "name": "G User"})
    params = oauth_code(client.get("/api/v1/auth/google/callback?code=x&state=y", follow_redirects=False))
    first = client.post("/api/v1/auth/google/exchange", json={"code": params["code"]})
    assert first.status_code == 200
    body = first.json()
    assert body["user"]["google_linked"] and body["user"]["has_password"] is False
    assert client.post("/api/v1/auth/google/exchange", json={"code": params["code"]}).status_code == 401

    # Google-only user can set a password, then sign in with it
    headers = {"Authorization": f"Bearer {body['access_token']}"}
    assert client.post("/api/v1/auth/set-password", headers=headers, json={"new_password": "S3tPassw0rd"}).status_code == 200
    login = client.post("/api/v1/auth/login", json={"email": body["user"]["email"], "password": "S3tPassw0rd"})
    assert login.status_code == 200


def test_existing_email_is_linked_not_duplicated(client, google, user):
    _, existing = user
    google.update({"sub": uuid.uuid4().hex, "email": existing["user"]["email"], "email_verified": True})
    params = oauth_code(client.get("/api/v1/auth/google/callback?code=x&state=y", follow_redirects=False))
    body = client.post("/api/v1/auth/google/exchange", json={"code": params["code"]}).json()
    assert body["user"]["id"] == existing["user"]["id"] and body["user"]["google_linked"]


def test_linking_revokes_a_pre_registered_password(client, google):
    """Account pre-hijacking: an attacker registers the victim's email first."""
    email = f"victim.{uuid.uuid4().hex[:8]}@gmail.com"
    attacker = client.post("/api/v1/auth/register", json={
        "email": email, "username": f"v{uuid.uuid4().hex[:8]}", "password": "Att4ckerPass"}).json()

    # The real owner signs in with Google
    google.update({"sub": uuid.uuid4().hex, "email": email, "email_verified": True})
    params = oauth_code(client.get("/api/v1/auth/google/callback?code=x&state=y", follow_redirects=False))
    owner = client.post("/api/v1/auth/google/exchange", json={"code": params["code"]}).json()
    assert owner["user"]["has_password"] is False

    # The attacker's password and refresh token no longer work
    assert client.post("/api/v1/auth/login", json={"email": email, "password": "Att4ckerPass"}).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": attacker["refresh_token"]}).status_code == 401


def test_failed_verification_redirects_with_error(client, google, monkeypatch):
    def fail(*_):
        raise google_oauth.GoogleAuthError("Your Google account's email isn't verified.")
    monkeypatch.setattr(google_oauth, "verify_callback", fail)
    params = oauth_code(client.get("/api/v1/auth/google/callback?code=x&state=y", follow_redirects=False))
    assert "isn't verified" in params["error"]


def test_cancelled_sign_in(client, google):
    params = oauth_code(client.get("/api/v1/auth/google/callback?error=access_denied", follow_redirects=False))
    assert "cancelled" in params["error"]


def test_state_mismatch_is_rejected():
    _, cookie = google_oauth.start()
    with pytest.raises(google_oauth.GoogleAuthError):
        google_oauth.verify_callback("code", "not-the-state", cookie)


def test_username_from_email_is_unique():
    taken = {"jane.doe", "jane.doe2"}
    assert google_oauth.username_from_email("Jane.Doe+news@gmail.com", taken.__contains__) == "jane.doe3"
