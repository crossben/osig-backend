"""
OSIG Backend - Sign in with Google (OAuth 2.0 authorization code + PKCE)

Flow
  1. /auth/google/start: state + PKCE verifier go into a short-lived, signed,
     httpOnly cookie (never the URL); redirect to Google.
  2. /auth/google/callback: state must match the cookie; the code is exchanged
     (with the verifier); Google's ID token is verified (signature via Google's
     JWKS, audience, issuer, expiry, email_verified).
  3. The user is found by Google id, else linked by verified email, else created.
  4. Tokens never travel in a URL: the callback redirects to the frontend with a
     one-time code (Redis, 60 s) that the frontend POSTs to /auth/google/exchange.
"""
import base64
import hashlib
import re
import secrets
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

import httpx
import jwt
import redis

from app.core.config import settings

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
ISSUERS = ("https://accounts.google.com", "accounts.google.com")
COOKIE = "osig_google_oauth"
COOKIE_TTL = timedelta(minutes=10)
ONE_TIME_TTL_S = 60

_jwks: Optional[jwt.PyJWKClient] = None
_redis: Optional[redis.Redis] = None


class GoogleAuthError(Exception):
    """Shown to the user as the reason sign-in failed."""


def enabled() -> bool:
    return bool(settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET)


def _store() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(settings.REDIS_URL)
    return _redis


def start() -> tuple[str, str]:
    """(google_url, signed_cookie_value)"""
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    cookie = jwt.encode(
        {"state": state, "verifier": verifier, "exp": datetime.utcnow() + COOKIE_TTL, "type": "google_oauth"},
        settings.SECRET_KEY, algorithm=settings.ALGORITHM,
    )
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    return f"{AUTH_URL}?{urlencode(params)}", cookie


def verify_callback(code: str, state: str, cookie: Optional[str]) -> dict:
    """Validate state, exchange the code, verify the ID token. Returns its claims."""
    if not cookie:
        raise GoogleAuthError("The sign-in session expired. Try again.")
    try:
        saved = jwt.decode(cookie, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.PyJWTError:
        raise GoogleAuthError("The sign-in session expired. Try again.")
    if saved.get("type") != "google_oauth" or not secrets.compare_digest(saved.get("state", ""), state):
        raise GoogleAuthError("Sign-in couldn't be verified. Try again.")

    resp = httpx.post(TOKEN_URL, timeout=15, data={
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": saved["verifier"],
    })
    if resp.status_code != 200 or "id_token" not in resp.json():
        raise GoogleAuthError("Google didn't accept the sign-in. Try again.")
    return verify_id_token(resp.json()["id_token"])


def verify_id_token(id_token: str) -> dict:
    global _jwks
    if _jwks is None:
        _jwks = jwt.PyJWKClient(JWKS_URL, cache_keys=True)
    try:
        key = _jwks.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(id_token, key.key, algorithms=["RS256"], audience=settings.GOOGLE_CLIENT_ID,
                            options={"require": ["exp", "iat", "sub", "aud", "iss"]})
    except jwt.PyJWTError as e:
        raise GoogleAuthError(f"Google's response couldn't be verified ({type(e).__name__}).")
    if claims.get("iss") not in ISSUERS:
        raise GoogleAuthError("Google's response couldn't be verified (issuer).")
    if not claims.get("email") or not claims.get("email_verified"):
        raise GoogleAuthError("Your Google account's email isn't verified.")
    return claims


def issue_one_time_code(user_id: str) -> str:
    code = secrets.token_urlsafe(32)
    _store().setex(f"oauth:code:{code}", ONE_TIME_TTL_S, user_id)
    return code


def redeem_one_time_code(code: str) -> Optional[str]:
    key = f"oauth:code:{code}"
    pipe = _store().pipeline()
    pipe.get(key)
    pipe.delete(key)  # single use, even if the exchange fails afterwards
    user_id, _ = pipe.execute()
    return user_id.decode() if user_id else None


def username_from_email(email: str, taken) -> str:
    """'jane.doe+x@gmail.com' -> 'jane.doe', or 'jane.doe2' etc. if taken."""
    base = re.sub(r"[^a-z0-9._-]", "", email.split("@")[0].split("+")[0].lower())[:40] or "user"
    if len(base) < 3:
        base = f"{base}user"
    candidate, n = base, 1
    while taken(candidate):
        n += 1
        candidate = f"{base}{n}"
    return candidate
