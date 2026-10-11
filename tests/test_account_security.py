"""Email verification, password reset, session revocation, 2FA, deleting data."""
import re

import pyotp

from app.models.platform import MailOutbox
from app.models.user import User


def _last_token(db, email, kind):
    db.expire_all()
    mail = (db.query(MailOutbox).filter(MailOutbox.to == email, MailOutbox.kind == kind)
            .order_by(MailOutbox.created_at.desc()).first())
    assert mail, f"no {kind} mail for {email}"
    return re.search(r"token=([\w\-\.]+)", mail.body).group(1)


def test_unverified_cannot_scan_until_link_used(client, db, unverified_user):
    headers, body = unverified_user
    scan = {"target_type": "domain", "target_value": "example.com", "scan_type": "quick", "disclaimer_accepted": True}
    assert client.post("/api/v1/scans", json=scan, headers=headers).status_code == 403
    token = _last_token(db, body["user"]["email"], "verify_email")
    r = client.post("/api/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 200 and r.json()["email_verified"] is True
    assert client.post("/api/v1/scans", json=scan, headers=headers).status_code == 201


def test_verify_rejects_garbage(client):
    assert client.post("/api/v1/auth/verify-email", json={"token": "nope"}).status_code == 400


def test_forgot_password_never_reveals_accounts(client):
    r = client.post("/api/v1/auth/forgot-password", json={"email": "nobody-here@gmail.com"})
    assert r.status_code == 202


def test_reset_password_is_single_use_and_ends_sessions(client, db, user):
    headers, body = user
    email = body["user"]["email"]
    client.post("/api/v1/auth/forgot-password", json={"email": email})
    token = _last_token(db, email, "reset_password")
    assert client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "BrandNew123!"}).status_code == 204
    # used once: the password fingerprint changed
    assert client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "Other123!x"}).status_code == 400
    # old access and refresh tokens are dead
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": body["refresh_token"]}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": email, "password": "BrandNew123!"}).status_code == 200


def test_logout_all_revokes_access_tokens(client, user):
    headers, body = user
    assert client.post("/api/v1/auth/logout-all", headers=headers).status_code == 204
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": body["refresh_token"]}).status_code == 401


def test_two_factor_flow(client, db, user):
    headers, body = user
    email = body["user"]["email"]
    setup = client.post("/api/v1/auth/2fa/setup", headers=headers).json()
    assert setup["qr_svg"].lstrip().startswith("<")
    totp = pyotp.TOTP(setup["secret"])
    assert client.post("/api/v1/auth/2fa/enable", json={"code": "000000"}, headers=headers).status_code == 400
    codes = client.post("/api/v1/auth/2fa/enable", json={"code": totp.now()}, headers=headers).json()["recovery_codes"]
    assert len(codes) == 10
    # the secret is stored encrypted
    db.expire_all()
    stored = db.query(User).filter(User.email == email).one()
    assert setup["secret"] not in (stored.totp_secret_enc or "")

    step = client.post("/api/v1/auth/login", json={"email": email, "password": "Passw0rd!x"}).json()
    assert step["mfa_required"] is True and "access_token" not in step
    bad = client.post("/api/v1/auth/2fa/verify", json={"mfa_token": step["mfa_token"], "code": "123456"})
    assert bad.status_code == 401
    ok = client.post("/api/v1/auth/2fa/verify", json={"mfa_token": step["mfa_token"], "code": totp.now()})
    assert ok.status_code == 200 and ok.json()["access_token"]

    # a recovery code works once
    r1 = client.post("/api/v1/auth/2fa/verify", json={"mfa_token": step["mfa_token"], "code": codes[0]})
    r2 = client.post("/api/v1/auth/2fa/verify", json={"mfa_token": step["mfa_token"], "code": codes[0]})
    assert r1.status_code == 200 and r2.status_code == 401


def test_delete_my_data_then_account(client, db, user):
    headers, body = user
    client.post("/api/v1/scans", json={"target_type": "domain", "target_value": "example.com", "scan_type": "quick", "disclaimer_accepted": True}, headers=headers)
    assert client.post("/api/v1/auth/delete-my-data", json={"confirm": "yes"}, headers=headers).status_code == 400
    r = client.post("/api/v1/auth/delete-my-data", json={"confirm": "DELETE"}, headers=headers)
    assert r.status_code == 200 and r.json()["scans"] == 1
    assert client.get("/api/v1/scans", headers=headers).json()["total"] == 0
    assert client.post("/api/v1/auth/delete-account", json={"confirm": "wrong@x.com"}, headers=headers).status_code == 400
    assert client.post("/api/v1/auth/delete-account", json={"confirm": body["user"]["email"]}, headers=headers).status_code == 204
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_webhook_url_must_be_https(client, user):
    headers, _ = user
    r = client.patch("/api/v1/auth/me", json={"webhook_url": "http://hooks.slack.com/x"}, headers=headers)
    assert r.status_code == 422
    r = client.patch("/api/v1/auth/me", json={"webhook_url": "https://hooks.slack.com/x", "retention_days": 30, "language": "fr"}, headers=headers)
    assert r.status_code == 200 and r.json()["language"] == "fr"


def test_pre_registrant_cannot_plant_credentials(client, unverified_user):
    headers, _ = unverified_user
    assert client.post("/api/v1/api-keys", json={"name": "x"}, headers=headers).status_code == 403
    assert client.post("/api/v1/auth/2fa/setup", headers=headers).status_code == 403
    assert client.patch("/api/v1/auth/me", json={"webhook_url": "https://evil.example/h"}, headers=headers).status_code == 403


def test_reset_of_unverified_account_evicts_pre_registrant(client, db, unverified_user):
    from app.core.crypto import sha256
    from app.models.platform import ApiKey
    headers, body = unverified_user
    uid, email = body["user"]["id"], body["user"]["email"]
    # simulate anything planted before the gates existed
    db.add(ApiKey(user_id=uid, name="planted", prefix="osig_planted", key_hash=sha256("osig_planted_key")))
    db.query(User).filter(User.id == uid).update({"webhook_url": "https://evil.example/h", "totp_enabled": True,
                                                  "totp_secret_enc": "x"})
    db.commit()
    client.post("/api/v1/auth/forgot-password", json={"email": email})
    token = _last_token(db, email, "reset_password")
    assert client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "Owner12345!"}).status_code == 204
    db.expire_all()
    u = db.query(User).filter(User.id == uid).one()
    assert u.email_verified and not u.totp_enabled and u.webhook_url is None
    assert db.query(ApiKey).filter(ApiKey.user_id == uid, ApiKey.revoked.is_(False)).count() == 0
    assert client.get("/api/v1/auth/me", headers={"Authorization": "Bearer osig_planted_key"}).status_code == 401
