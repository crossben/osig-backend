"""
OSIG Backend - Authentication API

Registration (+ email verification), sign-in (+ optional TOTP second step),
token refresh with session versions, password reset, Google sign-in,
account preferences, and deleting your data or account.
"""
import secrets
from typing import Union
from urllib.parse import quote

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crypto import constant_time_in, decrypt, encrypt, sha256
from app.core.deps import get_current_user, get_db, get_session_user
from app.core.rate_limit import limiter
from app.core.security import (
    create_purpose_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    password_fingerprint,
    verify_password,
)
from app.models.user import User, UserPlan
from app.schemas.user import (
    AuthResponse,
    PasswordChange,
    RefreshRequest,
    TokenPair,
    UserCreate,
    UserLogin,
    UserResponse,
    UserUpdate,
)
from app.services import audit_service, google_oauth, mail_service
from app.services.auth_service import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])

MFA_TOKEN_MINUTES = 5
VERIFY_TOKEN_MINUTES = 48 * 60
RESET_TOKEN_MINUTES = 60


# ── helpers ──────────────────────────────────────────────────────
class MfaRequired(BaseModel):
    """Returned instead of tokens when the account has two-factor sign-in on."""
    mfa_required: bool = True
    mfa_token: str


def _tokens(user: User) -> dict:
    return {
        "access_token": auth_service.create_user_token(user),
        "refresh_token": create_refresh_token(str(user.id), user.hashed_password, user.session_version or 0),
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


def _signed_in(user: User) -> Union[AuthResponse, MfaRequired]:
    if user.totp_enabled:
        return MfaRequired(mfa_token=create_purpose_token("mfa", str(user.id), MFA_TOKEN_MINUTES,
                                                          sv=user.session_version or 0))
    return AuthResponse(user=UserResponse.model_validate(user), **_tokens(user))


def _revoke_sessions(user: User) -> None:
    user.session_version = (user.session_version or 0) + 1


def _evict_pre_registrant(db: Session, user: User) -> None:
    """The real owner of an UNverified address just proved they control it
    (Google link or reset link). Whoever registered it first may have planted
    credentials or settings: drop them all."""
    from app.models.platform import ApiKey
    db.query(ApiKey).filter(ApiKey.user_id == user.id).update({ApiKey.revoked: True}, synchronize_session=False)
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.recovery_codes = []
    user.webhook_url = None
    _revoke_sessions(user)


def _require_verified(user: User) -> None:
    if not user.email_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Confirm your email address first. Check your inbox for the link.")


def _send_verification(db: Session, user: User) -> None:
    token = create_purpose_token("verify_email", str(user.id), VERIFY_TOKEN_MINUTES, email=user.email)
    mail_service.send(
        db, user.email, "Confirm your email for OSIG",
        "Hi,\n\nConfirm this address to start running scans on OSIG:\n\n"
        f"{mail_service.link('/verify-email?token=' + token)}\n\n"
        "The link works for 48 hours. If you didn't create an OSIG account, ignore this email.\n",
        kind="verify_email",
    )


def _verify_totp(user: User, code: str) -> bool:
    """A 6-digit authenticator code, or one unused recovery code (consumed)."""
    code = (code or "").strip().replace(" ", "").replace("-", "")
    if not user.totp_secret_enc:
        return False
    if code.isdigit() and len(code) == 6:
        return pyotp.TOTP(decrypt(user.totp_secret_enc)).verify(code, valid_window=1)
    hashed = sha256(code.lower())
    if constant_time_in(hashed, user.recovery_codes or []):
        user.recovery_codes = [h for h in user.recovery_codes if h != hashed]
        return True
    return False


# ── register / sign in / refresh ─────────────────────────────────
@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def register(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    """Create an account and email a confirmation link. Scans need a confirmed email."""
    user = auth_service.create_user(db, user_data)
    _send_verification(db, user)
    audit_service.record(db, "register", request=request, user_id=user.id)
    return AuthResponse(user=UserResponse.model_validate(user), **_tokens(user))


@router.post("/login", response_model=Union[AuthResponse, MfaRequired])
@limiter.limit(settings.RATE_LIMIT_AUTH)
def login(request: Request, credentials: UserLogin, db: Session = Depends(get_db)):
    """Sign in with email and password. With 2FA on, returns an MFA step instead of tokens."""
    user = auth_service.authenticate_user(db, credentials)
    if not user:
        audit_service.record(db, "login_failed", request=request, target=credentials.email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account is deactivated")
    audit_service.record(db, "login" if not user.totp_enabled else "login_password_ok", request=request, user_id=user.id)
    return _signed_in(user)


class MfaVerify(BaseModel):
    mfa_token: str
    code: str = Field(..., min_length=6, max_length=20)


@router.post("/2fa/verify", response_model=AuthResponse)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def mfa_verify(request: Request, body: MfaVerify, db: Session = Depends(get_db)):
    """Second sign-in step: authenticator code or a recovery code."""
    payload = decode_token(body.mfa_token, "mfa")
    user = db.query(User).filter(User.id == payload.get("sub")).first() if payload else None
    if not user or payload.get("sv") != (user.session_version or 0):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="This sign-in expired. Start again.")
    if not _verify_totp(user, body.code):
        audit_service.record(db, "mfa_failed", request=request, user_id=user.id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="That code isn't right. Try the current one.")
    db.commit()  # persists a consumed recovery code
    audit_service.record(db, "login", request=request, user_id=user.id)
    return AuthResponse(user=UserResponse.model_validate(user), **_tokens(user))


@router.post("/refresh", response_model=TokenPair)
@limiter.limit("30/minute")
def refresh(request: Request, body: RefreshRequest, db: Session = Depends(get_db)):
    """Trade a refresh token for a new token pair (the refresh token rotates)."""
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your session has expired. Sign in again.")
    payload = decode_token(body.refresh_token, "refresh")
    if not payload:
        raise invalid
    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if (not user or not user.is_active
            or payload.get("pwf") != password_fingerprint(user.hashed_password)
            or payload.get("sv", 0) != (user.session_version or 0)):
        raise invalid
    return TokenPair(**_tokens(user))


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_session_user)):
    """End every session on every device, including this one."""
    _revoke_sessions(current_user)
    db.commit()
    audit_service.record(db, "logout_all", request=request, user_id=current_user.id)


# ── email verification / password reset ──────────────────────────
class TokenIn(BaseModel):
    token: str


class EmailIn(BaseModel):
    email: str = Field(..., max_length=320)


class ResetIn(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=100)


@router.post("/verify-email", response_model=UserResponse)
def verify_email(body: TokenIn, request: Request, db: Session = Depends(get_db)):
    payload = decode_token(body.token, "verify_email")
    user = db.query(User).filter(User.id == payload.get("sub")).first() if payload else None
    if not user or payload.get("email") != user.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This confirmation link is invalid or has expired. Request a new one.")
    if not user.email_verified:
        user.email_verified = True
        db.commit()
        audit_service.record(db, "email_verified", request=request, user_id=user.id)
    return UserResponse.model_validate(user)


@router.post("/resend-verification", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(settings.RATE_LIMIT_EMAIL)
def resend_verification(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_session_user)):
    if not current_user.email_verified:
        _send_verification(db, current_user)


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(settings.RATE_LIMIT_EMAIL)
def forgot_password(request: Request, body: EmailIn, db: Session = Depends(get_db)):
    """Always 202, whether or not the address has an account (no account enumeration)."""
    user = db.query(User).filter(User.email == body.email.strip().lower()).first()
    if user and user.is_active:
        # Bound to the current password: using the link (or any password change) voids it
        token = create_purpose_token("reset_password", str(user.id), RESET_TOKEN_MINUTES,
                                     pwf=password_fingerprint(user.hashed_password))
        mail_service.send(
            db, user.email, "Reset your OSIG password",
            "Hi,\n\nSomeone asked to reset the password for this OSIG account. If it was you, choose a new one here:\n\n"
            f"{mail_service.link('/reset-password?token=' + token)}\n\n"
            "The link works for one hour and only once. If it wasn't you, ignore this email: nothing has changed.\n",
            kind="reset_password",
        )
        audit_service.record(db, "password_reset_requested", request=request, user_id=user.id)


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def reset_password(request: Request, body: ResetIn, db: Session = Depends(get_db)):
    payload = decode_token(body.token, "reset_password")
    user = db.query(User).filter(User.id == payload.get("sub")).first() if payload else None
    if not user or payload.get("pwf") != password_fingerprint(user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This reset link is invalid, expired or already used. Request a new one.")
    if not user.email_verified:
        _evict_pre_registrant(db, user)
    user.hashed_password = get_password_hash(body.new_password)
    user.has_password = True
    user.email_verified = True  # they proved they can read this inbox
    _revoke_sessions(user)
    db.commit()
    audit_service.record(db, "password_reset", request=request, user_id=user.id)


# ── profile / password ───────────────────────────────────────────
@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)


@router.patch("/me", response_model=UserResponse)
def update_profile(request: Request, update: UserUpdate, db: Session = Depends(get_db),
                   current_user: User = Depends(get_session_user)):
    """Update name, avatar and preferences (retention, alerts, language)."""
    changes = update.model_dump(exclude_unset=True)
    if changes.get("webhook_url"):
        _require_verified(current_user)
    for url_field in ("avatar_url", "webhook_url"):
        if changes.get(url_field) and not str(changes[url_field]).startswith("https://"):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                                detail=f"{url_field.replace('_', ' ').capitalize()} must start with https://")
    for field, value in changes.items():
        setattr(current_user, field, (value or None) if isinstance(value, str) and field != "language" else value)
    db.commit()
    db.refresh(current_user)
    if "language" in changes:  # to-dos are written in the user's language
        from app.services import footprint_service
        try:
            footprint_service.recompute(db, current_user, notify=False)
        except Exception:
            db.rollback()
    audit_service.record(db, "profile_updated", request=request, user_id=current_user.id)
    return UserResponse.model_validate(current_user)


@router.post("/change-password", response_model=TokenPair)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def change_password(request: Request, body: PasswordChange, db: Session = Depends(get_db),
                    current_user: User = Depends(get_session_user)):
    """Change the password; every other session ends immediately, this one gets fresh tokens."""
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Your current password is incorrect")
    if body.current_password == body.new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose a password you haven't used here")
    current_user.hashed_password = get_password_hash(body.new_password)
    _revoke_sessions(current_user)
    db.commit()
    db.refresh(current_user)
    audit_service.record(db, "password_changed", request=request, user_id=current_user.id)
    return TokenPair(**_tokens(current_user))


class SetPassword(BaseModel):
    new_password: str


@router.post("/set-password", response_model=TokenPair)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def set_password(request: Request, body: SetPassword, db: Session = Depends(get_db),
                 current_user: User = Depends(get_session_user)):
    """For accounts created through Google: add a password for email sign-in."""
    if current_user.has_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Use change password instead")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Use at least 8 characters")
    current_user.hashed_password = get_password_hash(body.new_password)
    current_user.has_password = True
    db.commit()
    db.refresh(current_user)
    audit_service.record(db, "password_set", request=request, user_id=current_user.id)
    return TokenPair(**_tokens(current_user))


# ── two-factor sign-in (TOTP) ────────────────────────────────────
class CodeIn(BaseModel):
    code: str = Field(..., min_length=6, max_length=20)


@router.post("/2fa/setup")
def mfa_setup(db: Session = Depends(get_db), current_user: User = Depends(get_session_user)):
    """Start enabling 2FA: a new secret, as an otpauth URI and a QR code (SVG)."""
    _require_verified(current_user)
    if current_user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Two-factor sign-in is already on")
    import io
    import segno
    secret = pyotp.random_base32()
    current_user.totp_secret_enc = encrypt(secret)
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="OSIG")
    buf = io.BytesIO()
    segno.make(uri, error="m").save(buf, kind="svg", scale=5, border=2, dark="#13233F", light="#ffffff")
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": buf.getvalue().decode()}


@router.post("/2fa/enable")
def mfa_enable(request: Request, body: CodeIn, db: Session = Depends(get_db),
               current_user: User = Depends(get_session_user)):
    """Confirm with a first code; returns 10 single-use recovery codes, shown once."""
    if current_user.totp_enabled or not current_user.totp_secret_enc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Start the setup first")
    if not pyotp.TOTP(decrypt(current_user.totp_secret_enc)).verify(body.code.strip(), valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="That code isn't right. Try the current one.")
    codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(10)]
    current_user.recovery_codes = [sha256(c.replace("-", "")) for c in codes]
    current_user.totp_enabled = True
    db.commit()
    audit_service.record(db, "mfa_enabled", request=request, user_id=current_user.id)
    return {"recovery_codes": codes}


@router.post("/2fa/disable", status_code=status.HTTP_204_NO_CONTENT)
def mfa_disable(request: Request, body: CodeIn, db: Session = Depends(get_db),
                current_user: User = Depends(get_session_user)):
    if not current_user.totp_enabled:
        return
    if not _verify_totp(current_user, body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="That code isn't right")
    current_user.totp_enabled = False
    current_user.totp_secret_enc = None
    current_user.recovery_codes = []
    db.commit()
    audit_service.record(db, "mfa_disabled", request=request, user_id=current_user.id)


# ── your data ────────────────────────────────────────────────────
class ConfirmIn(BaseModel):
    confirm: str


def delete_user_data(db: Session, user: User) -> dict:
    """Delete everything the user owns (not the account)."""
    import os
    from app.models.investigation import Investigation, Watch
    from app.models.report import Report
    from app.models.scan import Scan
    counts = {}
    for report in db.query(Report).filter(Report.user_id == user.id).all():
        if report.file_path and os.path.exists(report.file_path):
            os.remove(report.file_path)
    counts["reports"] = db.query(Report).filter(Report.user_id == user.id).delete(synchronize_session=False)
    counts["watches"] = db.query(Watch).filter(Watch.user_id == user.id).delete(synchronize_session=False)
    counts["investigations"] = db.query(Investigation).filter(Investigation.user_id == user.id).delete(synchronize_session=False)
    scans = db.query(Scan).filter(Scan.user_id == user.id).all()
    counts["scans"] = len(scans)
    for scan in scans:
        db.delete(scan)  # cascades modules and results
    db.commit()
    return counts


@router.post("/delete-my-data")
def delete_my_data(request: Request, body: ConfirmIn, db: Session = Depends(get_db),
                   current_user: User = Depends(get_session_user)):
    """Delete every scan, result, report, investigation and watch you own. The account stays."""
    if body.confirm != "DELETE":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Type DELETE to confirm")
    counts = delete_user_data(db, current_user)
    audit_service.record(db, "data_deleted", request=request, user_id=current_user.id, target=str(counts))
    return counts


@router.post("/delete-account", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(request: Request, body: ConfirmIn, db: Session = Depends(get_db),
                   current_user: User = Depends(get_session_user)):
    """Delete all your data and the account itself. Audit entries keep no link to you."""
    if body.confirm != current_user.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Type your email address to confirm")
    delete_user_data(db, current_user)
    audit_service.record(db, "account_deleted", request=request, target=sha256(current_user.email)[:16])
    db.delete(current_user)
    db.commit()


# ── Sign in with Google ──────────────────────────────────────────
class ProvidersOut(BaseModel):
    google: bool


class OneTimeCode(BaseModel):
    code: str


@router.get("/providers", response_model=ProvidersOut)
def providers():
    """Which sign-in methods are available (public; drives the login page)."""
    return ProvidersOut(google=google_oauth.enabled())


@router.get("/google/start")
@limiter.limit(settings.RATE_LIMIT_AUTH)
def google_start(request: Request):
    if not google_oauth.enabled():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Google sign-in isn't configured")
    url, cookie = google_oauth.start()
    response = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        google_oauth.COOKIE, cookie, max_age=int(google_oauth.COOKIE_TTL.total_seconds()),
        httponly=True, samesite="lax", secure=settings.FRONTEND_URL.startswith("https://"),
        path="/api/v1/auth/google",
    )
    return response


def _frontend_redirect(**params) -> RedirectResponse:
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    response = RedirectResponse(f"{settings.FRONTEND_URL}/#/oauth?{query}", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(google_oauth.COOKIE, path="/api/v1/auth/google")
    return response


@router.get("/google/callback")
def google_callback(request: Request, code: str = "", state: str = "", error: str = "",
                    db: Session = Depends(get_db)):
    if error or not code:
        return _frontend_redirect(error="Google sign-in was cancelled.")
    try:
        claims = google_oauth.verify_callback(code, state, request.cookies.get(google_oauth.COOKIE))
    except google_oauth.GoogleAuthError as e:
        return _frontend_redirect(error=str(e))

    email = claims["email"].lower()
    user = db.query(User).filter(User.google_sub == claims["sub"]).first()
    action = "login_google"
    if not user:
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.google_sub = claims["sub"]
            # A password set on an UNverified account could belong to whoever
            # pre-registered this address: it must not survive the link.
            if not user.email_verified:
                if user.has_password:
                    user.hashed_password = get_password_hash(secrets.token_urlsafe(32))
                    user.has_password = False
                _evict_pre_registrant(db, user)
            user.email_verified = True
            action = "google_linked"
        else:
            user = User(
                email=email,
                username=google_oauth.username_from_email(
                    email, lambda u: db.query(User).filter(User.username == u).first() is not None),
                full_name=claims.get("name"),
                avatar_url=claims.get("picture") if str(claims.get("picture", "")).startswith("https://") else None,
                google_sub=claims["sub"],
                hashed_password=get_password_hash(secrets.token_urlsafe(32)),
                has_password=False,
                email_verified=True,  # Google verified it
                plan=UserPlan.FREE, is_active=True, is_superuser=False,
            )
            db.add(user)
            action = "register_google"
        db.commit()
        db.refresh(user)
    if not user.is_active:
        return _frontend_redirect(error="This account is deactivated.")
    audit_service.record(db, action, request=request, user_id=user.id)
    return _frontend_redirect(code=google_oauth.issue_one_time_code(str(user.id)))


@router.post("/google/exchange", response_model=Union[AuthResponse, MfaRequired])
@limiter.limit(settings.RATE_LIMIT_AUTH)
def google_exchange(request: Request, body: OneTimeCode, db: Session = Depends(get_db)):
    """Swap the one-time code from the callback redirect for tokens (or the 2FA step)."""
    user_id = google_oauth.redeem_one_time_code(body.code)
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="This sign-in link has expired. Try again.")
    return _signed_in(user)
