"""
OSIG Backend - Authentication API Endpoints

Registration, sign-in, token refresh and account management.
"""
import secrets
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps import get_db, get_current_user
from app.core.rate_limit import limiter
from app.core.security import (
    create_refresh_token,
    decode_token,
    get_password_hash,
    password_fingerprint,
    verify_password,
)
from app.models.user import User
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
from app.services import audit_service, google_oauth
from app.models.user import UserPlan
from app.services.auth_service import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _tokens(user: User) -> dict:
    return {
        "access_token": auth_service.create_user_token(user),
        "refresh_token": create_refresh_token(str(user.id), user.hashed_password),
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def register(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    """Create an account. Returns the user plus access and refresh tokens."""
    user = auth_service.create_user(db, user_data)
    audit_service.record(db, "register", request=request, user_id=user.id)
    return AuthResponse(user=UserResponse.model_validate(user), **_tokens(user))


@router.post("/login", response_model=AuthResponse)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def login(request: Request, credentials: UserLogin, db: Session = Depends(get_db)):
    """Sign in with email and password."""
    user = auth_service.authenticate_user(db, credentials)
    if not user:
        audit_service.record(db, "login_failed", request=request, target=credentials.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account is deactivated")
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
    # Fingerprint mismatch = password changed since this token was issued
    if not user or not user.is_active or payload.get("pwf") != password_fingerprint(user.hashed_password):
        raise invalid
    return TokenPair(**_tokens(user))


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """The signed-in user's profile."""
    return UserResponse.model_validate(current_user)


@router.patch("/me", response_model=UserResponse)
def update_profile(
    request: Request,
    update: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update display name or avatar URL."""
    changes = update.model_dump(exclude_unset=True)
    if "avatar_url" in changes and changes["avatar_url"] and not str(changes["avatar_url"]).startswith("https://"):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Avatar URL must start with https://")
    for field, value in changes.items():
        setattr(current_user, field, (value or None) if isinstance(value, str) else value)
    db.commit()
    db.refresh(current_user)
    audit_service.record(db, "profile_updated", request=request, user_id=current_user.id)
    return UserResponse.model_validate(current_user)


@router.post("/change-password", response_model=TokenPair)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def change_password(
    request: Request,
    body: PasswordChange,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Change the password. Every other session's refresh token stops working;
    this session gets a fresh token pair so it stays signed in.
    """
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Your current password is incorrect")
    if body.current_password == body.new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose a password you haven't used here")
    current_user.hashed_password = get_password_hash(body.new_password)
    db.commit()
    db.refresh(current_user)
    audit_service.record(db, "password_changed", request=request, user_id=current_user.id)
    return TokenPair(**_tokens(current_user))


# ── Sign in with Google ──────────────────────────────────────────
class ProvidersOut(BaseModel):
    google: bool


class OneTimeCode(BaseModel):
    code: str


class SetPassword(BaseModel):
    new_password: str


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
            # Google has verified this email; our registration has not. Anyone
            # could have pre-registered the address with a password of their
            # choosing, so linking must not leave that password usable: replace
            # it (which also revokes every refresh token via the fingerprint).
            # The owner can set a new password from the Account page.
            user.google_sub = claims["sub"]
            if user.has_password:
                user.hashed_password = get_password_hash(secrets.token_urlsafe(32))
                user.has_password = False
            action = "google_linked"
        else:
            user = User(
                email=email,
                username=google_oauth.username_from_email(
                    email, lambda u: db.query(User).filter(User.username == u).first() is not None),
                full_name=claims.get("name"),
                avatar_url=claims.get("picture") if str(claims.get("picture", "")).startswith("https://") else None,
                google_sub=claims["sub"],
                # Unusable random password until the user sets one
                hashed_password=get_password_hash(secrets.token_urlsafe(32)),
                has_password=False,
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


@router.post("/google/exchange", response_model=AuthResponse)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def google_exchange(request: Request, body: OneTimeCode, db: Session = Depends(get_db)):
    """Swap the one-time code from the callback redirect for tokens."""
    user_id = google_oauth.redeem_one_time_code(body.code)
    user = db.query(User).filter(User.id == user_id).first() if user_id else None
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="This sign-in link has expired. Try again.")
    return AuthResponse(user=UserResponse.model_validate(user), **_tokens(user))


@router.post("/set-password", response_model=TokenPair)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def set_password(request: Request, body: SetPassword, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
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
