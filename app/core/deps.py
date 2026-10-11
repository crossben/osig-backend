"""
OSIG Backend - Dependencies

FastAPI dependencies for database session, authentication, etc.
"""
from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.core.security import decode_token
from app.models.user import User

# HTTP Bearer token security
security = HTTPBearer()


def get_db() -> Generator:
    """
    Database session dependency.
    
    Yields a database session and ensures it's closed after use.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token.
    
    Args:
        credentials: HTTP Authorization credentials
        db: Database session
        
    Returns:
        Current user object
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials

    # Personal API keys (scripts, CLI) are opaque "osig_..." strings
    if token.startswith("osig_"):
        from datetime import datetime
        from app.core.crypto import sha256
        from app.models.platform import ApiKey
        key = db.query(ApiKey).filter(ApiKey.key_hash == sha256(token), ApiKey.revoked.is_(False)).first()
        if not key or not key.user or not key.user.is_active:
            raise credentials_exception
        key.last_used_at = datetime.utcnow()
        db.commit()
        key.user.via_api_key = True  # transient: key holders can't manage keys or admin
        return key.user

    payload = decode_token(token, "access")  # refresh tokens are rejected here
    if payload is None:
        raise credentials_exception

    user_id: Optional[str] = payload.get("sub")
    if user_id is None:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    # Revoked sessions: password changed, signed out everywhere, 2FA changed
    if payload.get("sv", 0) != (user.session_version or 0):
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )

    return user


def get_current_active_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Get current user and verify they are a superuser.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Current user if they are a superuser
        
    Raises:
        HTTPException: If user is not a superuser
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user


def get_verified_user(user: User = Depends(get_current_user)) -> User:
    """For actions that need a confirmed email (running scans, sharing)."""
    if not user.email_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Confirm your email address first. Check your inbox for the link.")
    return user


def get_session_user(user: User = Depends(get_current_user)) -> User:
    """Signed in interactively (not with an API key)."""
    if getattr(user, "via_api_key", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API keys can't do this; sign in instead")
    return user


def get_admin_user(user: User = Depends(get_session_user)) -> User:
    if not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only")
    return user
