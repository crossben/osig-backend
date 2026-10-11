"""
OSIG Backend - Security Utilities

Password hashing and JWT token generation/validation.
"""
import hashlib
from datetime import datetime, timedelta
from typing import Optional
import jwt
from jwt import PyJWTError as JWTError
from passlib.context import CryptContext
from app.core.config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Dictionary containing claims to encode
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    
    return encoded_jwt


def password_fingerprint(hashed_password: str) -> str:
    """Short digest of the stored hash: changing the password changes it."""
    return hashlib.sha256(hashed_password.encode()).hexdigest()[:16]


def create_purpose_token(purpose: str, sub: str, minutes: int, **claims) -> str:
    """Short-lived signed token for one job (verify email, reset password, 2FA step)."""
    payload = {"sub": sub, "type": purpose, "exp": datetime.utcnow() + timedelta(minutes=minutes), **claims}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(user_id: str, hashed_password: str, session_version: int = 0) -> str:
    """
    Long-lived token used only to obtain new access tokens.
    Bound to the password fingerprint, so a password change revokes every
    outstanding refresh token without needing a token table.
    """
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {"sub": user_id, "type": "refresh", "pwf": password_fingerprint(hashed_password),
               "sv": session_version, "exp": expire}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str, expected_type: str) -> Optional[dict]:
    """Decode and check the token type (tokens from before typing count as access)."""
    payload = decode_access_token(token)
    if payload is None or payload.get("type", "access") != expected_type:
        return None
    return payload


def decode_access_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT access token.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded token payload or None if invalid
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None
