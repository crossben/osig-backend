"""Symmetric encryption for secrets at rest (TOTP seeds), keyed from SECRET_KEY."""
import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def _fernet() -> Fernet:
    key = hashlib.sha256(("osig-at-rest:" + settings.SECRET_KEY).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise ValueError("Secret could not be decrypted (SECRET_KEY changed?)") from e


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def constant_time_in(value_hash: str, hashes) -> bool:
    return any(hmac.compare_digest(value_hash, h) for h in hashes)
