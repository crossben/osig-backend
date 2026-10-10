"""
Per-IP rate limits (slowapi) for the endpoints worth abusing: sign-in,
sign-up and scan creation. Daily scan quotas per plan still apply on top.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

# Limits live in Redis so they hold across API workers/restarts
limiter = Limiter(key_func=get_remote_address, storage_uri=settings.REDIS_URL, headers_enabled=False)
