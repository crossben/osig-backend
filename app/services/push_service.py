"""
Web Push (VAPID) for footprint and watch alerts.

Subscription endpoints come from the browser, so they are attacker-controlled
URLs: only the big push services are accepted (no SSRF to internal hosts), and
each one is re-checked before sending. Gone subscriptions (404/410) are
removed. Sending never raises.
"""
import json
import logging
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.personal import PushSubscription

logger = logging.getLogger(__name__)

PUSH_HOSTS = {"fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com"}
PUSH_HOST_SUFFIXES = (".notify.windows.com", ".push.apple.com")


def enabled() -> bool:
    return bool(settings.VAPID_PUBLIC_KEY and settings.VAPID_PRIVATE_KEY)


def allowed_endpoint(endpoint: str) -> bool:
    try:
        u = urlparse(endpoint)
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    if u.scheme != "https" or not host or u.username or u.password or (u.port not in (None, 443)):
        return False
    return host in PUSH_HOSTS or host.endswith(PUSH_HOST_SUFFIXES)


def _webpush(sub: PushSubscription, payload: str):
    from pywebpush import webpush
    return webpush(
        subscription_info={"endpoint": sub.endpoint, "keys": {"p256dh": sub.p256dh, "auth": sub.auth}},
        data=payload, vapid_private_key=settings.VAPID_PRIVATE_KEY,
        vapid_claims={"sub": settings.VAPID_SUBJECT}, timeout=10, ttl=24 * 3600,
    )


def send(db: Session, user_id, title: str, body: str, url: str = "#/footprint") -> int:
    """Push to every device of the user. Returns how many were delivered."""
    if not enabled():
        return 0
    sent = 0
    try:
        subs = db.query(PushSubscription).filter(PushSubscription.user_id == user_id).all()
        payload = json.dumps({"title": title[:120], "body": body[:240], "url": url})
        for sub in subs:
            if not allowed_endpoint(sub.endpoint):
                db.delete(sub)
                continue
            try:
                _webpush(sub, payload)
                sent += 1
            except Exception as e:
                status: Optional[int] = getattr(getattr(e, "response", None), "status_code", None)
                if status in (404, 410):
                    db.delete(sub)
                else:
                    logger.info(f"Push to user {user_id} failed: {e}")
        db.commit()
    except Exception as e:  # push is best effort
        db.rollback()
        logger.warning(f"Push sending failed for user {user_id}: {e}")
    return sent
