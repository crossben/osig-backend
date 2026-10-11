"""
Watch alerts: when a watched target's run has fully finished, compare it with
the previous finished run and tell the owner what changed, by email and/or a
webhook (Slack and Discord payloads are recognised from the URL; anything else
gets plain JSON). Nothing is sent when nothing changed.
"""
import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.models.investigation import Watch
from app.models.scan import Scan
from app.models.user import User
from app.services import mail_service
from app.services.diff_service import diff, finished

logger = logging.getLogger(__name__)
MAX_LINES = 25


def _lines(changes: dict) -> list:
    out = [f"+ {e['kind']}: {e['label']}" for e in changes["added"]]
    out += [f"- {e['kind']}: {e['label']}" for e in changes["removed"]]
    if len(out) > MAX_LINES:
        out = out[:MAX_LINES] + [f"...and {len(out) - MAX_LINES} more"]
    return out


def webhook_payload(url: str, title: str, lines: list, link: str) -> dict:
    text = f"{title}\n" + "\n".join(lines) + f"\n{link}"
    if "hooks.slack.com" in url:
        return {"text": text}
    if "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
        return {"content": text[:1990]}
    return {"title": title, "changes": lines, "url": link}


def watch_run_finished(db: Session, scan_id: str) -> Optional[dict]:
    """Called after a watch scan's background modules finish. Returns the diff sent, if any."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or not scan.watch_id or not finished(scan):
        return None
    watch = db.query(Watch).filter(Watch.id == scan.watch_id).first()
    user = db.query(User).filter(User.id == scan.user_id).first() if watch else None
    if not watch or not user:
        return None
    runs = [s for s in watch.scans if finished(s)]
    if len(runs) < 2 or runs[-1].id != scan.id:
        return None
    changes = diff(db, runs[-2], scan)
    if not changes["added"] and not changes["removed"]:
        return None

    title = (f"OSIG: {len(changes['added'])} new, {len(changes['removed'])} gone "
             f"for {watch.target_value}")
    lines = _lines(changes)
    link = mail_service.link("/watches")
    if user.notify_email:
        mail_service.send(db, user.email, title,
                          f"Your watch on {watch.target_value} found changes since the previous run:\n\n"
                          + "\n".join(lines) + f"\n\nSee them in OSIG: {link}\n\n"
                          "Turn these emails off under Profile > Alerts.\n", kind="watch_alert")
    from app.services import push_service
    push_service.send(db, user.id, title, "\n".join(lines[:3]), "#/watches")
    if user.webhook_url:
        from app.osint.safe_http import safe_post_json
        try:
            safe_post_json(user.webhook_url, webhook_payload(user.webhook_url, title, lines, link))
        except Exception as e:  # a broken webhook must never break the worker
            logger.info(f"Webhook for user {user.id} failed: {e}")
    return changes
