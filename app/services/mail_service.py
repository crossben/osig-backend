"""
OSIG Backend - Outgoing email

Every message is written to the mail_outbox table first. If SMTP is
configured it is then delivered; otherwise it stays in the outbox (and the
log), which is how local development and the tests read verification links.
"""
import logging
import smtplib
from email.message import EmailMessage

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.platform import MailOutbox

logger = logging.getLogger(__name__)


def send(db: Session, to: str, subject: str, body: str, kind: str) -> MailOutbox:
    row = MailOutbox(to=to, subject=subject, body=body, kind=kind)
    db.add(row)
    db.commit()
    if not settings.SMTP_HOST:
        logger.info(f"[mail:{kind}] SMTP not configured; queued for {to}: {subject}")
        return row
    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as smtp:
            if settings.SMTP_STARTTLS:
                smtp.starttls()
            if settings.SMTP_USER:
                smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            smtp.send_message(msg)
        row.sent = True
    except Exception as e:  # delivery problems must not break the request that triggered them
        row.error = str(e)[:500]
        logger.warning(f"[mail:{kind}] delivery to {to} failed: {e}")
    db.commit()
    return row


def link(path: str) -> str:
    """Absolute link into the frontend's hash router."""
    return f"{settings.FRONTEND_URL.rstrip('/')}/#{path}"
