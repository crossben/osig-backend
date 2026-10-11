"""
OSIG Backend - "Is this a scam?" checker API

POST /check works signed out (anonymous: per-IP limit) or signed in (per-user
limit). The pasted input is never stored: only a hash, a redacted subject and
the extracted indicators (in `details`, returned to the requester only).
GET /check/{share_id} is public and shows the verdict without details.
"""
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from app.core.crypto import sha256
from app.core.deps import get_current_user, get_db
from app.core.rate_limit import limiter
from app.core.security import decode_token
from app.models.personal import ScamCheck
from app.models.user import User
from app.services import audit_service, scam_check

router = APIRouter(prefix="/check", tags=["Scam check"])

ANON_LIMIT = "10/hour"
USER_LIMIT = "60/hour"
CACHE_HOURS = 6
_KEY_SALT = ""  # tests isolate their limit buckets with this


def _bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer ") and auth[7:].strip():
        return auth[7:].strip()
    return None


def _rate_key(request: Request) -> str:
    token = _bearer(request)
    if token:
        if token.startswith("osig_"):
            # Only a real, unrevoked key earns the signed-in limit, bucketed per owner
            from app.db.session import SessionLocal
            from app.models.platform import ApiKey
            db = SessionLocal()
            try:
                key = db.query(ApiKey.user_id).filter(ApiKey.key_hash == sha256(token),
                                                      ApiKey.revoked.is_(False)).first()
            finally:
                db.close()
            if key:
                return f"{_KEY_SALT}u:{key[0]}"
            return f"{_KEY_SALT}ip:{get_remote_address(request)}"
        payload = decode_token(token, "access")
        if payload and payload.get("sub"):
            return f"{_KEY_SALT}u:{payload['sub']}"
    return f"{_KEY_SALT}ip:{get_remote_address(request)}"


def _limit_for(key: str) -> str:
    return USER_LIMIT if key.startswith(f"{_KEY_SALT}u:") else ANON_LIMIT


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    token = _bearer(request)
    if not token:
        return None
    try:
        return get_current_user(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token), db)
    except HTTPException:
        return None  # a stale token shouldn't block a public tool


class CheckRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=5000)
    country: Optional[str] = Field(None, min_length=2, max_length=2, pattern=r"^[A-Za-z]{2}$")


def _public(row: ScamCheck) -> dict:
    return {"shareId": row.share_id, "kind": row.kind, "subject": row.subject, "verdict": row.verdict,
            "score": row.score, "reasons": row.reasons or [], "checkedAt": row.created_at.isoformat() + "Z"}


@router.post("")
@limiter.limit(_limit_for, key_func=_rate_key)
async def create_check(request: Request, body: CheckRequest, db: Session = Depends(get_db),
                       user: Optional[User] = Depends(get_optional_user)):
    text = body.input.strip()
    if not text:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Nothing to check")
    digest = scam_check.input_hash(text, body.country)
    cached = (db.query(ScamCheck)
              .filter(ScamCheck.input_hash == digest,
                      ScamCheck.created_at >= datetime.utcnow() - timedelta(hours=CACHE_HOURS))
              .order_by(ScamCheck.created_at.desc()).first())
    if cached:
        result = {"kind": cached.kind, "subject": cached.subject, "verdict": cached.verdict,
                  "score": cached.score, "reasons": cached.reasons, "details": {**(cached.details or {}), "cached": True}}
    else:
        result = await run_in_threadpool(scam_check.run_check, text, body.country)
    row = ScamCheck(share_id=secrets.token_urlsafe(8)[:10], user_id=user.id if user else None,
                    kind=result["kind"], subject=result["subject"][:300], input_hash=digest,
                    verdict=result["verdict"], score=result["score"], reasons=result["reasons"],
                    details=result["details"])
    db.add(row)
    db.commit()
    db.refresh(row)
    audit_service.record(db, "scam_check", request=request, user_id=user.id if user else None,
                         target=f"{row.share_id}:{row.verdict}")
    return {**_public(row), "details": row.details}


@router.get("/history")
def history(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = (db.query(ScamCheck).filter(ScamCheck.user_id == user.id)
            .order_by(ScamCheck.created_at.desc()).limit(50).all())
    return [_public(r) for r in rows]


@router.get("/{share_id}")
def get_check(share_id: str, db: Session = Depends(get_db)):
    row = db.query(ScamCheck).filter(ScamCheck.share_id == share_id[:16]).first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Check not found")
    return _public(row)
