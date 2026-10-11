"""
OSIG Backend - "Check a photo" API

POST /photo/inspect returns what a photo's metadata reveals (EXIF/XMP, GPS,
device, dates). POST /photo/strip returns the same photo re-encoded without
metadata. Both work in memory: neither the image nor its metadata is stored;
only an audit entry without content is written.
"""
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db
from app.core.rate_limit import limiter
from app.core.security import decode_token
from app.models.user import User
from app.services import audit_service, photo_service

router = APIRouter(prefix="/photo", tags=["Photo check"])

LIMIT = "30/hour"
_KEY_SALT = ""  # tests isolate their limit buckets with this


def _rate_key(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if token and not token.startswith("osig_"):
        payload = decode_token(token, "access")
        if payload and payload.get("sub"):
            return f"{_KEY_SALT}photo:u:{payload['sub']}"
    return f"{_KEY_SALT}photo:ip:{get_remote_address(request)}"


async def _read(file: UploadFile) -> bytes:
    data = await file.read(photo_service.MAX_BYTES + 1)
    await file.close()
    if len(data) > photo_service.MAX_BYTES:
        raise HTTPException(status_code=413, detail="The photo is larger than 15 MB.")
    return data


@router.post("/inspect")
@limiter.limit(LIMIT, key_func=_rate_key)
async def inspect_photo(request: Request, file: UploadFile = File(...),
                        user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    data = await _read(file)
    try:
        result = await run_in_threadpool(photo_service.inspect, data)
    except photo_service.PhotoError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    finally:
        del data
    audit_service.record(db, "photo_checked", request=request, user_id=user.id)
    return result


@router.post("/strip")
@limiter.limit(LIMIT, key_func=_rate_key)
async def strip_photo(request: Request, file: UploadFile = File(...),
                      user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    name = (file.filename or "photo").rsplit("/", 1)[-1].rsplit(".", 1)[0][:80] or "photo"
    data = await _read(file)
    try:
        body, mime, ext = await run_in_threadpool(photo_service.strip, data)
    except photo_service.PhotoError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    finally:
        del data
    audit_service.record(db, "photo_stripped", request=request, user_id=user.id)
    filename = f"{name}-clean.{ext}"
    return Response(content=body, media_type=mime, headers={
        "Content-Disposition": f"attachment; filename=\"photo-clean.{ext}\"; filename*=UTF-8''{quote(filename)}",
        "Cache-Control": "no-store",
    })
