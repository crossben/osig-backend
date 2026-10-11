"""Check a photo: metadata extraction, stripping, limits, nothing stored."""
import io
import uuid

import pytest
from PIL import ExifTags, Image
from PIL.TiffImagePlugin import IFDRational
from sqlalchemy import text

from app.api.v1 import photo as photo_api
from app.db.session import Base
from app.models.audit_log import AuditLog
from app.services import photo_service


@pytest.fixture(autouse=True)
def fresh_limit_bucket(monkeypatch):
    monkeypatch.setattr(photo_api, "_KEY_SALT", uuid.uuid4().hex[:8])


def _dms(value: float):
    d = int(value)
    m = int((value - d) * 60)
    s = round(((value - d) * 60 - m) * 60, 4)
    return (IFDRational(d), IFDRational(m), IFDRational(round(s * 10000), 10000))


def make_jpeg(gps=True, size=(64, 48), thumb_size=None) -> bytes:
    im = Image.new("RGB", size, (200, 120, 40))
    exif = Image.Exif()
    exif[271] = "Canon"
    exif[272] = "Canon EOS R6"
    exif[305] = "Firmware 1.8"
    exif[274] = 1
    sub = exif.get_ifd(ExifTags.IFD.Exif)
    sub[36867] = "2024:05:17 14:03:22"
    sub[42036] = "RF24-105mm F4 L IS USM"
    sub[33437] = IFDRational(4)
    sub[33434] = IFDRational(1, 250)
    sub[34855] = 400
    if gps:
        g = exif.get_ifd(ExifTags.IFD.GPSInfo)
        g[1], g[2] = "N", _dms(14.6937)
        g[3], g[4] = "W", _dms(17.4441)
        g[5], g[6] = 0, IFDRational(42)
    out = io.BytesIO()
    im.save(out, "JPEG", exif=exif)
    return out.getvalue()


def png_bytes(**kw) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (10, 10), "white").save(out, "PNG", **kw)
    return out.getvalue()


def test_dms_to_decimal():
    assert photo_service.dms_to_decimal((14, 41, 37.32), "N") == 14.6937
    assert photo_service.dms_to_decimal((17, 26, 38.76), "W") == -17.4441
    assert photo_service.dms_to_decimal((1, 2), "N") is None
    assert photo_service.dms_to_decimal(None, "N") is None


def test_inspect_reads_exif_and_gps():
    r = photo_service.inspect(make_jpeg())
    assert r["gps"]["latitude"] == pytest.approx(14.6937, abs=1e-4)
    assert r["gps"]["longitude"] == pytest.approx(-17.4441, abs=1e-4)
    assert r["gps"]["altitude"] == 42
    assert r["camera"]["make"] == "Canon"
    assert r["camera"]["model"] == "Canon EOS R6"
    assert r["camera"]["lens"].startswith("RF24")
    assert r["dates"]["taken"] == "2024-05-17T14:03:22"
    assert r["settings"]["exposure_time"] == "1/250"
    assert r["file"]["format"] == "JPEG" and r["file"]["width"] == 64
    assert r["metadata_stripped"] is False
    assert r["orientation"] == "Normal"


def test_inspect_without_metadata_says_stripped():
    r = photo_service.inspect(png_bytes())
    assert r["metadata_stripped"] is True
    assert r["gps"] is None and r["camera"] == {}


def test_strip_removes_exif():
    clean, mime, ext = photo_service.strip(make_jpeg())
    assert mime == "image/jpeg" and ext == "jpg"
    im = Image.open(io.BytesIO(clean))
    assert not im.getexif()
    assert "exif" not in im.info
    assert photo_service.inspect(clean)["metadata_stripped"] is True


def test_strip_png_text_chunks():
    from PIL.PngImagePlugin import PngInfo
    info = PngInfo()
    info.add_text("Author", "Someone")
    clean, mime, _ = photo_service.strip(png_bytes(pnginfo=info))
    assert mime == "image/png"
    assert "Author" not in Image.open(io.BytesIO(clean)).info


def test_decompression_bomb_refused():
    out = io.BytesIO()
    Image.new("1", (10000, 10000)).save(out, "PNG")  # 100 MP, tiny file
    with pytest.raises(photo_service.PhotoError) as e:
        photo_service.inspect(out.getvalue())
    assert e.value.status in (413, 415)


def test_unsupported_types():
    for data in (b"%PDF-1.4 hello", b"GIF89a" + b"\x00" * 20, b"\x00\x00\x00\x18ftypheic" + b"\x00" * 20):
        with pytest.raises(photo_service.PhotoError) as e:
            photo_service.inspect(data)
        assert e.value.status == 415
    gif = io.BytesIO()
    Image.new("RGB", (4, 4)).save(gif, "GIF")
    with pytest.raises(photo_service.PhotoError) as e:
        photo_service.inspect(gif.getvalue())
    assert e.value.status == 415


def test_truncated_image_rejected():
    data = make_jpeg()[:200]
    with pytest.raises(photo_service.PhotoError):
        photo_service.strip(data)


def test_api_requires_sign_in(client):
    r = client.post("/api/v1/photo/inspect", files={"file": ("a.jpg", make_jpeg(), "image/jpeg")})
    assert r.status_code in (401, 403)


def _counts(db):
    # Every table but users/tokens touched by sign-in: an inspect must add exactly one audit row
    return {t: db.execute(text(f'SELECT count(*) FROM "{t}"')).scalar() for t in Base.metadata.tables}


def test_api_inspect_and_nothing_stored(client, user, db):
    headers, body = user
    before = _counts(db)
    r = client.post("/api/v1/photo/inspect", headers=headers,
                    files={"file": ("holiday.jpg", make_jpeg(), "image/jpeg")})
    assert r.status_code == 200, r.text
    assert r.json()["gps"]["latitude"] == pytest.approx(14.6937, abs=1e-4)
    db.expire_all()
    after = _counts(db)
    after["audit_logs"] -= 1
    assert before == after
    logs = db.query(AuditLog).filter(AuditLog.user_id == body["user"]["id"],
                                     AuditLog.action == "photo_checked").all()
    assert len(logs) == 1 and logs[0].target is None


def test_api_strip_and_errors(client, user):
    headers, _ = user
    r = client.post("/api/v1/photo/strip", headers=headers,
                    files={"file": ("holiday.jpg", make_jpeg(), "image/jpeg")})
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/jpeg"
    assert "holiday-clean.jpg" in r.headers["content-disposition"]
    assert not Image.open(io.BytesIO(r.content)).getexif()

    r = client.post("/api/v1/photo/inspect", headers=headers,
                    files={"file": ("x.pdf", b"%PDF-1.4", "application/pdf")})
    assert r.status_code == 415
    r = client.post("/api/v1/photo/inspect", headers=headers,
                    files={"file": ("big.jpg", b"\xff" * (photo_service.MAX_BYTES + 10), "image/jpeg")})
    assert r.status_code == 413


def test_api_rate_limited(client, user, monkeypatch):
    headers, _ = user
    monkeypatch.setattr(photo_api, "_KEY_SALT", uuid.uuid4().hex[:8])
    codes = [client.post("/api/v1/photo/inspect", headers=headers,
                         files={"file": ("a.png", png_bytes(), "image/png")}).status_code for _ in range(31)]
    assert codes[:30] == [200] * 30 and codes[30] == 429
