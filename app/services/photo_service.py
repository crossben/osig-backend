"""
OSIG Backend - photo metadata inspection ("Check a photo")

Everything happens in memory: the uploaded bytes are read, inspected or
re-encoded, and dropped. Nothing about the image is written to the database.
No face detection, no third-party upload.
"""
import io
import re
import warnings
from datetime import datetime
from typing import Any, Optional

from PIL import ExifTags, Image, ImageOps, UnidentifiedImageError

MAX_BYTES = 15 * 1024 * 1024
MAX_PIXELS = 50_000_000  # ~8K x 6K; anything bigger is refused before decoding

# Pillow format name -> (mime type, file extension)
FORMATS = {
    "JPEG": ("image/jpeg", "jpg"),
    "PNG": ("image/png", "png"),
    "WEBP": ("image/webp", "webp"),
    "TIFF": ("image/tiff", "tiff"),
}


class PhotoError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _open(data: bytes) -> Image.Image:
    if not data:
        raise PhotoError(400, "The file is empty.")
    if len(data) > MAX_BYTES:
        raise PhotoError(413, "The photo is larger than 15 MB.")
    if data[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1", b"ftyphevc", b"ftypmsf1"):
        raise PhotoError(415, "HEIC photos aren't supported yet. Export the photo as JPEG and try again.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            im = Image.open(io.BytesIO(data))  # lazy: reads the header only
    except (UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise PhotoError(415, "This file isn't a supported image (JPEG, PNG, WebP or TIFF).")
    except Exception:
        raise PhotoError(400, "The image could not be read.")
    if im.format not in FORMATS:
        raise PhotoError(415, "This file isn't a supported image (JPEG, PNG, WebP or TIFF).")
    w, h = im.size
    if w <= 0 or h <= 0 or w * h > MAX_PIXELS:
        raise PhotoError(413, "The image has too many pixels to process.")
    return im


def _verify(data: bytes) -> None:
    """Pillow's structural check (needs a fresh handle: verify() consumes it)."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            Image.open(io.BytesIO(data)).verify()
    except Exception:
        raise PhotoError(400, "The image is damaged or incomplete.")


# ---------------------------------------------------------------- helpers

def _num(v: Any) -> Optional[float]:
    try:
        f = float(v)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    return f if f == f and abs(f) != float("inf") else None


def _text(v: Any, limit: int = 200) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    s = str(v).replace("\x00", "").strip()
    return s[:limit] or None


def dms_to_decimal(dms: Any, ref: Any) -> Optional[float]:
    """((deg), (min), (sec)) + 'N'/'S'/'E'/'W' -> signed decimal degrees."""
    try:
        d, m, s = (_num(x) for x in dms)
    except (TypeError, ValueError):
        return None
    if d is None or m is None or s is None:
        return None
    value = d + m / 60 + s / 3600
    if _text(ref) in ("S", "W"):
        value = -value
    return round(value, 6)


def _parse_exif_date(v: Any) -> Optional[str]:
    s = _text(v, 40)
    if not s:
        return None
    try:
        return datetime.strptime(s[:19], "%Y:%m:%d %H:%M:%S").isoformat()
    except ValueError:
        return None


_XMP_FIELDS = {
    "creator_tool": r"xmp:CreatorTool(?:=\"|>)([^\"<]{1,200})",
    "create_date": r"xmp:CreateDate(?:=\"|>)([^\"<]{1,40})",
    "modify_date": r"xmp:ModifyDate(?:=\"|>)([^\"<]{1,40})",
    "software_agent": r"stEvt:softwareAgent(?:=\"|>)([^\"<]{1,200})",
}


def _xmp(im: Image.Image, data: bytes) -> Optional[dict]:
    raw = im.info.get("xmp") or im.info.get("XML:com.adobe.xmp")
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    if not raw:
        start = data.find(b"<x:xmpmeta")
        if start == -1:
            return None
        end = data.find(b"</x:xmpmeta>", start)
        raw = data[start:end + 12 if end != -1 else start + 65536]
    text = raw[:262144].decode("utf-8", "replace")
    out = {k: m.group(1).strip() for k, p in _XMP_FIELDS.items() if (m := re.search(p, text))}
    return out


def _thumbnail(im: Image.Image, width: int, height: int) -> Optional[dict]:
    """EXIF IFD1 thumbnail: if its shape differs from the photo, the photo was likely cropped or edited."""
    raw = im.info.get("exif")
    if not raw:
        return None
    try:
        ifd1 = im.getexif().get_ifd(ExifTags.IFD.IFD1)
        offset, length = ifd1.get(0x0201), ifd1.get(0x0202)
        if not offset or not length or length > 1_000_000:
            return None
        base = 6 if raw[:6] == b"Exif\x00\x00" else 0
        blob = raw[base + offset: base + offset + length]
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            th = Image.open(io.BytesIO(blob))
            tw, tht = th.size
    except Exception:
        return None
    if not tw or not tht:
        return None
    ratio_photo = width / height
    ratio_thumb = tw / tht
    # A rotated orientation tag can swap the main image but leave the thumbnail as stored
    mismatch = min(abs(ratio_photo - ratio_thumb), abs(1 / ratio_photo - ratio_thumb)) > 0.03 * max(ratio_thumb, 1)
    return {"width": tw, "height": tht, "mismatch": mismatch}


# ---------------------------------------------------------------- public API

ORIENTATIONS = {
    1: "Normal", 2: "Mirrored", 3: "Rotated 180°", 4: "Mirrored vertically",
    5: "Mirrored and rotated 90°", 6: "Rotated 90°", 7: "Mirrored and rotated 270°", 8: "Rotated 270°",
}


def inspect(data: bytes) -> dict:
    im = _open(data)
    _verify(data)
    fmt = im.format
    width, height = im.size
    exif = im.getexif()
    sub = exif.get_ifd(ExifTags.IFD.Exif) if exif else {}
    gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo) if exif else {}

    gps = None
    if gps_ifd:
        lat = dms_to_decimal(gps_ifd.get(2), gps_ifd.get(1))
        lon = dms_to_decimal(gps_ifd.get(4), gps_ifd.get(3))
        if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180 and (lat, lon) != (0, 0):
            alt = _num(gps_ifd.get(6))
            if alt is not None and gps_ifd.get(5) in (1, b"\x01"):
                alt = -alt
            gps = {"latitude": lat, "longitude": lon,
                   "altitude": round(alt, 1) if alt is not None else None,
                   "timestamp": _text(gps_ifd.get(29), 20)}

    orientation = exif.get(274) if exif else None
    camera = {
        "make": _text(exif.get(271)),
        "model": _text(exif.get(272)),
        "lens": _text(sub.get(42036)) or _text(sub.get(42035)),
        "serial_number": _text(sub.get(42033), 80),
        "software": _text(exif.get(305)),
        "artist": _text(exif.get(315)),
        "copyright": _text(exif.get(33432)),
    }
    exposure = _num(sub.get(33434))
    settings = {
        "f_number": _num(sub.get(33437)),
        "exposure_time": (f"1/{round(1 / exposure)}" if exposure and exposure < 1 else (f"{exposure:g}" if exposure else None)),
        "iso": _num(sub.get(34855)),
        "focal_length": _num(sub.get(37386)),
    }
    dates = {
        "taken": _parse_exif_date(sub.get(36867)),
        "digitized": _parse_exif_date(sub.get(36868)),
        "modified": _parse_exif_date(exif.get(306)),
        "offset": _text(sub.get(36881), 10),
    }
    xmp = _xmp(im, data)
    thumb = _thumbnail(im, width, height)

    camera = {k: v for k, v in camera.items() if v}
    settings = {k: v for k, v in settings.items() if v is not None}
    dates = {k: v for k, v in dates.items() if v}
    has_exif = bool(exif)
    stripped = not has_exif and not xmp
    mime, ext = FORMATS[fmt]
    return {
        "file": {
            "format": fmt, "mime_type": mime, "extension": ext, "width": width, "height": height,
            "megapixels": round(width * height / 1e6, 1), "size_bytes": len(data), "mode": im.mode,
            "animated": bool(getattr(im, "is_animated", False)),
            "has_icc_profile": bool(im.info.get("icc_profile")),
        },
        "gps": gps,
        "camera": camera,
        "settings": settings,
        "dates": dates,
        "orientation": ORIENTATIONS.get(orientation) if isinstance(orientation, int) else None,
        "xmp": xmp or None,
        "thumbnail": thumb,
        "has_exif": has_exif,
        "metadata_stripped": stripped,
    }


def strip(data: bytes) -> tuple[bytes, str, str]:
    """Re-encode the pixels only (orientation applied, first frame), dropping EXIF/XMP/comments."""
    im = _open(data)
    _verify(data)
    fmt = im.format
    try:
        im = ImageOps.exif_transpose(im)
        im.load()
    except Exception:
        raise PhotoError(400, "The image could not be read.")
    icc = im.info.get("icc_profile")  # colour data only: kept so colours don't shift
    transparency = im.info.get("transparency")
    clean = im.copy()
    clean.info = {}  # EXIF, XMP, text chunks and comments all live here
    if transparency is not None and fmt == "PNG":
        clean.info["transparency"] = transparency
    out = io.BytesIO()
    kw: dict[str, Any] = {"icc_profile": icc} if icc else {}
    if fmt == "JPEG":
        if clean.mode not in ("RGB", "L", "CMYK"):
            clean = clean.convert("RGB")
        clean.save(out, "JPEG", quality=92, optimize=True, **kw)
    elif fmt == "WEBP":
        clean.save(out, "WEBP", quality=92, **kw)
    elif fmt == "TIFF":
        clean.save(out, "TIFF", compression="tiff_lzw", **kw)
    else:
        clean.save(out, "PNG", optimize=True, **kw)
    mime, ext = FORMATS[fmt]
    return out.getvalue(), mime, ext
