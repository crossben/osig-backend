"""
Homepage snapshot (core module; domain targets) for watch change detection.

Fetches the homepage through safe_http.safe_get (target-controlled URL) and
records a fingerprint of its visible text: scripts, styles, tags and
whitespace are stripped and digits are collapsed, so clocks, counters, dates
and cache-busting tokens don't register as changes. The graph turns the
fingerprint into a `snapshot` entity, so a watch diff reports "Homepage
content changed" when it differs from the previous run.
"""
import hashlib
import html
import re
from typing import List, Optional

from app.osint.base import BaseOSINTModule, OSINTResult

STRIP_BLOCKS = re.compile(r"<(script|style|noscript|template|svg)\b.*?</\1\s*>|<!--.*?-->", re.I | re.S)
TAGS = re.compile(r"<[^>]+>")
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
MONTHS = re.compile(r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|janv|févr|mars|avr|mai|juin|juil|"
                    r"août|sept|oct|nov|déc)[a-zé]*\.?\b", re.I)


def visible_text(page: str) -> str:
    text = TAGS.sub(" ", STRIP_BLOCKS.sub(" ", page or ""))
    return " ".join(html.unescape(text).split())


def fingerprint(page: str) -> str:
    """Stable hash of the page's visible text, insensitive to numbers and dates."""
    text = visible_text(page).lower()
    text = MONTHS.sub("<m>", re.sub(r"\d+", "0", text))
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def snapshot(domain: str) -> Optional[dict]:
    from app.osint.safe_http import safe_get
    for scheme in ("https", "http"):
        try:
            resp = safe_get(f"{scheme}://{domain}/", timeout=10, max_bytes=1024 * 1024,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; OSIG/1.0)"})
        except Exception:
            continue
        if resp.status_code >= 400 or "html" not in resp.headers.get("content-type", "html").lower():
            return None
        page = resp.text
        m = TITLE.search(page)
        text = visible_text(page)
        return {"url": f"{scheme}://{domain}/", "final_url": str(resp.request.url), "status": resp.status_code,
                "title": " ".join(html.unescape(m.group(1)).split())[:200] if m else None,
                "fingerprint": fingerprint(page), "text_sample": text[:200], "text_length": len(text)}
    return None


class PageSnapshotModule(BaseOSINTModule):
    def __init__(self):
        super().__init__(name="page_snapshot", display_name="Homepage Snapshot")

    def run(self, target: str) -> List[OSINTResult]:
        snap = snapshot(target.strip().lower())
        if not snap:
            return []
        return [OSINTResult(source="Homepage Snapshot", source_url=snap["final_url"], data_type="page_snapshot",
                            data=snap, confidence=0.95)]
