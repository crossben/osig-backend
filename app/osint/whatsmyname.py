"""
WhatsMyName username checks (https://github.com/WebBreacher/WhatsMyName).

Every site in the community dataset defines BOTH an "exists" signal
(e_code + e_string) and a "missing" signal (m_code + m_string). A handle is
reported only when the exists signal matches; anything ambiguous counts as
"couldn't check", never as a hit. That is what keeps false positives down.

Skipped on purpose: adult and dating sites (membership there is sensitive
personal information), archived sites, entries marked invalid, and sites
behind a CAPTCHA.
"""
import concurrent.futures
import threading
import time
from typing import Dict, List, Optional, Tuple

import httpx

DATASET_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
SKIP_CATEGORIES = {"xx NSFW xx", "dating", "archived"}
SKIP_PROTECTION = {"captcha", "anubis"}
CACHE_SECONDS = 24 * 3600
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36"

_cache: Dict[str, object] = {"sites": None, "at": 0.0}
_lock = threading.Lock()


def sites() -> List[dict]:
    with _lock:
        if _cache["sites"] is None or time.time() - float(_cache["at"]) > CACHE_SECONDS:
            data = httpx.get(DATASET_URL, timeout=30).json()
            _cache["sites"] = [
                s for s in data.get("sites", [])
                if s.get("cat") not in SKIP_CATEGORIES
                and s.get("valid", True) is not False
                and not SKIP_PROTECTION.intersection(s.get("protection", []))
            ]
            _cache["at"] = time.time()
        return list(_cache["sites"])  # type: ignore[arg-type]


def classify(site: dict, status: int, body: str) -> str:
    """'found' | 'missing' | 'unknown' using the site's own signals."""
    if status == site.get("e_code") and site.get("e_string", "") in body:
        return "found"
    m_string = site.get("m_string", "")
    if status == site.get("m_code") and (not m_string or m_string in body):
        return "missing"
    return "unknown"


def check_site(client: httpx.Client, site: dict, username: str) -> Tuple[str, Optional[str]]:
    handle = username
    for ch in site.get("strip_bad_char", "") or "":
        handle = handle.replace(ch, "")
    url = site["uri_check"].replace("{account}", handle)
    headers = {"User-Agent": UA, **(site.get("headers") or {})}
    if site.get("post_body"):
        r = client.post(url, content=site["post_body"].replace("{account}", handle), headers=headers)
    else:
        r = client.get(url, headers=headers)
    state = classify(site, r.status_code, r.text)
    profile_url = (site.get("uri_pretty") or site["uri_check"]).replace("{account}", handle)
    return state, profile_url


def check_all(username: str, workers: int = 32, timeout: float = 8.0, budget_s: float = 120.0):
    """Returns (found: [{name, url, category}], missing_count, unknown_count)."""
    found: List[dict] = []
    missing = unknown = 0
    started = time.time()
    with httpx.Client(timeout=timeout, follow_redirects=False) as client, \
            concurrent.futures.ThreadPoolExecutor(workers) as pool:
        futures = {pool.submit(check_site, client, s, username): s for s in sites()}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=budget_s):
                site = futures[fut]
                try:
                    state, url = fut.result()
                except Exception:
                    unknown += 1
                    continue
                if state == "found":
                    found.append({"name": site["name"], "url": url, "category": site.get("cat")})
                elif state == "missing":
                    missing += 1
                else:
                    unknown += 1
        except concurrent.futures.TimeoutError:
            unknown += sum(1 for f in futures if not f.done())
            for f in futures:
                f.cancel()
    return sorted(found, key=lambda f: f["name"].lower()), missing, unknown
