"""
Dark web mentions (background module; domain and organization targets).

Source: ransomware.live victim search (https://api.ransomware.live/v2/searchvictims/<keyword>),
a clearnet index of ransomware leak-site claims. Only the claim's metadata is
kept: victim, group, dates, the .onion HOST of the claim (never fetched) and a
short snippet. Gated behind ENABLE_RANSOMWARE_LIVE (default off): its free API
terms could not be confirmed for commercial use - check them (or use their paid
PRO API) before enabling on a paid deployment.

Not used: Ahmia (ahmia.fi). Its robots.txt disallows /search/ for all agents,
and it offers no search API, so OSIG does not query it. OSIG never connects to
.onion services.
"""
import re
from typing import List
from urllib.parse import quote, urlparse

import httpx

from app.osint.base import BaseOSINTModule, OSINTResult

UA = {"User-Agent": "OSIG/1.0 (open source intelligence research)"}
API = "https://api.ransomware.live/v2/searchvictims/"
MIN_SIMILARITY = 90
MAX_RESULTS = 10


def keyword(target_type: str, target: str) -> str:
    """ransomware.live matches victim names: 'acme' for acme.com, the name for organizations."""
    t = target.strip().lower()
    if target_type == "domain":
        import tldextract
        return tldextract.extract(t).domain or t
    return t


def is_match(target_type: str, target: str, victim: dict) -> bool:
    t = target.strip().lower()
    domain = str(victim.get("domain") or "").lower().removeprefix("www.")
    name = str(victim.get("victim") or "").lower()
    if target_type == "domain":
        return domain == t or name == t or name.removeprefix("www.") == t
    from rapidfuzz import fuzz
    norm = lambda s: re.sub(r"\b(inc|ltd|llc|gmbh|sa|sas|plc|corp|co|group)\b\.?", "", s).strip(" .,")  # noqa: E731
    return fuzz.token_sort_ratio(norm(t), norm(name)) >= MIN_SIMILARITY


def ransomware_live(target_type: str, target: str) -> List[OSINTResult]:
    try:
        r = httpx.get(API + quote(keyword(target_type, target), safe=""), headers=UA, timeout=20)
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    body = r.json()
    victims = body if isinstance(body, list) else (body or {}).get("victims") or []
    out: List[OSINTResult] = []
    for v in victims:
        if not isinstance(v, dict) or not is_match(target_type, target, v):
            continue
        onion = urlparse(str(v.get("claim_url") or "")).hostname or ""
        out.append(OSINTResult(
            source="ransomware.live", source_url=v.get("url") or "https://www.ransomware.live/",
            data_type="darkweb_mention",
            data={"target": target, "victim": v.get("victim"), "group": v.get("group"),
                  "title": f"{v.get('group') or 'Ransomware group'} claims {v.get('victim')}",
                  "onion_host": onion if onion.endswith(".onion") else None,
                  "snippet": " ".join(str(v.get("description") or "").split())[:300] or None,
                  "attack_date": str(v.get("attackdate") or "")[:10] or None,
                  "discovered": str(v.get("discovered") or "")[:10] or None,
                  "country": v.get("country") or None, "kind": "ransomware_claim"},
            confidence=0.85 if target_type == "domain" else 0.6,
        ))
        if len(out) >= MAX_RESULTS:
            break
    return out


class DarkWebModule(BaseOSINTModule):
    def __init__(self, target_type: str = "domain"):
        super().__init__(name="darkweb", display_name="Dark Web Mentions")
        self.target_type = target_type

    def run(self, target: str) -> List[OSINTResult]:
        from app.core.config import settings
        if not settings.ENABLE_RANSOMWARE_LIVE:
            return []
        self.log_start(target)
        results = ransomware_live(self.target_type, target)
        self.log_success(len(results))
        return results
