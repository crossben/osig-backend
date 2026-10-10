"""
Search Dork Module

Runs targeted search queries through DuckDuckGo (ddgs; free, no key) for every
target type, in the background after the core modules.

DuckDuckGo treats operators like site: as hints, not filters, so every hit is
checked against the query's intent before it is kept (see is_relevant_hit).
Phone numbers are searched in all their common written formats.
"""

import re
import time
from typing import Dict, List
from urllib.parse import urlparse

from app.osint.base import BaseOSINTModule, OSINTResult

_SITE_RE = re.compile(r"site:(\S+)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _host_matches(host: str, site: str) -> bool:
    host, site = host.lower(), site.lower().lstrip(".")
    return host == site or host.endswith("." + site)


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def phone_formats(number: str) -> List[str]:
    """E.164, international and national spellings of a number."""
    try:
        import phonenumbers
        p = phonenumbers.parse(number, None)
        fmt = phonenumbers.PhoneNumberFormat
        return list(dict.fromkeys([
            phonenumbers.format_number(p, fmt.E164),
            phonenumbers.format_number(p, fmt.INTERNATIONAL),
            phonenumbers.format_number(p, fmt.NATIONAL),
        ]))
    except Exception:
        return [number]


def is_relevant_hit(query: str, hit: dict, needles: List[str], phone: bool = False) -> bool:
    """
    Enforce the query's intent on a hit:
    - site:X / site:X OR site:Y -> the hit's host must be one of them (unless negated with -site:)
    - otherwise one of the target spellings must appear in the title, snippet or URL
    """
    url = hit.get("href") or hit.get("url") or ""
    host = urlparse(url).hostname or ""
    positive_sites = [m.strip('"()') for m in _SITE_RE.findall(query.replace("-site:", "-x:"))]
    if positive_sites and not any(_host_matches(host, s) for s in positive_sites):
        return False
    for neg in re.findall(r"-site:(\S+)", query):
        if _host_matches(host, neg):
            return False
    if positive_sites and not any(f'"{n}"' in query for n in needles):
        return True  # site-scoped query about the target itself
    haystack = " ".join([hit.get("title", ""), hit.get("body", ""), url]).lower()
    if phone:
        digits = _digits(haystack)
        return any(len(_digits(n)) >= 7 and _digits(n)[-9:] in digits for n in needles)
    return any(n.lower() in haystack for n in needles)


def build_queries(target_type: str, target: str) -> Dict[str, object]:
    """Queries plus the spellings a relevant hit must contain."""
    t = target.strip()
    if target_type == "email":
        local, _, domain = t.partition("@")
        return {"needles": [t], "queries": [
            f'"{t}"',
            f'"{t}" site:github.com OR site:gitlab.com OR site:pastebin.com',
            f'"{t}" site:linkedin.com OR site:x.com OR site:facebook.com',
            f'"{local}" "{domain}" -site:{domain}',
        ]}
    if target_type == "username":
        return {"needles": [t], "queries": [
            f'"{t}"',
            f'"{t}" site:github.com OR site:gitlab.com OR site:stackoverflow.com',
            f'"{t}" site:reddit.com OR site:x.com OR site:youtube.com',
            f'"@{t}"',
        ]}
    if target_type == "domain":
        return {"needles": [t], "queries": [
            f"site:{t} -site:www.{t}",
            f"site:{t} filetype:pdf OR filetype:doc OR filetype:xls",
            f'"@{t}"',
            f'"{t}" -site:{t}',
        ]}
    if target_type == "phone":
        formats = phone_formats(t)
        return {"needles": formats, "phone": True, "queries": [
            " OR ".join(f'"{f}"' for f in formats),
            f'"{formats[0]}" site:facebook.com OR site:linkedin.com OR site:instagram.com',
        ]}
    if target_type == "ip":
        return {"needles": [t], "queries": [
            f'"{t}"',
            f'"{t}" abuse OR malware OR phishing OR botnet',
            f'"{t}" site:pastebin.com OR site:github.com',
        ]}
    if target_type == "organization":
        return {"needles": [t], "queries": [
            f'"{t}"',
            f'"{t}" site:linkedin.com',
            f'"{t}" breach OR leak OR lawsuit OR fine',
            f'"{t}" filetype:pdf annual report OR filing',
        ]}
    return {"needles": [t], "queries": [f'"{t}"']}


class GoogleDorkModule(BaseOSINTModule):
    """Public mentions of the target found through search engines."""

    MAX_RESULTS_PER_QUERY = 10  # fetch extra; irrelevant hits are dropped
    KEEP_PER_QUERY = 6
    TOTAL_TIMEOUT_SECONDS = 45

    def __init__(self, target_type: str = "email"):
        super().__init__(name="google_dork", display_name="Search Engine Dork")
        self.target_type = target_type

    def run(self, target: str) -> List[OSINTResult]:
        self.log_start(target)
        results: List[OSINTResult] = []
        plan = build_queries(self.target_type, target)
        needles, phone = plan["needles"], bool(plan.get("phone"))

        try:
            from ddgs import DDGS
        except ImportError:
            self.logger.error("ddgs not installed. Run: pip install ddgs")
            return results

        start = time.time()
        seen_urls = set()
        domain = target.lower() if self.target_type == "domain" else None
        with DDGS() as ddgs:
            for query in plan["queries"]:
                if time.time() - start > self.TOTAL_TIMEOUT_SECONDS:
                    self.logger.warning("Dork module hit its time budget, stopping early")
                    break
                try:
                    hits = list(ddgs.text(query, max_results=self.MAX_RESULTS_PER_QUERY))
                except Exception as e:
                    self.logger.info(f"Dork query failed [{query}]: {e}")
                    continue
                kept = 0
                for hit in hits:
                    url = hit.get("href") or hit.get("url")
                    if not url or url in seen_urls or not is_relevant_hit(query, hit, needles, phone):
                        continue
                    seen_urls.add(url)
                    snippet = hit.get("body", "")[:400]
                    data = {"query": query, "title": hit.get("title", ""), "snippet": snippet,
                            "url": url, "target": target}
                    if domain:
                        emails = sorted({e.lower() for e in EMAIL_RE.findall(snippet + " " + data["title"])
                                         if e.lower().endswith("@" + domain) or e.lower().endswith("." + domain)})
                        if emails:
                            data["emails"] = emails
                    results.append(OSINTResult(source="DuckDuckGo Dork", source_url=url,
                                               data_type="dork_result", data=data, confidence=0.7))
                    kept += 1
                    if kept >= self.KEEP_PER_QUERY:
                        break
                time.sleep(0.4)

        self.log_success(len(results))
        return results


google_dork = GoogleDorkModule()
