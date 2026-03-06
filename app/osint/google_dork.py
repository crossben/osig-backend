"""
Google Dork Module

Uses DuckDuckGo (via duckduckgo-search) to run targeted dork queries
against the scan target — 100% free, no API key required.

Runs on ALL target types alongside other OSINT modules.
"""

from typing import List, Optional
import time
from app.osint.base import BaseOSINTModule, OSINTResult

# Target-type dork templates — keep short: 3 quick queries per type
DORK_TEMPLATES = {
    "email": [
        '"{}" site:linkedin.com OR site:github.com',
        '"{}" site:pastebin.com',
        '"{}" "leaked" OR "breach" OR "dump"',
    ],
    "username": [
        '"{}" site:github.com OR site:reddit.com',
        '"{}" site:twitter.com OR site:instagram.com',
        '"{}" site:pastebin.com OR site:keybase.io',
    ],
    "domain": [
        'site:{} filetype:pdf OR filetype:xls',
        '"{}" site:pastebin.com',
        'inurl:{} "admin" OR "login" OR ".env"',
    ],
    "phone": [
        '"{}" site:linkedin.com',
        '"{}" site:truecaller.com OR site:whitepages.com',
        '"{}" site:pastebin.com',
    ],
}


class GoogleDorkModule(BaseOSINTModule):
    """
    Google Dork intelligence module — runs DuckDuckGo dork queries.

    Runs alongside all target types. Returns dork query results with
    URLs and snippets from public search results.
    """

    MAX_RESULTS_PER_QUERY = 2
    TOTAL_TIMEOUT_SECONDS = 30  # Hard stop for the whole module

    def __init__(self, target_type: str = "email"):
        super().__init__(
            name="google_dork",
            display_name="Search Engine Dork"
        )
        self.target_type = target_type

    def run(self, target: str) -> List[OSINTResult]:
        self.log_start(target)
        results: List[OSINTResult] = []

        templates = DORK_TEMPLATES.get(self.target_type, [])
        if not templates:
            self.logger.warning(f"No dork templates for type: {self.target_type}")
            return results

        try:
            from ddgs import DDGS
        except ImportError:
            self.logger.error("ddgs not installed. Run: pip install ddgs")
            return results

        import time as _time
        start = _time.time()

        try:
            with DDGS() as ddgs:
                for template in templates:
                    # Hard global timeout
                    if _time.time() - start > self.TOTAL_TIMEOUT_SECONDS:
                        self.logger.warning("Dork module hit global timeout, stopping early")
                        break

                    query = template.format(target)
                    try:
                        hits = list(ddgs.text(query, max_results=self.MAX_RESULTS_PER_QUERY))
                        for hit in hits:
                            result = OSINTResult(
                                source="DuckDuckGo Dork",
                                source_url=hit.get("href") or hit.get("url"),
                                data_type="dork_result",
                                data={
                                    "query": query,
                                    "title": hit.get("title", ""),
                                    "snippet": hit.get("body", "")[:400],
                                    "url": hit.get("href") or hit.get("url"),
                                    "target": target,
                                },
                                confidence=0.7,
                            )
                            results.append(result)
                        _time.sleep(0.3)
                    except Exception as e:
                        self.logger.warning(f"Dork query failed [{query}]: {e}")
                        continue
        except Exception as e:
            self.logger.warning(f"DuckDuckGo session error: {e}")

        self.log_success(len(results))
        return results


# Module instance
google_dork = GoogleDorkModule()
