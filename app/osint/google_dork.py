"""
Google Dork Module

Uses DuckDuckGo (via duckduckgo-search) to run targeted dork queries
against the scan target — 100% free, no API key required.

Runs on ALL target types alongside other OSINT modules.
"""

from typing import List, Optional
import time
from app.osint.base import BaseOSINTModule, OSINTResult

# Target-type dork templates
DORK_TEMPLATES = {
    "email": [
        '"{target}" site:linkedin.com',
        '"{target}" site:github.com',
        '"{target}" site:pastebin.com',
        '"{target}" site:reddit.com',
        '"{target}" "leaked" OR "breach" OR "dump"',
        '"{target}" site:twitter.com OR site:x.com',
        '"{target}" intext:password OR intext:passwd',
    ],
    "username": [
        '"{target}" site:github.com',
        '"{target}" site:reddit.com',
        '"{target}" site:twitter.com OR site:x.com',
        '"{target}" site:linkedin.com',
        '"{target}" site:instagram.com',
        '"{target}" site:pastebin.com',
        '"{target}" site:keybase.io',
    ],
    "domain": [
        'site:{target} filetype:pdf',
        'site:{target} filetype:xls OR filetype:csv',
        '"{target}" site:pastebin.com',
        'inurl:{target} "admin" OR "login" OR "panel"',
        '"{target}" "password" OR "credentials"',
        'site:{target} inurl:".git" OR inurl:".env"',
        '"{target}" site:shodan.io',
    ],
    "phone": [
        '"{target}" site:linkedin.com',
        '"{target}" site:truecaller.com OR site:whitepages.com',
        '"{target}" "contact" OR "whatsapp"',
        '"{target}" site:reddit.com',
        '"{target}" site:pastebin.com',
    ],
}


class GoogleDorkModule(BaseOSINTModule):
    """
    Google Dork intelligence module — runs DuckDuckGo dork queries.

    Runs alongside all target types. Returns dork query results with
    URLs and snippets from public search results.
    """

    MAX_RESULTS_PER_QUERY = 3  # Keep reasonable to avoid rate limits

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
            from duckduckgo_search import DDGS
        except ImportError:
            self.logger.error("duckduckgo-search not installed. Run: pip install duckduckgo-search")
            return results

        with DDGS() as ddgs:
            for template in templates:
                query = template.replace("{target}", target).replace('"{target}"', f'"{target}"')
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
                                "snippet": hit.get("body", "")[:500],
                                "url": hit.get("href") or hit.get("url"),
                                "target": target,
                            },
                            confidence=0.7,
                        )
                        results.append(result)

                    # Small delay between queries to be respectful
                    time.sleep(0.5)

                except Exception as e:
                    self.logger.warning(f"Dork query failed for [{query}]: {e}")
                    continue

        self.log_success(len(results))
        return results


# Module instance
google_dork = GoogleDorkModule()
