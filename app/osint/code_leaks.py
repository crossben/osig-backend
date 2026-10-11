"""
Leaked secrets in public code (background module; domain and email targets).

GitHub code search (REST /search/code) for the target next to secret-ish terms
(password, api_key, secret, token, smtp, private keys) and in typical config
files (.env, config.php, settings.py...). Needs GITHUB_TOKEN (code search
requires authentication); skipped silently without it.

Terms: public repositories through GitHub's documented API, within its rate
limits (code search: 10 requests/minute) - allowed under the GitHub Terms of
Service / API terms, including commercial use. We stop at the first 403/429.

Secrets are NEVER stored: only that one exists, where (repo, path, link), what
kind it looks like, and a redacted preview (first 4 characters + "…").
"""
import re
import time
from typing import Dict, List, Optional

import httpx

from app.osint.base import BaseOSINTModule, OSINTResult, redact

SEARCH_URL = "https://api.github.com/search/code"
TERMS = ["password", "api_key", "secret", "token", "smtp", '"BEGIN RSA PRIVATE KEY"']
CONFIG_FILES = [".env", "config.php", "settings.py", "wp-config.php"]
CONFIG_NAMES = re.compile(r"(^|/)(\.env(\.\w+)?|config\.php|wp-config\.php|settings\.py|application\.properties|"
                          r"config\.ya?ml|secrets?\.\w+|credentials(\.\w+)?)$", re.I)
ASSIGN = re.compile(
    r"""(?P<key>[A-Za-z0-9_.\-]*(?:pass(?:word|wd)?|pwd|secret|api[_\-]?key|token|auth|smtp_pass)[A-Za-z0-9_.\-]*)"""
    r"""["']?\s*(?:=>|[:=])\s*["']?(?P<value>[^\s"',;)]{4,})""", re.I)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
PLACEHOLDER = re.compile(r"^(x+|\*+|changeme|password|secret|example|test|null|none|true|false|your[_\-].*|"
                         r"<.*>|\$\{.*|\{\{.*|%.*%|process\.env.*|os\.environ.*|getenv.*|env\(.*|\.\.\.)$", re.I)
MAX_RESULTS = 20
TIME_BUDGET = 35


def classify(fragment: str, path: str) -> Dict[str, object]:
    """What a matched code fragment exposes, with only a redacted preview."""
    if PRIVATE_KEY.search(fragment or ""):
        return {"kind": "private_key", "preview": "-----BEGIN … PRIVATE KEY-----", "likely_credential": True}
    for m in ASSIGN.finditer(fragment or ""):
        value = m.group("value")
        if PLACEHOLDER.match(value):
            continue
        return {"kind": m.group("key").lower()[:40], "preview": f"{m.group('key')}={redact(value)}",
                "likely_credential": True}
    exposed = bool(CONFIG_NAMES.search(path or ""))
    return {"kind": "config_file" if exposed else "mention", "preview": None, "likely_credential": False}


def build_queries(target_type: str, target: str) -> List[str]:
    t = target.strip().lower()
    queries = [f'"{t}" {term}' for term in TERMS]
    if target_type == "domain":
        queries += [f'"{t}" filename:{name}' for name in CONFIG_FILES]
    else:
        queries += [f'"{t}" filename:.env']
    return queries


class CodeLeaksModule(BaseOSINTModule):
    def __init__(self, target_type: str = "domain"):
        super().__init__(name="code_leaks", display_name="Leaked Secrets in Code")
        self.target_type = target_type

    def run(self, target: str) -> List[OSINTResult]:
        from app.core.config import settings
        if not settings.GITHUB_TOKEN:
            return []
        self.log_start(target)
        headers = {"Authorization": f"Bearer {settings.GITHUB_TOKEN}",
                   "Accept": "application/vnd.github.text-match+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "OSIG/1.0"}
        results: List[OSINTResult] = []
        seen = set()
        start = time.time()
        for query in build_queries(self.target_type, target):
            if len(results) >= MAX_RESULTS or time.time() - start > TIME_BUDGET:
                break
            items = self._search(query, headers)
            if items is None:  # rate limited / forbidden: stop early
                break
            term = query.split('" ', 1)[1] if '" ' in query else query
            for item in items:
                url = item.get("html_url")
                if not url or url in seen:
                    continue
                seen.add(url)
                fragment = "\n".join(m.get("fragment") or "" for m in item.get("text_matches") or [])
                if target.lower() not in fragment.lower() and target.lower() not in url.lower():
                    continue  # code search matched tokens, not the target itself
                info = classify(fragment, item.get("path") or "")
                repo = (item.get("repository") or {}).get("full_name")
                results.append(OSINTResult(
                    source="GitHub Code Search", source_url=url, data_type="code_leak",
                    data={"target": target, "repo": repo, "path": item.get("path"), "html_url": url,
                          "matched_term": term, "kind": info["kind"], "preview": info["preview"],
                          "likely_credential": info["likely_credential"],
                          "exposed_config": bool(CONFIG_NAMES.search(item.get("path") or ""))},
                    confidence=0.8 if info["likely_credential"] else 0.6,
                ))
                if len(results) >= MAX_RESULTS:
                    break
        self.log_success(len(results))
        return results

    def _search(self, query: str, headers: Dict[str, str]) -> Optional[List[dict]]:
        try:
            r = httpx.get(SEARCH_URL, params={"q": query, "per_page": 10}, headers=headers, timeout=15)
        except httpx.HTTPError:
            return []
        if r.status_code in (401, 403, 429):
            self.logger.info(f"GitHub code search stopped: HTTP {r.status_code}")
            return None
        if r.status_code != 200:
            return []
        return (r.json() or {}).get("items") or []
