"""
Email Intelligence Module

Quick:
- Gravatar (v3 API): public profile, location, employer, verified linked accounts
- Disposable-provider check against the community blocklist
- Mail domain: MX records (can the address receive mail at all)
- XposedOrNot: known breaches the address appears in (names, dates, exposed data types)
Deep adds:
- Holehe: which of ~120 sites the address is registered on
- EmailRep: reputation (rate limited without a key)
- Have I Been Pwned: only when HIBP_API_KEY is set
"""

import hashlib
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import List, Optional, Set

import httpx

from app.osint.base import BaseOSINTModule, OSINTResult

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) OSIG/1.0"}

# Fallback if the community list can't be fetched
_BUILTIN_DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwam.com", "sharklasers.com",
    "guerrillamailblock.com", "yopmail.com", "trashmail.com", "dispostable.com", "mailnull.com",
    "spamgourmet.com", "spamgourmet.net", "fakeinbox.com", "maildrop.cc", "getairmail.com",
    "10minutemail.com", "discard.email", "spam.la", "temp-mail.org", "tempail.com",
}
_DISPOSABLE_URL = (
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/"
    "master/disposable_email_blocklist.conf"
)
_disposable_cache: Optional[Set[str]] = None
_disposable_lock = threading.Lock()


def disposable_domains() -> Set[str]:
    """Community blocklist (~4k domains), fetched once per process."""
    global _disposable_cache
    with _disposable_lock:
        if _disposable_cache is None:
            try:
                r = httpx.get(_DISPOSABLE_URL, timeout=8)
                r.raise_for_status()
                _disposable_cache = {l.strip().lower() for l in r.text.splitlines() if l.strip()} | _BUILTIN_DISPOSABLE
            except Exception:
                _disposable_cache = set(_BUILTIN_DISPOSABLE)
        return _disposable_cache


def _venv_bin(name: str) -> Optional[str]:
    """CLI tools installed alongside the interpreter (venv/bin, /usr/local/bin)."""
    exe = shutil.which(name) or str(Path(sys.executable).with_name(name))
    return exe if Path(exe).exists() else None


class EmailIntelModule(BaseOSINTModule):
    """Accounts, breach exposure and reputation tied to an email address."""

    def __init__(self):
        super().__init__(name="email_intel", display_name="Email Intelligence")

    def run(self, target: str, deep: bool = False) -> List[OSINTResult]:
        self.log_start(target)
        email = target.strip().lower()
        if not self.validate_target(email, "email"):
            self.logger.warning(f"Invalid email format: {target}")
            return []

        results: List[OSINTResult] = []
        checks = [self._check_gravatar, self._check_disposable, self._check_email_domain, self._check_xposedornot,
                  self._check_github_commits, self._check_exposure]
        if deep:
            checks += [self._check_holehe, self._check_emailrep, self._check_hibp]
        for check in checks:
            try:
                results.extend(check(email))
            except Exception as e:  # one failing source must not sink the module
                self.logger.warning(f"{check.__name__} failed: {e}")

        self.log_success(len(results))
        return results

    # ── quick ───────────────────────────────────────────────
    def _check_gravatar(self, email: str) -> List[OSINTResult]:
        sha = hashlib.sha256(email.encode()).hexdigest()
        r = httpx.get(f"https://api.gravatar.com/v3/profiles/{sha}", headers=UA, timeout=10)
        if r.status_code != 200:
            return []  # no public profile; nothing to report
        p = r.json()
        accounts = [
            {"service": a.get("service_label"), "url": a.get("url")}
            for a in p.get("verified_accounts", []) if a.get("url") and not a.get("is_hidden")
        ]
        return [OSINTResult(
            source="Gravatar",
            source_url=p.get("profile_url"),
            data_type="profile",
            data={
                "has_profile": True,
                "name": p.get("display_name"),
                "location": p.get("location") or None,
                "job_title": p.get("job_title") or None,
                "company": p.get("company") or None,
                "bio": p.get("description") or None,
                "avatar_url": p.get("avatar_url"),
                "profile_url": p.get("profile_url"),
                "verified_accounts": accounts,
                "links": [l.get("url") for l in p.get("links", []) if l.get("url")],
            },
            confidence=0.95,
        )]

    def _check_disposable(self, email: str) -> List[OSINTResult]:
        domain = email.split("@")[-1]
        is_disposable = domain in disposable_domains()
        return [OSINTResult(
            source="Disposable Email Check",
            data_type="email_validation",
            data={"email": email, "domain": domain, "is_disposable": is_disposable,
                  "risk": "high" if is_disposable else "low"},
            confidence=0.9,
        )]

    def _check_email_domain(self, email: str) -> List[OSINTResult]:
        import dns.resolver
        domain = email.split("@")[-1]
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=6)
            mx = sorted(({"exchange": str(a.exchange).rstrip("."), "priority": a.preference} for a in answers),
                        key=lambda m: m["priority"])
            valid = True
        except Exception:
            mx, valid = [], False
        return [OSINTResult(
            source="Email Domain Check",
            data_type="email_validation",
            data={"email": email, "domain": domain, "mx_records": mx, "domain_valid": valid,
                  "provider": _mail_provider(mx)},
            confidence=0.95,
        )]

    def _check_xposedornot(self, email: str) -> List[OSINTResult]:
        r = httpx.get("https://api.xposedornot.com/v1/breach-analytics", params={"email": email},
                      headers=UA, timeout=20)
        if r.status_code != 200:
            return []
        details = ((r.json().get("ExposedBreaches") or {}).get("breaches_details")) or []
        results = []
        for b in details:
            exposed = [x.strip() for x in (b.get("xposed_data") or "").split(";") if x.strip()]
            results.append(OSINTResult(
                source="XposedOrNot",
                source_url=f"https://xposedornot.com/xposed#{email}",
                data_type="breach",
                data={
                    "email": email,
                    "name": b.get("breach"),
                    "domain": b.get("domain") or None,
                    "breach_date": b.get("xposed_date"),
                    "records": b.get("xposed_records"),
                    "data_classes": exposed,
                    "password_risk": b.get("password_risk"),
                    "description": b.get("details"),
                    "risk": "high" if any("password" in x.lower() for x in exposed) else "medium",
                },
                confidence=0.85,
            ))
        return results

    def _check_exposure(self, email: str) -> List[OSINTResult]:
        """Infostealer exposure (Hudson Rock) and published PGP keys."""
        from app.osint.exposure import hudson_rock, pgp_keys
        return hudson_rock("email", email) + pgp_keys(email)

    def _check_github_commits(self, email: str) -> List[OSINTResult]:
        """GitHub accounts that authored public commits with this address."""
        from app.core.config import settings
        headers = {**UA, "Accept": "application/vnd.github+json"}
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"
        r = httpx.get("https://api.github.com/search/commits", headers=headers, timeout=15,
                      params={"q": f"author-email:{email}", "per_page": 50})
        if r.status_code != 200:
            return []
        body = r.json()
        accounts: dict = {}
        for item in body.get("items", []):
            login = (item.get("author") or {}).get("login")
            if not login:
                continue
            acct = accounts.setdefault(login, {"repos": set(), "latest": None})
            acct["repos"].add(item["repository"]["full_name"])
            date = ((item.get("commit") or {}).get("author") or {}).get("date")
            if date and (not acct["latest"] or date > acct["latest"]):
                acct["latest"] = date
        return [OSINTResult(
            source="GitHub Commits",
            source_url=f"https://github.com/{login}",
            data_type="social_profile",
            data={
                "platform": "GitHub", "username": login, "url": f"https://github.com/{login}", "exists": True,
                "profile": {"commits_with_email": body.get("total_count"), "latest_commit": info["latest"],
                            "repositories": sorted(info["repos"])[:10]},
            },
            confidence=0.9,
        ) for login, info in accounts.items()]

    # ── deep ────────────────────────────────────────────────
    def _check_holehe(self, email: str) -> List[OSINTResult]:
        exe = _venv_bin("holehe")
        if not exe:
            self.logger.info("Holehe is not installed; skipping")
            return []
        proc = subprocess.run([exe, email, "--only-used", "--no-color", "--no-clear"],
                              capture_output=True, text=True, timeout=90)
        results = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("[+]") and "Email used" not in line:
                site = line[3:].strip()
                if site:
                    results.append(OSINTResult(
                        source="Holehe",
                        data_type="account_existence",
                        data={"platform": site, "email": email, "exists": True},
                        confidence=0.85,
                    ))
        return results

    def _check_emailrep(self, email: str) -> List[OSINTResult]:
        headers = {**UA}
        from app.core.config import settings
        if settings.EMAILREP_API_KEY:
            headers["Key"] = settings.EMAILREP_API_KEY
        r = httpx.get(f"https://emailrep.io/{email}", headers=headers, timeout=10)
        if r.status_code == 429:
            self.logger.info("EmailRep rate limited (set EMAILREP_API_KEY for more)")
            return []
        if r.status_code != 200:
            return []
        return [OSINTResult(source="EmailRep", source_url=f"https://emailrep.io/{email}",
                            data_type="reputation", data=r.json(), confidence=0.85)]

    def _check_hibp(self, email: str) -> List[OSINTResult]:
        from app.core.config import settings
        key = settings.HIBP_API_KEY
        if not key:
            return []  # account search requires a paid key; XposedOrNot covers breaches
        r = httpx.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            params={"truncateResponse": "false"},
            headers={**UA, "hibp-api-key": key},
            timeout=15,
        )
        if r.status_code != 200:
            return []
        return [OSINTResult(
            source="Have I Been Pwned",
            source_url=f"https://haveibeenpwned.com/account/{email}",
            data_type="breach",
            data={
                "email": email, "name": b.get("Name"), "domain": b.get("Domain"),
                "breach_date": b.get("BreachDate"), "records": b.get("PwnCount"),
                "data_classes": b.get("DataClasses", []), "description": b.get("Description"),
                "risk": "high" if "Passwords" in b.get("DataClasses", []) else "medium",
            },
            confidence=0.95,
        ) for b in r.json()]


def _mail_provider(mx: list) -> Optional[str]:
    hosts = " ".join(m["exchange"].lower() for m in mx)
    for needle, name in (
        ("google.com", "Google Workspace / Gmail"), ("outlook.com", "Microsoft 365 / Outlook"),
        ("protonmail", "Proton Mail"), ("zoho", "Zoho Mail"), ("yahoodns", "Yahoo Mail"),
        ("icloud.com", "iCloud Mail"), ("mimecast", "Mimecast"), ("pphosted", "Proofpoint"),
        ("fastmail", "Fastmail"), ("ovh.net", "OVH"), ("gandi.net", "Gandi"),
    ):
        if needle in hosts:
            return name
    return None


email_intel = EmailIntelModule()
