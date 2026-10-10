"""
Shared exposure lookups used by several modules.

- Hudson Rock Cavalier (free): has this email/username/domain shown up in
  infostealer malware logs? Only exposure facts are kept: Hudson Rock also
  returns masked password and login fragments, which are deliberately dropped.
- PGP keyservers: keys.openpgp.org only lists addresses verified by email;
  keyserver.ubuntu.com accepts anyone's uploads, so its keys are marked
  unverified (they can be impersonations).
"""
from typing import List, Optional
from urllib.parse import quote

import httpx

from app.osint.base import OSINTResult

UA = {"User-Agent": "OSIG/1.0 (open source intelligence research)"}
CAVALIER = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"


def _not_found(value: Optional[str]) -> bool:
    return not value or str(value).strip().lower() in ("not found", "n/a", "")


def hudson_rock(kind: str, value: str) -> List[OSINTResult]:
    """kind: 'email' | 'username' | 'domain'"""
    if kind == "domain":
        try:
            r = httpx.get(f"{CAVALIER}/urls-by-domain", params={"domain": value}, headers=UA, timeout=20)
        except httpx.HTTPError:
            return []
        if r.status_code != 200:
            return []
        data = r.json().get("data") or {}
        employees = [u for u in data.get("employees_urls", []) if u.get("url")]
        clients = [u for u in data.get("clients_urls", []) if u.get("url")]
        if not employees and not clients:
            return []
        return [OSINTResult(
            source="Hudson Rock",
            source_url="https://www.hudsonrock.com/free-tools",
            data_type="infostealer_domain",
            data={
                "domain": value,
                "employee_login_urls": [u["url"] for u in employees[:15]],
                "employee_infections": sum(int(u.get("occurrence") or 0) for u in employees),
                "user_login_urls": [u["url"] for u in clients[:15]],
                "user_infections": sum(int(u.get("occurrence") or 0) for u in clients),
            },
            confidence=0.8,
        )]

    endpoint = "search-by-email" if kind == "email" else "search-by-username"
    try:
        r = httpx.get(f"{CAVALIER}/{endpoint}", params={kind: value}, headers=UA, timeout=20)
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    stealers = r.json().get("stealers") or []
    if not stealers:
        return []
    infections = []
    for s in stealers[:10]:
        infections.append({
            "date_compromised": (s.get("date_compromised") or "")[:10] or None,
            "operating_system": None if _not_found(s.get("operating_system")) else s.get("operating_system"),
            "user_services": s.get("total_user_services"),
            "corporate_services": s.get("total_corporate_services"),
            # top_passwords / top_logins / ip are intentionally not stored
        })
    return [OSINTResult(
        source="Hudson Rock",
        source_url="https://www.hudsonrock.com/free-tools",
        data_type="infostealer",
        data={kind: value, "infections": infections, "infection_count": len(stealers),
              "latest": max((i["date_compromised"] or "" for i in infections), default=None) or None},
        confidence=0.85,
    )]


def pgp_keys(email: str) -> List[OSINTResult]:
    results: List[OSINTResult] = []
    # Verified: keys.openpgp.org only serves addresses confirmed by email
    try:
        r = httpx.get(f"https://keys.openpgp.org/vks/v1/by-email/{quote(email)}", headers=UA, timeout=15)
        if r.status_code == 200 and "BEGIN PGP PUBLIC KEY" in r.text:
            results.append(OSINTResult(
                source="keys.openpgp.org",
                source_url=f"https://keys.openpgp.org/search?q={quote(email)}",
                data_type="pgp_key",
                data={"email": email, "verified": True, "keyserver": "keys.openpgp.org"},
                confidence=0.95,
            ))
    except httpx.HTTPError:
        pass
    # Unverified: SKS-style keyserver, machine-readable index
    try:
        r = httpx.get("https://keyserver.ubuntu.com/pks/lookup",
                      params={"op": "index", "options": "mr", "search": email}, headers=UA, timeout=30)
    except httpx.HTTPError:
        return results
    if r.status_code != 200:
        return results
    key = None
    for line in r.text.splitlines():
        parts = line.split(":")
        if parts[0] == "pub":
            key = {"fingerprint": parts[1], "algorithm": parts[2], "bits": parts[3], "created": parts[4], "uids": []}
            results.append(OSINTResult(
                source="Ubuntu keyserver",
                source_url=f"https://keyserver.ubuntu.com/pks/lookup?search={quote(email)}&op=index",
                data_type="pgp_key",
                data={"email": email, "verified": False, "keyserver": "keyserver.ubuntu.com", "key": key},
                confidence=0.6,
            ))
        elif parts[0] == "uid" and key is not None:
            from urllib.parse import unquote
            key["uids"].append(unquote(parts[1]))
    for res in results:
        k = res.data.get("key")
        if k and k.get("created"):
            from datetime import datetime, timezone
            try:
                k["created"] = datetime.fromtimestamp(int(k["created"]), tz=timezone.utc).date().isoformat()
            except ValueError:
                pass
    return results
