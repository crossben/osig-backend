"""
Threat-intel reputation feeds (core module; domain and IP targets).

- AlienVault (LevelBlue) OTX: pulses (community threat reports) that mention the
  domain / IP, with malware families, tags and allow-list validation. Needs
  OTX_API_KEY (skipped without it). The OTX EULA grants a limited, terminable
  licence; its commercial-use terms were not confirmed - review before using
  OTX on a paid deployment.
- GreyNoise: for domain targets, the domain's IPv4 addresses (IP targets get it
  from ip_intel, which shares `greynoise()`). The keyless Community API is what
  GreyNoise offers for non-commercial use; set GREYNOISE_API_KEY (paid plan) on
  commercial deployments and it is sent as the `key` header.
"""
import ipaddress
from typing import List, Optional

import httpx

from app.osint.base import BaseOSINTModule, OSINTResult

UA = {"User-Agent": "OSIG/1.0 (open source intelligence research)"}
OTX = "https://otx.alienvault.com/api/v1/indicators"
MAX_DOMAIN_IPS = 3


def greynoise(ip: str) -> Optional[OSINTResult]:
    from app.core.config import settings
    if not settings.GREYNOISE_API_KEY:
        return None  # keyless community access is for non-commercial use; OSIG is a paid service
    headers = {**UA, "key": settings.GREYNOISE_API_KEY}
    r = httpx.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers, timeout=12)
    if r.status_code not in (200, 404):
        return None
    d = r.json()
    return OSINTResult(
        source="GreyNoise",
        source_url=f"https://viz.greynoise.io/ip/{ip}",
        data_type="ip_reputation",
        data={
            "ip": ip,
            "scanning_internet": bool(d.get("noise")),
            "known_benign_service": bool(d.get("riot")),
            "classification": d.get("classification"),
            "name": d.get("name"),
            "last_seen": d.get("last_seen"),
        },
        confidence=0.9,
    )


def otx(kind: str, value: str, api_key: str) -> Optional[OSINTResult]:
    """kind: 'domain' | 'ip'"""
    if not api_key:
        return None
    if kind == "ip":
        section = "IPv6" if ":" in value else "IPv4"
    else:
        section = "domain"
    try:
        r = httpx.get(f"{OTX}/{section}/{value}/general", timeout=15,
                      headers={**UA, "X-OTX-API-KEY": api_key})
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    d = r.json() or {}
    pulses = (d.get("pulse_info") or {}).get("pulses") or []
    count = (d.get("pulse_info") or {}).get("count") or len(pulses)
    malware, tags = [], []
    for p in pulses:
        for m in p.get("malware_families") or []:
            name = m.get("display_name") if isinstance(m, dict) else m
            if name and name not in malware:
                malware.append(name)
        for t in p.get("tags") or []:
            if t and t not in tags:
                tags.append(t)
    allow = [v.get("name") or v.get("source") for v in d.get("validation") or [] if isinstance(v, dict)]
    return OSINTResult(
        source="AlienVault OTX",
        source_url=f"https://otx.alienvault.com/indicator/{'ip' if kind == 'ip' else 'domain'}/{value}",
        data_type="threat_intel",
        data={"indicator": value, "kind": kind, "pulse_count": count,
              "malware_families": malware[:10], "tags": tags[:15],
              "pulses": [p.get("name") for p in pulses[:5] if p.get("name")],
              "allowlisted": [a for a in allow if a][:5]},
        confidence=0.8,
    )


def _domain_ipv4s(domain: str) -> List[str]:
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    try:
        answers = resolver.resolve(domain, "A")
    except Exception:
        return []
    ips = [a.to_text() for a in answers]
    return [ip for ip in ips if ipaddress.ip_address(ip).is_global][:MAX_DOMAIN_IPS]


class ReputationFeedsModule(BaseOSINTModule):
    def __init__(self, target_type: str = "domain"):
        super().__init__(name="reputation_feeds", display_name="Threat Intel Feeds")
        self.target_type = target_type

    def run(self, target: str) -> List[OSINTResult]:
        from app.core.config import settings
        self.log_start(target)
        value = target.strip().lower()
        checks = [lambda: otx(self.target_type, value, settings.OTX_API_KEY)]
        if self.target_type == "domain":
            checks += [lambda ip=ip: greynoise(ip) for ip in _domain_ipv4s(value)]
        results: List[OSINTResult] = []
        for check in checks:
            try:
                out = check()
            except Exception as e:
                self.logger.info(f"Reputation feed failed: {e}")
                continue
            if out:
                results.append(out)
        self.log_success(len(results))
        return results
