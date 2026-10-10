"""
IP Intelligence Module (target type: ip)

Quick:
- Reverse DNS (PTR) and forward-confirmation
- Network owner / ASN / location (RDAP + ip-api, shared with domain scans)
- Shodan InternetDB: open ports, software, known CVEs (passive)
- GreyNoise community: is this IP mass-scanning the internet, and is it a
  known benign service (RIOT)?
Deep adds:
- Other domains hosted on it (HackerTarget reverse IP)
- AbuseIPDB abuse reports (when ABUSEIPDB_API_KEY is set)
"""
import socket
from typing import List, Optional

import httpx

from app.osint.base import BaseOSINTModule, OSINTResult

UA = {"User-Agent": "OSIG/1.0 (open source intelligence research)"}


class IPIntelModule(BaseOSINTModule):
    def __init__(self):
        super().__init__(name="ip_intel", display_name="IP Intelligence")

    def run(self, target: str, deep: bool = False) -> List[OSINTResult]:
        self.log_start(target)
        ip = target.strip()
        from app.osint.domain_intel import DomainIntelModule
        domain_mod = DomainIntelModule()

        results: List[OSINTResult] = []
        checks = [
            lambda: self._reverse_dns(ip),
            lambda: domain_mod._lookup_ip_info(ip, None),
            lambda: domain_mod._internetdb([ip]),
            lambda: self._greynoise(ip),
        ]
        if deep:
            checks += [lambda: self._hosted_domains(ip), lambda: self._abuseipdb(ip)]
        for check in checks:
            try:
                out = check()
            except Exception as e:  # one failing source must not sink the module
                self.logger.warning(f"IP check failed: {e}")
                continue
            if isinstance(out, list):
                results.extend(out)
            elif out:
                results.append(out)
        self.log_success(len(results))
        return results

    def _reverse_dns(self, ip: str) -> Optional[OSINTResult]:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None
        # Forward-confirmed reverse DNS: the name resolves back to this IP
        try:
            confirmed = ip in {a[4][0] for a in socket.getaddrinfo(hostname, None)}
        except socket.gaierror:
            confirmed = False
        return OSINTResult(
            source="Reverse DNS",
            data_type="ip_info",
            data={"ip_address": ip, "reverse_hostname": hostname, "forward_confirmed": confirmed},
            confidence=0.95 if confirmed else 0.7,
        )

    def _greynoise(self, ip: str) -> Optional[OSINTResult]:
        r = httpx.get(f"https://api.greynoise.io/v3/community/{ip}", headers=UA, timeout=12)
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

    def _hosted_domains(self, ip: str) -> Optional[OSINTResult]:
        if ":" in ip:
            return None
        r = httpx.get("https://api.hackertarget.com/reverseiplookup/", params={"q": ip}, timeout=15)
        text = r.text.strip()
        if r.status_code != 200 or not text or "error" in text.lower() or "API count" in text:
            return None
        hosts = [h.strip().lower() for h in text.splitlines() if h.strip()]
        if not hosts:
            return None
        return OSINTResult(
            source="Reverse IP Lookup",
            source_url="https://hackertarget.com/reverse-ip-lookup/",
            data_type="ip_info",
            data={"ip_address": ip, "domains": hosts[:50], "count": len(hosts),
                  "shared_hosting": len(hosts) > 100},
            confidence=0.8,
        )

    def _abuseipdb(self, ip: str) -> Optional[OSINTResult]:
        from app.core.config import settings
        if not settings.ABUSEIPDB_API_KEY:
            return None
        r = httpx.get("https://api.abuseipdb.com/api/v2/check", timeout=12,
                      params={"ipAddress": ip, "maxAgeInDays": 90},
                      headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"})
        if r.status_code != 200:
            return None
        d = r.json().get("data") or {}
        return OSINTResult(
            source="AbuseIPDB",
            source_url=f"https://www.abuseipdb.com/check/{ip}",
            data_type="ip_reputation",
            data={"ip": ip, "abuse_score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
                  "usage_type": d.get("usageType"), "isp": d.get("isp"), "is_tor": d.get("isTor")},
            confidence=0.9,
        )
