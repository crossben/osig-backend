"""
Domain Intelligence Module

This module gathers intelligence on domain names using free OSINT tools:
- python-whois: Domain registration information (owner, registrar, dates)
- dnspython: DNS records (A, MX, TXT, NS, etc.)
- Manual subdomain enumeration
- theHarvester: Email and subdomain discovery (placeholder)

All findings are returned in a standardized format for storage and display.
"""

import concurrent.futures
import os
import re
from typing import List, Dict, Any, Optional, Set
import httpx
import dns.resolver
import dns.exception
import whois
from datetime import datetime
import socket
from app.osint.base import BaseOSINTModule, OSINTResult
from app.osint.safe_http import UnsafeTargetError, safe_get, safe_tls_connect


class DomainIntelModule(BaseOSINTModule):
    """
    Domain Intelligence gathering module.
    
    This module investigates domains to find:
    - WHOIS registration information (owner, registrar, creation date)
    - DNS records (A, MX, TXT, NS, CNAME, etc.)
    - Subdomains (common patterns)
    - Associated email addresses
    - Name servers and mail servers
    """
    
    # Common subdomains to check
    # These are the most frequently used subdomain names
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "mx", "autodiscover",
        "webdisk", "admin", "portal", "api", "dev", "staging", "stage", "test", "qa", "uat", "beta",
        "blog", "shop", "store", "mobile", "m", "vpn", "remote", "cdn", "static", "assets", "img",
        "ssh", "git", "gitlab", "jenkins", "ci", "docs", "wiki", "help", "support", "status",
        "app", "dashboard", "login", "auth", "sso", "id", "accounts", "cloud", "files", "media",
        "news", "forum", "community", "events", "careers", "jobs", "intranet", "crm", "erp",
    ]
    WORKERS = 24
    # Reverse-IP on CDN/shared-cloud IPs returns thousands of unrelated sites
    SHARED_HOSTING_ASNS = {"13335", "54113", "16509", "14618", "15169", "8075", "20940", "16625", "396982"}
    
    def __init__(self):
        """Initialize the Domain Intel module."""
        super().__init__(
            name="domain_intel",
            display_name="Domain Intelligence"
        )
    
    def run(self, target: str, deep: bool = False) -> List[OSINTResult]:
        """
        Execute domain intelligence gathering.
        
        Args:
            target: Domain name to investigate (e.g., "example.com")
            deep: If True, run extended checks (crt.sh, reverse IP)
            
        Returns:
            List of findings about the domain
        """
        self.log_start(target)
        results = []
        
        if not self.validate_target(target, "domain"):
            self.logger.warning(f"Invalid domain format: {target}")
            return results
        
        try:
            domain_parts = self._extract_domain_parts(target)
            if domain_parts:
                results.append(domain_parts)

            whois_results = self._lookup_whois(target)
            if whois_results:
                results.append(whois_results)
            
            dns_results = self._lookup_dns_records(target)
            results.extend(dns_results)
            
            subdomain_results = self._check_subdomains(target)
            results.extend(subdomain_results)
            
            harvester_results = self._check_harvester(target)
            results.extend(harvester_results)

            https_res = self._probe_https(target)
            if https_res:
                results.append(https_res)

            # IP intelligence for every address the domain resolves to (in parallel)
            ips_to_check = sorted({
                ip for r in dns_results
                if r.data.get("record_type") in ("A", "AAAA")
                for ip in r.data.get("records", [])
            })
            with concurrent.futures.ThreadPoolExecutor(8) as pool:
                ip_results = [r for r in pool.map(lambda ip: self._lookup_ip_info(ip, target), ips_to_check) if r]
            results.extend(ip_results)

            for extra in (self._hygiene(target), self._mail_security(target)):
                if extra:
                    results.append(extra)
            from app.osint.exposure import hudson_rock
            try:
                results.extend(hudson_rock("domain", target))
            except Exception as e:
                self.logger.info(f"Hudson Rock failed: {e}")

            # Passive exposure for the domain's and its subdomains' servers (no key, no probing)
            sub_ips = {ip for r in subdomain_results for ip in r.data.get("ip_addresses", [])}
            results.extend(self._internetdb(sorted(set(ips_to_check) | sub_ips)))

            if deep:
                results.extend(self._urlscan(target))
                vt = self._virustotal(target)
                if vt:
                    results.append(vt)

                # Deep: scrape homepage for basic meta info and emails
                scrape_res = self._scrape_homepage(target)
                if scrape_res:
                    results.append(scrape_res)

                # Deep: every hostname ever issued a certificate (crt.sh / Cert Spotter), resolved
                known = {r.data.get("full_domain") for r in subdomain_results}
                results.extend(self._check_cert_transparency(target, known))

                # Deep: other sites hosted on the same (non-CDN) servers
                results.extend(self._reverse_ip_lookup(target, ip_results))

                # Deep: sublist3r for expanded subdomain enumeration
                subl_results = self._check_sublist3r(target)
                results.extend(subl_results)

                results.extend(self._lookalikes(target))

                wayback = self._check_wayback(target)
                if wayback:
                    results.append(wayback)

                # Active probing of the target's hosts: opt-in only
                from app.core.config import settings
                if settings.ENABLE_PORT_SCAN:
                    for ip in [i for i in ips_to_check if ":" not in i][:4]:
                        port_scan_res = self._scan_ports(ip, target)
                        if port_scan_res:
                            results.append(port_scan_res)

            self.log_success(len(results))
            
        except Exception as e:
            self.log_error(e)
            raise
        
        return results
    
    def _lookup_whois(self, domain: str) -> Optional[OSINTResult]:
        """
        Perform WHOIS lookup to get domain registration information.
        
        WHOIS provides:
        - Domain owner (registrant) information
        - Registrar (company that sold the domain)
        - Registration and expiration dates
        - Name servers
        - Status (active, locked, etc.)
        
        Args:
            domain: Domain name to lookup
            
        Returns:
            OSINTResult with WHOIS data, or None if lookup fails
        """
        try:
            # Perform WHOIS lookup
            whois_data = whois.whois(domain)
            
            # Extract and clean data
            # WHOIS data can be messy, so we need to normalize it
            data = {
                "domain": domain,
                "registrar": self._clean_whois_field(whois_data.registrar),
                "creation_date": self._format_whois_date(whois_data.creation_date),
                "expiration_date": self._format_whois_date(whois_data.expiration_date),
                "updated_date": self._format_whois_date(whois_data.updated_date),
                "name_servers": self._clean_whois_field(whois_data.name_servers),
                "status": self._clean_whois_field(whois_data.status),
                "emails": self._clean_whois_field(whois_data.emails),
                "org": self._clean_whois_field(whois_data.org),
                "country": self._clean_whois_field(whois_data.country),
            }
            
            # Create result
            result = OSINTResult(
                source="WHOIS",
                source_url=None,
                data_type="domain_registration",
                data=data,
                confidence=0.95  # WHOIS is authoritative source
            )
            
            self.logger.info(f"WHOIS lookup successful for {domain}")
            return result
            
        except Exception as e:
            # WHOIS lookups can fail for various reasons:
            # - Domain doesn't exist
            # - WHOIS server is down
            # - Rate limiting
            self.logger.warning(f"WHOIS lookup failed for {domain}: {str(e)}")
            return None
    
    def _lookup_dns_records(self, domain: str) -> List[OSINTResult]:
        """
        Query DNS records for the domain asynchronously using aiodns.
        """
        results = []
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        async def fetch_dns(resolver, rtype):
            try:
                answers = await resolver.query(domain, rtype)
                records = []
                for ans in answers:
                    if rtype == 'MX':
                        records.append({"priority": ans.priority, "exchange": ans.host})
                    elif rtype == 'SOA':
                        records.append(f"{ans.nsname} {ans.hostmaster}")
                    elif rtype in ['A', 'AAAA', 'NS', 'CNAME']:
                        records.append(ans.host)
                    elif rtype == 'TXT':
                        records.append(ans.text)
                    else:
                        records.append(str(ans))
                return rtype, records
            except Exception:
                return rtype, []
        
        async def run_queries():
            import aiodns
            import asyncio
            resolver = aiodns.DNSResolver(timeout=2.0)
            tasks = [fetch_dns(resolver, t) for t in record_types]
            return await asyncio.gather(*tasks)
            
        try:
            import asyncio
            # Run async queries in the sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            queries_results = loop.run_until_complete(run_queries())
            loop.close()
            
            for rtype, records in queries_results:
                if records:
                    results.append(OSINTResult(
                        source="DNS (aiodns)",
                        source_url=None,
                        data_type="dns_record",
                        data={
                            "domain": domain,
                            "record_type": rtype,
                            "records": records,
                            "count": len(records)
                        },
                        confidence=0.99
                    ))
                    self.logger.info(f"Found {len(records)} {rtype} records for {domain}")
                    
        except ImportError:
            self.logger.warning("aiodns not installed, skipping fast DNS lookup.")
        except Exception as e:
            self.logger.error(f"DNS queries failed: {e}")
            
        return results
    
    def _check_subdomains(self, domain: str) -> List[OSINTResult]:
        """
        Check for common subdomains via DNS resolution with a timeout.
        Uses dns.resolver to avoid blocking indefinitely.
        """
        results = []
        try:
            import dns.resolver
        except ImportError:
            self.logger.warning("dnspython not available, skipping subdomain check")
            return results

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3

        # Wildcard DNS answers every name; detect it so we don't report noise
        wildcard_ips = set(self._resolve(resolver, f"osig-{os.urandom(4).hex()}.{domain}"))

        def probe(name):
            full_domain = f"{name}.{domain}"
            ips = self._resolve(resolver, full_domain)
            if not ips or (wildcard_ips and set(ips) <= wildcard_ips):
                return None
            return OSINTResult(
                source="Subdomain Enumeration",
                source_url=f"https://{full_domain}",
                data_type="subdomain",
                data={"subdomain": name, "full_domain": full_domain, "ip_addresses": ips, "exists": True},
                confidence=0.85,
            )

        with concurrent.futures.ThreadPoolExecutor(self.WORKERS) as pool:
            results = [r for r in pool.map(probe, self.COMMON_SUBDOMAINS) if r]
        return results
    
    def _check_harvester(self, domain: str) -> List[OSINTResult]:
        """
        Extract emails and additional subdomains from existing data.
        
        Instead of using theHarvester (which requires installation),
        we leverage the WHOIS and DNS data we already collected to find:
        - Email addresses from WHOIS records
        - Additional subdomains from DNS TXT records (SPF, DKIM)
        - Name server domains
        
        This is more reliable and doesn't require external dependencies.
        
        Args:
            domain: Domain to search for
            
        Returns:
            List of OSINTResult objects with discovered emails/subdomains
        """
        results = []
        
        try:
            # Method 1: Extract emails from TXT records
            # TXT records often contain SPF records with email servers
            try:
                txt_answers = dns.resolver.resolve(domain, 'TXT')
                
                for rdata in txt_answers:
                    txt_content = str(rdata)
                    
                    # Look for email patterns in TXT records
                    # SPF records often have "include:domain.com" which reveals email infrastructure
                    if 'spf' in txt_content.lower() or 'include:' in txt_content:
                        result = OSINTResult(
                            source="DNS TXT Analysis",
                            source_url=None,
                            data_type="email_infrastructure",
                            data={
                                "domain": domain,
                                "record": txt_content,
                                "type": "SPF/Email Infrastructure"
                            },
                            confidence=0.90
                        )
                        results.append(result)
                        
            except dns.exception.DNSException:
                pass  # No TXT records or DNS error
            
            # Method 2: Check for DMARC records
            # DMARC records contain email addresses for reporting
            try:
                dmarc_domain = f"_dmarc.{domain}"
                dmarc_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                
                for rdata in dmarc_answers:
                    dmarc_content = str(rdata)
                    
                    # Record every DMARC policy (risk scoring needs p=none vs reject),
                    # report addresses are extracted from it downstream
                    if 'v=dmarc1' in dmarc_content.lower():
                        result = OSINTResult(
                            source="DMARC Analysis",
                            source_url=None,
                            data_type="email_address",
                            data={
                                "domain": domain,
                                "record": dmarc_content,
                                "type": "DMARC Policy",
                                "policy": (re.search(r"\bp=(\w+)", dmarc_content, re.I) or [None, None])[1]
                            },
                            confidence=0.95
                        )
                        results.append(result)
                        
            except dns.exception.DNSException:
                pass  # No DMARC record
            
            # Method 3: Check common email-related subdomains
            # These often exist and reveal infrastructure
            email_subdomains = ['mail', 'smtp', 'webmail', 'email', 'imap', 'pop', 'pop3']
            
            for subdomain in email_subdomains:
                try:
                    full_domain = f"{subdomain}.{domain}"
                    # Try to get MX records for this subdomain
                    mx_answers = dns.resolver.resolve(full_domain, 'MX')
                    
                    if mx_answers:
                        result = OSINTResult(
                            source="Email Subdomain Discovery",
                            source_url=f"http://{full_domain}",
                            data_type="email_subdomain",
                            data={
                                "subdomain": subdomain,
                                "full_domain": full_domain,
                                "has_mx": True,
                                "type": "Email Infrastructure"
                            },
                            confidence=0.85
                        )
                        results.append(result)
                        
                except dns.exception.DNSException:
                    continue
            
            # Note: For comprehensive email harvesting, you could install theHarvester:
            # pip install theharvester
            # Then run: theHarvester -d domain.com -b all
            # This searches public sources like search engines, PGP servers, etc.
            
        except Exception as e:
            self.logger.error(f"Email/subdomain discovery failed: {str(e)}")
        
        return results

    @staticmethod
    def _resolve(resolver, name: str) -> List[str]:
        import dns.resolver
        ips: List[str] = []
        for rtype in ("A", "AAAA"):
            try:
                ips += [str(r) for r in resolver.resolve(name, rtype)]
            except Exception:
                continue
        return ips

    def _ct_names(self, domain: str) -> Set[str]:
        """Hostnames from certificate transparency: crt.sh, falling back to Cert Spotter."""
        names: Set[str] = set()
        try:
            r = httpx.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30,
                          headers={"User-Agent": "OSIG/1.0"})
            if r.status_code == 200:
                for cert in r.json():
                    names.update(cert.get("name_value", "").split("\n"))
        except Exception as e:
            self.logger.info(f"crt.sh unavailable ({e}); trying Cert Spotter")
        if not names:
            try:
                r = httpx.get("https://api.certspotter.com/v1/issuances", timeout=20, params={
                    "domain": domain, "include_subdomains": "true", "expand": "dns_names"})
                if r.status_code == 200:
                    for cert in r.json():
                        names.update(cert.get("dns_names", []))
            except Exception as e:
                self.logger.info(f"Cert Spotter unavailable: {e}")
        cleaned = set()
        for n in names:
            n = n.strip().lower().lstrip("*.").rstrip(".")
            if n and n != domain and n.endswith("." + domain):
                cleaned.add(n)
        return cleaned

    def _check_cert_transparency(self, domain: str, already_found: Set[str]) -> List[OSINTResult]:
        import dns.resolver
        names = sorted(self._ct_names(domain) - {n for n in already_found if n})[:200]
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3

        def resolve(name):
            return name, self._resolve(resolver, name)

        results = []
        with concurrent.futures.ThreadPoolExecutor(self.WORKERS) as pool:
            for name, ips in pool.map(resolve, names):
                results.append(OSINTResult(
                    source="Certificate Transparency",
                    source_url=f"https://crt.sh/?q={name}",
                    data_type="subdomain",
                    data={
                        "subdomain": name[: -(len(domain) + 1)],
                        "full_domain": name,
                        "ip_addresses": ips,
                        "exists": True,
                        "live": bool(ips),
                    },
                    # Still resolving = current; otherwise only historically certified
                    confidence=0.9 if ips else 0.6,
                ))
        return results

    def _reverse_ip_lookup(self, domain: str, ip_results: List[OSINTResult]) -> List[OSINTResult]:
        """Other domains on the same server (HackerTarget, free tier ~50/day)."""
        results = []
        for r in ip_results:
            ip = r.data.get("ip")
            if not ip or ":" in ip or str(r.data.get("asn")) in self.SHARED_HOSTING_ASNS:
                continue
            try:
                resp = httpx.get("https://api.hackertarget.com/reverseiplookup/", params={"q": ip}, timeout=15)
            except Exception as e:
                self.logger.info(f"Reverse IP lookup failed for {ip}: {e}")
                continue
            text = resp.text.strip()
            if resp.status_code != 200 or not text or "error" in text.lower() or "API count" in text:
                continue
            hosts = [h.strip().lower() for h in text.splitlines() if h.strip() and h.strip().lower() != domain]
            if not hosts or len(hosts) > 100:  # >100 = shared hosting; not meaningful
                continue
            results.append(OSINTResult(
                source="Reverse IP Lookup",
                source_url=f"https://hackertarget.com/reverse-ip-lookup/",
                data_type="ip_info",
                data={"domain": domain, "ip_address": ip, "domains": hosts[:50], "count": len(hosts)},
                confidence=0.8,
            ))
        return results

    def _internetdb(self, ips: List[str]) -> List[OSINTResult]:
        """Shodan InternetDB: ports, software and known CVEs per IP, from Shodan's passive scans."""
        ipv4 = [ip for ip in ips if ":" not in ip][:25]

        def one(ip):
            try:
                r = httpx.get(f"https://internetdb.shodan.io/{ip}", timeout=8)
            except Exception:
                return None
            if r.status_code != 200:
                return None
            d = r.json()
            if not d.get("ports"):
                return None
            return OSINTResult(
                source="Shodan InternetDB",
                source_url=f"https://www.shodan.io/host/{ip}",
                data_type="host_exposure",
                data={"ip": ip, "ports": d.get("ports", []), "hostnames": d.get("hostnames", []),
                      "software": [c.replace("cpe:/", "").replace(":", " ", 2) for c in d.get("cpes", [])],
                      "vulns": d.get("vulns", []), "tags": d.get("tags", [])},
                confidence=0.85,
            )

        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            return [r for r in pool.map(one, ipv4) if r]

    def _urlscan(self, domain: str) -> List[OSINTResult]:
        """Recent public URLScan.io scans of the site (what it loaded, where it was hosted)."""
        from app.core.config import settings
        headers = {"API-Key": settings.URLSCAN_API_KEY} if settings.URLSCAN_API_KEY else {}
        try:
            r = httpx.get("https://urlscan.io/api/v1/search/", timeout=15, headers=headers,
                          # Wildcards (subdomains too) need an API key on URLScan
                          params={"q": f"page.domain:{domain} OR page.domain:*.{domain}" if headers
                                  else f"page.domain:{domain}", "size": 10})
        except Exception as e:
            self.logger.info(f"URLScan unavailable: {e}")
            return []
        if r.status_code != 200:
            return []
        out = []
        for hit in r.json().get("results", []):
            page = hit.get("page") or {}
            out.append(OSINTResult(
                source="URLScan",
                source_url=hit.get("result", "").replace("/api/v1/result/", "/result/") or None,
                data_type="web_scan",
                data={"url": page.get("url"), "domain": page.get("domain"), "ip": page.get("ip"),
                      "server": page.get("server"), "country": page.get("country"),
                      "scanned_at": (hit.get("task") or {}).get("time"), "screenshot": hit.get("screenshot")},
                confidence=0.85,
            ))
        return out

    def _virustotal(self, domain: str) -> Optional[OSINTResult]:
        """VirusTotal reputation (only when VIRUSTOTAL_API_KEY is set)."""
        from app.core.config import settings
        if not settings.VIRUSTOTAL_API_KEY:
            return None
        try:
            r = httpx.get(f"https://www.virustotal.com/api/v3/domains/{domain}", timeout=15,
                          headers={"x-apikey": settings.VIRUSTOTAL_API_KEY})
        except Exception as e:
            self.logger.info(f"VirusTotal unavailable: {e}")
            return None
        if r.status_code != 200:
            return None
        attrs = (r.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        return OSINTResult(
            source="VirusTotal",
            source_url=f"https://www.virustotal.com/gui/domain/{domain}",
            data_type="reputation",
            data={"domain": domain, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                  "harmless": stats.get("harmless", 0), "reputation": attrs.get("reputation"),
                  "categories": sorted(set((attrs.get("categories") or {}).values()))},
            confidence=0.9,
        )

    def _hygiene(self, domain: str) -> Optional[OSINTResult]:
        """security.txt, robots.txt, sitemap and favicon fingerprint (all via the SSRF guard)."""
        ua = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) OSIG/1.0"}
        data: Dict[str, Any] = {"domain": domain}

        def fetch(path):
            try:
                r = safe_get(f"https://{domain}{path}", headers=ua, timeout=8)
                return r if r.status_code == 200 else None
            except Exception:
                return None

        sec = fetch("/.well-known/security.txt") or fetch("/security.txt")
        if sec and "contact:" in sec.text.lower():
            fields: Dict[str, List[str]] = {}
            for line in sec.text.splitlines():
                if ":" in line and not line.startswith("#"):
                    k, v = line.split(":", 1)
                    fields.setdefault(k.strip().lower(), []).append(v.strip())
            data["security_txt"] = {k: v for k, v in fields.items()
                                    if k in ("contact", "expires", "policy", "acknowledgments", "hiring", "preferred-languages")}
        robots = fetch("/robots.txt")
        if robots and "user-agent" in robots.text.lower():
            disallowed = sorted({l.split(":", 1)[1].strip() for l in robots.text.splitlines()
                                 if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip() not in ("", "/")})
            data["robots_disallowed"] = disallowed[:40]
            data["sitemaps"] = [l.split(":", 1)[1].strip() for l in robots.text.splitlines()
                                if l.lower().startswith("sitemap:")][:10]
        fav = fetch("/favicon.ico")
        if fav and fav.content and len(fav.content) < 500_000 and not fav.headers.get("content-type", "").startswith("text/"):
            import base64
            import mmh3
            h = mmh3.hash(base64.encodebytes(fav.content))
            data["favicon_hash"] = h
            # Same favicon on other servers often means the same app or owner
            data["favicon_shodan_query"] = f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}"
        if len(data) == 1:
            return None
        return OSINTResult(source="Site Hygiene", source_url=f"https://{domain}", data_type="web_hygiene",
                           data=data, confidence=0.9)

    def _mail_security(self, domain: str) -> Optional[OSINTResult]:
        """MTA-STS, BIMI and common DKIM selectors."""
        import dns.resolver

        def txt(name):
            try:
                return [b"".join(r.strings).decode(errors="replace") for r in dns.resolver.resolve(name, "TXT", lifetime=4)]
            except Exception:
                return []

        data: Dict[str, Any] = {"domain": domain}
        sts = [t for t in txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
        data["mta_sts"] = bool(sts)
        if sts:
            try:
                pol = safe_get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout=8)
                m = re.search(r"mode:\s*(\w+)", pol.text) if pol.status_code == 200 else None
                data["mta_sts_mode"] = m.group(1) if m else None
            except Exception:
                data["mta_sts_mode"] = None
        bimi = [t for t in txt(f"default._bimi.{domain}") if t.lower().startswith("v=bimi1")]
        data["bimi"] = bool(bimi)
        selectors = ["google", "selector1", "selector2", "default", "k1", "k2", "s1", "s2", "mail", "dkim",
                     "smtp", "mandrill", "mxvault", "pm", "zoho", "fm1", "everlytickey1", "mailjet", "sendgrid"]
        with concurrent.futures.ThreadPoolExecutor(10) as pool:
            hits = [sel for sel, recs in zip(selectors, pool.map(lambda s: txt(f"{s}._domainkey.{domain}"), selectors))
                    if any("p=" in r for r in recs)]
        # A domain answering any selector (wildcard) would make every guess a "hit"
        if hits and any("p=" in r for r in txt(f"osig{os.urandom(3).hex()}._domainkey.{domain}")):
            hits = []
            data["dkim_wildcard"] = True
        data["dkim_selectors"] = hits
        return OSINTResult(source="Mail Security", data_type="mail_security", data=data, confidence=0.9)

    def _lookalikes(self, domain: str) -> List[OSINTResult]:
        """Registered lookalike domains (dnstwist): typo-squats, homoglyphs, TLD swaps."""
        try:
            import dnstwist
            found = dnstwist.run(domain=domain, registered=True, format="null", threads=24,
                                 fuzzers="addition,bitsquatting,homoglyph,hyphenation,insertion,omission,"
                                         "repetition,replacement,subdomain,transposition,vowel-swap,dictionary,tld-swap")
        except Exception as e:
            self.logger.warning(f"dnstwist failed: {e}")
            return []
        out = []
        for d in found:
            if d.get("fuzzer") == "*original" or not d.get("domain"):
                continue
            out.append(OSINTResult(
                source="dnstwist",
                source_url=f"https://{d['domain']}",
                data_type="lookalike_domain",
                data={"domain": d["domain"], "technique": d.get("fuzzer"),
                      "ip_addresses": (d.get("dns_a") or []) + (d.get("dns_aaaa") or []),
                      "mail_servers": d.get("dns_mx") or [], "nameservers": d.get("dns_ns") or [],
                      "can_receive_mail": bool(d.get("dns_mx"))},
                confidence=0.85,
            ))
        # Lookalikes with mail servers first: those can send and receive phishing email
        out.sort(key=lambda r: (not r.data["can_receive_mail"], r.data["domain"]))
        return out[:80]

    def _probe_https(self, domain: str) -> Optional[OSINTResult]:
        """What answers on https://domain: status, redirects, server, title, TLS certificate."""
        import ssl
        data: Dict[str, Any] = {"domain": domain}
        try:
            r = safe_get(f"https://{domain}", timeout=10,
                         headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) OSIG/1.0"})
            data.update({
                "status": r.status_code,
                "final_url": str(r.url),
                "server": r.headers.get("server"),
                "powered_by": r.headers.get("x-powered-by"),
                "hsts": "strict-transport-security" in r.headers,
                "csp": "content-security-policy" in r.headers,
            })
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:200000], re.I | re.S)
            if m:
                data["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
            from app.osint.web_fingerprint import detect
            data["technologies"] = detect(dict(r.headers), r.text)
        except Exception as e:
            data["https_error"] = str(e)[:200]
        try:
            ctx = ssl.create_default_context()
            with safe_tls_connect(domain, 443, timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                    cert = tls.getpeercert()
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            data["tls"] = {
                "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                "expires": cert.get("notAfter"),
                "names": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:20],
            }
        except Exception as e:
            data.setdefault("tls_error", str(e)[:200])
        if len(data) <= 2:
            return None
        return OSINTResult(source="HTTPS Probe", source_url=f"https://{domain}", data_type="web_server",
                           data=data, confidence=0.95)

    def _check_wayback(self, domain: str) -> Optional[OSINTResult]:
        """First and latest Wayback Machine captures: how long the site has existed publicly."""
        try:
            base = "https://web.archive.org/cdx/search/cdx"
            # CDX is slow (~15s) but the only way to get the first capture
            first = httpx.get(base, params={"url": domain, "limit": 1, "fl": "timestamp", "output": "json"}, timeout=40).json()
            latest = httpx.get("https://archive.org/wayback/available", params={"url": domain}, timeout=15).json()
            last_ts = ((latest.get("archived_snapshots") or {}).get("closest") or {}).get("timestamp")
        except Exception as e:
            self.logger.info(f"Wayback lookup failed: {e}")
            return None
        if len(first) < 2:
            return None
        fmt = lambda ts: f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        return OSINTResult(
            source="Wayback Machine",
            source_url=f"https://web.archive.org/web/*/{domain}",
            data_type="web_history",
            data={"domain": domain, "first_capture": fmt(first[1][0]),
                  "latest_capture": fmt(last_ts) if last_ts else None},
            confidence=0.95,
        )

    # Helper methods for data cleaning
    
    def _clean_whois_field(self, field: Any) -> Any:
        """
        Clean WHOIS field data.
        
        WHOIS data can be:
        - A list (convert to simple list)
        - A string (return as-is)
        - None (return None)
        """
        if field is None:
            return None
        elif isinstance(field, list):
            return [str(item) for item in field if item]
        else:
            return str(field)
    
    def _lookup_ip_info(self, ip_address: str, domain: str) -> Optional[OSINTResult]:
        """
        Lookup IP intelligence (ASN, GeoIP, Network) using ipwhois and geoip2.
        """
        try:
            from ipwhois import IPWhois
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                obj = IPWhois(ip_address)
                res = obj.lookup_rdap(depth=1)
                
                network = res.get('network', {})
                country_code = res.get('asn_country_code')
                
                data = {
                    "ip": ip_address,
                    "domain": domain,
                    "asn": res.get('asn'),
                    "asn_description": res.get('asn_description'),
                    "country_code": country_code,
                    "cidr": network.get('cidr'),
                    "network_name": network.get('name'),
                    "geo": {}
                }

                # Try to add more precise GeoIP data if geoip2 is available
                try:
                    # In a real scenario, the user would provide a path to a MaxMind DB.
                    # For now, we'll use an API fallback or just structure the data.
                    import httpx
                    geo_resp = httpx.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query", timeout=5.0)
                    if geo_resp.status_code == 200:
                        geo_data = geo_resp.json()
                        if geo_data.get("status") == "success":
                            data["geo"] = {
                                "city": geo_data.get("city"),
                                "region": geo_data.get("regionName"),
                                "country": geo_data.get("country"),
                                "lat": geo_data.get("lat"),
                                "lon": geo_data.get("lon"),
                                "isp": geo_data.get("isp"),
                                "timezone": geo_data.get("timezone")
                            }
                except Exception as geo_e:
                    self.logger.debug(f"GeoIP API fallback failed: {geo_e}")
                
                return OSINTResult(
                    source="IP Intelligence (IPWhois + GeoIP)",
                    source_url=None,
                    data_type="ip_intel",
                    data=data,
                    confidence=0.9
                )
        except Exception as e:
            self.logger.warning(f"IP info lookup failed for {ip_address}: {str(e)}")
            return None

    def _check_sublist3r(self, domain: str) -> List[OSINTResult]:
        """
        Run sublist3r to find additional subdomains.
        """
        results = []
        try:
            import sublist3r
            import concurrent.futures
            
            def run_sublist3r():
                return sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines='baidu,yahoo,google,bing,ask,netcraft,virustotal,ssl,passivedns')
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_sublist3r)
                # sublist3r can take a while, cap it at 45 seconds
                subdomains = future.result(timeout=45)
                
            if subdomains and isinstance(subdomains, (list, set, tuple)):
                unique_subs = list(set(subdomains))
                if unique_subs:
                    results.append(OSINTResult(
                        source="Sublist3r",
                        source_url=None,
                        data_type="subdomains",
                        data={
                            "domain": domain,
                            "count": len(unique_subs),
                            "subdomains": unique_subs
                        },
                        confidence=0.8
                    ))
        except Exception as e:
            self.logger.warning(f"Sublist3r failed for {domain}: {str(e)}")
            
        return results

    def _format_whois_date(self, date_field: Any) -> Optional[str]:
        """
        Format date fields from WHOIS data.
        
        WHOIS dates can be datetime objects or lists of datetime objects.
        We convert them to ISO format strings.
        """
        if date_field is None:
            return None
        
        # If it's a list, take the first date
        if isinstance(date_field, list):
            date_field = date_field[0] if date_field else None
        
        # Convert datetime to string
        if isinstance(date_field, datetime):
            return date_field.isoformat()
        
        return str(date_field) if date_field else None

    def _extract_domain_parts(self, domain: str) -> Optional[OSINTResult]:
        try:
            import tldextract
            ext = tldextract.extract(domain)
            data = {
                "subdomain": ext.subdomain,
                "domain": ext.domain,
                "suffix": ext.suffix,
                "registered_domain": ext.registered_domain,
                "fqdn": ext.fqdn
            }
            return OSINTResult(
                source="TLDExtract",
                source_url=None,
                data_type="domain_parts",
                data=data,
                confidence=1.0
            )
        except Exception as e:
            self.logger.warning(f"TLDExtract failed for {domain}: {e}")
            return None

    def _scrape_homepage(self, domain: str) -> Optional[OSINTResult]:
        try:
            import httpx
            from bs4 import BeautifulSoup
            from fake_useragent import UserAgent
            import spacy
            from rapidfuzz import fuzz
            import tldextract
            import warnings
            
            # 1. Evasive Scraping Setup
            ua = UserAgent()
            random_ua = ua.random
            
            urls_to_try = [f"https://{domain}", f"http://{domain}"]
            html_content = None
            final_url = None
            
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                if True:  # target-controlled URLs: SSRF-guarded fetch
                    for url in urls_to_try:
                        try:
                            resp = safe_get(url, headers={"User-Agent": random_ua}, timeout=10.0, verify=False)
                            if resp.status_code == 200:
                                html_content = resp.text
                                final_url = str(resp.url)
                                break
                        except Exception:
                            continue
            
            if not html_content:
                return None
                
            # 2. BeautifulSoup Parsing
            soup = BeautifulSoup(html_content, 'lxml')
            
            title = soup.title.string.strip() if soup.title and soup.title.string else None
            
            meta_desc = None
            desc_tag = soup.find('meta', attrs={'name': 'description'})
            if desc_tag and desc_tag.get('content'):
                meta_desc = desc_tag['content'].strip()
                
            emails = set()
            for a in soup.find_all('a', href=True):
                if a.get('href') and a['href'].startswith('mailto:'):
                    emails.add(a['href'].replace('mailto:', '').split('?')[0])
            
            # 3. NLP Entity Extraction (Spacy)
            try:
                nlp = spacy.load("en_core_web_sm")
            except Exception:
                # Silent fallback if model is somehow missing
                spacy.cli.download("en_core_web_sm")
                nlp = spacy.load("en_core_web_sm")
                
            # Extract plain text from body, ignoring scripts/styles
            for script in soup(["script", "style", "noscript", "meta"]):
                script.decompose()
            text = soup.get_text(separator=' ', strip=True)
            
            # Analyze up to first 5000 characters to save processing time
            doc = nlp(text[:5000])
            
            entities_found = {"ORG": set(), "PERSON": set(), "GPE": set()}
            for ent in doc.ents:
                if ent.label_ in entities_found and len(ent.text) > 2:
                    entities_found[ent.label_].add(ent.text)
                    
            nlp_data = {
                "organizations": list(entities_found["ORG"])[:10],
                "people": list(entities_found["PERSON"])[:10],
                "locations": list(entities_found["GPE"])[:10]
            }
            
            # 4. Phishing Risk Analysis (RapidFuzz)
            # We check if the typed domain name appears in the extracted Organizations
            ext = tldextract.extract(domain)
            base_name = ext.domain.lower()
            
            is_phishing_risk = False
            highest_match = 0
            
            if len(entities_found["ORG"]) > 0:
                for org in entities_found["ORG"]:
                    # Clean org name slightly
                    clean_org = org.lower().replace(',', '').replace('.', '').replace(' inc', '').replace(' llc', '').strip()
                    # Calculate similarity between domain base name and scraped organization
                    similarity = fuzz.ratio(base_name, clean_org)
                    if similarity > highest_match:
                        highest_match = similarity
                        
                # If they claim to be an org but the similarity is very low, it might be an impersonator
                # Note: This is a basic generic heuristic demonstrating rapidfuzz
                if highest_match < 40 and len(base_name) > 3:
                     is_phishing_risk = True
                     
            data = {
                "url": final_url,
                "title": title,
                "meta_description": meta_desc,
                "visible_emails": list(emails),
                "nlp_entities": nlp_data,
                "phishing_analysis": {
                    "base_domain": base_name,
                    "highest_org_match": round(highest_match, 2),
                    "potential_risk": is_phishing_risk
                }
            }
            
            return OSINTResult(
                source="AI Homepage Scraper",
                source_url=final_url,
                data_type="webpage_info",
                data=data,
                confidence=0.9
            )
        except Exception as e:
            self.logger.warning(f"Homepage scraping/NLP failed for {domain}: {e}")
            return None

    def _scan_ports(self, ip_address: str, domain: str) -> Optional[OSINTResult]:
        try:
            import nmap
            nm = nmap.PortScanner()
            # Scan top web/mail/system ports quickly without ping (-Pn)
            ports = "21,22,25,53,80,110,143,443,465,587,993,995,3306,5432,8080"
            nm.scan(hosts=ip_address, arguments=f'-p {ports} -Pn -T4 --host-timeout 30s')
            
            if ip_address not in nm.all_hosts():
                return None
                
            open_ports = []
            host_data = nm[ip_address]
            
            for proto in host_data.all_protocols():
                ports_data = host_data[proto].keys()
                for port in sorted(ports_data):
                    state = host_data[proto][port]['state']
                    if state == 'open':
                        open_ports.append({
                            "port": port,
                            "protocol": proto,
                            "name": host_data[proto][port]['name'],
                            "product": host_data[proto][port].get('product', '')
                        })
            
            if not open_ports:
                return None
                
            data = {
                "ip": ip_address,
                "domain": domain,
                "open_ports": open_ports,
                "total_open": len(open_ports)
            }
            
            return OSINTResult(
                source="Nmap Port Scan",
                source_url=None,
                data_type="open_ports",
                data=data,
                confidence=0.95
            )
        except ImportError:
            self.logger.warning("python-nmap is not installed. Port scanning disabled.")
            return None
        except Exception as e:
            self.logger.warning(f"Port scan failed for {ip_address}: {e}")
            return None


# Create module instance for easy import
domain_intel = DomainIntelModule()

