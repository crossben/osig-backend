"""
Domain Intelligence Module

This module gathers intelligence on domain names using free OSINT tools:
- python-whois: Domain registration information (owner, registrar, dates)
- dnspython: DNS records (A, MX, TXT, NS, etc.)
- Manual subdomain enumeration
- theHarvester: Email and subdomain discovery (placeholder)

All findings are returned in a standardized format for storage and display.
"""

from typing import List, Dict, Any, Optional
import dns.resolver
import dns.exception
import whois
from datetime import datetime
import socket
from app.osint.base import BaseOSINTModule, OSINTResult


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
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
        "webdisk", "admin", "api", "dev", "staging", "test", "blog",
        "shop", "mobile", "m", "vpn", "cdn", "ssh", "git", "docs"
    ]
    
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

            # Extract IPs from DNS A records to run IP intelligence
            ips_to_check = set()
            for r in dns_results:
                if r.data.get("record_type") == "A":
                    for ip in r.data.get("records", []):
                        ips_to_check.add(ip)
            
            for ip in ips_to_check:
                ip_res = self._lookup_ip_info(ip, target)
                if ip_res:
                    results.append(ip_res)
                    
                # Scan ports for each resolved IP
                port_scan_res = self._scan_ports(ip, target)
                if port_scan_res:
                    results.append(port_scan_res)

            if deep:
                # Deep: scrape homepage for basic meta info and emails
                scrape_res = self._scrape_homepage(target)
                if scrape_res:
                    results.append(scrape_res)

                # Deep: certificate transparency logs via crt.sh
                crt_results = self._check_crtsh(target)
                results.extend(crt_results)

                # Deep: reverse IP lookup
                reverse_results = self._reverse_ip_lookup(target)
                results.extend(reverse_results)
                
                # Deep: sublist3r for expanded subdomain enumeration
                subl_results = self._check_sublist3r(target)
                results.extend(subl_results)

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
        resolver.timeout = 2    # 2s per query
        resolver.lifetime = 2   # 2s total lifetime per query

        for subdomain_name in self.COMMON_SUBDOMAINS:
            try:
                full_domain = f"{subdomain_name}.{domain}"
                answers = resolver.resolve(full_domain, 'A')
                ip_addresses = [str(r) for r in answers]

                result = OSINTResult(
                    source="Subdomain Enumeration",
                    source_url=f"http://{full_domain}",
                    data_type="subdomain",
                    data={
                        "subdomain": subdomain_name,
                        "full_domain": full_domain,
                        "ip_addresses": ip_addresses,
                        "exists": True,
                    },
                    confidence=0.85,
                )
                results.append(result)
                self.logger.info(f"Found subdomain: {full_domain}")

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                # Subdomain doesn't exist or timed out — normal, skip
                continue
            except Exception as e:
                self.logger.debug(f"Error checking subdomain {subdomain_name}: {e}")
                continue

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
                    
                    # Extract email addresses from DMARC policy
                    # Format: v=DMARC1; p=none; rua=mailto:email@domain.com
                    if 'mailto:' in dmarc_content:
                        result = OSINTResult(
                            source="DMARC Analysis",
                            source_url=None,
                            data_type="email_address",
                            data={
                                "domain": domain,
                                "record": dmarc_content,
                                "type": "DMARC Reporting Address"
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

    def _check_crtsh(self, domain: str) -> List[OSINTResult]:
        """
        Query crt.sh (certificate transparency logs) for subdomains.
        Free, no API key required — returns all SSL certificates ever issued for the domain.
        """
        results = []
        try:
            import httpx
            import json
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            with httpx.Client(timeout=15.0) as client:
                resp = client.get(url, headers={"User-Agent": "OSIG-Scanner/1.0"})
                if resp.status_code == 200:
                    certs = resp.json()
                    seen_names = set()
                    for cert in certs[:100]:  # cap at 100 entries
                        name = cert.get("name_value", "").strip()
                        for n in name.split("\n"):
                            n = n.strip().lstrip("*.").lower()
                            if n and n not in seen_names and domain in n and n != domain:
                                seen_names.add(n)
                                results.append(OSINTResult(
                                    source="crt.sh (Certificate Transparency)",
                                    source_url=f"https://crt.sh/?q={n}",
                                    data_type="subdomain",
                                    data={
                                        "subdomain": n,
                                        "full_domain": n,
                                        "issuer": cert.get("issuer_name", ""),
                                        "not_before": cert.get("not_before"),
                                        "not_after": cert.get("not_after"),
                                        "exists": True,
                                    },
                                    confidence=0.9,
                                ))
        except Exception as e:
            self.logger.warning(f"crt.sh lookup failed: {e}")
        return results

    def _reverse_ip_lookup(self, domain: str) -> List[OSINTResult]:
        """
        Find the IP address for the domain and look up its hostname.
        Useful for identifying shared hosting / cloud providers.
        """
        results = []
        try:
            ip = socket.gethostbyname(domain)
            hostname = socket.gethostbyaddr(ip)[0] if ip else None
            results.append(OSINTResult(
                source="Reverse IP Lookup",
                source_url=None,
                data_type="ip_info",
                data={
                    "domain": domain,
                    "ip_address": ip,
                    "reverse_hostname": hostname,
                },
                confidence=0.95,
            ))
        except Exception as e:
            self.logger.warning(f"Reverse IP lookup failed: {e}")
        return results
    
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
                return sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            
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
                with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
                    for url in urls_to_try:
                        try:
                            resp = client.get(url, headers={"User-Agent": random_ua})
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

