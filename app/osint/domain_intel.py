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
    
    def run(self, target: str) -> List[OSINTResult]:
        """
        Execute domain intelligence gathering.
        
        Args:
            target: Domain name to investigate (e.g., "example.com")
            
        Returns:
            List of findings about the domain
        """
        self.log_start(target)
        results = []
        
        # Validate domain format
        if not self.validate_target(target, "domain"):
            self.logger.warning(f"Invalid domain format: {target}")
            return results
        
        try:
            # Method 1: WHOIS lookup
            whois_results = self._lookup_whois(target)
            if whois_results:
                results.append(whois_results)
            
            # Method 2: DNS records
            dns_results = self._lookup_dns_records(target)
            results.extend(dns_results)
            
            # Method 3: Common subdomain enumeration
            subdomain_results = self._check_subdomains(target)
            results.extend(subdomain_results)
            
            # Method 4: theHarvester (placeholder)
            harvester_results = self._check_harvester(target)
            results.extend(harvester_results)
            
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
                "creation_date": self._format_date(whois_data.creation_date),
                "expiration_date": self._format_date(whois_data.expiration_date),
                "updated_date": self._format_date(whois_data.updated_date),
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
        Query DNS records for the domain.
        
        DNS records tell us:
        - A records: IP addresses the domain points to
        - MX records: Mail servers (where email is sent)
        - TXT records: Text data (often used for verification, SPF, DKIM)
        - NS records: Name servers (DNS servers for this domain)
        - CNAME records: Aliases (alternative names for the domain)
        
        Args:
            domain: Domain to query
            
        Returns:
            List of OSINTResult objects, one for each record type found
        """
        results = []
        
        # Record types we want to query
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                # Query DNS for this record type
                answers = dns.resolver.resolve(domain, record_type)
                
                # Extract the data from DNS response
                records = []
                for rdata in answers:
                    # Format depends on record type
                    if record_type == 'MX':
                        # MX records have priority and exchange
                        records.append({
                            "priority": rdata.preference,
                            "exchange": str(rdata.exchange)
                        })
                    else:
                        # Most other records are simple strings
                        records.append(str(rdata))
                
                # Create result for this record type
                result = OSINTResult(
                    source="DNS",
                    source_url=None,
                    data_type="dns_record",
                    data={
                        "domain": domain,
                        "record_type": record_type,
                        "records": records,
                        "count": len(records)
                    },
                    confidence=0.99  # DNS is authoritative
                )
                results.append(result)
                
                self.logger.info(f"Found {len(records)} {record_type} records for {domain}")
                
            except dns.resolver.NXDOMAIN:
                # Domain doesn't exist
                self.logger.warning(f"Domain {domain} does not exist")
                break  # No point checking other record types
            except dns.resolver.NoAnswer:
                # No records of this type (normal, not all domains have all record types)
                self.logger.debug(f"No {record_type} records for {domain}")
                continue
            except dns.exception.Timeout:
                # DNS query timed out
                self.logger.warning(f"DNS timeout for {record_type} records of {domain}")
                continue
            except Exception as e:
                # Other DNS errors
                self.logger.error(f"DNS query failed for {record_type}: {str(e)}")
                continue
        
        return results
    
    def _check_subdomains(self, domain: str) -> List[OSINTResult]:
        """
        Check for common subdomains.
        
        We try to resolve common subdomain patterns (www, mail, api, etc.)
        to see if they exist. This gives insight into the domain's infrastructure.
        
        Args:
            domain: Base domain
            
        Returns:
            List of OSINTResult objects for found subdomains
        """
        results = []
        
        for subdomain_name in self.COMMON_SUBDOMAINS:
            try:
                # Construct full subdomain (e.g., www.example.com)
                full_domain = f"{subdomain_name}.{domain}"
                
                # Try to resolve it to an IP address
                # If it resolves, the subdomain exists
                ip_addresses = socket.gethostbyname_ex(full_domain)[2]
                
                # Subdomain found!
                result = OSINTResult(
                    source="Subdomain Enumeration",
                    source_url=f"http://{full_domain}",
                    data_type="subdomain",
                    data={
                        "subdomain": subdomain_name,
                        "full_domain": full_domain,
                        "ip_addresses": ip_addresses,
                        "exists": True
                    },
                    confidence=0.85
                )
                results.append(result)
                
                self.logger.info(f"Found subdomain: {full_domain}")
                
            except socket.gaierror:
                # Subdomain doesn't exist (normal)
                continue
            except Exception as e:
                # Other errors
                self.logger.debug(f"Error checking subdomain {subdomain_name}: {str(e)}")
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
    
    def _format_date(self, date_field: Any) -> Optional[str]:
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


# Create module instance for easy import
domain_intel = DomainIntelModule()
