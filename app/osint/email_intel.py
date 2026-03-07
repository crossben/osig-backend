"""
Email Intelligence Module

This module gathers intelligence on email addresses using free OSINT tools:
- Holehe: Checks if email is registered on 120+ websites (GitHub, Twitter, etc.)
- Gravatar: Fetches publicly available avatar and profile information

All findings are returned in a standardized format for storage and display.
"""

from typing import List, Dict, Any, Optional
import asyncio
import hashlib
import httpx
import socket
import subprocess
import json
from app.osint.base import BaseOSINTModule, OSINTResult

# Known disposable/temporary email domains (partial list, extended in run-time)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwam.com",
    "sharklasers.com", "guerrillamailblock.com", "yopmail.com", "trashmail.com",
    "dispostable.com", "mailnull.com", "spamgourmet.com", "spamgourmet.net",
    "throwam.com", "fakeinbox.com", "maildrop.cc", "getairmail.com",
    "10minutemail.com", "discard.email", "spam.la", "nospam.ze.tc",
}


class EmailIntelModule(BaseOSINTModule):
    """
    Email Intelligence gathering module.
    
    This module investigates email addresses to find:
    - Which websites/services the email is registered on
    - Public profile information from Gravatar
    - Associated social media accounts
    """
    
    def __init__(self):
        """Initialize the Email Intel module."""
        super().__init__(
            name="email_intel",
            display_name="Email Intelligence"
        )
    
    def run(self, target: str, deep: bool = False) -> List[OSINTResult]:
        """
        Execute email intelligence gathering.
        
        Args:
            target: Email address to investigate
            deep: If True, run extended checks
            
        Returns:
            List of findings about the email address
        """
        self.log_start(target)
        results = []
        
        # Validate email format
        if not self.validate_target(target, "email"):
            self.logger.warning(f"Invalid email format: {target}")
            return results
        
        try:
            # Always: Check Gravatar
            gravatar_results = self._check_gravatar(target)
            results.extend(gravatar_results)

            # Always: Disposable email detection
            disposable_result = self._check_disposable(target)
            if disposable_result:
                results.append(disposable_result)

            # Always: MX record check for the domain
            mx_result = self._check_email_domain(target)
            if mx_result:
                results.append(mx_result)

            if deep:
                # Deep only: check EmailRep for reputation and risk score
                emailrep_result = self._check_emailrep(target)
                if emailrep_result:
                    results.append(emailrep_result)

                # Deep only: check HIBP for data breaches
                hibp_results = self._check_hibp(target)
                results.extend(hibp_results)

                # Deep only: check Holehe via CLI
                holehe_results = self._check_holehe(target)
                results.extend(holehe_results)
                
                # Deep only: check h8mail via CLI for leaks
                h8mail_results = self._check_h8mail(target)
                results.extend(h8mail_results)
            
            self.log_success(len(results))
            
        except Exception as e:
            self.log_error(e)
            raise
        
        return results
    
    def _check_gravatar(self, email: str) -> List[OSINTResult]:
        """
        Check Gravatar for public profile information.
        
        Gravatar is a service that provides globally recognized avatars.
        If a user has registered their email with Gravatar, we can fetch
        their public profile data.
        
        Args:
            email: Email address to check
            
        Returns:
            List of OSINTResult objects with Gravatar findings
        """
        results = []
        
        try:
            # Step 1: Generate MD5 hash of email (Gravatar's format)
            # Gravatar uses MD5 hash of lowercase email for lookups
            email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
            
            # Step 2: Construct Gravatar API URLs
            avatar_url = f"https://www.gravatar.com/avatar/{email_hash}"
            profile_url = f"https://www.gravatar.com/{email_hash}.json"
            
            # Step 3: Check if profile exists
            # We use httpx for async HTTP requests (safer than requests)
            with httpx.Client(timeout=10.0) as client:
                response = client.get(profile_url)
                
                # If profile exists (status 200), extract data
                if response.status_code == 200:
                    profile_data = response.json()
                    
                    # Gravatar profile found!
                    result = OSINTResult(
                        source="Gravatar",
                        source_url=f"https://gravatar.com/{email_hash}",
                        data_type="profile",
                        data={
                            "email_hash": email_hash,
                            "avatar_url": avatar_url,
                            "profile": profile_data,
                            "has_profile": True
                        },
                        confidence=0.95  # High confidence - direct API response
                    )
                    results.append(result)
                    
                    self.logger.info(f"Gravatar profile found for {email}")
                else:
                    # No profile, but we still record this finding
                    result = OSINTResult(
                        source="Gravatar",
                        source_url=f"https://gravatar.com/{email_hash}",
                        data_type="profile",
                        data={
                            "email_hash": email_hash,
                            "avatar_url": avatar_url,  # Still might have default avatar
                            "has_profile": False
                        },
                        confidence=0.5  # Lower confidence - no profile found
                    )
                    results.append(result)
                    
        except Exception as e:
            self.logger.error(f"Gravatar check failed: {str(e)}")
            # Don't raise - we want to continue with other checks
        
        return results

    def _check_disposable(self, email: str) -> OSINTResult | None:
        """
        Check if the email belongs to a known disposable/temporary email service.
        Uses a local list — no external API required.
        """
        try:
            domain = email.split('@')[-1].lower().strip()
            is_disposable = domain in DISPOSABLE_DOMAINS

            return OSINTResult(
                source="Disposable Email Check",
                source_url=None,
                data_type="email_validation",
                data={
                    "email": email,
                    "domain": domain,
                    "is_disposable": is_disposable,
                    "risk": "high" if is_disposable else "low",
                },
                confidence=0.9,
            )
        except Exception as e:
            self.logger.warning(f"Disposable check failed: {e}")
            return None

    def _check_email_domain(self, email: str) -> OSINTResult | None:
        """
        Verify that the email domain has valid MX records (can actually receive mail).
        Uses DNS resolution — no external API required.
        """
        try:
            import dns.resolver
            domain = email.split('@')[-1].lower().strip()
            mx_records = []
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                mx_records = [str(r.exchange) for r in answers]
                valid = True
            except Exception:
                valid = False

            return OSINTResult(
                source="Email Domain Check",
                source_url=None,
                data_type="email_validation",
                data={
                    "email": email,
                    "domain": domain,
                    "mx_records": mx_records,
                    "domain_valid": valid,
                },
                confidence=0.95,
            )
        except Exception as e:
            self.logger.warning(f"Email domain check failed: {e}")
            return None
    
    def _check_hibp(self, email: str) -> List[OSINTResult]:
        """
        Check HaveIBeenPwned for email breaches using pyhibp.
        """
        results = []
        try:
            from pyhibp import pwnedpasswords as pw
            from pyhibp import hipb_base
            # NOTE: For account breaches, HIBP requires an API key now.
            # However, we can use the library to structure the request.
            # If no API key is set, this might fail or return limited info.
            # For now, we'll try a basic check if the library supports unauthenticated (unlikely for account)
            # or just provide the placeholder structure for where the key would go.
            
            # Since we want to stay "Free", we might rely on the fact that 
            # some parts of HIBP-like data are indexed by other free tools,
            # but we'll implement the pyhibp call structure here.
            
            # Mapping pyhibp to results
            self.logger.info(f"Checking HIBP for {email}")
            # Placeholder for actual HIBP API key if provided in settings
            # api_key = settings.HIBP_API_KEY
            
            # For account breaches, an API key is required. Without one, this will likely fail.
            # We'll simulate a call structure but won't execute a real network request without a key.
            # If a key were available:
            # hipb_base.set_api_key(api_key)
            # breaches = hipb_base.get_all_breaches_for_account(email)
            # if breaches:
            #     for breach in breaches:
            #         results.append(OSINTResult(
            #             source="HaveIBeenPwned",
            #             source_url=f"https://haveibeenpwned.com/account/{email}",
            #             data_type="breach",
            #             data={
            #                 "email": email,
            #                 "name": breach.Name,
            #                 "domain": breach.Domain,
            #                 "breach_date": breach.BreachDate,
            #                 "description": breach.Description,
            #                 "data_classes": breach.DataClasses
            #             },
            #             confidence=0.98
            #         ))
            # else:
            #     self.logger.info(f"No HIBP breaches found for {email}")
            
            self.logger.warning("HIBP account breach check requires an API key for full functionality. Skipping actual API call.")
            
        except Exception as e:
            self.logger.warning(f"HIBP check failed: {e}")
            
        return results

    def _check_holehe(self, email: str) -> List[OSINTResult]:
        """
        Check if email is registered on various platforms using Holehe CLI.
        """
        results = []
        try:
            self.logger.info(f"Running Holehe for {email}...")
            # Run holehe via subprocess to avoid async conflicts and get latest site checks
            cmd = ["holehe", email, "--only-used", "--no-color"]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Holehe output is usually text-based in the simplest form, 
            # but we can parse the "used" lines.
            output = process.stdout
            for line in output.split('\n'):
                if "[+]" in line:
                    # Platform found!
                    platform = line.split("[+]")[-1].strip()
                    results.append(OSINTResult(
                        source="Holehe",
                        source_url=None,
                        data_type="account_existence",
                        data={"platform": platform, "email": email, "exists": True},
                        confidence=0.9
                    ))
            
            self.logger.info(f"Holehe found {len(results)} platforms for {email}")
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Holehe check timed out for {email}")
        except Exception as e:
            self.logger.warning(f"Holehe check failed: {e}")
            
        return results
        
    def _check_h8mail(self, email: str) -> List[OSINTResult]:
        """
        Check for breached credentials and leaks using h8mail CLI.
        """
        results = []
        try:
            self.logger.info(f"Running h8mail for {email}...")
            # Run h8mail quietly and output JSON
            import tempfile
            import os
            
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = os.path.join(tmpdir, "h8mail_results.json")
                cmd = ["h8mail", "-t", email, "-q", "-j", output_file]
                
                # This can take time depending on local/remote APIs
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                    
                    # h8mail JSON structure: {'targets': [{'target': 'email', 'data': [findings]}]}
                    if 'targets' in data and len(data['targets']) > 0:
                        target_data = data['targets'][0].get('data', [])
                        
                        # Only create a result if actual leaks were found
                        if target_data and len(target_data) > 0 and type(target_data[0]) is not str:
                            results.append(OSINTResult(
                                source="h8mail",
                                source_url=None,
                                data_type="breach",
                                data={"email": email, "leaks_found": len(target_data), "raw_findings": target_data[:5]}, # Store top 5
                                confidence=0.85
                            ))
                            self.logger.info(f"h8mail found {len(target_data)} leak signals for {email}")
                        else:
                            self.logger.info(f"h8mail found no specific leak data for {email}")
        except subprocess.TimeoutExpired:
            self.logger.warning(f"h8mail check timed out for {email}")
        except Exception as e:
            self.logger.warning(f"h8mail check failed: {e}")
            
        return results
    
    def _check_emailrep(self, email: str) -> Optional[OSINTResult]:
        """
        Check EmailRep for email reputation and risk.
        """
        try:
            import httpx
            # The free tier of EmailRep allows unauthenticated queries, rate limited
            url = f"https://emailrep.io/{email}"
            headers = {"User-Agent": "OSIG-Scan-Engine"}
            
            with httpx.Client(timeout=10.0) as client:
                response = client.get(url, headers=headers)
                
            if response.status_code == 200:
                data = response.json()
                return OSINTResult(
                    source="EmailRep",
                    source_url=url,
                    data_type="reputation",
                    data=data,
                    confidence=0.85
                )
            elif response.status_code == 429:
                self.logger.warning(f"EmailRep rate limit exceeded for {email}")
            else:
                self.logger.warning(f"EmailRep lookup failed: {response.status_code}")
                
        except Exception as e:
            self.logger.warning(f"EmailRep lookup failed for {email}: {str(e)}")
            
        return None

    def _analyze_risk(self, email: str, results: List[OSINTResult]) -> Dict[str, Any]:
        """
        Analyze findings to determine risk level.
        
        More public profiles = higher visibility = potentially higher risk
        
        Args:
            results: List of all findings
            
        Returns:
            Risk analysis dictionary
        """
        profile_count = sum(1 for r in results if r.data.get("has_profile", False))
        account_count = sum(1 for r in results if r.data_type == "account_existence")
        breach_count = sum(1 for r in results if r.data_type == "breach")
        
        # Calculate risk score
        score = profile_count + account_count + (breach_count * 2)
        
        if score > 15:
            risk_level = "high"
        elif score > 5:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_level": risk_level,
            "profile_count": profile_count,
            "account_count": account_count,
            "breach_count": breach_count,
            "total_findings": len(results)
        }


# Create module instance for easy import
email_intel = EmailIntelModule()
