"""
Email Intelligence Module

This module gathers intelligence on email addresses using free OSINT tools:
- Holehe: Checks if email is registered on 120+ websites (GitHub, Twitter, etc.)
- Gravatar: Fetches publicly available avatar and profile information

All findings are returned in a standardized format for storage and display.
"""

from typing import List, Dict, Any
import asyncio
import hashlib
import httpx
from app.osint.base import BaseOSINTModule, OSINTResult


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
    
    def run(self, target: str) -> List[OSINTResult]:
        """
        Execute email intelligence gathering.
        
        Args:
            target: Email address to investigate
            
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
            # Method 1: Check Gravatar
            gravatar_results = self._check_gravatar(target)
            results.extend(gravatar_results)
            
            # Method 2: Check Holehe (account existence across platforms)
            # Note: Holehe requires subprocess execution, implemented in next iteration
            holehe_results = self._check_holehe(target)
            results.extend(holehe_results)
            
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
    
    def _check_holehe(self, email: str) -> List[OSINTResult]:
        """
        Check if email is registered on various platforms using Holehe.
        
        Holehe is a tool that checks if an email is associated with accounts
        on 120+ websites (GitHub, Twitter, Instagram, etc.) by analyzing
        registration/password reset pages.
        
        Note: Holehe integration is marked as advanced/optional due to complex
        async requirements. For production use, install holehe and run via CLI:
        
        ```bash
        pip install holehe
        holehe email@example.com -o json > output.json
        ```
        
        Then parse the JSON output in your application.
        
        Args:
            email: Email address to check
            
        Returns:
            List of OSINTResult objects with service findings
        """
        results = []
        
        # Holehe requires complex async setup that's not ideal for library integration
        # For now, we recommend using it via CLI and parsing the JSON output
        # 
        # Future improvement: Run holehe as subprocess:
        # ```python
        # import subprocess
        # import json
        # 
        # cmd = ['holehe', email, '-o', 'json']
        # process = subprocess.run(cmd, capture_output=True, text=True)
        # data = json.loads(process.stdout)
        # 
        # for platform, info in data.items():
        #     if info.get('exists'):
        #         result = OSINTResult(
        #             source="Holehe",
        #             source_url=info.get('url'),
        #             data_type="account_existence",
        #             data={"platform": platform, "email": email, "exists": True},
        #             confidence=0.85
        #         )
        #         results.append(result)
        # ```
        
        self.logger.info("Holehe check: Use CLI version for best results (holehe email@example.com)")
        
        return results
    
    def _analyze_risk(self, results: List[OSINTResult]) -> Dict[str, Any]:
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
        
        # Calculate risk score
        # More exposed accounts = higher risk score
        if profile_count + account_count > 10:
            risk_level = "high"
        elif profile_count + account_count > 5:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_level": risk_level,
            "profile_count": profile_count,
            "account_count": account_count,
            "total_findings": len(results)
        }


# Create module instance for easy import
email_intel = EmailIntelModule()
