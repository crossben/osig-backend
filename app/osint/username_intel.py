"""
Username Intelligence Module

This module searches for usernames across social media platforms and websites
using free OSINT tools like Sherlock and WhatsMyName dataset.

Sherlock can check 300+ social media platforms to find where a username exists,
providing URLs to discovered profiles.
"""

from typing import List, Dict, Any
import httpx
from app.osint.base import BaseOSINTModule, OSINTResult


class UsernameIntelModule(BaseOSINTModule):
    """
    Username Intelligence gathering module.
    
    This module investigates usernames to find:
    - Social media profiles across 300+ platforms
    - Public accounts and profiles
    - Online presence footprint
    """
    
    # Top platforms to check (used for quick scans)
    # We prioritize the most popular platforms for faster results
    TOP_PLATFORMS = [
        {"name": "GitHub", "url": "https://github.com/{}", "check_type": "status_code"},
        {"name": "Twitter", "url": "https://twitter.com/{}", "check_type": "status_code"},
        {"name": "Instagram", "url": "https://instagram.com/{}", "check_type": "status_code"},
        {"name": "Reddit", "url": "https://reddit.com/user/{}", "check_type": "status_code"},
        {"name": "LinkedIn", "url": "https://linkedin.com/in/{}", "check_type": "status_code"},
        {"name": "Medium", "url": "https://medium.com/@{}", "check_type": "status_code"},
        {"name": "dev.to", "url": "https://dev.to/{}", "check_type": "status_code"},
        {"name": "Twitch", "url": "https://twitch.tv/{}", "check_type": "status_code"},
        {"name": "YouTube", "url": "https://youtube.com/@{}", "check_type": "status_code"},
        {"name": "TikTok", "url": "https://tiktok.com/@{}", "check_type": "status_code"},
    ]
    
    def __init__(self):
        """Initialize the Username Intel module."""
        super().__init__(
            name="username_intel",
            display_name="Username Intelligence"
        )
    
    def run(self, target: str) -> List[OSINTResult]:
        """
        Execute username intelligence gathering.
        
        Args:
            target: Username to investigate
            
        Returns:
            List of findings about the username across platforms
        """
        self.log_start(target)
        results = []
        
        # Validate username format
        if not self.validate_target(target, "username"):
            self.logger.warning(f"Invalid username format: {target}")
            return results
        
        try:
            # Method 1: Quick check of top platforms
            # This gives fast results for common platforms
            quick_results = self._check_top_platforms(target)
            results.extend(quick_results)
            
            # Method 2: Sherlock comprehensive scan
            # Note: Sherlock requires subprocess execution or library import
            # Implemented as placeholder for now
            sherlock_results = self._check_sherlock(target)
            results.extend(sherlock_results)
            
            self.log_success(len(results))
            
        except Exception as e:
            self.log_error(e)
            raise
        
        return results
    
    def _check_top_platforms(self, username: str) -> List[OSINTResult]:
        """
        Quick check of top 10 social media platforms.
        
        We send HTTP requests to check if the username exists on major platforms.
        This is faster than running full Sherlock scan when we just need quick results.
        
        Detection method: If the profile page returns 200 OK, the username likely exists.
        
        Args:
            username: Username to check
            
        Returns:
            List of OSINTResult objects for each platform checked
        """
        results = []
        
        # Create HTTP client with reasonable timeout
        # We use a custom user agent to avoid being blocked
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        with httpx.Client(timeout=5.0, headers=headers, follow_redirects=True) as client:
            
            for platform in self.TOP_PLATFORMS:
                try:
                    # Format the URL with the username
                    # Example: https://github.com/{username}
                    url = platform["url"].format(username)
                    
                    # Send HEAD request (faster than GET - only checks if page exists)
                    response = client.head(url, follow_redirects=True)
                    
                    # Determine if profile exists based on status code
                    exists = response.status_code == 200
                    
                    # Create result object
                    result = OSINTResult(
                        source="Username Check",
                        source_url=url if exists else None,
                        data_type="social_profile",
                        data={
                            "platform": platform["name"],
                            "username": username,
                            "url": url,
                            "exists": exists,
                            "status_code": response.status_code
                        },
                        # Higher confidence if found, lower if not found
                        confidence=0.85 if exists else 0.6
                    )
                    results.append(result)
                    
                    if exists:
                        self.logger.info(f"Found {username} on {platform['name']}")
                    
                except Exception as e:
                    # If check fails (timeout, connection error), log but continue
                    self.logger.warning(f"Failed to check {platform['name']}: {str(e)}")
                    continue
        
        return results
    
    def _check_sherlock(self, username: str) -> List[OSINTResult]:
        """
        Use Sherlock to check username across 300+ websites.
        
        Sherlock is a powerful tool that checks username availability
        across hundreds of social networks and websites.
        
        Args:
            username: Username to search for
            
        Returns:
            List of OSINTResult objects with Sherlock findings
        """
        results = []
        
        try:
            import subprocess
            import json
            import tempfile
            import os
            
            # Check if sherlock is installed/available
            # We'll try to run it as a module first
            try:
                # Create temp directory for output
                with tempfile.TemporaryDirectory() as tmpdir:
                    output_file = os.path.join(tmpdir, f"{username}.json")
                    
                    # Run Sherlock as Python module
                    # -o: output directory
                    # --json: JSON output format
                    # --timeout: reasonable timeout per site (5 seconds)
                    # --no-color: disable color codes in output
                    cmd = [
                        'python3', '-m', 'sherlock',
                        username,
                        '-o', tmpdir,
                        '--json', output_file,
                        '--timeout', '5',
                        '--no-color'
                    ]
                    
                    # Run with timeout to prevent hanging
                    # Sherlock can take a while with 300+ sites
                    process = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=120  # 2 minute timeout
                    )
                    
                    # Check if output file was created
                    if os.path.exists(output_file):
                        # Read and parse JSON output
                        with open(output_file, 'r') as f:
                            sherlock_data = json.load(f)
                        
                        # Convert Sherlock results to OSINTResult objects
                        # Sherlock JSON format: {platform: {url, exists, ...}}
                        for platform, data in sherlock_data.items():
                            # Only include results where username was found
                            if isinstance(data, dict) and data.get('url_user'):
                                result = OSINTResult(
                                    source="Sherlock",
                                    source_url=data.get('url_user'),
                                    data_type="social_profile",
                                    data={
                                        "platform": platform,
                                        "username": username,
                                        "url": data.get('url_user'),
                                        "exists": True,
                                        "http_status": data.get('http_status'),
                                        "response_time": data.get('response_time_s')
                                    },
                                    confidence=0.90  # Sherlock is very reliable
                                )
                                results.append(result)
                                
                                self.logger.info(f"Sherlock: Found {username} on {platform}")
                    else:
                        self.logger.warning("Sherlock output file not created")
                        
            except subprocess.TimeoutExpired:
                self.logger.warning("Sherlock check timed out after 2 minutes")
            except FileNotFoundError:
                # Sherlock not installed as module
                self.logger.info("Sherlock not installed. Install with: pip install sherlock-project")
                
        except Exception as e:
            self.logger.error(f"Sherlock check failed: {str(e)}")
        
        return results


# Create module instance for easy import
username_intel = UsernameIntelModule()
