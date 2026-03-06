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
    TOP_PLATFORMS = [
        {"name": "GitHub", "url": "https://github.com/{}"},
        {"name": "Twitter", "url": "https://twitter.com/{}"},
        {"name": "Instagram", "url": "https://instagram.com/{}"},
        {"name": "Reddit", "url": "https://reddit.com/user/{}"},
        {"name": "LinkedIn", "url": "https://linkedin.com/in/{}"},
        {"name": "Medium", "url": "https://medium.com/@{}"},
        {"name": "dev.to", "url": "https://dev.to/{}"},
        {"name": "Twitch", "url": "https://twitch.tv/{}"},
        {"name": "YouTube", "url": "https://youtube.com/@{}"},
        {"name": "TikTok", "url": "https://tiktok.com/@{}"},
    ]

    # Extended platforms for deep scans
    EXTENDED_PLATFORMS = [
        {"name": "Pinterest", "url": "https://pinterest.com/{}"},
        {"name": "Flickr", "url": "https://flickr.com/people/{}"},
        {"name": "SoundCloud", "url": "https://soundcloud.com/{}"},
        {"name": "Steam", "url": "https://steamcommunity.com/id/{}"},
        {"name": "GitLab", "url": "https://gitlab.com/{}"},
        {"name": "Keybase", "url": "https://keybase.io/{}"},
        {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}"},
        {"name": "Mastodon", "url": "https://mastodon.social/@{}"},
        {"name": "Telegram", "url": "https://t.me/{}"},
        {"name": "Vimeo", "url": "https://vimeo.com/{}"},
        {"name": "Patreon", "url": "https://patreon.com/{}"},
        {"name": "Behance", "url": "https://behance.net/{}"},
        {"name": "Dribbble", "url": "https://dribbble.com/{}"},
        {"name": "ProductHunt", "url": "https://producthunt.com/@{}"},
        {"name": "Trello", "url": "https://trello.com/{}"},
        {"name": "Codecademy", "url": "https://codecademy.com/profiles/{}"},
        {"name": "HackerEarth", "url": "https://hackerearth.com/@{}"},
        {"name": "Kaggle", "url": "https://kaggle.com/{}"},
        {"name": "DockerHub", "url": "https://hub.docker.com/u/{}"},
        {"name": "NPM", "url": "https://npmjs.com/~{}"},
    ]
    
    def __init__(self):
        """Initialize the Username Intel module."""
        super().__init__(
            name="username_intel",
            display_name="Username Intelligence"
        )
    
    def run(self, target: str, deep: bool = False) -> List[OSINTResult]:
        """
        Execute username intelligence gathering.
        
        Args:
            target: Username to investigate
            deep: If True, check 30+ platforms and run Sherlock
            
        Returns:
            List of findings about the username across platforms
        """
        self.log_start(target)
        results = []
        
        if not self.validate_target(target, "username"):
            self.logger.warning(f"Invalid username format: {target}")
            return results
        
        try:
            # Always: Quick check of top platforms
            platforms_to_check = self.TOP_PLATFORMS[:]
            if deep:
                # Deep: also check extended platform list
                platforms_to_check = self.TOP_PLATFORMS + self.EXTENDED_PLATFORMS

            quick_results = self._check_platforms(target, platforms_to_check)
            results.extend(quick_results)
            
            if deep:
                # Deep: run Sherlock if installed
                sherlock_results = self._check_sherlock(target)
                results.extend(sherlock_results)
            
            self.log_success(len(results))
            
        except Exception as e:
            self.log_error(e)
            raise
        
        return results
    
    def _check_platforms(self, username: str, platforms: list) -> List[OSINTResult]:
        """
        Check username on a given list of platform definitions.
        """
        results = []
        
        # Create HTTP client with reasonable timeout
        # We use a custom user agent to avoid being blocked
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        with httpx.Client(timeout=5.0, headers=headers, follow_redirects=True) as client:
            for platform in platforms:
                try:
                    url = platform["url"].format(username)
                    response = client.head(url, follow_redirects=True)
                    exists = response.status_code == 200
                    
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
                        confidence=0.85 if exists else 0.6
                    )
                    results.append(result)
                    
                    if exists:
                        self.logger.info(f"Found {username} on {platform['name']}")
                    
                except Exception as e:
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
