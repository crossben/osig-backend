"""
Username Intelligence Module

Finds where a username exists, and pulls the public profile when it does.

Each platform is checked with a rule that was verified against a real user and
a random non-existent handle (plain "HTTP 200 = exists" gives false positives on
sites that answer 200 for anything, like Instagram, TikTok or LinkedIn):
  - public JSON APIs where available (GitHub, GitLab, Keybase, Mastodon, ...):
    reliable yes/no plus profile data (name, bio, location, website, links)
  - status codes or page markers where there is no API
Sites that cannot be verified without logging in are left to Sherlock on deep
scans, which ships its own per-site detection rules.
"""

import concurrent.futures
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

from app.osint.base import BaseOSINTModule, OSINTResult

UA = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36",
    "Accept-Language": "en",
}

Profile = Dict[str, Any]


# ── profile extractors (only for JSON APIs) ──────────────────────
def _github(j: dict) -> Profile:
    return {
        "name": j.get("name"), "bio": j.get("bio"), "location": j.get("location"),
        "website": j.get("blog") or None, "company": j.get("company"),
        "email": j.get("email"), "twitter": j.get("twitter_username"),
        "followers": j.get("followers"), "public_repos": j.get("public_repos"),
        "created": j.get("created_at"), "avatar": j.get("avatar_url"),
    }


def _gitlab(j: list) -> Profile:
    u = j[0]
    return {"name": u.get("name"), "avatar": u.get("avatar_url"), "state": u.get("state")}


def _keybase(j: dict) -> Profile:
    them = j["them"][0]
    basics = them.get("basics") or {}
    prof = them.get("profile") or {}
    linked = [
        {"service": p.get("proof_type"), "handle": p.get("nametag"), "url": p.get("service_url")}
        for p in (them.get("proofs_summary") or {}).get("all", [])
    ]
    return {
        "name": prof.get("full_name"), "bio": prof.get("bio"), "location": prof.get("location"),
        "created": basics.get("ctime"), "linked_accounts": linked,
    }


def _hn(j: dict) -> Profile:
    return {"karma": j.get("karma"), "about": j.get("about"), "created": j.get("created")}


def _devto(j: dict) -> Profile:
    return {
        "name": j.get("name"), "bio": j.get("summary"), "location": j.get("location"),
        "website": j.get("website_url"), "twitter": j.get("twitter_username"),
        "github": j.get("github_username"), "created": j.get("joined_at"),
    }


def _mastodon(j: dict) -> Profile:
    return {
        "name": j.get("display_name"), "bio": j.get("note"), "followers": j.get("followers_count"),
        "created": j.get("created_at"), "url": j.get("url"),
        "links": [f.get("value") for f in j.get("fields", []) if f.get("value")],
    }


def _bluesky(j: dict) -> Profile:
    return {
        "name": j.get("displayName"), "bio": j.get("description"),
        "followers": j.get("followersCount"), "created": j.get("createdAt"),
    }


def _dockerhub(j: dict) -> Profile:
    return {"name": j.get("full_name"), "location": j.get("location"), "company": j.get("company"),
            "created": j.get("date_joined")}


def _codeberg(j: dict) -> Profile:
    return {"name": j.get("full_name"), "bio": j.get("description"), "location": j.get("location"),
            "website": j.get("website") or None, "created": j.get("created")}


def _chess(j: dict) -> Profile:
    return {"name": j.get("name"), "location": j.get("location"), "created": j.get("joined")}


def _lichess(j: dict) -> Profile:
    prof = j.get("profile") or {}
    return {"name": prof.get("realName"), "bio": prof.get("bio"), "location": prof.get("location"),
            "created": j.get("createdAt")}


# ── platform rules ───────────────────────────────────────────────
# check:   URL fetched to decide existence
# profile: public profile URL shown to the user
# exists:  (response) -> bool
# extract: optional (json) -> profile dict
def _status_ok(r: httpx.Response) -> bool:
    return r.status_code == 200


PLATFORMS: List[Dict[str, Any]] = [
    # quick
    {"name": "GitHub", "check": "https://api.github.com/users/{}", "profile": "https://github.com/{}",
     "exists": _status_ok, "extract": _github},
    {"name": "GitLab", "check": "https://gitlab.com/api/v4/users?username={}", "profile": "https://gitlab.com/{}",
     "exists": lambda r: r.status_code == 200 and r.text.strip() not in ("", "[]"), "extract": _gitlab},
    {"name": "Codeberg", "check": "https://codeberg.org/api/v1/users/{}", "profile": "https://codeberg.org/{}",
     "exists": _status_ok, "extract": _codeberg},
    {"name": "Keybase", "check": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}",
     "profile": "https://keybase.io/{}",
     "exists": lambda r: r.status_code == 200 and bool((r.json().get("them") or [None])[0]), "extract": _keybase},
    {"name": "Hacker News", "check": "https://hacker-news.firebaseio.com/v0/user/{}.json",
     "profile": "https://news.ycombinator.com/user?id={}",
     "exists": lambda r: r.status_code == 200 and r.text.strip() != "null", "extract": _hn},
    {"name": "DEV", "check": "https://dev.to/api/users/by_username?url={}", "profile": "https://dev.to/{}",
     "exists": _status_ok, "extract": _devto},
    {"name": "Mastodon (mastodon.social)", "check": "https://mastodon.social/api/v1/accounts/lookup?acct={}",
     "profile": "https://mastodon.social/@{}", "exists": _status_ok, "extract": _mastodon},
    {"name": "Bluesky", "check": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social",
     "profile": "https://bsky.app/profile/{}.bsky.social", "exists": _status_ok, "extract": _bluesky},
    {"name": "Docker Hub", "check": "https://hub.docker.com/v2/users/{}/", "profile": "https://hub.docker.com/u/{}",
     "exists": _status_ok, "extract": _dockerhub},
    {"name": "Telegram", "check": "https://t.me/{}", "profile": "https://t.me/{}",
     "exists": lambda r: r.status_code == 200 and "tgme_page_title" in r.text},
    # deep
    {"name": "Chess.com", "check": "https://api.chess.com/pub/player/{}", "profile": "https://www.chess.com/member/{}",
     "exists": _status_ok, "extract": _chess, "deep": True},
    {"name": "Lichess", "check": "https://lichess.org/api/user/{}", "profile": "https://lichess.org/@/{}",
     "exists": _status_ok, "extract": _lichess, "deep": True},
    {"name": "Steam", "check": "https://steamcommunity.com/id/{}", "profile": "https://steamcommunity.com/id/{}",
     "exists": lambda r: r.status_code == 200 and "The specified profile could not be found" not in r.text, "deep": True},
    {"name": "SoundCloud", "check": "https://soundcloud.com/{}", "profile": "https://soundcloud.com/{}",
     "exists": _status_ok, "deep": True},
    {"name": "Patreon", "check": "https://www.patreon.com/{}", "profile": "https://www.patreon.com/{}",
     "exists": _status_ok, "deep": True},
    {"name": "Replit", "check": "https://replit.com/@{}", "profile": "https://replit.com/@{}",
     "exists": _status_ok, "deep": True},
]


def _clean(profile: Profile) -> Profile:
    return {k: v for k, v in profile.items() if v not in (None, "", [], {})}


class UsernameIntelModule(BaseOSINTModule):
    """Where does this handle exist, and what do those public profiles say?"""

    MAX_WORKERS = 12
    TIMEOUT = 8.0
    SHERLOCK_TIMEOUT = 180

    def __init__(self):
        super().__init__(name="username_intel", display_name="Username Intelligence")

    def run(self, target: str, deep: bool = False) -> List[OSINTResult]:
        self.log_start(target)
        username = target.strip().lstrip("@")
        if not self.validate_target(username, "username"):
            self.logger.warning(f"Invalid username format: {target}")
            return []

        platforms = [p for p in PLATFORMS if deep or not p.get("deep")]
        results, missing, unknown = self._check_platforms(username, platforms)

        # Infostealer exposure for the handle (quick; exposure facts only)
        from app.osint.exposure import hudson_rock
        try:
            results.extend(hudson_rock("username", username))
        except Exception as e:
            self.logger.info(f"Hudson Rock failed: {e}")

        if deep:
            # WhatsMyName: ~650 sites with explicit exists/missing signals.
            # Replaces Sherlock here: as broad, far fewer false positives, ~30s vs ~3min.
            known = {r.data["platform"].lower() for r in results if r.data_type == "social_profile"}
            try:
                from app.osint import whatsmyname
                found, wmn_missing, wmn_unknown = whatsmyname.check_all(username)
                for f in found:
                    if f["name"].lower() in known or any(k in f["name"].lower() for k in known):
                        continue
                    results.append(OSINTResult(
                        source="WhatsMyName", source_url=f["url"], data_type="social_profile",
                        data={"platform": f["name"], "username": username, "url": f["url"], "exists": True,
                              "category": f["category"]},
                        confidence=0.75,
                    ))
                unknown = unknown + [f"{wmn_unknown} WhatsMyName sites"] if wmn_unknown else unknown
            except Exception as e:
                self.logger.warning(f"WhatsMyName failed: {e}")
            insta = self._check_instaloader(username)
            if insta:
                results.append(insta)

        # One summary so "not found" is visible without padding the findings
        results.append(OSINTResult(
            source="Username Check",
            data_type="username_summary",
            data={
                "username": username,
                "found_on": sorted({r.data["platform"] for r in results if r.data_type == "social_profile"}),
                "not_found_on": sorted(missing),
                "could_not_check": sorted(unknown),
            },
            confidence=1.0,
        ))
        self.log_success(len(results))
        return results

    def _check_one(self, client: httpx.Client, username: str, p: Dict[str, Any]):
        r = client.get(p["check"].format(username))
        if r.status_code in (403, 429) or r.status_code >= 500:
            return "unknown", None
        if not p["exists"](r):
            return "missing", None
        profile: Profile = {}
        if p.get("extract"):
            try:
                profile = _clean(p["extract"](r.json()))
            except (ValueError, KeyError, IndexError, TypeError):
                profile = {}
        return "found", profile

    def _check_platforms(self, username: str, platforms: List[Dict[str, Any]]):
        found: List[OSINTResult] = []
        missing: List[str] = []
        unknown: List[str] = []
        with httpx.Client(timeout=self.TIMEOUT, headers=UA, follow_redirects=True) as client, \
                concurrent.futures.ThreadPoolExecutor(self.MAX_WORKERS) as pool:
            futures = {pool.submit(self._check_one, client, username, p): p for p in platforms}
            for fut in concurrent.futures.as_completed(futures):
                p = futures[fut]
                try:
                    state, profile = fut.result()
                except Exception as e:
                    self.logger.info(f"{p['name']} check failed: {e}")
                    unknown.append(p["name"])
                    continue
                if state == "missing":
                    missing.append(p["name"])
                elif state == "unknown":
                    unknown.append(p["name"])
                else:
                    url = p["profile"].format(username)
                    found.append(OSINTResult(
                        source="Username Check",
                        source_url=url,
                        data_type="social_profile",
                        data={"platform": p["name"], "username": username, "url": url, "exists": True,
                              "profile": profile},
                        confidence=0.95 if p.get("extract") else 0.8,
                    ))
        found.sort(key=lambda r: r.data["platform"])
        return found, missing, unknown

    def _sherlock_cmd(self) -> Optional[List[str]]:
        exe = shutil.which("sherlock") or str(Path(sys.executable).with_name("sherlock"))
        return [exe] if Path(exe).exists() else None

    def _check_sherlock(self, username: str) -> List[OSINTResult]:
        cmd = self._sherlock_cmd()
        if not cmd:
            self.logger.info("Sherlock is not installed; skipping")
            return []
        results: List[OSINTResult] = []
        try:
            proc = subprocess.run(
                cmd + [username, "--timeout", "6", "--print-found", "--no-color"],
                capture_output=True, text=True, timeout=self.SHERLOCK_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            self.logger.warning("Sherlock timed out")
            return results
        except Exception as e:
            self.logger.warning(f"Sherlock failed: {e}")
            return results
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("[+]"):
                continue
            platform, _, url = line[3:].partition(":")
            url = url.strip()
            if not url.startswith("http"):
                continue
            results.append(OSINTResult(
                source="Sherlock",
                source_url=url,
                data_type="social_profile",
                data={"platform": platform.strip(), "username": username, "url": url, "exists": True},
                confidence=0.75,
            ))
        return results

    def _check_instaloader(self, username: str) -> Optional[OSINTResult]:
        try:
            import instaloader

            class _FailFast(instaloader.RateController):
                # Instagram 429s otherwise make Instaloader sleep for ~11 minutes
                def sleep(self, secs):
                    raise instaloader.exceptions.TooManyRequestsException("rate limited")

            loader = instaloader.Instaloader(
                quiet=True, max_connection_attempts=1, request_timeout=8,
                rate_controller=lambda ctx: _FailFast(ctx),
            )
            p = instaloader.Profile.from_username(loader.context, username)
        except Exception as e:  # not on Instagram, rate limited, or login wall
            self.logger.debug(f"Instaloader: {e}")
            return None
        url = f"https://instagram.com/{username}"
        return OSINTResult(
            source="Instaloader",
            source_url=url,
            data_type="social_profile",
            data={
                "platform": "Instagram", "username": username, "url": url, "exists": True,
                "profile": _clean({
                    "name": p.full_name, "bio": p.biography, "website": p.external_url,
                    "followers": p.followers, "following": p.followees,
                    "verified": p.is_verified, "private": p.is_private,
                }),
            },
            confidence=0.95,
        )


username_intel = UsernameIntelModule()
