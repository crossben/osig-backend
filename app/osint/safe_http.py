"""
SSRF-safe HTTP for fetching target-controlled URLs.

A scan target is user input: `evil.example` can resolve to 127.0.0.1, 10.x,
or 169.254.169.254 (cloud metadata). Anything that fetches the target itself
must go through here:
  - every hostname is resolved and ALL its addresses must be public
  - the connection is pinned to the checked IP (no DNS-rebinding window),
    with Host header and TLS SNI/verification still using the real hostname
  - redirects are followed manually, re-checking each hop, with a hop cap
Third-party APIs with fixed hostnames (crt.sh, ip-api, ...) don't need this.
"""

import ipaddress
import socket
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

MAX_REDIRECTS = 5


class UnsafeTargetError(Exception):
    """The target resolves to a non-public address."""


def public_addresses(host: str, port: int = 443) -> List[str]:
    """All addresses for host, or UnsafeTargetError if any is not globally routable."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnsafeTargetError(f"{host} does not resolve") from e
    ips = list(dict.fromkeys(info[4][0] for info in infos))
    for ip in ips:
        addr = ipaddress.ip_address(ip.split("%")[0])
        if not addr.is_global or addr.is_multicast:
            raise UnsafeTargetError(f"{host} resolves to non-public address {ip}")
    if not ips:
        raise UnsafeTargetError(f"{host} does not resolve")
    return ips


def _pinned(url: str) -> Tuple[str, str, str]:
    """Rewrite url to connect to a vetted IP; returns (pinned_url, host, ip)."""
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UnsafeTargetError(f"Refusing to fetch {url!r}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    ip = public_addresses(parts.hostname, port)[0]
    netloc_ip = f"[{ip}]" if ":" in ip else ip
    if parts.port:
        netloc_ip += f":{parts.port}"
    return urlunparse(parts._replace(netloc=netloc_ip)), parts.hostname, ip


def safe_get(url: str, *, headers: Optional[Dict[str, str]] = None, timeout: float = 10.0,
             verify: bool = True) -> httpx.Response:
    """GET a target-controlled URL; follows up to MAX_REDIRECTS hops, each one re-vetted."""
    headers = dict(headers or {})
    with httpx.Client(timeout=timeout, verify=verify, follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            pinned_url, host, _ip = _pinned(url)
            resp = client.get(
                pinned_url,
                headers={**headers, "Host": urlparse(url).netloc},
                extensions={"sni_hostname": host},
            )
            if resp.is_redirect and resp.headers.get("location"):
                url = urljoin(url, resp.headers["location"])
                continue
            # Report the real URL, not the pinned IP form
            resp.request.url = httpx.URL(url)
            return resp
    raise UnsafeTargetError(f"Too many redirects starting from {url}")


def safe_tls_connect(host: str, port: int = 443, timeout: float = 6.0) -> socket.socket:
    """TCP connection to a vetted public address of host (caller wraps it in TLS)."""
    ip = public_addresses(host, port)[0]
    return socket.create_connection((ip, port), timeout=timeout)


def safe_post_json(url: str, payload: dict, timeout: float = 10.0) -> httpx.Response:
    """POST JSON to a user-supplied https URL (webhooks). No redirects are followed."""
    if urlparse(url).scheme != "https":
        raise UnsafeTargetError("Webhooks must use https")
    pinned_url, host, _ip = _pinned(url)
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        return client.post(pinned_url, json=payload, headers={"Host": urlparse(url).netloc},
                           extensions={"sni_hostname": host})
