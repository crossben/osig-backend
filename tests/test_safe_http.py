"""SSRF guard: targets resolving to non-public addresses are refused."""
import socket

import pytest

from app.osint.safe_http import UnsafeTargetError, public_addresses, safe_get


def fake_resolver(mapping):
    def getaddrinfo(host, port, *args, **kwargs):
        ips = mapping[host]
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]
    return getaddrinfo


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "192.168.0.10", "172.16.5.5", "169.254.169.254", "::1", "fc00::1", "0.0.0.0"])
def test_non_public_addresses_are_blocked(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver({"evil.test": [ip]}))
    with pytest.raises(UnsafeTargetError):
        public_addresses("evil.test")


def test_mixed_answers_are_blocked(monkeypatch):
    # One public + one private record must still be refused (DNS round-robin trick)
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver({"mixed.test": ["93.184.215.14", "10.0.0.5"]}))
    with pytest.raises(UnsafeTargetError):
        public_addresses("mixed.test")


def test_public_address_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver({"ok.test": ["93.184.215.14"]}))
    assert public_addresses("ok.test") == ["93.184.215.14"]


def test_non_http_scheme_refused():
    with pytest.raises(UnsafeTargetError):
        safe_get("file:///etc/passwd")
