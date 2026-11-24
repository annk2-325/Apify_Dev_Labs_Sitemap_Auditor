"""Offline unit tests for core.ssrf (URL normalization & SSRF protection)."""

from __future__ import annotations

import socket
from typing import Any

import pytest

from core.ssrf import (
    DNSResolutionError,
    SSRFBlockedError,
    ValidatedTarget,
    extract_host,
    is_ip_globally_routable,
    is_same_host,
    normalize_url,
    validate_url,
    validate_url_async,
)


def _fake_addrinfo(*ips: str, port: int = 443) -> list[tuple[Any, ...]]:
    """Build standard socket.getaddrinfo-shaped 5-tuples for offline tests."""
    entries: list[tuple[Any, ...]] = []
    for ip in ips:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
        entries.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
    return entries


class TestUrlNormalization:
    """Tests for RFC 3986 URL normalization and scheme enforcement."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("HTTPS://EXAMPLE.COM", "https://example.com/"),
            ("https://Example.COM/Docs/Index.HTML", "https://example.com/Docs/Index.HTML"),
            ("http://example.com:80/sitemap.xml", "http://example.com/sitemap.xml"),
            ("https://example.com:443/sitemap.xml", "https://example.com/sitemap.xml"),
            ("https://example.com:8443/sitemap.xml", "https://example.com:8443/sitemap.xml"),
            ("https://example.com/blog/", "https://example.com/blog/"),
            ("https://example.com/blog", "https://example.com/blog"),
            ("https://example.com/a/b/../c", "https://example.com/a/c"),
            ("https://example.com/a/b/..", "https://example.com/a/"),
            ("https://example.com/./x/./y", "https://example.com/x/y"),
            ("https://example.com/page#section-2", "https://example.com/page"),
            ("https://example.com/search?q=seo&lang=en#top", "https://example.com/search?q=seo&lang=en"),
            ("https://example.com/page?", "https://example.com/page"),
            ("https://example.com./sitemap.xml", "https://example.com/sitemap.xml"),
            ("  https://example.com/a  ", "https://example.com/a"),
            ("https://例え.jp/path", "https://xn--r8jz45g.jp/path"),
        ],
    )
    def test_valid_http_https_urls(self, raw: str, expected: str) -> None:
        assert normalize_url(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("example.com", "https://example.com/"),
            ("Example.COM/sitemap.xml", "https://example.com/sitemap.xml"),
            ("example.com:8443/sitemap.xml", "https://example.com:8443/sitemap.xml"),
            ("docs.python.org/3/", "https://docs.python.org/3/"),
        ],
    )
    def test_bare_host_allowed_when_enabled(self, raw: str, expected: str) -> None:
        assert normalize_url(raw, allow_bare_host=True) == expected

    def test_bare_host_rejected_in_strict_mode(self) -> None:
        with pytest.raises(SSRFBlockedError):
            normalize_url("example.com")

    @pytest.mark.parametrize(
        "bad_url",
        [
            "",
            "   ",
            "file:///etc/passwd",
            "file:/etc/passwd",
            "ftp://example.com/sitemap.xml",
            "javascript:alert(1)",
            "data:text/html,<h1>hi</h1>",
            "gopher://127.0.0.1:6379/_INFO",
            "mailto:user@example.com",
            "http:example.com",
            "https:example.com",
            "//example.com/sitemap.xml",
            "https://user:pass@example.com/",
            "https://trusted.com@127.0.0.1/",
            r"https://good.com\@127.0.0.1/",
            "https://example.com/path with spaces",
            "https://example.com/\r\nInjected: 1",
            "https://example.com:0/",
            "https://example.com:70000/",
            "http://[fe80::1%eth0]/",
            "https://example..com/",
        ],
    )
    @pytest.mark.parametrize("allow_bare_host", [False, True])
    def test_disallowed_schemes_and_malformed_urls_blocked(
        self, bad_url: str, allow_bare_host: bool
    ) -> None:
        with pytest.raises(SSRFBlockedError):
            normalize_url(bad_url, allow_bare_host=allow_bare_host)

    def test_extract_host_and_is_same_host(self) -> None:
        assert extract_host("HTTPS://Docs.Python.ORG./3/") == "docs.python.org"
        assert is_same_host("https://example.com/a", "http://EXAMPLE.COM./b") is True
        assert is_same_host("https://example.com/a", "https://www.example.com/a") is False


class TestGlobalIpCheck:
    """Tests for IP address global routability classification."""

    @pytest.mark.parametrize(
        "global_ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ],
    )
    def test_global_ips_allowed(self, global_ip: str) -> None:
        assert is_ip_globally_routable(global_ip) is True

    @pytest.mark.parametrize(
        "blocked_ip",
        [
            "127.0.0.1",
            "127.255.255.254",
            "::1",
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.100",
            "169.254.169.254",
            "169.254.0.1",
            "0.0.0.0",
            "::",
            "100.64.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "fe80::1",
            "fe80::1%eth0",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "64:ff9b::127.0.0.1",
            "64:ff9b::8.8.8.8",
            "not-an-ip",
            "",
        ],
    )
    def test_non_global_ips_blocked(self, blocked_ip: str) -> None:
        assert is_ip_globally_routable(blocked_ip) is False


class TestSsrfValidation:
    """Tests for sync & async SSRF validation with mocked DNS resolution."""

    @pytest.mark.parametrize(
        "blocked_target",
        [
            "http://localhost/",
            "http://localhost:8080/admin",
            "https://sub.localhost/sitemap.xml",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://10.0.0.1/internal",
            "http://172.16.0.5/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://0.0.0.0/",
            "http://100.64.0.1/",
            "http://224.0.0.1/",
            # Obfuscated numeric IPv4 literals
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://127.1/",
            "http://2852039166/latest/meta-data/",
        ],
    )
    def test_direct_private_and_localhost_targets_blocked_offline(
        self, blocked_target: str
    ) -> None:
        called = False

        def fail_if_dns_called(host: str, port: int) -> list[str]:
            nonlocal called
            called = True
            return ["8.8.8.8"]

        with pytest.raises(SSRFBlockedError):
            validate_url(blocked_target, resolver=fail_if_dns_called)
        assert called is False

    def test_direct_global_ip_literal_allowed(self) -> None:
        target = validate_url("https://93.184.216.34/sitemap.xml")
        assert target == ValidatedTarget(
            normalized_url="https://93.184.216.34/sitemap.xml",
            scheme="https",
            hostname="93.184.216.34",
            port=443,
            resolved_ips=("93.184.216.34",),
        )

    def test_dns_mock_global_ipv4_and_ipv6_allowed(self) -> None:
        def mock_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
            assert host == "www.sitemaps.org"
            assert port == 443
            return _fake_addrinfo("93.184.216.34", "2606:4700:4700::1111", "93.184.216.34")

        target = validate_url("https://www.sitemaps.org/sitemap.xml", resolver=mock_resolver)
        assert target.normalized_url == "https://www.sitemaps.org/sitemap.xml"
        assert target.resolved_ips == ("93.184.216.34", "2606:4700:4700::1111")

    @pytest.mark.parametrize(
        "resolved_ip",
        [
            "127.0.0.1",
            "::1",
            "10.0.0.10",
            "172.16.12.34",
            "192.168.10.20",
            "169.254.169.254",
            "::ffff:127.0.0.1",
        ],
    )
    def test_dns_mock_resolving_to_non_global_ip_blocked(self, resolved_ip: str) -> None:
        def mock_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
            return _fake_addrinfo(resolved_ip, port=port)

        with pytest.raises(SSRFBlockedError, match="Blocked non-global IP"):
            validate_url("https://evil.example/sitemap.xml", resolver=mock_resolver)

    def test_dns_mock_mixed_global_and_private_ips_blocked(self) -> None:
        """All resolved IPs must be global; a single private IP must block the host."""

        def mock_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
            return _fake_addrinfo("8.8.8.8", "10.0.0.1", port=port)

        with pytest.raises(SSRFBlockedError, match="10.0.0.1"):
            validate_url("https://rebind.example/", resolver=mock_resolver)

    def test_dns_mock_empty_result_blocked(self) -> None:
        with pytest.raises(SSRFBlockedError, match="no IP addresses"):
            validate_url("https://empty.example/", resolver=lambda h, p: [])

    def test_dns_failure_raises_dns_resolution_error(self) -> None:
        def failing_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
            raise socket.gaierror(11001, "getaddrinfo failed")

        with pytest.raises(DNSResolutionError):
            validate_url("https://nonexistent.invalid/", resolver=failing_resolver)

    async def test_validate_url_async_supports_async_resolver_and_redirect_hop_check(
        self,
    ) -> None:
        dns_table: dict[str, list[str]] = {
            "public.example": ["93.184.216.34"],
            "internal-redirect.example": ["169.254.169.254"],
        }

        async def async_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
            if host not in dns_table:
                raise socket.gaierror(11001, "NXDOMAIN")
            return _fake_addrinfo(*dns_table[host], port=port)

        hop1 = await validate_url_async("https://public.example/start", resolver=async_resolver)
        assert hop1.resolved_ips == ("93.184.216.34",)

        # Redirect target resolving to cloud metadata IP must be blocked
        with pytest.raises(SSRFBlockedError, match="169.254.169.254"):
            await validate_url_async(
                "http://internal-redirect.example/latest/meta-data/",
                resolver=async_resolver,
            )

    async def test_validate_url_async_accepts_sync_mock_resolver(self) -> None:
        target = await validate_url_async(
            "https://docs.python.org/3/",
            resolver=lambda h, p: ["151.101.0.223"],
        )
        assert target.hostname == "docs.python.org"
        assert target.resolved_ips == ("151.101.0.223",)
