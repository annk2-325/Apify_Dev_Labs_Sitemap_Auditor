"""Offline unit tests for core.http_client and core.sitemap_parser."""

from __future__ import annotations

import gzip
from pathlib import Path

import httpx
import pytest

from core.http_client import (
    MAX_REDIRECT_HOPS,
    DomainHttpClient,
    is_waf_or_rate_limit_block,
)
from core.robots import RobotsChecker
from core.sitemap_parser import (
    GzipBombError,
    GzipDecompressError,
    discover_and_parse_sitemaps,
    is_explicit_sitemap_url,
    is_valid_lastmod,
    parse_sitemap_bytes,
    safe_decompress_gzip,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _public_dns(host: str, port: int) -> list[str]:
    """Offline mock DNS resolving all test domains to a global IP."""
    return ["93.184.216.34"]


class TestDomainHttpClient:
    """Offline tests for manual redirects, per-hop SSRF checks, OOM caps, and proxy escalation."""

    async def test_manual_redirect_chain_and_multi_headers(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url == "https://example.com/old":
                return httpx.Response(301, headers={"Location": "/mid"})
            if url == "https://example.com/mid":
                return httpx.Response(302, headers={"Location": "https://example.com/final"})
            return httpx.Response(
                200,
                headers=[
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("X-Robots-Tag", "noindex"),
                    ("X-Robots-Tag", "nofollow"),
                ],
                content=b"<html><body>ok</body></html>",
            )

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            res = await client.fetch("https://example.com/old")

        assert res.status_code == 200
        assert res.final_url == "https://example.com/final"
        assert res.redirect_hops == 2
        assert res.redirect_chain == [
            "https://example.com/old",
            "https://example.com/mid",
            "https://example.com/final",
        ]
        assert res.get_header_values("x-robots-tag") == ["noindex", "nofollow"]
        assert res.error is None

    async def test_redirect_to_private_or_metadata_ip_blocked_by_ssrf(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == "https://example.com/start":
                return httpx.Response(
                    302,
                    headers={"Location": "http://169.254.169.254/latest/meta-data/"},
                )
            pytest.fail("HTTP request must never reach the SSRF redirect target.")

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            res = await client.fetch("https://example.com/start")

        assert res.ssrf_blocked is True
        assert res.error is not None and "SSRF_BLOCKED" in res.error

    async def test_redirect_to_host_resolving_to_private_ip_blocked(self) -> None:
        def split_dns(host: str, port: int) -> list[str]:
            if host == "internal.attacker.test":
                return ["10.0.0.5"]
            return ["93.184.216.34"]

        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == "https://example.com/start":
                return httpx.Response(
                    302, headers={"Location": "https://internal.attacker.test/secret"}
                )
            pytest.fail("Redirect target with private DNS resolution must be blocked.")

        async with DomainHttpClient(
            dns_resolver=split_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            res = await client.fetch("https://example.com/start")

        assert res.ssrf_blocked is True

    async def test_redirect_loop_detected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == "https://example.com/a":
                return httpx.Response(302, headers={"Location": "https://example.com/b"})
            return httpx.Response(302, headers={"Location": "https://example.com/a"})

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            res = await client.fetch("https://example.com/a")

        assert res.redirect_loop is True
        assert res.error is not None and "REDIRECT_LOOP" in res.error
        assert res.redirect_chain == [
            "https://example.com/a",
            "https://example.com/b",
            "https://example.com/a",
        ]

    async def test_too_many_redirects_enforces_max_10_hops(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            step = int(request.url.path.lstrip("/hop-"))
            return httpx.Response(302, headers={"Location": f"/hop-{step + 1}"})

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            res = await client.fetch("https://example.com/hop-0")

        assert res.too_many_redirects is True
        assert res.redirect_hops == MAX_REDIRECT_HOPS
        assert res.error is not None and "TOO_MANY_REDIRECTS" in res.error

    async def test_streaming_oom_byte_limit_truncates_safely(self) -> None:
        payload = b"x" * 1024

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=payload)

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            res = await client.fetch("https://example.com/big", max_bytes=128)

        assert res.status_code == 200
        assert res.truncated is True
        assert len(res.body) == 128

    async def test_proxy_escalation_on_403_is_sticky_per_domain(self) -> None:
        direct_calls = 0
        proxy_calls = 0
        factory_calls: list[bool] = []

        def direct_handler(request: httpx.Request) -> httpx.Response:
            nonlocal direct_calls
            direct_calls += 1
            return httpx.Response(403, content=b"Blocked by WAF")

        def proxy_handler(request: httpx.Request) -> httpx.Response:
            nonlocal proxy_calls
            proxy_calls += 1
            return httpx.Response(200, content=b"Proxy OK")

        async def proxy_factory(escalated: bool) -> str | None:
            factory_calls.append(escalated)
            return "http://proxy.internal.test:8000"

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(direct_handler),
            proxy_url_factory=proxy_factory,
            proxy_transport_factory=lambda _url: httpx.MockTransport(proxy_handler),
            auto_escalate_proxy=True,
        ) as client:
            res1 = await client.fetch("https://example.com/page-1")
            res2 = await client.fetch("https://example.com/page-2")
            assert client.proxy_escalated is True

        assert res1.status_code == 200
        assert res1.used_proxy is True
        assert res2.status_code == 200
        assert res2.used_proxy is True
        # First request hits direct once then escalates; second goes straight to proxy
        assert direct_calls == 1
        assert proxy_calls == 2
        assert factory_calls == [True]

    async def test_proxy_escalation_respects_allow_flag_for_ai_bot_probes(self) -> None:
        factory_called = False

        async def proxy_factory(escalated: bool) -> str | None:
            nonlocal factory_called
            factory_called = True
            return "http://proxy.internal.test:8000"

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(lambda _req: httpx.Response(403)),
            proxy_url_factory=proxy_factory,
            auto_escalate_proxy=True,
        ) as client:
            res = await client.fetch(
                "https://example.com/", allow_proxy_escalation=False
            )
            assert client.proxy_escalated is False

        assert res.status_code == 403
        assert res.used_proxy is False
        assert factory_called is False

    def test_waf_block_detection_signals(self) -> None:
        assert is_waf_or_rate_limit_block(403, {}, b"") is True
        assert is_waf_or_rate_limit_block(429, {}, b"") is True
        assert is_waf_or_rate_limit_block(503, {}, b"") is True
        assert is_waf_or_rate_limit_block(200, {"cf-mitigated": "challenge"}, b"") is True
        assert (
            is_waf_or_rate_limit_block(
                200,
                {"content-type": "text/html"},
                b"<html><title>Just a moment...</title>Cloudflare</html>",
            )
            is True
        )
        assert (
            is_waf_or_rate_limit_block(
                200, {"content-type": "text/html"}, b"<html><body>Hello</body></html>"
            )
            is False
        )


class TestSitemapUnitParsing:
    """Offline fixture tests for single-file Sitemap parsing & security defenses."""

    def test_parse_xml_urlset_fixture_detects_duplicates_cross_host_and_lastmod(
        self,
    ) -> None:
        raw = (FIXTURES / "sitemap_urlset.xml").read_bytes()
        parsed = parse_sitemap_bytes(
            raw,
            sitemap_url="https://example.com/sitemap.xml",
            target_host="example.com",
        )
        assert parsed.file_result.format == "xml_urlset"
        assert parsed.file_result.recovered_xml is False
        assert parsed.file_result.is_gzipped is False
        assert parsed.file_result.url_count == 5

        by_raw = {u.raw_url: u for u in parsed.urls}
        # Duplicate normalized URL matches https://example.com/
        assert by_raw["https://EXAMPLE.COM:443/#duplicate-fragment"].url == "https://example.com/"
        assert by_raw["https://example.com/docs/guide"].lastmod_valid is True
        assert by_raw["https://example.com/docs/guide"].priority == 0.8
        assert by_raw["https://example.com/blog/bad-date"].lastmod_valid is False
        assert by_raw["https://other-host.example/landing"].is_cross_host is True

    def test_parse_xml_index_fixture(self) -> None:
        raw = (FIXTURES / "sitemap_index.xml").read_bytes()
        parsed = parse_sitemap_bytes(
            raw,
            sitemap_url="https://example.com/sitemap_index.xml",
            target_host="example.com",
        )
        assert parsed.file_result.format == "xml_index"
        assert parsed.file_result.child_sitemap_count == 2
        assert parsed.child_sitemaps == [
            "https://example.com/sitemaps/pages.xml",
            "https://example.com/sitemaps/posts.xml.gz",
        ]

    def test_parse_gzipped_sitemap_detected_by_magic_bytes_without_gz_extension(
        self,
    ) -> None:
        raw_gz = (FIXTURES / "sitemap_urlset.xml.gz").read_bytes()
        parsed = parse_sitemap_bytes(
            raw_gz,
            sitemap_url="https://example.com/sitemap.xml",  # intentionally no .gz suffix
            target_host="example.com",
        )
        assert parsed.file_result.is_gzipped is True
        assert parsed.file_result.format == "xml_urlset"
        assert parsed.file_result.url_count == 5

    def test_gzip_bomb_blocked_at_decompression_cap(self) -> None:
        # 2 MB of zeroes compresses to ~2 KB, simulating a high-ratio gzip bomb
        bomb = gzip.compress(b"0" * (2 * 1024 * 1024), mtime=0)
        with pytest.raises(GzipBombError):
            safe_decompress_gzip(bomb, max_out_bytes=64 * 1024)

        parsed = parse_sitemap_bytes(
            bomb,
            sitemap_url="https://example.com/bomb.xml.gz",
            target_host="example.com",
            max_decompressed_bytes=64 * 1024,
        )
        assert parsed.file_result.is_gzipped is True
        assert parsed.file_result.truncated is True
        assert parsed.file_result.error is not None
        assert "GZIP_DECOMPRESSION_LIMIT_EXCEEDED" in parsed.file_result.error

    def test_corrupted_gzip_handled_without_crashing(self) -> None:
        corrupt = b"\x1f\x8b\x08\x00corrupt-data"
        with pytest.raises(GzipDecompressError):
            safe_decompress_gzip(corrupt)

        parsed = parse_sitemap_bytes(
            corrupt,
            sitemap_url="https://example.com/bad.xml.gz",
            target_host="example.com",
        )
        assert parsed.file_result.is_gzipped is True
        assert parsed.file_result.error is not None
        assert "GZIP_DECOMPRESS_ERROR" in parsed.file_result.error

    def test_broken_xml_recovers_and_sets_recovered_flag(self) -> None:
        raw = (FIXTURES / "sitemap_broken.xml").read_bytes()
        parsed = parse_sitemap_bytes(
            raw,
            sitemap_url="https://example.com/broken.xml",
            target_host="example.com",
        )
        assert parsed.file_result.format == "xml_urlset"
        assert parsed.file_result.recovered_xml is True
        urls = [entry.url for entry in parsed.urls]
        assert "https://example.com/recovered-1" in urls
        assert "https://example.com/recovered-2" in urls

    def test_xxe_entity_expansion_is_disabled(self) -> None:
        raw = (FIXTURES / "sitemap_xxe.xml").read_bytes()
        parsed = parse_sitemap_bytes(
            raw,
            sitemap_url="https://example.com/xxe.xml",
            target_host="example.com",
        )
        assert parsed.file_result.format == "xml_urlset"
        assert [entry.url for entry in parsed.urls] == ["https://example.com/safe-page"]

    def test_plain_text_sitemap_fixture(self) -> None:
        raw = (FIXTURES / "sitemap_plain.txt").read_bytes()
        parsed = parse_sitemap_bytes(
            raw,
            sitemap_url="https://example.com/sitemap.txt",
            target_host="example.com",
        )
        assert parsed.file_result.format == "text"
        assert parsed.file_result.url_count == 5
        assert any(u.is_cross_host for u in parsed.urls)

    def test_html_soft_404_rejected_as_unknown_format(self) -> None:
        html = b"<!DOCTYPE html><html><head><title>404</title></head><body>Not found</body></html>"
        parsed = parse_sitemap_bytes(
            html,
            sitemap_url="https://example.com/sitemap.xml",
            target_host="example.com",
        )
        assert parsed.file_result.format == "unknown"
        assert parsed.file_result.error is not None
        assert "UNSUPPORTED_XML_ROOT" in parsed.file_result.error

    def test_exceeded_50k_url_limit_flagged(self) -> None:
        # 50,001 plain-text URLs verifies the exact 50,000 sitemaps.org threshold
        payload = "\n".join(f"https://example.com/p/{i}" for i in range(50_001)).encode()
        parsed = parse_sitemap_bytes(
            payload,
            sitemap_url="https://example.com/huge.txt",
            target_host="example.com",
        )
        assert parsed.file_result.format == "text"
        assert parsed.file_result.url_count == 50_001
        assert parsed.file_result.exceeded_50k_limit is True

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("2026", True),
            ("2026-11", True),
            ("2026-11-24", True),
            ("2026-11-24T12:30Z", True),
            ("2026-11-24T12:30:45+09:00", True),
            ("2026-11-24T12:30:45.123-05:00", True),
            ("2026-02-30", False),
            ("2026-13-01", False),
            ("2026-11-24 12:30:00", False),
            ("24/11/2026", False),
            ("not-a-date", False),
        ],
    )
    def test_is_valid_lastmod(self, value: str, expected: bool) -> None:
        assert is_valid_lastmod(value) is expected

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://example.com/", False),
            ("https://example.com/docs/", False),
            ("https://example.com/robots.txt", False),
            ("https://example.com/llms.txt", False),
            ("https://example.com/sitemap.xml", True),
            ("https://example.com/sitemap_index.xml", True),
            ("https://example.com/sitemap.xml.gz", True),
            ("https://example.com/urls.txt", True),
            ("https://example.com/wp-sitemap", True),
        ],
    )
    def test_is_explicit_sitemap_url(self, url: str, expected: bool) -> None:
        assert is_explicit_sitemap_url(url) is expected


class TestSitemapDiscoveryAndRecursion:
    """Offline orchestration tests for discovery order, nested indexes, cycles, and caps."""

    async def test_discovery_from_robots_txt_expands_nested_index_and_gzip(self) -> None:
        index_bytes = (FIXTURES / "sitemap_index.xml").read_bytes()
        urlset_bytes = (FIXTURES / "sitemap_urlset.xml").read_bytes()
        gz_bytes = (FIXTURES / "sitemap_urlset.xml.gz").read_bytes()
        broken_bytes = (FIXTURES / "sitemap_broken.xml").read_bytes()

        routes: dict[str, bytes] = {
            "https://example.com/sitemap_index.xml": index_bytes,
            "https://example.com/sitemaps/pages.xml": urlset_bytes,
            "https://example.com/sitemaps/posts.xml.gz": gz_bytes,
            "https://example.com/extra-sitemap.xml": broken_bytes,
        }

        def handler(request: httpx.Request) -> httpx.Response:
            body = routes.get(str(request.url))
            if body is None:
                return httpx.Response(404)
            return httpx.Response(200, content=body)

        robots = RobotsChecker.from_text(
            "https://example.com/robots.txt",
            (FIXTURES / "robots_standard.txt").read_text(encoding="utf-8"),
        )

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            discovery = await discover_and_parse_sitemaps(
                client,
                "https://example.com/",
                robots_checker=robots,
                max_urls_per_domain=50,
                max_sitemap_files=10,
            )

        stats = discovery.stats
        assert stats.discovery_method == "robots_txt"
        assert stats.sitemap_files_fetched == 4
        assert stats.sitemap_files_failed == 0
        assert stats.recovered_xml_files_count == 1
        assert stats.duplicate_urls_count >= 6  # pages.xml + identical posts.xml.gz + dup fragment
        assert stats.cross_host_urls_count == 1
        assert stats.invalid_lastmod_count == 1
        assert 0.0 < stats.lastmod_coverage_rate <= 1.0
        assert any(e.url == "https://example.com/recovered-1" for e in discovery.entries)

    async def test_fallback_probing_order_stops_at_first_valid_sitemap(self) -> None:
        requested: list[str] = []
        gz_bytes = (FIXTURES / "sitemap_urlset.xml.gz").read_bytes()

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            requested.append(url)
            if url == "https://example.com/sitemap.xml.gz":
                return httpx.Response(200, content=gz_bytes)
            return httpx.Response(404)

        empty_robots = RobotsChecker.from_text("https://example.com/robots.txt", "User-agent: *\nAllow: /\n")

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            discovery = await discover_and_parse_sitemaps(
                client,
                "https://example.com/",
                robots_checker=empty_robots,
            )

        assert requested == [
            "https://example.com/sitemap.xml",
            "https://example.com/sitemap_index.xml",
            "https://example.com/sitemap.xml.gz",
        ]
        assert discovery.stats.discovery_method == "fallback"
        assert discovery.stats.sitemap_files_fetched == 3
        assert discovery.stats.sitemap_files_failed == 2
        assert discovery.stats.unique_urls_count == 4

    async def test_explicit_sitemap_url_bypasses_robots_and_fallback(self) -> None:
        plain_bytes = (FIXTURES / "sitemap_plain.txt").read_bytes()

        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == "https://example.com/custom/urls.txt":
                return httpx.Response(200, content=plain_bytes)
            pytest.fail(f"Unexpected request: {request.url}")

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            discovery = await discover_and_parse_sitemaps(
                client,
                "https://example.com/custom/urls.txt",
                max_urls_per_domain=2,
            )

        assert discovery.stats.discovery_method == "explicit"
        assert discovery.stats.total_urls_found == 5
        assert discovery.stats.unique_urls_count == 4
        assert discovery.stats.duplicate_urls_count == 1
        assert discovery.stats.cross_host_urls_count == 1
        # Returned entries capped at max_urls_per_domain while stats remain accurate
        assert len(discovery.entries) == 2

    async def test_circular_sitemap_index_and_max_depth_guards(self) -> None:
        cycle_a = b"""<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <sitemap><loc>https://example.com/cycle-b.xml</loc></sitemap>
        </sitemapindex>"""
        cycle_b = b"""<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <sitemap><loc>https://example.com/cycle-a.xml</loc></sitemap>
        </sitemapindex>"""

        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == "https://example.com/cycle-a.xml":
                return httpx.Response(200, content=cycle_a)
            if str(request.url) == "https://example.com/cycle-b.xml":
                return httpx.Response(200, content=cycle_b)
            return httpx.Response(404)

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            discovery = await discover_and_parse_sitemaps(
                client,
                "https://example.com/cycle-a.xml",
                max_sitemap_files=20,
            )

        assert discovery.stats.sitemap_files_fetched == 2
        assert discovery.stats.unique_urls_count == 0

    async def test_nested_sitemap_index_respects_max_depth_5(self) -> None:
        # Build chain: depth 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 (depth 6 must NOT be fetched)
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            depth = int(path.removeprefix("/idx-").removesuffix(".xml"))
            if depth < 6:
                xml = (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    f"<sitemap><loc>https://example.com/idx-{depth + 1}.xml</loc></sitemap>"
                    "</sitemapindex>"
                ).encode()
                return httpx.Response(200, content=xml)
            xml = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                "<url><loc>https://example.com/too-deep</loc></url>"
                "</urlset>"
            ).encode()
            return httpx.Response(200, content=xml)

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            discovery = await discover_and_parse_sitemaps(
                client,
                "https://example.com/idx-0.xml",
                max_sitemap_files=20,
            )

        # Depths 0, 1, 2, 3, 4, 5 fetched (6 files total); depth 6 skipped because depth == MAX_SITEMAP_DEPTH (5)
        assert discovery.stats.sitemap_files_fetched == 6
        assert discovery.entries == []

