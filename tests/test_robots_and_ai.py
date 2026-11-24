"""Offline unit tests for core.robots (RFC 9309) and core.ai_probe (AI bots & /llms.txt)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from core.ai_probe import (
    analyze_llms_txt,
    is_differential_block,
    probe_ai_bots_and_llms,
)
from core.http_client import DomainHttpClient, FetchResult
from core.models import AI_BOT_NAMES
from core.robots import RobotsChecker, build_robots_url, fetch_robots

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _public_dns(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


class TestRobotsParser:
    """RFC 9309 robots.txt parsing, Sitemap directive extraction, and fallback rules."""

    def test_build_robots_url_uses_normalized_origin(self) -> None:
        assert build_robots_url("HTTPS://Example.COM:443/docs/page?x=1") == (
            "https://example.com/robots.txt"
        )
        assert build_robots_url("http://example.com:8080/a/b") == (
            "http://example.com:8080/robots.txt"
        )

    def test_parse_fixture_rules_and_ai_bot_directives(self) -> None:
        text = (FIXTURES / "robots_standard.txt").read_text(encoding="utf-8")
        checker = RobotsChecker.from_text("https://example.com/robots.txt", text)

        assert checker.info.status == "loaded"
        assert checker.info.http_status == 200

        # Wildcard rules including Allow precedence over shorter Disallow
        assert checker.can_fetch("https://example.com/", "*") is True
        assert checker.can_fetch("https://example.com/admin/settings", "*") is False
        assert checker.can_fetch("https://example.com/admin/public/info", "*") is True
        assert checker.can_fetch("https://example.com/private-page", "*") is False

        # Specific AI bot rules
        assert checker.can_fetch("https://example.com/", "GPTBot") is False
        assert checker.can_fetch("https://example.com/", "OAI-SearchBot") is True
        assert checker.can_fetch("https://example.com/docs/proprietary/spec", "ClaudeBot") is False
        assert checker.can_fetch("https://example.com/docs/public/guide", "ClaudeBot") is True
        # PerplexityBot falls back to wildcard (*)
        assert checker.can_fetch("https://example.com/", "PerplexityBot") is True
        assert checker.can_fetch("https://example.com/admin/panel", "PerplexityBot") is False

        # Sitemap directives: normalized, relative resolved, deduplicated, file:// skipped
        assert checker.sitemaps == [
            "https://example.com/sitemap_index.xml",
            "https://example.com/extra-sitemap.xml",
        ]

    def test_utf8_bom_handled_cleanly(self) -> None:
        bom_robots = "\ufeffUser-agent: *\nDisallow: /secret\nSitemap: https://example.com/sm.xml\n"
        checker = RobotsChecker.from_text("https://example.com/robots.txt", bom_robots)
        assert checker.can_fetch("https://example.com/secret", "*") is False
        assert checker.can_fetch("https://example.com/open", "*") is True
        assert checker.sitemaps == ["https://example.com/sm.xml"]

    @pytest.mark.parametrize("status_code", [400, 403, 404, 410])
    async def test_fetch_robots_4xx_falls_back_to_allow_all(self, status_code: int) -> None:
        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(lambda _req: httpx.Response(status_code)),
            auto_escalate_proxy=False,
        ) as client:
            checker = await fetch_robots(client, "https://example.com/some/path")

        assert checker.info.status == "not_found_allow_all"
        assert checker.info.http_status == status_code
        assert checker.sitemaps == []
        assert checker.can_fetch("https://example.com/anything", "*") is True
        assert checker.can_fetch("https://example.com/anything", "GPTBot") is True

    @pytest.mark.parametrize("status_code", [500, 502, 503])
    async def test_fetch_robots_5xx_returns_unavailable_unknown(self, status_code: int) -> None:
        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(lambda _req: httpx.Response(status_code)),
            auto_escalate_proxy=False,
        ) as client:
            checker = await fetch_robots(client, "https://example.com/")

        assert checker.info.status == "unavailable_unknown"
        assert checker.info.http_status == status_code
        assert checker.info.error is not None
        assert checker.can_fetch("https://example.com/", "*") is None

    async def test_fetch_robots_timeout_returns_unavailable_unknown_without_crashing(
        self,
    ) -> None:
        def timeout_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out", request=request)

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(timeout_handler),
            auto_escalate_proxy=False,
        ) as client:
            checker = await fetch_robots(client, "https://example.com/")

        assert checker.info.status == "unavailable_unknown"
        assert checker.info.error is not None and "TIMEOUT" in checker.info.error
        assert checker.can_fetch("https://example.com/", "*") is None

    async def test_fetch_robots_redirect_to_metadata_ip_is_ssrf_blocked(self) -> None:
        def redirect_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
            )

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(redirect_handler),
            auto_escalate_proxy=False,
        ) as client:
            checker = await fetch_robots(client, "https://example.com/")

        assert checker.info.status == "blocked_ssrf"
        assert checker.can_fetch("https://example.com/", "*") is None


class TestAiProbeAndLlmsTxt:
    """Offline tests for AI bot differential CDN/WAF block detection & /llms.txt."""

    @pytest.mark.parametrize(
        ("browser_status", "bot_status", "expected"),
        [
            (200, 401, True),
            (200, 403, True),
            (200, 429, True),
            (200, 503, True),
            (200, 200, False),
            (200, 404, False),
            (403, 403, False),  # Browser also blocked -> not a bot-specific differential
            (503, 503, False),
            (None, 403, False),
        ],
    )
    def test_is_differential_block_matrix(
        self, browser_status: int | None, bot_status: int | None, expected: bool
    ) -> None:
        assert is_differential_block(browser_status, bot_status) is expected

    def test_analyze_llms_txt_valid_markdown_fixture(self) -> None:
        raw = (FIXTURES / "llms_valid.txt").read_bytes()
        res = analyze_llms_txt(
            "https://example.com/llms.txt",
            FetchResult(
                requested_url="https://example.com/llms.txt",
                final_url="https://example.com/llms.txt",
                status_code=200,
                headers={"content-type": "text/markdown; charset=utf-8"},
                body=raw,
            ),
        )
        assert res.llms_txt_present is True
        assert res.byte_size == len(raw)
        assert res.heading_count == 3  # # Example Docs, ## Getting Started, ## Guides
        assert res.link_count == 3  # 3 markdown links (excludes ![Logo](...) image)

    def test_analyze_llms_txt_rejects_html_and_short_bodies(self) -> None:
        # 1. HTML Content-Type soft-404
        html_ct = analyze_llms_txt(
            "https://example.com/llms.txt",
            FetchResult(
                requested_url="https://example.com/llms.txt",
                final_url="https://example.com/llms.txt",
                status_code=200,
                headers={"content-type": "text/html; charset=utf-8"},
                body=b"<html><body>Not Found Page With Enough Bytes</body></html>",
            ),
        )
        assert html_ct.llms_txt_present is False

        # 2. Misconfigured text/plain serving HTML SPA fallback
        html_body = analyze_llms_txt(
            "https://example.com/llms.txt",
            FetchResult(
                requested_url="https://example.com/llms.txt",
                final_url="https://example.com/llms.txt",
                status_code=200,
                headers={"content-type": "text/plain"},
                body=b"<!DOCTYPE html><html><head><title>App</title></head><body></body></html>",
            ),
        )
        assert html_body.llms_txt_present is False

        # 3. Exact byte length boundary: 19 bytes -> False, 20 bytes -> True
        short_19 = analyze_llms_txt(
            "https://example.com/llms.txt",
            FetchResult(
                requested_url="https://example.com/llms.txt",
                final_url="https://example.com/llms.txt",
                status_code=200,
                headers={"content-type": "text/plain"},
                body=b"# Short\n12345678901",  # 19 bytes
            ),
        )
        assert short_19.byte_size == 19
        assert short_19.llms_txt_present is False

        exact_20 = analyze_llms_txt(
            "https://example.com/llms.txt",
            FetchResult(
                requested_url="https://example.com/llms.txt",
                final_url="https://example.com/llms.txt",
                status_code=200,
                headers={"content-type": "text/plain"},
                body=b"# Exact\n123456789012",  # 20 bytes
            ),
        )
        assert exact_20.byte_size == 20
        assert exact_20.llms_txt_present is True
        assert exact_20.heading_count == 1

    async def test_probe_ai_bots_detects_waf_differential_blocks(self) -> None:
        llms_raw = (FIXTURES / "llms_valid.txt").read_bytes()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/llms.txt":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/plain; charset=utf-8"},
                    content=llms_raw,
                )
            ua = request.headers.get("user-agent", "")
            if "GPTBot" in ua:
                return httpx.Response(403, content=b"WAF blocked GPTBot")
            if "ClaudeBot" in ua:
                return httpx.Response(429, content=b"Rate limited ClaudeBot")
            return httpx.Response(200, content=b"<html><body>Welcome</body></html>")

        robots = RobotsChecker.from_text(
            "https://example.com/robots.txt",
            (FIXTURES / "robots_standard.txt").read_text(encoding="utf-8"),
        )

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=True,
        ) as client:
            summary = await probe_ai_bots_and_llms(
                client, "https://example.com/docs/page", robots_checker=robots
            )

        assert summary.target_url == "https://example.com/"
        assert summary.browser_http_status == 200
        assert summary.any_cdn_or_waf_diff_block is True
        assert [b.bot_name for b in summary.bots] == list(AI_BOT_NAMES)

        by_bot = {b.bot_name: b for b in summary.bots}
        assert by_bot["GPTBot"].robots_allowed is False
        assert by_bot["GPTBot"].http_status == 403
        assert by_bot["GPTBot"].cdn_or_waf_diff_block is True

        assert by_bot["ClaudeBot"].robots_allowed is True
        assert by_bot["ClaudeBot"].http_status == 429
        assert by_bot["ClaudeBot"].cdn_or_waf_diff_block is True

        assert by_bot["OAI-SearchBot"].http_status == 200
        assert by_bot["OAI-SearchBot"].cdn_or_waf_diff_block is False
        assert by_bot["PerplexityBot"].cdn_or_waf_diff_block is False

        assert summary.llms_txt is not None
        assert summary.llms_txt.llms_txt_present is True
        assert summary.llms_txt.heading_count == 3
        assert summary.llms_txt.link_count == 3

    async def test_probe_ai_bots_no_false_positive_when_browser_also_blocked(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/llms.txt":
                return httpx.Response(404)
            return httpx.Response(403, content=b"Everyone blocked")

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            summary = await probe_ai_bots_and_llms(client, "https://example.com/")

        assert summary.browser_http_status == 403
        assert summary.any_cdn_or_waf_diff_block is False
        assert all(not b.cdn_or_waf_diff_block for b in summary.bots)
        assert summary.llms_txt is not None
        assert summary.llms_txt.llms_txt_present is False
