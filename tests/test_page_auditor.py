"""Offline unit tests for core.page_auditor (Indexability, Canonical 5-way, SEO/JSON-LD)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from core.http_client import DomainHttpClient, FetchResult
from core.models import IssueCode, SitemapUrlEntry
from core.page_auditor import (
    THIN_CONTENT_CHAR_THRESHOLD,
    audit_fetched_page,
    audit_page,
    classify_canonical,
    has_header_noindex,
    parse_html_signals,
)
from core.robots import RobotsChecker

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _public_dns(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


def _entry(url: str = "https://example.com/docs/healthy") -> SitemapUrlEntry:
    return SitemapUrlEntry(
        url=url,
        raw_url=url,
        sitemap_source="https://example.com/sitemap.xml",
    )


class TestCanonicalClassification:
    """Tests for all 5 Canonical categories including index_file_equivalent anti-false-positive."""

    @pytest.mark.parametrize(
        ("page_url", "raw_canonical", "expected_status"),
        [
            ("https://example.com/docs/guide", "https://example.com/docs/guide", "self"),
            ("https://example.com/docs/guide", "/docs/guide", "self"),
            ("https://example.com/docs/guide", "HTTPS://EXAMPLE.COM:443/docs/guide#top", "self"),
            # index_file_equivalent (all 3 suffixes & both directions)
            ("https://example.com/", "https://example.com/index.html", "index_file_equivalent"),
            ("https://example.com/index.html", "https://example.com/", "index_file_equivalent"),
            ("https://example.com/docs/", "https://example.com/docs/index.html", "index_file_equivalent"),
            ("https://example.com/docs/index.htm", "https://example.com/docs/", "index_file_equivalent"),
            ("https://example.com/docs/", "https://example.com/docs/index.php", "index_file_equivalent"),
            ("https://example.com/docs/?v=1", "https://example.com/docs/index.html?v=1", "index_file_equivalent"),
            # cross_path_same_host
            ("https://example.com/blog/post-1", "https://example.com/blog/", "cross_path_same_host"),
            ("https://example.com/docs/?v=1", "https://example.com/docs/?v=2", "cross_path_same_host"),
            ("https://example.com/docs/page.html", "https://example.com/docs/", "cross_path_same_host"),
            ("http://example.com/docs/", "https://example.com/docs/", "cross_path_same_host"),
            # cross_host
            ("https://example.com/page", "https://www.example.com/page", "cross_host"),
            ("https://example.com/", "https://other.example/index.html", "cross_host"),
            # missing
            ("https://example.com/page", None, "missing"),
            ("https://example.com/page", "   ", "missing"),
        ],
    )
    def test_five_way_canonical_classification(
        self, page_url: str, raw_canonical: str | None, expected_status: str
    ) -> None:
        status, _ = classify_canonical(page_url, raw_canonical)
        assert status == expected_status

    def test_relative_canonical_respects_base_url(self) -> None:
        status, canon = classify_canonical(
            "https://example.com/docs/sub/page",
            "page",
            base_url="https://example.com/docs/sub/",
        )
        assert status == "self"
        assert canon == "https://example.com/docs/sub/page"


class TestNoindexDetection:
    """Tests for X-Robots-Tag HTTP header & meta tag noindex parsing."""

    @pytest.mark.parametrize(
        ("headers", "expected"),
        [
            (["noindex"], True),
            (["noindex, nofollow"], True),
            (["none"], True),
            (["googlebot: noindex"], True),
            (["GoogleBot: noarchive, NONE"], True),
            (["index, follow", "noindex"], True),
            (["bingbot: noindex"], False),
            (["index, follow"], False),
            (["noarchive, nosnippet"], False),
            ([], False),
        ],
    )
    def test_has_header_noindex(self, headers: list[str], expected: bool) -> None:
        assert has_header_noindex(headers) is expected


class TestPageAuditRules:
    """Tests for full Indexability & HTML SEO/JSON-LD page auditing."""

    def test_healthy_page_in_full_audit_has_zero_issues(self) -> None:
        html_bytes = (FIXTURES / "page_healthy.html").read_bytes()
        fetch = FetchResult(
            requested_url="https://example.com/docs/healthy",
            final_url="https://example.com/docs/healthy",
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            raw_headers=[("content-type", "text/html; charset=utf-8")],
            body=html_bytes,
            redirect_chain=["https://example.com/docs/healthy"],
            elapsed_ms=42,
        )
        robots = RobotsChecker.from_text("https://example.com/robots.txt", "User-agent: *\nAllow: /\n")
        rec = audit_fetched_page(
            _entry("https://example.com/docs/healthy"),
            fetch,
            domain="example.com",
            mode="full_audit",
            robots_checker=robots,
        )

        assert rec.audited is True
        assert rec.indexable is True
        assert rec.noindex is False
        assert rec.noindex_source is None
        assert rec.canonical_status == "self"
        assert rec.issues == []
        assert rec.title == "Healthy SEO Guide — Example Docs"
        assert rec.title_length == len("Healthy SEO Guide — Example Docs")
        assert rec.meta_description_length > 0
        assert rec.h1_count == 1
        assert rec.text_char_count is not None and rec.text_char_count >= THIN_CONTENT_CHAR_THRESHOLD
        assert rec.jsonld_count == 1
        assert rec.jsonld_types == ["WebSite", "Article", "TechArticle"]
        assert rec.jsonld_error_count == 0

    def test_issues_fixture_detects_noindex_cross_host_thin_content_and_invalid_jsonld(
        self,
    ) -> None:
        html_bytes = (FIXTURES / "page_issues.html").read_bytes()
        fetch = FetchResult(
            requested_url="https://example.com/broken-seo",
            final_url="https://example.com/broken-seo",
            status_code=200,
            headers={"content-type": "text/html", "x-robots-tag": "noindex"},
            raw_headers=[
                ("content-type", "text/html"),
                ("x-robots-tag", "noindex"),
            ],
            body=html_bytes,
            redirect_chain=["https://example.com/broken-seo"],
        )
        rec = audit_fetched_page(
            _entry("https://example.com/broken-seo"),
            fetch,
            domain="example.com",
            mode="full_audit",
        )

        assert rec.indexable is False
        assert rec.noindex is True
        assert rec.noindex_source == "both"
        assert rec.canonical_status == "cross_host"
        assert rec.jsonld_count == 1
        assert rec.jsonld_error_count == 1
        assert rec.text_char_count is not None and rec.text_char_count < 200
        assert set(rec.issue_codes) >= {
            IssueCode.NOINDEX_IN_SITEMAP,
            IssueCode.CANONICAL_MISMATCH_CROSS_HOST,
            IssueCode.MISSING_TITLE,
            IssueCode.MISSING_META_DESCRIPTION,
            IssueCode.H1_MISSING,
            IssueCode.SSR_THIN_CONTENT,
            IssueCode.INVALID_JSONLD,
        }

    def test_indexability_audit_mode_skips_seo_fields_and_thin_content(self) -> None:
        html_bytes = (FIXTURES / "page_issues.html").read_bytes()
        fetch = FetchResult(
            requested_url="https://example.com/broken-seo",
            final_url="https://example.com/broken-seo",
            status_code=200,
            headers={"content-type": "text/html"},
            raw_headers=[("content-type", "text/html")],
            body=html_bytes,
            redirect_chain=["https://example.com/broken-seo"],
        )
        rec = audit_fetched_page(
            _entry("https://example.com/broken-seo"),
            fetch,
            domain="example.com",
            mode="indexability_audit",
        )
        assert rec.noindex is True
        assert rec.noindex_source == "meta"
        assert rec.canonical_status == "cross_host"
        assert rec.title is None
        assert IssueCode.SSR_THIN_CONTENT not in rec.issue_codes
        assert IssueCode.INVALID_JSONLD not in rec.issue_codes

    def test_index_file_equivalent_keeps_page_indexable_with_info_severity(self) -> None:
        html = b'<html><head><link rel="canonical" href="https://example.com/docs/index.html"></head><body>ok</body></html>'
        fetch = FetchResult(
            requested_url="https://example.com/docs/",
            final_url="https://example.com/docs/",
            status_code=200,
            headers={"content-type": "text/html"},
            raw_headers=[("content-type", "text/html")],
            body=html,
            redirect_chain=["https://example.com/docs/"],
        )
        rec = audit_fetched_page(
            _entry("https://example.com/docs/"),
            fetch,
            domain="example.com",
            mode="indexability_audit",
        )
        assert rec.canonical_status == "index_file_equivalent"
        assert rec.indexable is True
        assert rec.issue_codes == [IssueCode.CANONICAL_INDEX_FILE_EQUIVALENT]
        assert rec.issue_severities == ["info"]

    def test_link_header_canonical_fallback(self) -> None:
        fetch = FetchResult(
            requested_url="https://example.com/doc.pdf",
            final_url="https://example.com/doc.pdf",
            status_code=200,
            headers={
                "content-type": "application/pdf",
                "link": '<https://example.com/doc.pdf>; rel="canonical"',
            },
            raw_headers=[
                ("content-type", "application/pdf"),
                ("link", '<https://example.com/doc.pdf>; rel="canonical"'),
            ],
            body=b"%PDF-1.7",
            redirect_chain=["https://example.com/doc.pdf"],
        )
        rec = audit_fetched_page(
            _entry("https://example.com/doc.pdf"),
            fetch,
            domain="example.com",
            mode="indexability_audit",
        )
        assert rec.canonical_status == "self"
        assert rec.indexable is True

    def test_thin_content_exact_200_char_boundary_and_multiple_h1(self) -> None:
        text_199 = "a" * 199
        html_199 = f"<html><head><title>T</title></head><body><h1>One</h1><h1>Two</h1><p>{text_199}</p></body></html>"
        _, _, _, seo_199 = parse_html_signals(html_199, extract_seo=True)
        assert seo_199 is not None
        assert seo_199.h1_count == 2
        assert seo_199.text_char_count == len("One Two ") + 199  # >= 200 because of headings

        # Pure body text exact boundary: 199 vs 200
        body_199 = f"<html><head><title>T</title></head><body><p>{'x' * 199}</p></body></html>"
        body_200 = f"<html><head><title>T</title></head><body><p>{'x' * 200}</p></body></html>"

        rec_199 = audit_fetched_page(
            _entry("https://example.com/p199"),
            FetchResult(
                requested_url="https://example.com/p199",
                final_url="https://example.com/p199",
                status_code=200,
                headers={"content-type": "text/html"},
                raw_headers=[("content-type", "text/html")],
                body=body_199.encode(),
            ),
            domain="example.com",
            mode="full_audit",
        )
        rec_200 = audit_fetched_page(
            _entry("https://example.com/p200"),
            FetchResult(
                requested_url="https://example.com/p200",
                final_url="https://example.com/p200",
                status_code=200,
                headers={"content-type": "text/html"},
                raw_headers=[("content-type", "text/html")],
                body=body_200.encode(),
            ),
            domain="example.com",
            mode="full_audit",
        )
        assert rec_199.text_char_count == 199
        assert IssueCode.SSR_THIN_CONTENT in rec_199.issue_codes
        assert rec_200.text_char_count == 200
        assert IssueCode.SSR_THIN_CONTENT not in rec_200.issue_codes

    def test_redirect_severities_http_errors_non_https_and_robots_conflict(self) -> None:
        robots = RobotsChecker.from_text(
            "https://example.com/robots.txt", "User-agent: *\nDisallow: /blocked\n"
        )

        # 1 hop redirect -> warning, http:// -> warning, robots -> critical
        rec_1hop = audit_fetched_page(
            _entry("http://example.com/blocked"),
            FetchResult(
                requested_url="http://example.com/blocked",
                final_url="https://example.com/blocked",
                status_code=200,
                headers={"content-type": "text/html"},
                raw_headers=[("content-type", "text/html")],
                body=b'<html><head><link rel="canonical" href="https://example.com/blocked"></head></html>',
                redirect_hops=1,
                redirect_chain=["http://example.com/blocked", "https://example.com/blocked"],
            ),
            domain="example.com",
            mode="indexability_audit",
            robots_checker=robots,
        )
        assert rec_1hop.indexable is False
        assert rec_1hop.robots_allowed is False
        issues_by_code = {i.code: i.severity for i in rec_1hop.issues}
        assert issues_by_code[IssueCode.HTTP_NON_HTTPS] == "warning"
        assert issues_by_code[IssueCode.REDIRECT_CHAIN] == "warning"
        assert issues_by_code[IssueCode.DISALLOWED_BY_ROBOTS] == "critical"

        # 2 hops + 404 -> both critical
        rec_404 = audit_fetched_page(
            _entry("https://example.com/dead"),
            FetchResult(
                requested_url="https://example.com/dead",
                final_url="https://example.com/dead-2",
                status_code=404,
                redirect_hops=2,
                redirect_chain=[
                    "https://example.com/dead",
                    "https://example.com/dead-1",
                    "https://example.com/dead-2",
                ],
            ),
            domain="example.com",
            mode="indexability_audit",
        )
        assert rec_404.indexable is False
        by_code_404 = {i.code: i.severity for i in rec_404.issues}
        assert by_code_404[IssueCode.REDIRECT_CHAIN] == "critical"
        assert by_code_404[IssueCode.HTTP_4XX] == "critical"

        # 503 server error
        rec_503 = audit_fetched_page(
            _entry("https://example.com/err"),
            FetchResult(
                requested_url="https://example.com/err",
                final_url="https://example.com/err",
                status_code=503,
            ),
            domain="example.com",
            mode="indexability_audit",
        )
        assert IssueCode.HTTP_5XX in rec_503.issue_codes
        assert rec_503.indexable is False

        # Redirect loop -> REDIRECT_LOOP & REDIRECT_CHAIN critical
        rec_loop = audit_fetched_page(
            _entry("https://example.com/loop"),
            FetchResult(
                requested_url="https://example.com/loop",
                final_url="https://example.com/loop",
                status_code=302,
                redirect_hops=2,
                redirect_loop=True,
                error="REDIRECT_LOOP",
            ),
            domain="example.com",
            mode="indexability_audit",
        )
        assert IssueCode.REDIRECT_LOOP in rec_loop.issue_codes
        assert IssueCode.REDIRECT_CHAIN in rec_loop.issue_codes
        assert rec_loop.indexable is False

    async def test_audit_page_async_end_to_end_with_mock_transport(self) -> None:
        html_bytes = (FIXTURES / "page_healthy.html").read_bytes()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html; charset=utf-8"},
                content=html_bytes,
            )

        async with DomainHttpClient(
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(handler),
            auto_escalate_proxy=False,
        ) as client:
            rec = await audit_page(
                client,
                _entry("https://example.com/docs/healthy"),
                domain="example.com",
                mode="full_audit",
            )

        assert rec.http_status == 200
        assert rec.indexable is True
        assert rec.canonical_status == "self"
        assert rec.jsonld_types == ["WebSite", "Article", "TechArticle"]
