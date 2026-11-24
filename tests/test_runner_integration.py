"""Offline mock-HTTP integration tests for core.runner across all 3 execution modes."""

from __future__ import annotations

from pathlib import Path

import httpx

from core.models import AuditConfig, IssueCode
from core.runner import audit_domain, run_audit

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _public_dns(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


def _build_site_transport() -> httpx.MockTransport:
    """Mock a full realistic website with robots.txt, sitemap, HTML pages, AI WAF diff, and llms.txt."""
    healthy_html = (FIXTURES / "page_healthy.html").read_bytes()
    issues_html = (FIXTURES / "page_issues.html").read_bytes()
    llms_bytes = (FIXTURES / "llms_valid.txt").read_bytes()

    robots_txt = (
        "User-agent: *\n"
        "Disallow: /private/\n"
        "User-agent: GPTBot\n"
        "Disallow: /\n"
        "Sitemap: https://site.example/sitemap.xml\n"
    ).encode()

    sitemap_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "  <url><loc>https://site.example/docs/healthy</loc><lastmod>2026-11-20</lastmod></url>\n"
        "  <url><loc>https://site.example/docs/</loc><lastmod>2026-11-20</lastmod></url>\n"
        "  <url><loc>https://site.example/broken-seo</loc></url>\n"
        "  <url><loc>https://site.example/private/secret</loc></url>\n"
        "  <url><loc>https://site.example/not-found</loc></url>\n"
        "</urlset>\n"
    ).encode()

    index_equiv_html = (
        '<html><head><title>Docs Index</title>'
        '<link rel="canonical" href="https://site.example/docs/index.html">'
        '</head><body><h1>Docs</h1><p>' + ("Documentation content text. " * 15) + "</p></body></html>"
    ).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        ua = request.headers.get("user-agent", "")

        if url == "https://site.example/robots.txt":
            return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=robots_txt)
        if url == "https://site.example/sitemap.xml":
            return httpx.Response(200, headers={"Content-Type": "application/xml"}, content=sitemap_xml)
        if url == "https://site.example/llms.txt":
            return httpx.Response(200, headers={"Content-Type": "text/markdown"}, content=llms_bytes)
        if url == "https://site.example/":
            if "GPTBot" in ua:
                return httpx.Response(403, content=b"Blocked GPTBot")
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=healthy_html)
        if url == "https://site.example/docs/healthy":
            # Adjust canonical to match site.example
            page = healthy_html.replace(b"https://example.com/", b"https://site.example/")
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=page)
        if url == "https://site.example/docs/":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=index_equiv_html)
        if url == "https://site.example/broken-seo":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=issues_html)
        if url == "https://site.example/private/secret":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=index_equiv_html)
        if url == "https://site.example/not-found":
            return httpx.Response(404, headers={"Content-Type": "text/html"}, content=b"Not Found")
        return httpx.Response(404)

    return httpx.MockTransport(handler)


class TestCoreRunnerIntegration:
    """End-to-end pure-Python integration tests for core.runner."""

    async def test_extract_only_mode_extracts_without_auditing_pages_or_ai_bots(self) -> None:
        cfg = AuditConfig.model_validate(
            {
                "startUrls": ["https://site.example"],
                "mode": "extract_only",
                "maxUrlsPerDomain": 100,
                "maxAuditPagesPerDomain": 50,  # forced to 0 in extract_only
            }
        )
        result = await run_audit(
            cfg,
            dns_resolver=_public_dns,
            direct_transport=_build_site_transport(),
        )

        assert result.summary_payload.mode == "extract_only"
        assert result.summary_payload.total_domains == 1
        assert result.summary_payload.total_urls_extracted == 5
        assert result.summary_payload.total_pages_audited == 0

        domain_res = result.domain_results[0]
        assert domain_res.summary.sitemap_stats.discovery_method == "robots_txt"
        assert domain_res.summary.pages_audited == 0
        assert domain_res.summary.ai_audit is None
        assert len(domain_res.url_records) == 5
        assert all(not r.audited for r in domain_res.url_records)
        assert domain_res.summary.health_score == 100

    async def test_indexability_audit_splits_audited_and_unaudited_and_filters_issues(
        self,
    ) -> None:
        cfg = AuditConfig.model_validate(
            {
                "startUrls": ["https://site.example"],
                "mode": "indexability_audit",
                "maxUrlsPerDomain": 10,
                "maxAuditPagesPerDomain": 3,
                "includeAiBotAudit": False,
                "onlyIssuesInDataset": True,
            }
        )
        domain_res = await audit_domain(
            cfg.start_urls[0],
            cfg,
            dns_resolver=_public_dns,
            direct_transport=_build_site_transport(),
        )

        assert domain_res.summary.pages_audited == 3
        assert domain_res.summary.ai_audit is None
        assert len(domain_res.url_records) == 5
        assert sum(1 for r in domain_res.url_records if r.audited) == 3
        assert sum(1 for r in domain_res.url_records if not r.audited) == 2

        # Healthy page has 0 issues; docs/ has info index_file_equivalent; broken-seo has critical issues
        assert domain_res.summary.canonical_breakdown["self"] == 1
        assert domain_res.summary.canonical_breakdown["index_file_equivalent"] == 1
        assert domain_res.summary.canonical_breakdown["cross_host"] == 1
        assert domain_res.summary.indexable_count == 2
        assert domain_res.summary.non_indexable_count == 1

        # Verify onlyIssuesInDataset filter excludes healthy & unaudited rows
        issues_only = domain_res.filtered_url_records(only_issues=True)
        assert len(issues_only) == 2
        assert all(r.has_issues for r in issues_only)

    async def test_full_audit_runs_seo_jsonld_ai_probe_llms_and_scoring(self) -> None:
        cfg = AuditConfig.model_validate(
            {
                "startUrls": ["https://site.example"],
                "mode": "full_audit",
                "maxAuditPagesPerDomain": 10,
                "includeAiBotAudit": True,
            }
        )
        result = await run_audit(
            cfg,
            dns_resolver=_public_dns,
            direct_transport=_build_site_transport(),
        )

        payload = result.summary_payload
        assert payload.total_domains == 1
        assert payload.total_urls_extracted == 5
        assert payload.total_pages_audited == 5

        summary = result.domain_results[0].summary
        assert summary.pages_audited == 5
        assert summary.indexable_count == 2  # healthy + docs/ (index_file_equivalent)
        assert summary.non_indexable_count == 3  # broken-seo + private/secret + 404
        assert summary.ai_audit is not None
        assert summary.ai_audit.any_cdn_or_waf_diff_block is True
        assert summary.ai_audit.llms_txt is not None
        assert summary.ai_audit.llms_txt.llms_txt_present is True
        assert summary.health_score is not None and 0 < summary.health_score < 100
        assert summary.top_priority_fixes
        assert summary.top_priority_fixes[0].severity == "critical"

        # Check full_audit SEO fields populated on healthy page
        by_url = {r.url: r for r in result.domain_results[0].url_records}
        healthy = by_url["https://site.example/docs/healthy"]
        assert healthy.title == "Healthy SEO Guide — Example Docs"
        assert healthy.jsonld_types == ["WebSite", "Article", "TechArticle"]

        broken = by_url["https://site.example/broken-seo"]
        assert IssueCode.INVALID_JSONLD in broken.issue_codes
        assert IssueCode.SSR_THIN_CONTENT in broken.issue_codes

    async def test_proxy_escalation_and_missing_sitemap_graceful_handling(self) -> None:
        async def proxy_factory(escalated: bool) -> str | None:
            return "http://proxy.test:8000"

        # Direct returns 403 -> escalates to proxy -> proxy returns 404 for sitemaps, 200 for root
        def direct_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, content=b"Direct blocked")

        def proxy_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/robots.txt":
                return httpx.Response(404)
            if request.url.path == "/":
                return httpx.Response(200, content=b"<html><body>Home</body></html>")
            return httpx.Response(404)

        cfg = AuditConfig.model_validate(
            {
                "startUrls": ["https://blocked.example"],
                "mode": "full_audit",
                "autoEscalateProxy": True,
            }
        )
        result = await run_audit(
            cfg,
            proxy_url_factory=proxy_factory,
            dns_resolver=_public_dns,
            direct_transport=httpx.MockTransport(direct_handler),
            proxy_transport_factory=lambda _url: httpx.MockTransport(proxy_handler),
        )

        assert result.summary_payload.proxy_escalated is True
        summary = result.domain_results[0].summary
        assert summary.proxy_escalated is True
        assert summary.sitemap_stats.discovery_method == "none"
        assert summary.pages_audited == 0
        assert summary.ai_audit is not None
        assert any("No valid Sitemap discovered" in err for err in summary.errors)
