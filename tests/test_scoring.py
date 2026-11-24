"""Offline unit tests for core.scoring (0-100 health score & top_priority_fixes)."""

from __future__ import annotations

from core.models import (
    AI_BOT_NAMES,
    AiAuditSummary,
    AiBotProbeResult,
    AuditIssue,
    IssueCode,
    LlmsTxtResult,
    SitemapDiscoveryStats,
    SitemapFileResult,
    UrlAuditRecord,
)
from core.scoring import (
    build_domain_summary,
    build_top_priority_fixes,
    compute_health_score,
    compute_score_breakdown,
)


def _clean_record(idx: int) -> UrlAuditRecord:
    return UrlAuditRecord(
        domain="example.com",
        url=f"https://example.com/page-{idx}",
        sitemap_source="https://example.com/sitemap.xml",
        audited=True,
        http_status=200,
        final_url=f"https://example.com/page-{idx}",
        robots_allowed=True,
        indexable=True,
        noindex=False,
        canonical_status="self",
        canonical_url=f"https://example.com/page-{idx}",
    )


def _clean_ai_audit() -> AiAuditSummary:
    return AiAuditSummary(
        target_url="https://example.com/",
        browser_http_status=200,
        bots=[
            AiBotProbeResult(
                bot_name=b,
                robots_allowed=True,
                http_status=200,
                cdn_or_waf_diff_block=False,
            )
            for b in AI_BOT_NAMES
        ],
        any_cdn_or_waf_diff_block=False,
        llms_txt=LlmsTxtResult(
            url="https://example.com/llms.txt",
            http_status=200,
            llms_txt_present=True,
            byte_size=300,
            heading_count=2,
            link_count=3,
        ),
    )


class TestHealthScoringBoundaries:
    """Boundary tests: 0 pages, all healthy, all broken, floor 0 guard, single-issue cap."""

    def test_zero_audited_pages_does_not_crash_and_stays_in_bounds(self) -> None:
        for mode in ("extract_only", "indexability_audit", "full_audit"):
            score = compute_health_score(
                mode=mode,
                url_records=[],
                sitemap_stats=SitemapDiscoveryStats(),
            )
            assert score == 100

    def test_all_healthy_domain_scores_exact_100(self) -> None:
        records = [_clean_record(i) for i in range(10)]
        stats = SitemapDiscoveryStats(
            discovery_method="robots_txt",
            sitemap_files_fetched=1,
            total_urls_found=10,
            unique_urls_count=10,
            lastmod_present_count=10,
            lastmod_coverage_rate=1.0,
        )
        for mode in ("extract_only", "indexability_audit", "full_audit"):
            score = compute_health_score(
                mode=mode,
                url_records=records,
                sitemap_stats=stats,
                ai_audit=_clean_ai_audit(),
            )
            assert score == 100

    def test_all_broken_domain_clamped_at_floor_zero(self) -> None:
        broken_records = [
            UrlAuditRecord(
                domain="example.com",
                url=f"http://example.com/bad-{i}",
                sitemap_source="https://example.com/sitemap.xml",
                audited=True,
                http_status=500,
                robots_allowed=False,
                indexable=False,
                noindex=True,
                canonical_status="cross_host",
                issues=[
                    AuditIssue(code=IssueCode.HTTP_5XX, severity="critical", detail="500"),
                    AuditIssue(code=IssueCode.DISALLOWED_BY_ROBOTS, severity="critical", detail="robots"),
                    AuditIssue(code=IssueCode.NOINDEX_IN_SITEMAP, severity="critical", detail="noindex"),
                    AuditIssue(code=IssueCode.CANONICAL_MISMATCH_CROSS_HOST, severity="critical", detail="canon"),
                    AuditIssue(code=IssueCode.REDIRECT_LOOP, severity="critical", detail="loop"),
                    AuditIssue(code=IssueCode.HTTP_NON_HTTPS, severity="warning", detail="http"),
                    AuditIssue(code=IssueCode.MISSING_TITLE, severity="warning", detail="no title"),
                    AuditIssue(code=IssueCode.SSR_THIN_CONTENT, severity="warning", detail="thin"),
                    AuditIssue(code=IssueCode.H1_MISSING, severity="warning", detail="no h1"),
                    AuditIssue(code=IssueCode.INVALID_JSONLD, severity="warning", detail="bad jsonld"),
                ],
            )
            for i in range(5)
        ]
        bad_stats = SitemapDiscoveryStats(
            discovery_method="robots_txt",
            sitemap_files_fetched=2,
            sitemap_files_failed=1,
            total_urls_found=20,
            unique_urls_count=5,
            duplicate_urls_count=15,
            cross_host_urls_count=5,
            recovered_xml_files_count=2,
            over_50k_files_count=1,
            lastmod_present_count=5,
            invalid_lastmod_count=5,
        )
        blocked_ai = AiAuditSummary(
            target_url="https://example.com/",
            browser_http_status=200,
            bots=[
                AiBotProbeResult(
                    bot_name=b,
                    robots_allowed=True,
                    http_status=403,
                    cdn_or_waf_diff_block=True,
                )
                for b in AI_BOT_NAMES
            ],
            any_cdn_or_waf_diff_block=True,
            llms_txt=LlmsTxtResult(
                url="https://example.com/llms.txt",
                http_status=404,
                llms_txt_present=False,
            ),
        )

        breakdown = compute_score_breakdown(
            mode="full_audit",
            url_records=broken_records,
            sitemap_stats=bad_stats,
            ai_audit=blocked_ai,
        )
        assert breakdown.indexability_deduction == 50.0
        assert breakdown.sitemap_deduction == 25.0
        assert breakdown.seo_and_ai_deduction == 25.0
        assert breakdown.health_score == 0

        idx_score = compute_health_score(
            mode="indexability_audit",
            url_records=broken_records,
            sitemap_stats=bad_stats,
            ai_audit=blocked_ai,
        )
        assert idx_score == 0

    def test_single_issue_category_cannot_collapse_score_to_zero(self) -> None:
        # 100% of URLs have 404 ONLY (no robots/noindex/canonical/sitemap/SEO issues)
        only_404 = [
            UrlAuditRecord(
                domain="example.com",
                url=f"https://example.com/missing-{i}",
                sitemap_source="https://example.com/sitemap.xml",
                audited=True,
                http_status=404,
                indexable=False,
                issues=[AuditIssue(code=IssueCode.HTTP_4XX, severity="critical", detail="404")],
            )
            for i in range(10)
        ]
        breakdown = compute_score_breakdown(
            mode="full_audit",
            url_records=only_404,
            sitemap_stats=SitemapDiscoveryStats(
                discovery_method="robots_txt",
                sitemap_files_fetched=1,
                total_urls_found=10,
                unique_urls_count=10,
            ),
            ai_audit=_clean_ai_audit(),
        )
        assert breakdown.indexability_deduction == 25.0
        assert breakdown.health_score == 75

    def test_index_file_equivalent_canonical_causes_zero_deduction(self) -> None:
        records = [
            UrlAuditRecord(
                domain="example.com",
                url=f"https://example.com/dir-{i}/",
                sitemap_source="https://example.com/sitemap.xml",
                audited=True,
                http_status=200,
                indexable=True,
                canonical_status="index_file_equivalent",
                canonical_url=f"https://example.com/dir-{i}/index.html",
                issues=[
                    AuditIssue(
                        code=IssueCode.CANONICAL_INDEX_FILE_EQUIVALENT,
                        severity="info",
                        detail="Trailing slash vs index.html",
                    )
                ],
            )
            for i in range(5)
        ]
        score = compute_health_score(
            mode="full_audit",
            url_records=records,
            sitemap_stats=SitemapDiscoveryStats(
                discovery_method="robots_txt",
                sitemap_files_fetched=1,
                total_urls_found=5,
                unique_urls_count=5,
            ),
            ai_audit=_clean_ai_audit(),
        )
        assert score == 100

    def test_indexability_audit_uses_two_axis_scaling_ignoring_axis3_seo_ai(self) -> None:
        # Only Axis 3 issues (missing title + blocked AI bots + no llms.txt)
        seo_issue_records = [
            UrlAuditRecord(
                domain="example.com",
                url=f"https://example.com/p-{i}",
                sitemap_source="https://example.com/sitemap.xml",
                audited=True,
                http_status=200,
                indexable=True,
                canonical_status="self",
                issues=[
                    AuditIssue(code=IssueCode.MISSING_TITLE, severity="warning", detail="no title"),
                    AuditIssue(code=IssueCode.INVALID_JSONLD, severity="warning", detail="bad json"),
                ],
            )
            for i in range(5)
        ]
        blocked_ai = AiAuditSummary(
            target_url="https://example.com/",
            browser_http_status=200,
            bots=[
                AiBotProbeResult(
                    bot_name="GPTBot",
                    http_status=403,
                    cdn_or_waf_diff_block=True,
                )
            ],
            any_cdn_or_waf_diff_block=True,
            llms_txt=LlmsTxtResult(
                url="https://example.com/llms.txt", http_status=404, llms_txt_present=False
            ),
        )
        stats = SitemapDiscoveryStats(
            discovery_method="robots_txt",
            sitemap_files_fetched=1,
            total_urls_found=5,
            unique_urls_count=5,
        )

        idx_score = compute_health_score(
            mode="indexability_audit",
            url_records=seo_issue_records,
            sitemap_stats=stats,
            ai_audit=blocked_ai,
        )
        full_score = compute_health_score(
            mode="full_audit",
            url_records=seo_issue_records,
            sitemap_stats=stats,
            ai_audit=blocked_ai,
        )
        assert idx_score == 100
        assert full_score < 100

    def test_benign_fallback_404_probes_do_not_penalize_sitemap_score(self) -> None:
        stats = SitemapDiscoveryStats(
            discovery_method="fallback",
            sitemap_files_fetched=2,
            sitemap_files_failed=1,  # /sitemap.xml 404, /sitemap_index.xml 200
            total_urls_found=10,
            unique_urls_count=10,
        )
        score = compute_health_score(
            mode="extract_only",
            url_records=[],
            sitemap_stats=stats,
        )
        assert score == 100


class TestPriorityFixesAndDomainSummary:
    """Tests for top_priority_fixes sorting/capping and build_domain_summary aggregation."""

    def test_top_priority_fixes_sorted_by_severity_then_count_and_capped_at_10(self) -> None:
        records: list[UrlAuditRecord] = []
        # Create 5 URLs with HTTP_4XX (critical), 2 URLs with NOINDEX (critical),
        # 4 URLs with MISSING_TITLE (warning), and many distinct info/warning codes
        for i in range(5):
            issues = [AuditIssue(code=IssueCode.HTTP_4XX, severity="critical", detail="404")]
            if i < 2:
                issues.append(
                    AuditIssue(code=IssueCode.NOINDEX_IN_SITEMAP, severity="critical", detail="noindex")
                )
            if i < 4:
                issues.append(
                    AuditIssue(code=IssueCode.MISSING_TITLE, severity="warning", detail="title")
                )
            issues.extend(
                [
                    AuditIssue(code=IssueCode.HTTP_NON_HTTPS, severity="warning", detail="http"),
                    AuditIssue(code=IssueCode.SSR_THIN_CONTENT, severity="warning", detail="thin"),
                    AuditIssue(code=IssueCode.H1_MISSING, severity="warning", detail="h1"),
                    AuditIssue(code=IssueCode.INVALID_JSONLD, severity="warning", detail="jsonld"),
                    AuditIssue(code=IssueCode.CANONICAL_MISMATCH_SAME_HOST, severity="warning", detail="c"),
                    AuditIssue(code=IssueCode.CANONICAL_MISSING, severity="info", detail="missing"),
                    AuditIssue(code=IssueCode.MISSING_META_DESCRIPTION, severity="info", detail="desc"),
                    AuditIssue(code=IssueCode.H1_MULTIPLE, severity="info", detail="multi"),
                ]
            )
            records.append(
                UrlAuditRecord(
                    domain="example.com",
                    url=f"https://example.com/u-{i}",
                    sitemap_source="https://example.com/sitemap.xml",
                    audited=True,
                    issues=issues,
                )
            )

        fixes = build_top_priority_fixes(
            url_records=records,
            sitemap_stats=SitemapDiscoveryStats(
                recovered_xml_files_count=1,
                sitemap_files=[
                    SitemapFileResult(
                        url="https://example.com/sitemap.xml",
                        format="xml_urlset",
                        recovered_xml=True,
                    )
                ],
            ),
            robots_status="unavailable_unknown",
            robots_url="https://example.com/robots.txt",
        )

        assert len(fixes) == 10
        # First two must be critical sorted by affected_count desc: HTTP_4XX (5) then NOINDEX (2)
        assert fixes[0].code == IssueCode.HTTP_4XX
        assert fixes[0].severity == "critical"
        assert fixes[0].affected_count == 5
        assert len(fixes[0].sample_urls) == 3  # max 3 sample URLs
        assert fixes[1].code == IssueCode.NOINDEX_IN_SITEMAP
        assert fixes[1].affected_count == 2
        # All subsequent items must be non-increasing severity order
        severity_ranks = [{"critical": 0, "warning": 1, "info": 2}[f.severity] for f in fixes]
        assert severity_ranks == sorted(severity_ranks)

    def test_build_domain_summary_aggregates_counts_and_canonical_breakdown(self) -> None:
        rec_ok = _clean_record(1)
        rec_bad = UrlAuditRecord(
            domain="example.com",
            url="https://example.com/bad",
            sitemap_source="https://example.com/sitemap.xml",
            audited=True,
            http_status=200,
            indexable=False,
            canonical_status="cross_host",
            issues=[
                AuditIssue(
                    code=IssueCode.CANONICAL_MISMATCH_CROSS_HOST,
                    severity="critical",
                    detail="Cross-host canonical.",
                )
            ],
        )
        rec_unaudited = UrlAuditRecord(
            domain="example.com",
            url="https://example.com/extra",
            sitemap_source="https://example.com/sitemap.xml",
            audited=False,
        )

        summary = build_domain_summary(
            domain="example.com",
            start_url="https://example.com/",
            mode="full_audit",
            robots_status="loaded",
            sitemap_stats=SitemapDiscoveryStats(
                discovery_method="robots_txt",
                sitemap_files_fetched=1,
                total_urls_found=3,
                unique_urls_count=3,
            ),
            url_records=[rec_ok, rec_bad, rec_unaudited],
            ai_audit=_clean_ai_audit(),
            proxy_escalated=True,
            elapsed_sec=0.456,
        )

        assert summary.pages_audited == 2
        assert summary.indexable_count == 1
        assert summary.non_indexable_count == 1
        assert summary.canonical_breakdown["self"] == 1
        assert summary.canonical_breakdown["cross_host"] == 1
        assert summary.issue_counts_by_severity["critical"] == 1
        assert summary.issue_counts_by_code[IssueCode.CANONICAL_MISMATCH_CROSS_HOST] == 1
        assert summary.proxy_escalated is True
        assert summary.health_score is not None and 0 < summary.health_score < 100
        assert summary.top_priority_fixes[0].code == IssueCode.CANONICAL_MISMATCH_CROSS_HOST
