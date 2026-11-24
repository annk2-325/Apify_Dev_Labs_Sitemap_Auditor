"""Offline unit tests for core.models (Pydantic v2 schemas & architecture guardrails)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from core.models import (
    AI_BOT_NAMES,
    AiAuditSummary,
    AiBotProbeResult,
    AuditConfig,
    AuditIssue,
    DomainAuditSummary,
    IssueCode,
    LlmsTxtResult,
    PriorityFix,
    RunSummaryPayload,
    SeoMetadata,
    SitemapDiscoveryStats,
    SitemapFileResult,
    SitemapUrlEntry,
    UrlAuditRecord,
)


class TestAuditConfig:
    """Validation tests for AuditConfig matching Specification.md §4.1."""

    def test_defaults_and_camel_case_input(self) -> None:
        cfg = AuditConfig.model_validate({"startUrls": ["https://www.sitemaps.org"]})
        assert cfg.start_urls == ["https://www.sitemaps.org/"]
        assert cfg.mode == "indexability_audit"
        assert cfg.max_urls_per_domain == 500
        assert cfg.max_audit_pages_per_domain == 50
        assert cfg.max_sitemap_files == 30
        assert cfg.concurrency == 5
        assert cfg.include_ai_bot_audit is True
        assert cfg.should_run_ai_bot_audit is True
        assert cfg.output_mode == "both"
        assert cfg.only_issues_in_dataset is False
        assert cfg.auto_escalate_proxy is True
        assert cfg.proxy_configuration == {"useApifyProxy": False}

    def test_snake_case_input_supported(self) -> None:
        cfg = AuditConfig(
            start_urls=["https://docs.python.org/3/"],
            mode="full_audit",
            max_urls_per_domain=100,
            max_audit_pages_per_domain=10,
            max_sitemap_files=5,
            concurrency=3,
            include_ai_bot_audit=False,
            output_mode="summary_only",
            only_issues_in_dataset=True,
            auto_escalate_proxy=False,
        )
        assert cfg.mode == "full_audit"
        assert cfg.max_urls_per_domain == 100
        assert cfg.max_audit_pages_per_domain == 10
        assert cfg.should_run_ai_bot_audit is False
        assert cfg.output_mode == "summary_only"

    def test_start_urls_accepts_request_list_bare_domains_and_deduplicates(self) -> None:
        cfg = AuditConfig.model_validate(
            {
                "startUrls": [
                    "sitemaps.org",
                    {"url": "https://SITEMAPS.ORG/"},
                    {"url": "docs.python.org/3/sitemap.xml"},
                    "https://docs.perplexity.ai#top",
                ]
            }
        )
        assert cfg.start_urls == [
            "https://sitemaps.org/",
            "https://docs.python.org/3/sitemap.xml",
            "https://docs.perplexity.ai/",
        ]

    @pytest.mark.parametrize(
        "invalid_start_urls",
        [
            [],
            "https://example.com",
            [""],
            [{"href": "https://example.com"}],
            ["ftp://example.com/sitemap.xml"],
            ["file:///etc/passwd"],
            ["javascript:alert(1)"],
            [{"url": "gopher://127.0.0.1:70/"}],
        ],
    )
    def test_start_urls_rejects_invalid_values(self, invalid_start_urls: object) -> None:
        with pytest.raises(ValidationError):
            AuditConfig.model_validate({"startUrls": invalid_start_urls})

    def test_extract_only_forces_zero_audit_pages_and_disables_ai_probe(self) -> None:
        cfg = AuditConfig.model_validate(
            {
                "startUrls": ["https://www.sitemaps.org"],
                "mode": "extract_only",
                "maxAuditPagesPerDomain": 200,
                "includeAiBotAudit": True,
            }
        )
        assert cfg.max_audit_pages_per_domain == 0
        assert cfg.should_run_ai_bot_audit is False

    def test_ai_bot_audit_flag_interaction(self) -> None:
        idx_on = AuditConfig.model_validate(
            {"startUrls": ["https://example.com"], "mode": "indexability_audit"}
        )
        idx_off = AuditConfig.model_validate(
            {
                "startUrls": ["https://example.com"],
                "mode": "indexability_audit",
                "includeAiBotAudit": False,
            }
        )
        full_on = AuditConfig.model_validate(
            {"startUrls": ["https://example.com"], "mode": "full_audit"}
        )
        full_off = AuditConfig.model_validate(
            {
                "startUrls": ["https://example.com"],
                "mode": "full_audit",
                "includeAiBotAudit": False,
            }
        )
        assert idx_on.should_run_ai_bot_audit is True
        assert idx_off.should_run_ai_bot_audit is False
        assert full_on.should_run_ai_bot_audit is True
        assert full_off.should_run_ai_bot_audit is False

    @pytest.mark.parametrize(
        "bad_field",
        [
            {"mode": "invalid_mode"},
            {"outputMode": "csv_only"},
            {"maxUrlsPerDomain": 0},
            {"maxUrlsPerDomain": 50001},
            {"maxAuditPagesPerDomain": -1},
            {"maxAuditPagesPerDomain": 2001},
            {"maxSitemapFiles": 0},
            {"maxSitemapFiles": 201},
            {"concurrency": 0},
            {"concurrency": 16},
        ],
    )
    def test_boundary_and_enum_validation(self, bad_field: dict[str, object]) -> None:
        payload: dict[str, object] = {"startUrls": ["https://example.com"], **bad_field}
        with pytest.raises(ValidationError):
            AuditConfig.model_validate(payload)


class TestAuditOutputModels:
    """Validation tests for URL records, summaries, AI probe results, and KVS payload."""

    def test_url_audit_record_computed_fields_and_seo_metadata(self) -> None:
        record = UrlAuditRecord(
            domain="example.com",
            url="https://example.com/blog/post",
            sitemap_source="https://example.com/sitemap.xml",
            audited=True,
            http_status=200,
            final_url="https://example.com/blog/post",
            robots_allowed=True,
            indexable=False,
            noindex=True,
            noindex_source="meta",
            canonical_status="cross_path_same_host",
            canonical_url="https://example.com/blog/",
            issues=[
                AuditIssue(
                    code=IssueCode.CANONICAL_MISMATCH_SAME_HOST,
                    severity="warning",
                    detail="Canonical points to /blog/.",
                ),
                AuditIssue(
                    code=IssueCode.NOINDEX_IN_SITEMAP,
                    severity="critical",
                    detail="Meta robots contains noindex.",
                ),
                AuditIssue(
                    code=IssueCode.CANONICAL_MISSING,
                    severity="info",
                    detail="Example info issue.",
                ),
                AuditIssue(
                    code=IssueCode.NOINDEX_IN_SITEMAP,
                    severity="critical",
                    detail="Duplicate code for dedup test.",
                ),
            ],
            elapsed_ms=145,
        )

        record.apply_seo_metadata(
            SeoMetadata(
                title="Example Post",
                title_length=12,
                meta_description="A helpful post.",
                meta_description_length=15,
                h1_count=1,
                text_char_count=850,
                jsonld_count=1,
                jsonld_types=["Article"],
                jsonld_error_count=0,
            )
        )

        assert record.has_issues is True
        assert record.issue_codes == [
            "CANONICAL_MISMATCH_SAME_HOST",
            "NOINDEX_IN_SITEMAP",
            "CANONICAL_MISSING",
        ]
        assert record.issue_severities == ["critical", "warning", "info"]

        dataset_row = record.to_dataset_dict()
        assert dataset_row["record_type"] == "url"
        assert dataset_row["issue_codes"] == record.issue_codes
        assert dataset_row["issue_severities"] == ["critical", "warning", "info"]
        assert len(dataset_row["issues"]) == 4
        assert dataset_row["title"] == "Example Post"
        assert dataset_row["jsonld_types"] == ["Article"]

    def test_domain_summary_and_run_payload_validation(self) -> None:
        summary = DomainAuditSummary(
            domain="example.com",
            start_url="https://example.com/",
            mode="full_audit",
            health_score=88,
            robots_status="loaded",
            sitemap_stats=SitemapDiscoveryStats(
                discovery_method="robots_txt",
                sitemap_files_fetched=1,
                total_urls_found=10,
                unique_urls_count=10,
                sitemap_files=[
                    SitemapFileResult(
                        url="https://example.com/sitemap.xml",
                        format="xml_urlset",
                        http_status=200,
                        url_count=10,
                    )
                ],
            ),
            pages_audited=10,
            indexable_count=9,
            non_indexable_count=1,
            ai_audit=AiAuditSummary(
                target_url="https://example.com/",
                browser_http_status=200,
                bots=[
                    AiBotProbeResult(
                        bot_name=bot,
                        robots_allowed=True,
                        http_status=200,
                    )
                    for bot in AI_BOT_NAMES
                ],
                llms_txt=LlmsTxtResult(
                    url="https://example.com/llms.txt",
                    http_status=200,
                    content_type="text/plain; charset=utf-8",
                    llms_txt_present=True,
                    byte_size=420,
                    heading_count=3,
                    link_count=5,
                ),
            ),
            top_priority_fixes=[
                PriorityFix(
                    code=IssueCode.NOINDEX_IN_SITEMAP,
                    severity="critical",
                    affected_count=1,
                    sample_urls=["https://example.com/private"],
                    recommended_action="Remove noindex URLs from the XML sitemap.",
                )
            ],
            elapsed_sec=1.25,
        )

        row = summary.to_dataset_dict()
        assert row["record_type"] == "summary"
        assert row["health_score"] == 88
        assert set(row["canonical_breakdown"].keys()) == {
            "self",
            "index_file_equivalent",
            "cross_path_same_host",
            "cross_host",
            "missing",
        }

        payload = RunSummaryPayload(
            mode="full_audit",
            total_domains=1,
            total_urls_extracted=10,
            total_pages_audited=10,
            elapsed_sec=1.25,
            domains=[summary],
        )
        dumped = payload.model_dump(mode="json")
        assert dumped["total_domains"] == 1
        assert len(dumped["domains"]) == 1

    def test_health_score_and_priority_fix_bounds(self) -> None:
        with pytest.raises(ValidationError):
            DomainAuditSummary(
                domain="example.com",
                start_url="https://example.com/",
                mode="indexability_audit",
                health_score=101,
            )

        with pytest.raises(ValidationError):
            DomainAuditSummary(
                domain="example.com",
                start_url="https://example.com/",
                mode="indexability_audit",
                health_score=-1,
            )

        with pytest.raises(ValidationError):
            PriorityFix(
                code=IssueCode.HTTP_4XX,
                severity="critical",
                affected_count=4,
                sample_urls=["u1", "u2", "u3", "u4"],
                recommended_action="Fix broken links.",
            )

    def test_sitemap_url_entry_priority_bounds(self) -> None:
        entry = SitemapUrlEntry(
            url="https://example.com/",
            raw_url="https://example.com/",
            sitemap_source="https://example.com/sitemap.xml",
            priority=0.8,
        )
        assert entry.priority == 0.8

        with pytest.raises(ValidationError):
            SitemapUrlEntry(
                url="https://example.com/",
                raw_url="https://example.com/",
                sitemap_source="https://example.com/sitemap.xml",
                priority=1.5,
            )

    def test_ai_bot_names_match_specification(self) -> None:
        assert AI_BOT_NAMES == (
            "OAI-SearchBot",
            "GPTBot",
            "ClaudeBot",
            "Claude-SearchBot",
            "PerplexityBot",
        )


class TestArchitectureGuardrails:
    """Ensure core/ remains 100% free of apify SDK dependencies."""

    def test_core_package_has_no_apify_imports(self) -> None:
        core_dir = Path(__file__).resolve().parent.parent / "core"
        py_files = sorted(core_dir.rglob("*.py"))
        assert py_files, "Expected at least one Python file under core/."

        for py_file in py_files:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name != "apify" and not alias.name.startswith("apify."), (
                            f"Forbidden apify import found in {py_file}"
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    assert node.module != "apify" and not node.module.startswith("apify."), (
                        f"Forbidden apify import found in {py_file}"
                    )
