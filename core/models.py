"""Pydantic v2 data models for Sitemap Extractor & Indexability Auditor.

All models in this module are pure Python (no dependency on ``apify``) and align
directly with ``Specification.md`` and ``Skills.md``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from core.ssrf import SSRFBlockedError, normalize_url

AuditMode = Literal["extract_only", "indexability_audit", "full_audit"]
OutputMode = Literal["both", "urls_only", "summary_only"]
IssueSeverity = Literal["critical", "warning", "info"]
CanonicalStatus = Literal[
    "self",
    "index_file_equivalent",
    "cross_path_same_host",
    "cross_host",
    "missing",
]
RobotsFetchStatus = Literal[
    "loaded",
    "not_found_allow_all",
    "unavailable_unknown",
    "blocked_ssrf",
]
SitemapFormat = Literal["xml_urlset", "xml_index", "text", "unknown"]
DiscoveryMethod = Literal["explicit", "robots_txt", "fallback", "none"]
NoindexSource = Literal["header", "meta", "both"] | None

AI_BOT_NAMES: tuple[str, ...] = (
    "OAI-SearchBot",
    "GPTBot",
    "ClaudeBot",
    "Claude-SearchBot",
    "PerplexityBot",
)

SEVERITY_ORDER: dict[IssueSeverity, int] = {
    "critical": 0,
    "warning": 1,
    "info": 2,
}


class IssueCode(StrEnum):
    """Canonical issue codes emitted by the auditor."""

    HTTP_4XX = "HTTP_4XX"
    HTTP_5XX = "HTTP_5XX"
    FETCH_ERROR = "FETCH_ERROR"
    SSRF_BLOCKED = "SSRF_BLOCKED"
    REDIRECT_CHAIN = "REDIRECT_CHAIN"
    REDIRECT_LOOP = "REDIRECT_LOOP"
    TOO_MANY_REDIRECTS = "TOO_MANY_REDIRECTS"
    HTTP_NON_HTTPS = "HTTP_NON_HTTPS"
    DISALLOWED_BY_ROBOTS = "DISALLOWED_BY_ROBOTS"
    NOINDEX_IN_SITEMAP = "NOINDEX_IN_SITEMAP"
    CANONICAL_INDEX_FILE_EQUIVALENT = "CANONICAL_INDEX_FILE_EQUIVALENT"
    CANONICAL_MISMATCH_SAME_HOST = "CANONICAL_MISMATCH_SAME_HOST"
    CANONICAL_MISMATCH_CROSS_HOST = "CANONICAL_MISMATCH_CROSS_HOST"
    CANONICAL_MISSING = "CANONICAL_MISSING"
    MISSING_TITLE = "MISSING_TITLE"
    MISSING_META_DESCRIPTION = "MISSING_META_DESCRIPTION"
    H1_MISSING = "H1_MISSING"
    H1_MULTIPLE = "H1_MULTIPLE"
    SSR_THIN_CONTENT = "SSR_THIN_CONTENT"
    INVALID_JSONLD = "INVALID_JSONLD"
    AI_BOT_CDN_BLOCK = "AI_BOT_CDN_BLOCK"
    LLMS_TXT_MISSING = "LLMS_TXT_MISSING"
    ROBOTS_TXT_UNAVAILABLE = "ROBOTS_TXT_UNAVAILABLE"
    RECOVERED_XML = "RECOVERED_XML"
    SITEMAP_URL_LIMIT_EXCEEDED = "SITEMAP_URL_LIMIT_EXCEEDED"
    SITEMAP_CROSS_HOST_URLS = "SITEMAP_CROSS_HOST_URLS"
    SITEMAP_DUPLICATE_URLS = "SITEMAP_DUPLICATE_URLS"
    INVALID_LASTMOD = "INVALID_LASTMOD"


def _default_severity_counts() -> dict[IssueSeverity, int]:
    return {"critical": 0, "warning": 0, "info": 0}


def _default_canonical_breakdown() -> dict[CanonicalStatus, int]:
    return {
        "self": 0,
        "index_file_equivalent": 0,
        "cross_path_same_host": 0,
        "cross_host": 0,
        "missing": 0,
    }


class AuditConfig(BaseModel):
    """Validated run configuration matching ``input_schema.json`` (camelCase & snake_case)."""

    model_config = ConfigDict(populate_by_name=True)

    start_urls: list[str] = Field(alias="startUrls", min_length=1)
    mode: AuditMode = "indexability_audit"
    max_urls_per_domain: int = Field(
        default=500, alias="maxUrlsPerDomain", ge=1, le=50000
    )
    max_audit_pages_per_domain: int = Field(
        default=50, alias="maxAuditPagesPerDomain", ge=0, le=2000
    )
    max_sitemap_files: int = Field(
        default=30, alias="maxSitemapFiles", ge=1, le=200
    )
    concurrency: int = Field(default=5, ge=1, le=15)
    include_ai_bot_audit: bool = Field(default=True, alias="includeAiBotAudit")
    output_mode: OutputMode = Field(default="both", alias="outputMode")
    only_issues_in_dataset: bool = Field(default=False, alias="onlyIssuesInDataset")
    auto_escalate_proxy: bool = Field(default=True, alias="autoEscalateProxy")
    proxy_configuration: dict[str, Any] = Field(
        default_factory=lambda: {"useApifyProxy": False},
        alias="proxyConfiguration",
    )

    @field_validator("start_urls", mode="before")
    @classmethod
    def _normalize_start_urls(cls, value: Any) -> list[str]:
        """Accept either ``list[str]`` or Apify RequestList ``list[{'url': str}]``."""
        if not isinstance(value, list):
            raise ValueError("startUrls must be a list of URL strings or RequestList objects.")

        normalized_list: list[str] = []
        seen: set[str] = set()

        for idx, item in enumerate(value):
            if isinstance(item, str):
                raw = item
            elif isinstance(item, dict) and isinstance(item.get("url"), str):
                raw = item["url"]
            else:
                raise ValueError(
                    f"startUrls[{idx}] must be a non-empty URL string or a dict with a 'url' string."
                )

            try:
                norm = normalize_url(raw, allow_bare_host=True)
            except SSRFBlockedError as exc:
                raise ValueError(f"startUrls[{idx}] is invalid: {exc}") from exc

            if norm not in seen:
                seen.add(norm)
                normalized_list.append(norm)

        if not normalized_list:
            raise ValueError("startUrls must contain at least one valid URL.")

        return normalized_list

    @model_validator(mode="after")
    def _enforce_mode_rules(self) -> AuditConfig:
        # Per Specification.md §4.1: in extract_only mode, maxAuditPagesPerDomain is treated as 0.
        if self.mode == "extract_only":
            self.max_audit_pages_per_domain = 0
        return self

    @property
    def should_run_ai_bot_audit(self) -> bool:
        """Whether AI search bot differential probing & /llms.txt check should run."""
        return self.mode != "extract_only" and self.include_ai_bot_audit


class AuditIssue(BaseModel):
    """Structured issue attached to an audited URL or domain."""

    code: str
    severity: IssueSeverity
    detail: str


class SitemapUrlEntry(BaseModel):
    """Single URL entry extracted from a Sitemap file."""

    url: str
    raw_url: str
    sitemap_source: str
    lastmod: str | None = None
    lastmod_valid: bool | None = None
    changefreq: str | None = None
    priority: float | None = Field(default=None, ge=0.0, le=1.0)
    is_cross_host: bool = False


class SitemapFileResult(BaseModel):
    """Fetch and parse diagnostics for a single Sitemap file."""

    url: str
    format: SitemapFormat = "unknown"
    http_status: int | None = None
    final_url: str | None = None
    url_count: int = Field(default=0, ge=0)
    child_sitemap_count: int = Field(default=0, ge=0)
    is_gzipped: bool = False
    recovered_xml: bool = False
    truncated: bool = False
    exceeded_50k_limit: bool = False
    error: str | None = None
    elapsed_ms: int = Field(default=0, ge=0)


class SitemapDiscoveryStats(BaseModel):
    """Domain-level Sitemap discovery and structural quality statistics."""

    discovery_method: DiscoveryMethod = "none"
    sitemap_files_fetched: int = Field(default=0, ge=0)
    sitemap_files_failed: int = Field(default=0, ge=0)
    total_urls_found: int = Field(default=0, ge=0)
    unique_urls_count: int = Field(default=0, ge=0)
    duplicate_urls_count: int = Field(default=0, ge=0)
    cross_host_urls_count: int = Field(default=0, ge=0)
    recovered_xml_files_count: int = Field(default=0, ge=0)
    over_50k_files_count: int = Field(default=0, ge=0)
    lastmod_present_count: int = Field(default=0, ge=0)
    lastmod_coverage_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    invalid_lastmod_count: int = Field(default=0, ge=0)
    sitemap_files: list[SitemapFileResult] = Field(default_factory=list)


class RobotsInfo(BaseModel):
    """Summary of robots.txt retrieval for a domain."""

    url: str
    status: RobotsFetchStatus
    http_status: int | None = None
    sitemap_urls: list[str] = Field(default_factory=list)
    truncated: bool = False
    error: str | None = None


class SeoMetadata(BaseModel):
    """HTML SEO & JSON-LD metadata collected in ``full_audit`` mode."""

    title: str | None = None
    title_length: int = Field(default=0, ge=0)
    meta_description: str | None = None
    meta_description_length: int = Field(default=0, ge=0)
    h1_count: int = Field(default=0, ge=0)
    text_char_count: int = Field(default=0, ge=0)
    jsonld_count: int = Field(default=0, ge=0)
    jsonld_types: list[str] = Field(default_factory=list)
    jsonld_error_count: int = Field(default=0, ge=0)


class UrlAuditRecord(BaseModel):
    """Flat URL-level audit record emitted to the Default Dataset (``record_type == 'url'``)."""

    record_type: Literal["url"] = "url"
    domain: str
    url: str
    sitemap_source: str
    lastmod: str | None = None
    audited: bool = False
    http_status: int | None = None
    final_url: str | None = None
    redirect_hops: int = Field(default=0, ge=0)
    redirect_chain: list[str] = Field(default_factory=list)
    robots_allowed: bool | None = None
    indexable: bool | None = None
    noindex: bool | None = None
    noindex_source: NoindexSource = None
    canonical_status: CanonicalStatus | None = None
    canonical_url: str | None = None
    issues: list[AuditIssue] = Field(default_factory=list)

    # Flat SEO & JSON-LD fields populated in full_audit mode
    title: str | None = None
    title_length: int | None = Field(default=None, ge=0)
    meta_description: str | None = None
    meta_description_length: int | None = Field(default=None, ge=0)
    h1_count: int | None = Field(default=None, ge=0)
    text_char_count: int | None = Field(default=None, ge=0)
    jsonld_count: int | None = Field(default=None, ge=0)
    jsonld_types: list[str] = Field(default_factory=list)
    jsonld_error_count: int | None = Field(default=None, ge=0)

    elapsed_ms: int | None = Field(default=None, ge=0)
    error: str | None = None

    @computed_field
    @property
    def issue_codes(self) -> list[str]:
        """Deduplicated issue codes preserving encounter order for easy Dataset filtering."""
        return list(dict.fromkeys(issue.code for issue in self.issues))

    @computed_field
    @property
    def issue_severities(self) -> list[IssueSeverity]:
        """Deduplicated severities ordered critical -> warning -> info."""
        present = {issue.severity for issue in self.issues}
        return sorted(present, key=lambda sev: SEVERITY_ORDER[sev])

    @property
    def has_issues(self) -> bool:
        return bool(self.issues)

    def apply_seo_metadata(self, seo: SeoMetadata) -> None:
        """Copy parsed HTML SEO/JSON-LD fields onto this flat URL record."""
        self.title = seo.title
        self.title_length = seo.title_length
        self.meta_description = seo.meta_description
        self.meta_description_length = seo.meta_description_length
        self.h1_count = seo.h1_count
        self.text_char_count = seo.text_char_count
        self.jsonld_count = seo.jsonld_count
        self.jsonld_types = list(seo.jsonld_types)
        self.jsonld_error_count = seo.jsonld_error_count

    def to_dataset_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable flat dictionary for Default Dataset output."""
        return self.model_dump(mode="json")


class AiBotProbeResult(BaseModel):
    """Per-bot robots.txt and live HTTP differential check result."""

    bot_name: str
    robots_allowed: bool | None = None
    http_status: int | None = None
    cdn_or_waf_diff_block: bool = False
    error: str | None = None
    elapsed_ms: int = Field(default=0, ge=0)


class LlmsTxtResult(BaseModel):
    """Diagnostic result for ``/llms.txt`` availability and structure."""

    url: str
    http_status: int | None = None
    content_type: str | None = None
    llms_txt_present: bool = False
    byte_size: int = Field(default=0, ge=0)
    heading_count: int = Field(default=0, ge=0)
    link_count: int = Field(default=0, ge=0)
    truncated: bool = False
    error: str | None = None


class AiAuditSummary(BaseModel):
    """Aggregated AI search crawler reachability and ``/llms.txt`` diagnostics."""

    target_url: str
    browser_http_status: int | None = None
    bots: list[AiBotProbeResult] = Field(default_factory=list)
    any_cdn_or_waf_diff_block: bool = False
    llms_txt: LlmsTxtResult | None = None


class PriorityFix(BaseModel):
    """Prioritized remediation item surfaced in domain summaries."""

    code: str
    severity: IssueSeverity
    affected_count: int = Field(ge=1)
    sample_urls: list[str] = Field(default_factory=list, max_length=3)
    recommended_action: str


class DomainAuditSummary(BaseModel):
    """Domain-level summary record emitted to Dataset (``record_type == 'summary'``)."""

    record_type: Literal["summary"] = "summary"
    domain: str
    start_url: str
    mode: AuditMode
    health_score: int | None = Field(default=None, ge=0, le=100)
    robots_status: RobotsFetchStatus = "unavailable_unknown"
    sitemap_stats: SitemapDiscoveryStats = Field(default_factory=SitemapDiscoveryStats)
    pages_audited: int = Field(default=0, ge=0)
    indexable_count: int = Field(default=0, ge=0)
    non_indexable_count: int = Field(default=0, ge=0)
    issue_counts_by_severity: dict[IssueSeverity, int] = Field(
        default_factory=_default_severity_counts
    )
    issue_counts_by_code: dict[str, int] = Field(default_factory=dict)
    canonical_breakdown: dict[CanonicalStatus, int] = Field(
        default_factory=_default_canonical_breakdown
    )
    ai_audit: AiAuditSummary | None = None
    top_priority_fixes: list[PriorityFix] = Field(default_factory=list, max_length=10)
    proxy_escalated: bool = False
    elapsed_sec: float = Field(default=0.0, ge=0.0)
    errors: list[str] = Field(default_factory=list)

    def to_dataset_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary for Default Dataset output."""
        return self.model_dump(mode="json")


class RunSummaryPayload(BaseModel):
    """Top-level payload saved under Key-Value Store key ``SUMMARY``."""

    mode: AuditMode
    total_domains: int = Field(default=0, ge=0)
    total_urls_extracted: int = Field(default=0, ge=0)
    total_pages_audited: int = Field(default=0, ge=0)
    elapsed_sec: float = Field(default=0.0, ge=0.0)
    proxy_escalated: bool = False
    charge_limit_reached: bool = False
    domains: list[DomainAuditSummary] = Field(default_factory=list)
