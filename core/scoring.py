"""Domain 0-100 health score calculation and prioritized fix aggregation.

Implements Specification.md §3.5:
- Deduction from 100 with per-category and per-sub-issue caps so a single issue
  type cannot collapse the entire domain score to 0.
- Weighting:
  - Indexability integrity (4xx/5xx/fetch, robots conflict, noindex, canonical
    mismatches; ``index_file_equivalent`` carries 0 penalty): max -50 pts.
  - Sitemap hygiene (duplicates, cross-host URLs, broken/recovered XML, >50k
    URLs, failed sitemap files, redirect chains, non-HTTPS, invalid lastmod):
    max -25 pts.
  - SEO/JSON-LD & AI Bot / ``/llms.txt`` (``full_audit`` only): max -25 pts.
  - ``indexability_audit`` scales the 75-point two-axis subtotal to 0-100.
  - ``extract_only`` scales the 25-point Sitemap hygiene axis to 0-100.
- ``top_priority_fixes`` aggregates all URL-level and domain-level issues sorted
  by severity (``critical`` > ``warning`` > ``info``) then descending affected
  count, keeping up to 10 items with up to 3 sample URLs each.

This module has zero dependency on ``apify``.
"""

from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, Field

from core.models import (
    SEVERITY_ORDER,
    AiAuditSummary,
    AuditMode,
    CanonicalStatus,
    DomainAuditSummary,
    IssueCode,
    IssueSeverity,
    PriorityFix,
    RobotsFetchStatus,
    SitemapDiscoveryStats,
    UrlAuditRecord,
)

MAX_INDEXABILITY_DEDUCTION = 50.0
MAX_SITEMAP_DEDUCTION = 25.0
MAX_SEO_AI_DEDUCTION = 25.0

RECOMMENDED_ACTIONS: dict[str, str] = {
    IssueCode.HTTP_4XX: (
        "Remove dead 4xx URLs from the Sitemap or restore/redirect them cleanly."
    ),
    IssueCode.HTTP_5XX: (
        "Investigate server-side 5xx errors and ensure Sitemap URLs return HTTP 200."
    ),
    IssueCode.FETCH_ERROR: (
        "Verify DNS, TLS, and origin stability for URLs failing to respond."
    ),
    IssueCode.SSRF_BLOCKED: (
        "Replace internal or non-public URLs in the Sitemap with valid public URLs."
    ),
    IssueCode.DISALLOWED_BY_ROBOTS: (
        "Either remove disallowed URLs from the Sitemap or allow them in robots.txt."
    ),
    IssueCode.NOINDEX_IN_SITEMAP: (
        "Remove noindex URLs from the Sitemap or drop the unintended noindex directive."
    ),
    IssueCode.CANONICAL_MISMATCH_CROSS_HOST: (
        "Align cross-host canonical tags with the Sitemap host or list only canonical URLs."
    ),
    IssueCode.CANONICAL_MISMATCH_SAME_HOST: (
        "Update the Sitemap to include only self-canonical URLs instead of non-canonical variants."
    ),
    IssueCode.CANONICAL_INDEX_FILE_EQUIVALENT: (
        "Standardize trailing '/' vs '/index.html' URLs for minor cleanliness (low impact)."
    ),
    IssueCode.CANONICAL_MISSING: (
        "Add a self-referencing <link rel='canonical'> tag to prevent duplicate indexing."
    ),
    IssueCode.REDIRECT_LOOP: (
        "Break circular redirect loops immediately and update Sitemap URLs to final destinations."
    ),
    IssueCode.TOO_MANY_REDIRECTS: (
        "Collapse long redirect chains (>10 hops) and point Sitemap URLs directly to final 200 URLs."
    ),
    IssueCode.REDIRECT_CHAIN: (
        "Update Sitemap entries to point directly to final 200 destination URLs without redirects."
    ),
    IssueCode.HTTP_NON_HTTPS: (
        "Update http:// URLs in the Sitemap to their canonical https:// equivalents."
    ),
    IssueCode.MISSING_TITLE: (
        "Add a unique, descriptive <title> tag to every indexable HTML page."
    ),
    IssueCode.MISSING_META_DESCRIPTION: (
        "Add a concise <meta name='description'> tag to improve search snippets."
    ),
    IssueCode.H1_MISSING: (
        "Include a clear primary <h1> heading reflecting the page's main topic."
    ),
    IssueCode.H1_MULTIPLE: (
        "Consolidate multiple <h1> tags into a single primary heading where appropriate."
    ),
    IssueCode.SSR_THIN_CONTENT: (
        "Verify server-side rendering (SSR) or expand thin page content (>= 200 visible chars)."
    ),
    IssueCode.INVALID_JSONLD: (
        "Fix JSON syntax errors inside <script type='application/ld+json'> blocks."
    ),
    IssueCode.AI_BOT_CDN_BLOCK: (
        "Review CDN/WAF bot-management rules blocking AI search crawlers despite browser HTTP 200."
    ),
    IssueCode.LLMS_TXT_MISSING: (
        "Publish a concise Markdown /llms.txt file at the site root to guide AI assistants."
    ),
    IssueCode.ROBOTS_TXT_UNAVAILABLE: (
        "Ensure /robots.txt responds reliably with HTTP 200 (or 404 if intentionally absent)."
    ),
    IssueCode.RECOVERED_XML: (
        "Fix malformed XML syntax (e.g. unescaped '&' or unclosed tags) in Sitemap files."
    ),
    IssueCode.SITEMAP_URL_LIMIT_EXCEEDED: (
        "Split Sitemap files exceeding 50,000 URLs into multiple files referenced by a sitemap index."
    ),
    IssueCode.SITEMAP_CROSS_HOST_URLS: (
        "Remove URLs belonging to other hosts from this domain's Sitemap files."
    ),
    IssueCode.SITEMAP_DUPLICATE_URLS: (
        "Deduplicate repeated URL entries across Sitemap files."
    ),
    IssueCode.INVALID_LASTMOD: (
        "Format <lastmod> values using valid W3C Datetime (e.g. YYYY-MM-DD or ISO 8601 with TZ)."
    ),
}


class ScoreBreakdown(BaseModel):
    """Transparent per-axis deduction breakdown for a domain's health score."""

    health_score: int = Field(ge=0, le=100)
    indexability_deduction: float = Field(ge=0.0, le=MAX_INDEXABILITY_DEDUCTION)
    sitemap_deduction: float = Field(ge=0.0, le=MAX_SITEMAP_DEDUCTION)
    seo_and_ai_deduction: float = Field(ge=0.0, le=MAX_SEO_AI_DEDUCTION)


def _scaled_deduction(
    count: int,
    total: int,
    *,
    weight: float,
    base_when_present: float,
    cap: float,
) -> float:
    if count <= 0 or total <= 0:
        return 0.0
    rate = min(1.0, count / total)
    return min(cap, rate * weight + base_when_present)


def compute_score_breakdown(
    *,
    mode: AuditMode,
    url_records: list[UrlAuditRecord],
    sitemap_stats: SitemapDiscoveryStats,
    ai_audit: AiAuditSummary | None = None,
) -> ScoreBreakdown:
    """Compute per-axis deductions and final clamped 0-100 integer health score."""
    audited = [r for r in url_records if r.audited]
    n = len(audited)

    # --- Axis 1: Indexability integrity (max -50 pts) ---
    indexability_deduction = 0.0
    if n > 0 and mode != "extract_only":
        broken_urls = 0
        robots_disallowed = 0
        noindex_urls = 0
        cross_host_canon = 0
        same_host_canon = 0

        for rec in audited:
            codes = set(rec.issue_codes)
            if codes & {
                IssueCode.HTTP_4XX,
                IssueCode.HTTP_5XX,
                IssueCode.FETCH_ERROR,
                IssueCode.SSRF_BLOCKED,
            }:
                broken_urls += 1
            if IssueCode.DISALLOWED_BY_ROBOTS in codes:
                robots_disallowed += 1
            if IssueCode.NOINDEX_IN_SITEMAP in codes:
                noindex_urls += 1
            if IssueCode.CANONICAL_MISMATCH_CROSS_HOST in codes:
                cross_host_canon += 1
            if IssueCode.CANONICAL_MISMATCH_SAME_HOST in codes:
                same_host_canon += 1

        d_broken = _scaled_deduction(
            broken_urls, n, weight=35.0, base_when_present=4.0, cap=25.0
        )
        d_robots = _scaled_deduction(
            robots_disallowed, n, weight=25.0, base_when_present=3.0, cap=15.0
        )
        d_noindex = _scaled_deduction(
            noindex_urls, n, weight=25.0, base_when_present=3.0, cap=15.0
        )
        d_cross_canon = _scaled_deduction(
            cross_host_canon, n, weight=25.0, base_when_present=3.0, cap=15.0
        )
        d_same_canon = _scaled_deduction(
            same_host_canon, n, weight=12.0, base_when_present=1.0, cap=8.0
        )
        indexability_deduction = min(
            MAX_INDEXABILITY_DEDUCTION,
            d_broken + d_robots + d_noindex + d_cross_canon + d_same_canon,
        )

    # --- Axis 2: Sitemap hygiene (max -25 pts) ---
    d_dup = _scaled_deduction(
        sitemap_stats.duplicate_urls_count,
        max(sitemap_stats.total_urls_found, 1),
        weight=16.0,
        base_when_present=1.5,
        cap=8.0,
    )
    d_cross_host_sm = _scaled_deduction(
        sitemap_stats.cross_host_urls_count,
        max(sitemap_stats.unique_urls_count, 1),
        weight=16.0,
        base_when_present=1.5,
        cap=8.0,
    )
    d_recovered = min(6.0, sitemap_stats.recovered_xml_files_count * 3.0)
    d_over_50k = min(5.0, sitemap_stats.over_50k_files_count * 5.0)

    # Only penalize sitemap fetch failures when not benign fallback probing that succeeded
    d_failed_sm = 0.0
    if sitemap_stats.sitemap_files_failed > 0 and sitemap_stats.discovery_method != "fallback":
        d_failed_sm = _scaled_deduction(
            sitemap_stats.sitemap_files_failed,
            max(sitemap_stats.sitemap_files_fetched, 1),
            weight=8.0,
            base_when_present=2.0,
            cap=8.0,
        )

    d_invalid_lastmod = _scaled_deduction(
        sitemap_stats.invalid_lastmod_count,
        max(sitemap_stats.lastmod_present_count, 1),
        weight=3.0,
        base_when_present=0.0,
        cap=3.0,
    )

    d_redir_crit = 0.0
    d_redir_warn = 0.0
    d_non_https = 0.0
    if n > 0 and mode != "extract_only":
        redir_crit = 0
        redir_warn = 0
        non_https = 0
        for rec in audited:
            has_crit_redir = any(
                iss.code
                in (
                    IssueCode.REDIRECT_LOOP,
                    IssueCode.TOO_MANY_REDIRECTS,
                    IssueCode.REDIRECT_CHAIN,
                )
                and iss.severity == "critical"
                for iss in rec.issues
            )
            has_warn_redir = any(
                iss.code == IssueCode.REDIRECT_CHAIN and iss.severity == "warning"
                for iss in rec.issues
            )
            if has_crit_redir:
                redir_crit += 1
            elif has_warn_redir:
                redir_warn += 1
            if IssueCode.HTTP_NON_HTTPS in rec.issue_codes:
                non_https += 1

        d_redir_crit = _scaled_deduction(
            redir_crit, n, weight=18.0, base_when_present=2.0, cap=10.0
        )
        d_redir_warn = _scaled_deduction(
            redir_warn, n, weight=8.0, base_when_present=1.0, cap=5.0
        )
        d_non_https = _scaled_deduction(
            non_https, n, weight=8.0, base_when_present=1.0, cap=5.0
        )

    sitemap_deduction = min(
        MAX_SITEMAP_DEDUCTION,
        d_dup
        + d_cross_host_sm
        + d_recovered
        + d_over_50k
        + d_failed_sm
        + d_invalid_lastmod
        + d_redir_crit
        + d_redir_warn
        + d_non_https,
    )

    # --- Axis 3: SEO / JSON-LD & AI Bot / llms.txt (full_audit only, max -25 pts) ---
    seo_and_ai_deduction = 0.0
    if mode == "full_audit":
        d_title = 0.0
        d_thin = 0.0
        d_h1 = 0.0
        d_jsonld = 0.0
        if n > 0:
            missing_title = sum(
                1 for r in audited if IssueCode.MISSING_TITLE in r.issue_codes
            )
            thin_content = sum(
                1 for r in audited if IssueCode.SSR_THIN_CONTENT in r.issue_codes
            )
            h1_missing = sum(
                1 for r in audited if IssueCode.H1_MISSING in r.issue_codes
            )
            invalid_jsonld = sum(
                1 for r in audited if IssueCode.INVALID_JSONLD in r.issue_codes
            )
            d_title = _scaled_deduction(
                missing_title, n, weight=10.0, base_when_present=1.0, cap=6.0
            )
            d_thin = _scaled_deduction(
                thin_content, n, weight=10.0, base_when_present=1.0, cap=6.0
            )
            d_h1 = _scaled_deduction(
                h1_missing, n, weight=5.0, base_when_present=0.0, cap=3.0
            )
            d_jsonld = _scaled_deduction(
                invalid_jsonld, n, weight=10.0, base_when_present=1.5, cap=6.0
            )

        d_ai_block = 0.0
        d_llms = 0.0
        if ai_audit is not None:
            blocked_bots = sum(1 for b in ai_audit.bots if b.cdn_or_waf_diff_block)
            d_ai_block = min(8.0, blocked_bots * 2.5)
            if ai_audit.llms_txt is not None and not ai_audit.llms_txt.llms_txt_present:
                d_llms = 2.0

        seo_and_ai_deduction = min(
            MAX_SEO_AI_DEDUCTION,
            d_title + d_thin + d_h1 + d_jsonld + d_ai_block + d_llms,
        )

    # Combine axes according to mode (Specification.md §3.5)
    if mode == "full_audit":
        raw_score = 100.0 - (
            indexability_deduction + sitemap_deduction + seo_and_ai_deduction
        )
    elif mode == "indexability_audit":
        two_axis_max = MAX_INDEXABILITY_DEDUCTION + MAX_SITEMAP_DEDUCTION  # 75.0
        raw_score = (
            (two_axis_max - (indexability_deduction + sitemap_deduction))
            / two_axis_max
        ) * 100.0
    else:
        raw_score = (
            (MAX_SITEMAP_DEDUCTION - sitemap_deduction) / MAX_SITEMAP_DEDUCTION
        ) * 100.0

    clamped = max(0, min(100, round(raw_score)))
    return ScoreBreakdown(
        health_score=clamped,
        indexability_deduction=round(indexability_deduction, 2),
        sitemap_deduction=round(sitemap_deduction, 2),
        seo_and_ai_deduction=round(seo_and_ai_deduction, 2),
    )


def compute_health_score(
    *,
    mode: AuditMode,
    url_records: list[UrlAuditRecord],
    sitemap_stats: SitemapDiscoveryStats,
    ai_audit: AiAuditSummary | None = None,
) -> int:
    """Return the integer 0-100 health score for a domain."""
    return compute_score_breakdown(
        mode=mode,
        url_records=url_records,
        sitemap_stats=sitemap_stats,
        ai_audit=ai_audit,
    ).health_score


def build_top_priority_fixes(
    *,
    url_records: list[UrlAuditRecord],
    sitemap_stats: SitemapDiscoveryStats,
    robots_status: RobotsFetchStatus = "loaded",
    robots_url: str | None = None,
    ai_audit: AiAuditSummary | None = None,
    limit: int = 10,
) -> list[PriorityFix]:
    """Aggregate URL and domain issues into top *limit* prioritized remediation items."""
    counts: dict[tuple[str, IssueSeverity], int] = defaultdict(int)
    samples: dict[tuple[str, IssueSeverity], list[str]] = defaultdict(list)

    def _add_issue(code: str, severity: IssueSeverity, count: int, urls: list[str]) -> None:
        if count <= 0:
            return
        key = (code, severity)
        counts[key] += count
        bucket = samples[key]
        for u in urls:
            if u and u not in bucket and len(bucket) < 3:
                bucket.append(u)

    # Aggregate URL-level issues (deduplicated per (url, code, severity))
    for rec in url_records:
        seen_for_url: set[tuple[str, IssueSeverity]] = set()
        for issue in rec.issues:
            key = (issue.code, issue.severity)
            if key in seen_for_url:
                continue
            seen_for_url.add(key)
            _add_issue(issue.code, issue.severity, 1, [rec.url])

    # Domain-level Sitemap structural issues
    if sitemap_stats.recovered_xml_files_count > 0:
        recovered_urls = [
            f.url for f in sitemap_stats.sitemap_files if f.recovered_xml
        ]
        _add_issue(
            IssueCode.RECOVERED_XML,
            "warning",
            sitemap_stats.recovered_xml_files_count,
            recovered_urls,
        )

    if sitemap_stats.over_50k_files_count > 0:
        over_urls = [
            f.url for f in sitemap_stats.sitemap_files if f.exceeded_50k_limit
        ]
        _add_issue(
            IssueCode.SITEMAP_URL_LIMIT_EXCEEDED,
            "warning",
            sitemap_stats.over_50k_files_count,
            over_urls,
        )

    if sitemap_stats.cross_host_urls_count > 0:
        sm_urls = [f.url for f in sitemap_stats.sitemap_files if f.error is None]
        _add_issue(
            IssueCode.SITEMAP_CROSS_HOST_URLS,
            "warning",
            sitemap_stats.cross_host_urls_count,
            sm_urls,
        )

    if sitemap_stats.duplicate_urls_count > 0:
        sm_urls = [f.url for f in sitemap_stats.sitemap_files if f.error is None]
        _add_issue(
            IssueCode.SITEMAP_DUPLICATE_URLS,
            "warning",
            sitemap_stats.duplicate_urls_count,
            sm_urls,
        )

    if sitemap_stats.invalid_lastmod_count > 0:
        sm_urls = [f.url for f in sitemap_stats.sitemap_files if f.error is None]
        _add_issue(
            IssueCode.INVALID_LASTMOD,
            "info",
            sitemap_stats.invalid_lastmod_count,
            sm_urls,
        )

    # robots.txt availability warning
    if robots_status == "unavailable_unknown":
        _add_issue(
            IssueCode.ROBOTS_TXT_UNAVAILABLE,
            "warning",
            1,
            [robots_url] if robots_url else [],
        )

    # AI bot & /llms.txt issues
    if ai_audit is not None:
        blocked_bots = [b for b in ai_audit.bots if b.cdn_or_waf_diff_block]
        if blocked_bots:
            _add_issue(
                IssueCode.AI_BOT_CDN_BLOCK,
                "warning",
                len(blocked_bots),
                [ai_audit.target_url],
            )
        if ai_audit.llms_txt is not None and not ai_audit.llms_txt.llms_txt_present:
            _add_issue(
                IssueCode.LLMS_TXT_MISSING,
                "info",
                1,
                [ai_audit.llms_txt.url],
            )

    sorted_keys = sorted(
        counts.keys(),
        key=lambda k: (SEVERITY_ORDER[k[1]], -counts[k], k[0]),
    )

    fixes: list[PriorityFix] = []
    for code, severity in sorted_keys[:limit]:
        fixes.append(
            PriorityFix(
                code=code,
                severity=severity,
                affected_count=counts[(code, severity)],
                sample_urls=samples[(code, severity)][:3],
                recommended_action=RECOMMENDED_ACTIONS.get(
                    code, f"Review and resolve detected {code} issues."
                ),
            )
        )
    return fixes


def build_domain_summary(
    *,
    domain: str,
    start_url: str,
    mode: AuditMode,
    robots_status: RobotsFetchStatus,
    robots_url: str | None = None,
    sitemap_stats: SitemapDiscoveryStats,
    url_records: list[UrlAuditRecord],
    ai_audit: AiAuditSummary | None = None,
    proxy_escalated: bool = False,
    elapsed_sec: float = 0.0,
    errors: list[str] | None = None,
) -> DomainAuditSummary:
    """Aggregate all domain audit outputs into a :class:`DomainAuditSummary`."""
    audited = [r for r in url_records if r.audited]
    indexable_count = sum(1 for r in audited if r.indexable is True)
    non_indexable_count = sum(1 for r in audited if r.indexable is False)

    severity_counts: dict[IssueSeverity, int] = {
        "critical": 0,
        "warning": 0,
        "info": 0,
    }
    code_counts: dict[str, int] = defaultdict(int)
    canonical_breakdown: dict[CanonicalStatus, int] = {
        "self": 0,
        "index_file_equivalent": 0,
        "cross_path_same_host": 0,
        "cross_host": 0,
        "missing": 0,
    }

    for rec in audited:
        if rec.canonical_status is not None:
            canonical_breakdown[rec.canonical_status] += 1
        for issue in rec.issues:
            severity_counts[issue.severity] += 1
            code_counts[issue.code] += 1

    # Also reflect domain-level AI/robots/sitemap warnings in issue counts
    if robots_status == "unavailable_unknown":
        severity_counts["warning"] += 1
        code_counts[IssueCode.ROBOTS_TXT_UNAVAILABLE] += 1
    if sitemap_stats.recovered_xml_files_count > 0:
        severity_counts["warning"] += sitemap_stats.recovered_xml_files_count
        code_counts[IssueCode.RECOVERED_XML] += sitemap_stats.recovered_xml_files_count
    if sitemap_stats.over_50k_files_count > 0:
        severity_counts["warning"] += sitemap_stats.over_50k_files_count
        code_counts[IssueCode.SITEMAP_URL_LIMIT_EXCEEDED] += sitemap_stats.over_50k_files_count
    if ai_audit is not None:
        blocked_bots = sum(1 for b in ai_audit.bots if b.cdn_or_waf_diff_block)
        if blocked_bots > 0:
            severity_counts["warning"] += blocked_bots
            code_counts[IssueCode.AI_BOT_CDN_BLOCK] += blocked_bots

    health_score = compute_health_score(
        mode=mode,
        url_records=url_records,
        sitemap_stats=sitemap_stats,
        ai_audit=ai_audit,
    )
    top_fixes = build_top_priority_fixes(
        url_records=url_records,
        sitemap_stats=sitemap_stats,
        robots_status=robots_status,
        robots_url=robots_url,
        ai_audit=ai_audit,
        limit=10,
    )

    return DomainAuditSummary(
        domain=domain,
        start_url=start_url,
        mode=mode,
        health_score=health_score,
        robots_status=robots_status,
        sitemap_stats=sitemap_stats,
        pages_audited=len(audited),
        indexable_count=indexable_count,
        non_indexable_count=non_indexable_count,
        issue_counts_by_severity=severity_counts,
        issue_counts_by_code=dict(code_counts),
        canonical_breakdown=canonical_breakdown,
        ai_audit=ai_audit,
        top_priority_fixes=top_fixes,
        proxy_escalated=proxy_escalated,
        elapsed_sec=round(elapsed_sec, 3),
        errors=list(errors or []),
    )
