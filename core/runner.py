"""Domain-level and multi-domain audit orchestrator (pure Python, Apify-independent).

Coordinates all core stages across the three execution modes:
- ``extract_only``: robots.txt (when needed) -> Sitemap discovery/expansion -> summary.
- ``indexability_audit``: Sitemap extraction -> up to ``maxAuditPagesPerDomain`` page
  indexability audits -> optional AI bot & ``/llms.txt`` probe -> 2-axis 0-100 score.
- ``full_audit``: Sitemap extraction -> full HTML SEO/JSON-LD + indexability audits ->
  AI bot & ``/llms.txt`` probe -> 3-axis 0-100 score & top priority fixes.

This module has zero dependency on ``apify``.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx
from pydantic import BaseModel, Field

from core.ai_probe import probe_ai_bots_and_llms
from core.http_client import (
    DomainHttpClient,
    ProxyTransportFactory,
    ProxyUrlFactory,
)
from core.models import (
    AiAuditSummary,
    AuditConfig,
    DomainAuditSummary,
    RobotsFetchStatus,
    RunSummaryPayload,
    UrlAuditRecord,
)
from core.page_auditor import audit_page
from core.robots import RobotsChecker, build_robots_url, fetch_robots
from core.scoring import build_domain_summary
from core.sitemap_parser import (
    discover_and_parse_sitemaps,
    is_explicit_sitemap_url,
)
from core.ssrf import Resolver, extract_host, normalize_url


class DomainAuditResult(BaseModel):
    """Complete output of auditing a single domain / start URL."""

    summary: DomainAuditSummary
    url_records: list[UrlAuditRecord] = Field(default_factory=list)

    def filtered_url_records(self, *, only_issues: bool = False) -> list[UrlAuditRecord]:
        """Return URL records optionally filtered to only those with detected issues."""
        if not only_issues:
            return list(self.url_records)
        return [rec for rec in self.url_records if rec.has_issues]


class RunAuditResult(BaseModel):
    """Aggregated output across all start URLs in a run."""

    summary_payload: RunSummaryPayload
    domain_results: list[DomainAuditResult] = Field(default_factory=list)


async def audit_domain(
    start_url: str,
    config: AuditConfig,
    *,
    proxy_url_factory: ProxyUrlFactory | None = None,
    initial_proxy_url: str | None = None,
    dns_resolver: Resolver | None = None,
    direct_transport: httpx.AsyncBaseTransport | None = None,
    proxy_transport_factory: ProxyTransportFactory | None = None,
    logger: logging.Logger | None = None,
) -> DomainAuditResult:
    """Execute the configured audit pipeline for a single start URL / domain."""
    log = logger or logging.getLogger(__name__)
    started = time.perf_counter()

    normalized_start = normalize_url(start_url, allow_bare_host=True)
    domain = extract_host(normalized_start)
    errors: list[str] = []

    async with DomainHttpClient(
        concurrency=config.concurrency,
        auto_escalate_proxy=config.auto_escalate_proxy,
        proxy_url_factory=proxy_url_factory,
        initial_proxy_url=initial_proxy_url,
        dns_resolver=dns_resolver,
        direct_transport=direct_transport,
        proxy_transport_factory=proxy_transport_factory,
        logger=log,
    ) as http_client:
        # Stage 1: robots.txt (skipped only when extract_only targets an explicit sitemap URL)
        robots_checker: RobotsChecker | None = None
        robots_status: RobotsFetchStatus = "unavailable_unknown"
        robots_url = build_robots_url(normalized_start)

        skip_robots = config.mode == "extract_only" and is_explicit_sitemap_url(
            normalized_start
        )
        if not skip_robots:
            robots_checker = await fetch_robots(http_client, normalized_start)
            robots_status = robots_checker.info.status
            robots_url = robots_checker.info.url
            if robots_checker.info.error:
                errors.append(f"robots.txt: {robots_checker.info.error}")

        # Stage 2: Sitemap discovery & recursive parsing
        discovery = await discover_and_parse_sitemaps(
            http_client,
            normalized_start,
            robots_checker=robots_checker,
            max_urls_per_domain=config.max_urls_per_domain,
            max_sitemap_files=config.max_sitemap_files,
        )
        if not discovery.entries and discovery.stats.discovery_method == "none":
            errors.append(f"No valid Sitemap discovered for {domain}.")

        # Stage 3: Page-level Indexability / HTML SEO auditing
        audit_limit = (
            0 if config.mode == "extract_only" else config.max_audit_pages_per_domain
        )
        entries_to_audit = discovery.entries[:audit_limit]
        unaudited_entries = discovery.entries[audit_limit:]

        audited_records: list[UrlAuditRecord] = []
        if entries_to_audit:
            audited_records = list(
                await asyncio.gather(
                    *(
                        audit_page(
                            http_client,
                            entry,
                            domain=domain,
                            mode=config.mode,
                            robots_checker=robots_checker,
                        )
                        for entry in entries_to_audit
                    )
                )
            )

        unaudited_records: list[UrlAuditRecord] = [
            UrlAuditRecord(
                domain=domain,
                url=entry.url,
                sitemap_source=entry.sitemap_source,
                lastmod=entry.lastmod,
                audited=False,
                robots_allowed=(
                    robots_checker.can_fetch(entry.url, "*")
                    if robots_checker is not None
                    else None
                ),
            )
            for entry in unaudited_entries
        ]
        all_url_records = audited_records + unaudited_records

        # Stage 4: AI Search Bot differential probe & /llms.txt
        ai_audit: AiAuditSummary | None = None
        if config.should_run_ai_bot_audit:
            ai_audit = await probe_ai_bots_and_llms(
                http_client,
                normalized_start,
                robots_checker=robots_checker,
            )

        elapsed_sec = time.perf_counter() - started
        summary = build_domain_summary(
            domain=domain,
            start_url=normalized_start,
            mode=config.mode,
            robots_status=robots_status,
            robots_url=robots_url,
            sitemap_stats=discovery.stats,
            url_records=all_url_records,
            ai_audit=ai_audit,
            proxy_escalated=http_client.proxy_escalated,
            elapsed_sec=elapsed_sec,
            errors=errors,
        )

    return DomainAuditResult(summary=summary, url_records=all_url_records)


async def run_audit(
    config: AuditConfig,
    *,
    proxy_url_factory: ProxyUrlFactory | None = None,
    initial_proxy_url: str | None = None,
    dns_resolver: Resolver | None = None,
    direct_transport: httpx.AsyncBaseTransport | None = None,
    proxy_transport_factory: ProxyTransportFactory | None = None,
    logger: logging.Logger | None = None,
) -> RunAuditResult:
    """Run audits across all configured ``start_urls`` sequentially and aggregate summary."""
    started = time.perf_counter()
    domain_results: list[DomainAuditResult] = []

    for start_url in config.start_urls:
        res = await audit_domain(
            start_url,
            config,
            proxy_url_factory=proxy_url_factory,
            initial_proxy_url=initial_proxy_url,
            dns_resolver=dns_resolver,
            direct_transport=direct_transport,
            proxy_transport_factory=proxy_transport_factory,
            logger=logger,
        )
        domain_results.append(res)

    elapsed_sec = round(time.perf_counter() - started, 3)
    summaries = [r.summary for r in domain_results]
    payload = RunSummaryPayload(
        mode=config.mode,
        total_domains=len(summaries),
        total_urls_extracted=sum(len(r.url_records) for r in domain_results),
        total_pages_audited=sum(s.pages_audited for s in summaries),
        elapsed_sec=elapsed_sec,
        proxy_escalated=any(s.proxy_escalated for s in summaries),
        domains=summaries,
    )
    return RunAuditResult(summary_payload=payload, domain_results=domain_results)
