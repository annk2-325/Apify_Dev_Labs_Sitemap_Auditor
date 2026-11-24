"""Thin Apify Actor adapter wrapping pure-Python ``core/`` logic with PPE billing.

Implements Specification.md §4 and Skills.md §4:
- Exact PPE event names:
  - ``sitemap-url-extracted`` (unaudited extracted-only URL rows)
  - ``page-indexability-audited`` (HTTP/HTML audited URL rows; never double-charged)
  - ``domain-audit-summary`` (1x per domain with deterministic idempotency key)
- Safe stop on ``event_charge_limit_reached == True`` from either ``charge`` or ``push_data``.
- Always persists Key-Value Store record ``SUMMARY`` (``RunSummaryPayload``).
- Lazy ``autoEscalateProxy`` integration via ``Actor.create_proxy_configuration``.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

# Ensure repo root (containing `core/`) is importable when `apify run` executes inside `apify_actor/`
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path and (_REPO_ROOT / "core").is_dir():
    sys.path.insert(0, str(_REPO_ROOT))

from core.http_client import ProxyUrlFactory
from core.models import AuditConfig, DomainAuditSummary, RunSummaryPayload, UrlAuditRecord
from core.runner import DomainAuditResult, audit_domain

EVENT_SITEMAP_URL_EXTRACTED = "sitemap-url-extracted"
EVENT_PAGE_INDEXABILITY_AUDITED = "page-indexability-audited"
EVENT_DOMAIN_AUDIT_SUMMARY = "domain-audit-summary"
URL_PUSH_BATCH_SIZE = 25

DomainAuditorFn = Callable[..., Awaitable[DomainAuditResult]]

logger = logging.getLogger(__name__)


def _get_actor_logger(actor: Any) -> logging.Logger:
    actor_log = getattr(actor, "log", None)
    return actor_log if isinstance(actor_log, logging.Logger) else logger


def _has_explicit_proxy_config(proxy_input: Any) -> bool:
    if not isinstance(proxy_input, dict):
        return False
    if bool(proxy_input.get("useApifyProxy")):
        return True
    proxy_urls = proxy_input.get("proxyUrls")
    return isinstance(proxy_urls, list) and len(proxy_urls) > 0


def _domain_idempotency_key(start_url: str) -> str:
    domain_hash = hashlib.sha256(start_url.encode("utf-8")).hexdigest()[:16]
    return f"summary-{domain_hash}"


def build_proxy_url_factory(
    actor: Any,
    proxy_configuration_input: dict[str, Any] | None,
    *,
    auto_escalate_proxy: bool,
    log: logging.Logger,
) -> ProxyUrlFactory:
    """Create a lazy proxy URL callback injected into ``core/`` HTTP clients."""
    default_proxy_cfg: Any = None
    default_initialized = False
    escalated_proxy_cfg: Any = None
    escalated_initialized = False

    async def proxy_url_factory(escalate: bool) -> str | None:
        nonlocal default_proxy_cfg, default_initialized
        nonlocal escalated_proxy_cfg, escalated_initialized

        if not escalate:
            if not _has_explicit_proxy_config(proxy_configuration_input):
                return None
            if not default_initialized:
                default_initialized = True
                try:
                    default_proxy_cfg = await actor.create_proxy_configuration(
                        actor_proxy_input=proxy_configuration_input
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "Failed to initialize explicit proxyConfiguration: %s", exc
                    )
                    default_proxy_cfg = None
            if default_proxy_cfg is None:
                return None
            return await default_proxy_cfg.new_url()

        if not auto_escalate_proxy:
            return None

        if not escalated_initialized:
            escalated_initialized = True
            try:
                # Use default Apify Proxy pool for lightweight escalation on 403/429/503
                escalated_proxy_cfg = await actor.create_proxy_configuration()
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "Failed to initialize Apify Proxy escalation: %s", exc
                )
                escalated_proxy_cfg = None

        if escalated_proxy_cfg is None:
            return None
        return await escalated_proxy_cfg.new_url()

    return proxy_url_factory


async def _push_data_with_event(
    actor: Any,
    data: Any,
    event_name: str | None = None,
) -> Any:
    """Push Dataset records with PPE event billing compatible across Apify SDK v2/v3."""
    if event_name is None:
        return await actor.push_data(data)

    try:
        params = inspect.signature(actor.push_data).parameters
    except (TypeError, ValueError):
        params = {}

    if "event_name" in params:
        return await actor.push_data(data, event_name=event_name)
    if "charged_event_name" in params:
        return await actor.push_data(data, charged_event_name=event_name)
    return await actor.push_data(data, event_name=event_name)


async def _charge_event(
    actor: Any,
    *,
    event_name: str,
    count: int = 1,
    idempotency_key: str | None = None,
) -> Any:
    """Charge a PPE event compatible across Apify SDK v2 (idempotency_key) and v3."""
    try:
        params = inspect.signature(actor.charge).parameters
    except (TypeError, ValueError):
        params = {}

    if idempotency_key is not None and "idempotency_key" in params:
        return await actor.charge(
            event_name=event_name,
            count=count,
            idempotency_key=idempotency_key,
        )
    return await actor.charge(event_name=event_name, count=count)


async def _push_url_batches(
    actor: Any,
    records: list[UrlAuditRecord],
    *,
    event_name: str,
    batch_size: int,
    log: logging.Logger,
) -> bool:
    """Push URL records in batches under *event_name*; return True if charge limit reached."""
    step = max(batch_size, 1)
    for start in range(0, len(records), step):
        batch = [rec.to_dataset_dict() for rec in records[start : start + step]]
        if not batch:
            continue
        push_result = await _push_data_with_event(
            actor,
            batch,
            event_name=event_name,
        )
        if bool(getattr(push_result, "event_charge_limit_reached", False)):
            log.info(
                "Charge limit reached while pushing %s; stopping cleanly.",
                event_name,
            )
            return True
    return False


async def run_actor(
    actor: Any,
    *,
    domain_auditor: DomainAuditorFn | None = None,
    batch_size: int = URL_PUSH_BATCH_SIZE,
) -> RunSummaryPayload:
    """Orchestrate Sitemap Extractor & Indexability Auditor inside an Apify Actor lifecycle."""
    started = time.perf_counter()
    log = _get_actor_logger(actor)

    raw_input = await actor.get_input() or {}
    config = AuditConfig.model_validate(raw_input)

    raw_proxy_config = raw_input.get("proxyConfiguration")
    if raw_proxy_config is None:
        raw_proxy_config = config.proxy_configuration

    proxy_factory = build_proxy_url_factory(
        actor,
        raw_proxy_config,
        auto_escalate_proxy=config.auto_escalate_proxy,
        log=log,
    )

    initial_proxy_url: str | None = None
    if _has_explicit_proxy_config(raw_proxy_config):
        initial_proxy_url = await proxy_factory(False)

    auditor_fn: DomainAuditorFn = domain_auditor or audit_domain

    completed_summaries: list[DomainAuditSummary] = []
    charged_summary_keys: set[str] = set()
    total_urls_extracted = 0
    charge_limit_reached = False

    try:
        for start_url in config.start_urls:
            if charge_limit_reached:
                break

            domain_res = await auditor_fn(
                start_url,
                config,
                proxy_url_factory=proxy_factory,
                initial_proxy_url=initial_proxy_url,
                logger=log,
            )
            completed_summaries.append(domain_res.summary)
            total_urls_extracted += len(domain_res.url_records)

            # 1) Charge domain-audit-summary once per unique start_url (SDK v2/v3 idempotency guard)
            idem_key = _domain_idempotency_key(domain_res.summary.start_url)
            limit_reached = False
            charged_count: int | None = None
            if idem_key not in charged_summary_keys:
                charged_summary_keys.add(idem_key)
                charge_result = await _charge_event(
                    actor,
                    event_name=EVENT_DOMAIN_AUDIT_SUMMARY,
                    count=1,
                    idempotency_key=idem_key,
                )
                limit_reached = bool(
                    getattr(charge_result, "event_charge_limit_reached", False)
                )
                charged_count = getattr(charge_result, "charged_count", None)

            if config.output_mode in ("both", "summary_only") and (
                charged_count is None or charged_count > 0 or not limit_reached
            ):
                await actor.push_data(domain_res.summary.to_dataset_dict())

            if limit_reached:
                charge_limit_reached = True
                log.info(
                    "Charge limit reached while billing %s; stopping cleanly.",
                    EVENT_DOMAIN_AUDIT_SUMMARY,
                )
                break

            # 2) Push URL rows partitioned strictly into audited vs extracted-only (zero double-charging)
            if config.output_mode in ("both", "urls_only"):
                output_urls = domain_res.filtered_url_records(
                    only_issues=config.only_issues_in_dataset
                )
                audited_urls = [rec for rec in output_urls if rec.audited]
                extracted_only_urls = [rec for rec in output_urls if not rec.audited]

                if audited_urls:
                    hit_limit = await _push_url_batches(
                        actor,
                        audited_urls,
                        event_name=EVENT_PAGE_INDEXABILITY_AUDITED,
                        batch_size=batch_size,
                        log=log,
                    )
                    if hit_limit:
                        charge_limit_reached = True
                        break

                if extracted_only_urls:
                    hit_limit = await _push_url_batches(
                        actor,
                        extracted_only_urls,
                        event_name=EVENT_SITEMAP_URL_EXTRACTED,
                        batch_size=batch_size,
                        log=log,
                    )
                    if hit_limit:
                        charge_limit_reached = True
                        break
    finally:
        summary_payload = RunSummaryPayload(
            mode=config.mode,
            total_domains=len(completed_summaries),
            total_urls_extracted=total_urls_extracted,
            total_pages_audited=sum(s.pages_audited for s in completed_summaries),
            elapsed_sec=round(time.perf_counter() - started, 3),
            proxy_escalated=any(s.proxy_escalated for s in completed_summaries),
            charge_limit_reached=charge_limit_reached,
            domains=completed_summaries,
        )
        await actor.set_value("SUMMARY", summary_payload.model_dump(mode="json"))

    return summary_payload


async def main() -> None:
    """Apify Actor runtime entrypoint."""
    from apify import Actor

    async with Actor:
        await run_actor(Actor)


if __name__ == "__main__":
    asyncio.run(main())
