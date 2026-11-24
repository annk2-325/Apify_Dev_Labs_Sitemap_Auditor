"""Offline E2E tests for apify_actor.src.main with a mocked Apify Actor SDK."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from apify_actor.src.main import (
    EVENT_DOMAIN_AUDIT_SUMMARY,
    EVENT_PAGE_INDEXABILITY_AUDITED,
    EVENT_SITEMAP_URL_EXTRACTED,
    run_actor,
)
from core.models import AuditConfig
from core.runner import DomainAuditResult, audit_domain

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _public_dns(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


@dataclass
class FakeChargeResult:
    charged_count: int = 1
    event_charge_limit_reached: bool = False


class FakeProxyConfiguration:
    def __init__(self, proxy_url: str) -> None:
        self.proxy_url = proxy_url
        self.new_url_calls = 0

    async def new_url(self) -> str:
        self.new_url_calls += 1
        return self.proxy_url


class MockApifyActor:
    """In-memory mock of the Apify Actor SDK supporting PPE billing & KVS."""

    def __init__(
        self,
        actor_input: dict[str, Any],
        *,
        limit_on_charge_call: int | None = None,
        limit_on_push_event_call: int | None = None,
        proxy_url: str = "http://apify-proxy.internal:8000",
    ) -> None:
        self._input = actor_input
        self._limit_on_charge_call = limit_on_charge_call
        self._limit_on_push_event_call = limit_on_push_event_call
        self._proxy_url = proxy_url
        self.log = logging.getLogger("test.mock_actor")

        self.dataset_items: list[dict[str, Any]] = []
        self.push_events: list[tuple[str | None, list[dict[str, Any]]]] = []
        self.charge_calls: list[dict[str, Any]] = []
        self.kvs: dict[str, Any] = {}
        self.proxy_config_calls: list[dict[str, Any]] = []
        self._push_event_counter = 0

    async def get_input(self) -> dict[str, Any]:
        return self._input

    async def create_proxy_configuration(self, **kwargs: Any) -> FakeProxyConfiguration:
        self.proxy_config_calls.append(kwargs)
        return FakeProxyConfiguration(self._proxy_url)

    async def charge(
        self,
        *,
        event_name: str,
        count: int = 1,
        idempotency_key: str | None = None,
    ) -> FakeChargeResult:
        self.charge_calls.append(
            {
                "event_name": event_name,
                "count": count,
                "idempotency_key": idempotency_key,
            }
        )
        call_num = len(self.charge_calls)
        if self._limit_on_charge_call is not None and call_num >= self._limit_on_charge_call:
            return FakeChargeResult(charged_count=0, event_charge_limit_reached=True)
        return FakeChargeResult(charged_count=count, event_charge_limit_reached=False)

    async def push_data(
        self,
        data: dict[str, Any] | list[dict[str, Any]],
        *,
        event_name: str | None = None,
    ) -> FakeChargeResult | None:
        batch = data if isinstance(data, list) else [data]
        self.dataset_items.extend(batch)
        self.push_events.append((event_name, batch))
        if event_name is None:
            return None
        self._push_event_counter += 1
        if (
            self._limit_on_push_event_call is not None
            and self._push_event_counter >= self._limit_on_push_event_call
        ):
            return FakeChargeResult(
                charged_count=len(batch),
                event_charge_limit_reached=True,
            )
        return FakeChargeResult(
            charged_count=len(batch),
            event_charge_limit_reached=False,
        )

    async def set_value(self, key: str, value: Any) -> None:
        self.kvs[key] = value

    def billed_urls_by_event(self, event_name: str) -> list[str]:
        urls: list[str] = []
        for ev, batch in self.push_events:
            if ev == event_name:
                urls.extend(item["url"] for item in batch if item.get("record_type") == "url")
        return urls


def _build_mock_transport() -> httpx.MockTransport:
    healthy_html = (FIXTURES / "page_healthy.html").read_bytes()
    issues_html = (FIXTURES / "page_issues.html").read_bytes()
    llms_bytes = (FIXTURES / "llms_valid.txt").read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        path = request.url.path
        base = f"https://{host}"

        if path == "/robots.txt":
            return httpx.Response(
                200,
                content=f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n".encode(),
            )
        if path == "/sitemap.xml":
            xml = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f"<url><loc>{base}/docs/healthy</loc></url>"
                f"<url><loc>{base}/broken-seo</loc></url>"
                f"<url><loc>{base}/dead-link</loc></url>"
                f"<url><loc>{base}/extra-1</loc></url>"
                f"<url><loc>{base}/extra-2</loc></url>"
                "</urlset>"
            ).encode()
            return httpx.Response(200, content=xml)
        if path == "/llms.txt":
            return httpx.Response(
                200, headers={"Content-Type": "text/markdown"}, content=llms_bytes
            )
        if path in ("/", "/docs/healthy", "/extra-1", "/extra-2"):
            page = healthy_html.replace(
                b"https://example.com/docs/healthy", f"{base}{path}".encode()
            )
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=page)
        if path == "/broken-seo":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=issues_html)
        if path == "/dead-link":
            return httpx.Response(404, content=b"Not Found")
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _make_mock_domain_auditor(
    transport: httpx.AsyncBaseTransport,
    proxy_transport: httpx.AsyncBaseTransport | None = None,
):
    async def _auditor(
        start_url: str,
        config: AuditConfig,
        *,
        proxy_url_factory: Any = None,
        initial_proxy_url: str | None = None,
        logger: Any = None,
    ) -> DomainAuditResult:
        return await audit_domain(
            start_url,
            config,
            proxy_url_factory=proxy_url_factory,
            initial_proxy_url=initial_proxy_url,
            dns_resolver=_public_dns,
            direct_transport=transport,
            proxy_transport_factory=(
                (lambda _url: proxy_transport) if proxy_transport is not None else None
            ),
            logger=logger,
        )

    return _auditor


class TestApifyActorE2EMock:
    """E2E tests verifying 3 modes, PPE billing, no double-charging, charge limit stop, KVS, proxy."""

    async def test_extract_only_mode_bills_only_extracted_and_summary(self) -> None:
        actor = MockApifyActor(
            {
                "startUrls": [{"url": "https://alpha.example"}],
                "mode": "extract_only",
                "maxUrlsPerDomain": 50,
            }
        )
        payload = await run_actor(
            actor,
            domain_auditor=_make_mock_domain_auditor(_build_mock_transport()),
        )

        assert payload.mode == "extract_only"
        assert payload.total_domains == 1
        assert payload.total_urls_extracted == 5
        assert payload.total_pages_audited == 0
        assert payload.charge_limit_reached is False

        # Billing assertions: 1x domain-audit-summary, 5x sitemap-url-extracted, 0x page-indexability-audited
        assert len(actor.charge_calls) == 1
        assert actor.charge_calls[0]["event_name"] == EVENT_DOMAIN_AUDIT_SUMMARY
        assert actor.charge_calls[0]["count"] == 1
        assert str(actor.charge_calls[0]["idempotency_key"]).startswith("summary-")

        extracted_billed = actor.billed_urls_by_event(EVENT_SITEMAP_URL_EXTRACTED)
        audited_billed = actor.billed_urls_by_event(EVENT_PAGE_INDEXABILITY_AUDITED)
        assert len(extracted_billed) == 5
        assert audited_billed == []

        # Dataset has 1 summary + 5 url rows; KVS SUMMARY saved; no proxy created
        assert sum(1 for d in actor.dataset_items if d["record_type"] == "summary") == 1
        assert sum(1 for d in actor.dataset_items if d["record_type"] == "url") == 5
        assert "SUMMARY" in actor.kvs
        assert actor.kvs["SUMMARY"]["total_urls_extracted"] == 5
        assert actor.proxy_config_calls == []

    async def test_indexability_audit_no_double_charging_between_audited_and_extracted(
        self,
    ) -> None:
        actor = MockApifyActor(
            {
                "startUrls": ["https://alpha.example"],
                "mode": "indexability_audit",
                "maxUrlsPerDomain": 50,
                "maxAuditPagesPerDomain": 3,
                "outputMode": "both",
            }
        )
        payload = await run_actor(
            actor,
            domain_auditor=_make_mock_domain_auditor(_build_mock_transport()),
        )

        assert payload.total_urls_extracted == 5
        assert payload.total_pages_audited == 3

        audited_billed = actor.billed_urls_by_event(EVENT_PAGE_INDEXABILITY_AUDITED)
        extracted_billed = actor.billed_urls_by_event(EVENT_SITEMAP_URL_EXTRACTED)

        assert len(audited_billed) == 3
        assert len(extracted_billed) == 2
        # Strict anti-double-charging proof: disjoint sets covering all 5 unique URLs
        assert set(audited_billed).isdisjoint(set(extracted_billed))
        assert len(set(audited_billed) | set(extracted_billed)) == 5
        assert len(actor.charge_calls) == 1
        assert actor.charge_calls[0]["event_name"] == EVENT_DOMAIN_AUDIT_SUMMARY

    async def test_full_audit_output_modes_and_only_issues_filter(self) -> None:
        # 1) urls_only + onlyIssuesInDataset=True
        actor_urls_only = MockApifyActor(
            {
                "startUrls": ["https://alpha.example"],
                "mode": "full_audit",
                "maxAuditPagesPerDomain": 5,
                "outputMode": "urls_only",
                "onlyIssuesInDataset": True,
            }
        )
        await run_actor(
            actor_urls_only,
            domain_auditor=_make_mock_domain_auditor(_build_mock_transport()),
        )
        # No summary pushed to Dataset, but domain-audit-summary still charged & KVS SUMMARY saved
        assert all(d["record_type"] == "url" for d in actor_urls_only.dataset_items)
        assert len(actor_urls_only.dataset_items) == 2  # broken-seo + dead-link only
        assert len(actor_urls_only.charge_calls) == 1
        assert "SUMMARY" in actor_urls_only.kvs
        assert actor_urls_only.kvs["SUMMARY"]["total_pages_audited"] == 5

        # 2) summary_only
        actor_summary_only = MockApifyActor(
            {
                "startUrls": ["https://alpha.example"],
                "mode": "full_audit",
                "maxAuditPagesPerDomain": 5,
                "outputMode": "summary_only",
            }
        )
        await run_actor(
            actor_summary_only,
            domain_auditor=_make_mock_domain_auditor(_build_mock_transport()),
        )
        assert len(actor_summary_only.dataset_items) == 1
        assert actor_summary_only.dataset_items[0]["record_type"] == "summary"
        assert actor_summary_only.billed_urls_by_event(EVENT_PAGE_INDEXABILITY_AUDITED) == []
        assert actor_summary_only.billed_urls_by_event(EVENT_SITEMAP_URL_EXTRACTED) == []
        assert "SUMMARY" in actor_summary_only.kvs

    async def test_charge_limit_reached_on_domain_summary_stops_safely_and_saves_kvs(
        self,
    ) -> None:
        actor = MockApifyActor(
            {
                "startUrls": ["https://first.example", "https://second.example"],
                "mode": "indexability_audit",
                "maxAuditPagesPerDomain": 3,
            },
            limit_on_charge_call=1,
        )
        payload = await run_actor(
            actor,
            domain_auditor=_make_mock_domain_auditor(_build_mock_transport()),
        )

        assert payload.charge_limit_reached is True
        # Stopped cleanly after first domain charge limit without auditing second domain
        assert payload.total_domains == 1
        assert len(actor.charge_calls) == 1
        assert actor.billed_urls_by_event(EVENT_PAGE_INDEXABILITY_AUDITED) == []
        assert "SUMMARY" in actor.kvs
        assert actor.kvs["SUMMARY"]["charge_limit_reached"] is True

    async def test_charge_limit_reached_on_url_batch_push_stops_safely_and_saves_kvs(
        self,
    ) -> None:
        actor = MockApifyActor(
            {
                "startUrls": ["https://first.example", "https://second.example"],
                "mode": "indexability_audit",
                "maxAuditPagesPerDomain": 3,
            },
            limit_on_push_event_call=1,
        )
        payload = await run_actor(
            actor,
            domain_auditor=_make_mock_domain_auditor(_build_mock_transport()),
            batch_size=2,
        )

        assert payload.charge_limit_reached is True
        # Stopped after first batch of 2 audited URLs on domain 1 (never pushed 3rd audited, unaudited, or domain 2)
        assert payload.total_domains == 1
        assert len(actor.billed_urls_by_event(EVENT_PAGE_INDEXABILITY_AUDITED)) == 2
        assert actor.billed_urls_by_event(EVENT_SITEMAP_URL_EXTRACTED) == []
        assert "SUMMARY" in actor.kvs
        assert actor.kvs["SUMMARY"]["charge_limit_reached"] is True

    async def test_auto_escalate_proxy_connects_to_actor_proxy_configuration(self) -> None:
        direct_403 = httpx.MockTransport(lambda _req: httpx.Response(403, content=b"Blocked"))
        proxy_ok = _build_mock_transport()

        actor = MockApifyActor(
            {
                "startUrls": ["https://blocked.example"],
                "mode": "indexability_audit",
                "maxAuditPagesPerDomain": 2,
                "includeAiBotAudit": False,
                "autoEscalateProxy": True,
                "proxyConfiguration": {"useApifyProxy": False},
            }
        )
        payload = await run_actor(
            actor,
            domain_auditor=_make_mock_domain_auditor(direct_403, proxy_transport=proxy_ok),
        )

        assert payload.proxy_escalated is True
        assert len(actor.proxy_config_calls) == 1
        assert actor.kvs["SUMMARY"]["proxy_escalated"] is True
        assert payload.total_pages_audited == 2

    async def test_auto_escalate_proxy_disabled_never_requests_proxy(self) -> None:
        direct_403 = httpx.MockTransport(lambda _req: httpx.Response(403, content=b"Blocked"))
        actor = MockApifyActor(
            {
                "startUrls": ["https://blocked.example"],
                "mode": "extract_only",
                "autoEscalateProxy": False,
                "proxyConfiguration": {"useApifyProxy": False},
            }
        )
        payload = await run_actor(
            actor,
            domain_auditor=_make_mock_domain_auditor(direct_403),
        )

        assert payload.proxy_escalated is False
        assert actor.proxy_config_calls == []

    def test_actor_json_and_schemas_match_specification(self) -> None:
        actor_json = json.loads(
            (REPO_ROOT / "apify_actor" / ".actor" / "actor.json").read_text(encoding="utf-8")
        )
        input_schema = json.loads(
            (REPO_ROOT / "apify_actor" / ".actor" / "input_schema.json").read_text(encoding="utf-8")
        )
        output_schema = json.loads(
            (REPO_ROOT / "apify_actor" / ".actor" / "output_schema.json").read_text(encoding="utf-8")
        )

        assert actor_json["dockerfile"] == "../Dockerfile"
        assert actor_json["dockerContextDir"] == "../.."
        assert actor_json["input"] == "./input_schema.json"
        assert actor_json["output"] == "./output_schema.json"
        assert actor_json["defaultRunOptions"]["memoryMbytes"] == 512
        assert actor_json["defaultRunOptions"]["timeoutSecs"] == 180

        overview_fields = actor_json["storages"]["dataset"]["views"]["overview"]["transformation"]["fields"]
        for expected in (
            "record_type",
            "domain",
            "url",
            "http_status",
            "indexable",
            "canonical_status",
            "health_score",
            "issue_codes",
        ):
            assert expected in overview_fields

        # Basic 6 fields at top + sectionCaption starting at maxSitemapFiles
        prop_keys = list(input_schema["properties"].keys())
        assert prop_keys[:6] == [
            "startUrls",
            "mode",
            "maxUrlsPerDomain",
            "maxAuditPagesPerDomain",
            "includeAiBotAudit",
            "outputMode",
        ]
        assert "sectionCaption" in input_schema["properties"]["maxSitemapFiles"]
        assert "SUMMARY" in output_schema["properties"]["summary"]["template"]

    async def test_apify_sdk_v3_signatures_charged_event_name_and_charge_without_idempotency(
        self,
    ) -> None:
        """Verify compatibility with apify>=3.x (charged_event_name & charge(event_name, count))."""

        class MockApifySdkV3Actor:
            log = logging.getLogger("test.sdk_v3")

            def __init__(self) -> None:
                self.pushed: list[tuple[str | None, Any]] = []
                self.charged: list[tuple[str, int]] = []
                self.kvs: dict[str, Any] = {}

            async def get_input(self) -> dict[str, Any]:
                return {
                    "startUrls": ["https://alpha.example"],
                    "mode": "extract_only",
                }

            async def charge(self, event_name: str, count: int = 1) -> FakeChargeResult:
                self.charged.append((event_name, count))
                return FakeChargeResult(charged_count=count, event_charge_limit_reached=False)

            async def push_data(
                self,
                data: dict[str, Any] | list[dict[str, Any]],
                charged_event_name: str | None = None,
            ) -> FakeChargeResult:
                self.pushed.append((charged_event_name, data))
                return FakeChargeResult(charged_count=1, event_charge_limit_reached=False)

            async def set_value(self, key: str, value: Any) -> None:
                self.kvs[key] = value

        v3_actor = MockApifySdkV3Actor()
        payload = await run_actor(
            v3_actor,
            domain_auditor=_make_mock_domain_auditor(_build_mock_transport()),
        )
        assert payload.total_urls_extracted == 5
        assert v3_actor.charged == [(EVENT_DOMAIN_AUDIT_SUMMARY, 1)]
        assert any(ev == EVENT_SITEMAP_URL_EXTRACTED for ev, _ in v3_actor.pushed)
        assert "SUMMARY" in v3_actor.kvs

