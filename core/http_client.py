"""Async HTTP/2 client with strict per-hop SSRF validation, OOM limits, and proxy escalation.

Key guarantees:
- ``follow_redirects=False`` with manual redirect loop (max 10 hops, loop detection).
- Every initial URL and every redirect target is validated via ``validate_url_async``.
- Streaming response reads enforce strict byte caps (Sitemap 15 MB, HTML 2 MB,
  robots.txt 1 MB, llms.txt 512 KB) to prevent OOM in 512 MB containers.
- Direct-first fetching with optional single-retry proxy escalation on 403/429/503
  or WAF challenge responses, sticky per domain.
- Zero dependency on ``apify`` (proxy URLs are injected via ``proxy_url_factory``).
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import re
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel, Field

from core.ssrf import DNSResolutionError, Resolver, SSRFBlockedError, validate_url_async

MAX_REDIRECT_HOPS = 10

# OOM streaming byte caps (Specification.md §3.1)
MAX_BYTES_SITEMAP = 15 * 1024 * 1024  # 15 MB
MAX_BYTES_HTML = 2 * 1024 * 1024  # 2 MB
MAX_BYTES_ROBOTS = 1 * 1024 * 1024  # 1 MB
MAX_BYTES_LLMS = 512 * 1024  # 512 KB

DEFAULT_TIMEOUT_SECS = 15.0

DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

ProxyUrlFactory = Callable[[bool], Awaitable[str | None]]
ProxyTransportFactory = Callable[[str], httpx.AsyncBaseTransport]

_CHARSET_RE = re.compile(r"charset=([^\s;\"']+)", re.IGNORECASE)
_BLOCK_STATUS_CODES = frozenset({403, 429, 503})
_WAF_BODY_MARKERS = (
    "/cdn-cgi/challenge-platform/",
    "cf-browser-verification",
    "attention required! | cloudflare",
    "checking if the site connection is secure",
)


def is_http2_available() -> bool:
    """Return True if the optional ``h2`` package required for HTTP/2 is installed."""
    return importlib.util.find_spec("h2") is not None


class FetchResult(BaseModel):
    """Structured result of a single logical HTTP GET (including redirect chain)."""

    requested_url: str
    final_url: str
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    raw_headers: list[tuple[str, str]] = Field(default_factory=list)
    body: bytes = b""
    truncated: bool = False
    redirect_hops: int = 0
    redirect_chain: list[str] = Field(default_factory=list)
    redirect_loop: bool = False
    too_many_redirects: bool = False
    ssrf_blocked: bool = False
    dns_error: bool = False
    used_proxy: bool = False
    elapsed_ms: int = 0
    error: str | None = None

    def get_header_values(self, name: str) -> list[str]:
        """Return all values for *name* (case-insensitive) preserving header order."""
        target = name.lower()
        values = [val for key, val in self.raw_headers if key == target]
        if not values and target in self.headers:
            values = [self.headers[target]]
        return values

    def decode_text(self, default_encoding: str = "utf-8") -> str:
        """Decode response body using declared Content-Type charset or UTF-8 fallback."""
        content_type = self.headers.get("content-type", "")
        encoding = default_encoding
        match = _CHARSET_RE.search(content_type)
        if match:
            candidate = match.group(1).strip()
            try:
                b"".decode(candidate)
                encoding = candidate
            except LookupError:
                encoding = default_encoding
        return self.body.decode(encoding, errors="replace")


def is_waf_or_rate_limit_block(
    status_code: int | None,
    headers: dict[str, str],
    body: bytes,
) -> bool:
    """Detect HTTP 403/429/503 or Cloudflare/WAF challenge responses."""
    if status_code in _BLOCK_STATUS_CODES:
        return True

    if headers.get("cf-mitigated", "").lower() == "challenge":
        return True

    content_type = headers.get("content-type", "").lower()
    if body and ("html" in content_type or not content_type):
        snippet = body[:8192].decode("utf-8", errors="ignore").lower()
        if any(marker in snippet for marker in _WAF_BODY_MARKERS):
            return True
        if "just a moment..." in snippet and "cloudflare" in snippet:
            return True

    return False


class DomainHttpClient:
    """Domain-scoped async HTTP client with SSRF protection, semaphore, and proxy escalation."""

    def __init__(
        self,
        *,
        concurrency: int = 5,
        timeout_secs: float = DEFAULT_TIMEOUT_SECS,
        max_redirects: int = MAX_REDIRECT_HOPS,
        user_agent: str = DEFAULT_BROWSER_USER_AGENT,
        auto_escalate_proxy: bool = True,
        proxy_url_factory: ProxyUrlFactory | None = None,
        initial_proxy_url: str | None = None,
        dns_resolver: Resolver | None = None,
        direct_transport: httpx.AsyncBaseTransport | None = None,
        proxy_transport_factory: ProxyTransportFactory | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1.")
        if max_redirects < 0:
            raise ValueError("max_redirects must be >= 0.")

        self._concurrency = concurrency
        self._semaphore = asyncio.Semaphore(concurrency)
        self._escalation_lock = asyncio.Lock()
        self._timeout = httpx.Timeout(timeout_secs, connect=min(timeout_secs, 10.0))
        self._max_redirects = max_redirects
        self._user_agent = user_agent
        self._auto_escalate_proxy = auto_escalate_proxy
        self._proxy_url_factory = proxy_url_factory
        self._dns_resolver = dns_resolver
        self._direct_transport = direct_transport
        self._proxy_transport_factory = proxy_transport_factory
        self._logger = logger or logging.getLogger(__name__)
        self._http2 = is_http2_available()

        self._proxy_escalated = False
        self._escalation_attempted = False
        self._direct_client: httpx.AsyncClient | None = None
        self._proxy_client: httpx.AsyncClient | None = None
        self._initial_proxy_url = initial_proxy_url

    @property
    def proxy_escalated(self) -> bool:
        """True if this domain escalated from direct HTTP to proxy during execution."""
        return self._proxy_escalated

    @property
    def http2_enabled(self) -> bool:
        """True if HTTP/2 support (``h2``) is available."""
        return self._http2

    def _build_client(
        self,
        *,
        proxy_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> httpx.AsyncClient:
        limits = httpx.Limits(
            max_connections=max(self._concurrency * 2, 10),
            max_keepalive_connections=max(self._concurrency, 5),
        )
        if transport is not None:
            return httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,
                timeout=self._timeout,
                limits=limits,
            )
        return httpx.AsyncClient(
            proxy=proxy_url,
            follow_redirects=False,
            http2=self._http2,
            timeout=self._timeout,
            limits=limits,
        )

    async def __aenter__(self) -> DomainHttpClient:
        self._ensure_initialized()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.aclose()

    def _ensure_initialized(self) -> None:
        if self._direct_client is None:
            self._direct_client = self._build_client(transport=self._direct_transport)
        if self._initial_proxy_url and self._proxy_client is None:
            proxy_transport = (
                self._proxy_transport_factory(self._initial_proxy_url)
                if self._proxy_transport_factory is not None
                else None
            )
            self._proxy_client = self._build_client(
                proxy_url=None if proxy_transport is not None else self._initial_proxy_url,
                transport=proxy_transport,
            )

    async def aclose(self) -> None:
        """Close underlying direct and proxied ``httpx.AsyncClient`` instances."""
        if self._direct_client is not None:
            await self._direct_client.aclose()
            self._direct_client = None
        if self._proxy_client is not None:
            await self._proxy_client.aclose()
            self._proxy_client = None

    async def _ensure_proxy_escalated(self) -> bool:
        """Request an escalated proxy URL once per domain and build the proxy client."""
        async with self._escalation_lock:
            if self._proxy_client is not None:
                return True
            if self._escalation_attempted or self._proxy_url_factory is None:
                return False

            self._escalation_attempted = True
            try:
                proxy_url = await self._proxy_url_factory(True)
            except Exception as exc:  # pragma: no cover - defensive guard
                self._logger.warning("Proxy URL factory failed during escalation: %s", exc)
                return False

            if not proxy_url:
                return False

            proxy_transport = (
                self._proxy_transport_factory(proxy_url)
                if self._proxy_transport_factory is not None
                else None
            )
            self._proxy_client = self._build_client(
                proxy_url=None if proxy_transport is not None else proxy_url,
                transport=proxy_transport,
            )
            self._proxy_escalated = True
            self._logger.info("Escalated domain HTTP client to proxy.")
            return True

    async def fetch(
        self,
        url: str,
        *,
        max_bytes: int = MAX_BYTES_HTML,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
        allow_proxy_escalation: bool = True,
        max_redirects: int | None = None,
    ) -> FetchResult:
        """Fetch *url* with manual SSRF-checked redirects, byte cap, and optional proxy escalation."""
        self._ensure_initialized()
        started = time.perf_counter()

        req_headers: dict[str, str] = {
            "User-Agent": user_agent or self._user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        }
        if headers:
            req_headers.update(headers)

        hop_limit = self._max_redirects if max_redirects is None else max_redirects

        # Use proxy client immediately if configured or already escalated for this domain
        if self._proxy_client is not None and allow_proxy_escalation:
            result = await self._fetch_with_semaphore(
                self._proxy_client,
                url,
                max_bytes=max_bytes,
                req_headers=req_headers,
                max_redirects=hop_limit,
                used_proxy=True,
            )
        else:
            assert self._direct_client is not None
            result = await self._fetch_with_semaphore(
                self._direct_client,
                url,
                max_bytes=max_bytes,
                req_headers=req_headers,
                max_redirects=hop_limit,
                used_proxy=False,
            )

            should_escalate = (
                allow_proxy_escalation
                and self._auto_escalate_proxy
                and self._proxy_url_factory is not None
                and not result.ssrf_blocked
                and not result.redirect_loop
                and not result.too_many_redirects
                and not result.dns_error
                and is_waf_or_rate_limit_block(
                    result.status_code, result.headers, result.body
                )
            )
            if should_escalate and await self._ensure_proxy_escalated():
                assert self._proxy_client is not None
                result = await self._fetch_with_semaphore(
                    self._proxy_client,
                    url,
                    max_bytes=max_bytes,
                    req_headers=req_headers,
                    max_redirects=hop_limit,
                    used_proxy=True,
                )

        result.elapsed_ms = max(0, int((time.perf_counter() - started) * 1000))
        return result

    async def _fetch_with_semaphore(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        max_bytes: int,
        req_headers: dict[str, str],
        max_redirects: int,
        used_proxy: bool,
    ) -> FetchResult:
        async with self._semaphore:
            return await self._fetch_once(
                client,
                url,
                max_bytes=max_bytes,
                req_headers=req_headers,
                max_redirects=max_redirects,
                used_proxy=used_proxy,
            )

    async def _fetch_once(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        max_bytes: int,
        req_headers: dict[str, str],
        max_redirects: int,
        used_proxy: bool,
    ) -> FetchResult:
        try:
            initial_target = await validate_url_async(url, resolver=self._dns_resolver)
        except SSRFBlockedError as exc:
            return FetchResult(
                requested_url=url,
                final_url=url,
                ssrf_blocked=True,
                used_proxy=used_proxy,
                error=f"SSRF_BLOCKED: {exc}",
            )
        except DNSResolutionError as exc:
            return FetchResult(
                requested_url=url,
                final_url=url,
                dns_error=True,
                used_proxy=used_proxy,
                error=f"DNS_ERROR: {exc}",
            )

        current_url = initial_target.normalized_url
        redirect_chain: list[str] = [current_url]
        visited: set[str] = {current_url}
        hops = 0

        while True:
            try:
                async with client.stream(
                    "GET", current_url, headers=req_headers
                ) as response:
                    status_code = response.status_code
                    raw_headers = [
                        (k.lower(), v) for k, v in response.headers.multi_items()
                    ]
                    flat_headers = {k.lower(): v for k, v in response.headers.items()}
                    location = flat_headers.get("location")
                    is_redirect = bool(
                        response.is_redirect
                        or (300 <= status_code < 400 and location)
                    )

                    if is_redirect and location:
                        if response.next_request is not None:
                            raw_next_url = str(response.next_request.url)
                        else:
                            raw_next_url = urljoin(current_url, location)

                        if hops >= max_redirects:
                            return FetchResult(
                                requested_url=initial_target.normalized_url,
                                final_url=current_url,
                                status_code=status_code,
                                headers=flat_headers,
                                raw_headers=raw_headers,
                                redirect_hops=hops,
                                redirect_chain=redirect_chain,
                                too_many_redirects=True,
                                used_proxy=used_proxy,
                                error=f"TOO_MANY_REDIRECTS: exceeded {max_redirects} hops",
                            )

                        try:
                            next_target = await validate_url_async(
                                raw_next_url, resolver=self._dns_resolver
                            )
                        except SSRFBlockedError as exc:
                            return FetchResult(
                                requested_url=initial_target.normalized_url,
                                final_url=current_url,
                                status_code=status_code,
                                headers=flat_headers,
                                raw_headers=raw_headers,
                                redirect_hops=hops,
                                redirect_chain=redirect_chain,
                                ssrf_blocked=True,
                                used_proxy=used_proxy,
                                error=f"SSRF_BLOCKED on redirect hop: {exc}",
                            )
                        except DNSResolutionError as exc:
                            return FetchResult(
                                requested_url=initial_target.normalized_url,
                                final_url=current_url,
                                status_code=status_code,
                                headers=flat_headers,
                                raw_headers=raw_headers,
                                redirect_hops=hops,
                                redirect_chain=redirect_chain,
                                dns_error=True,
                                used_proxy=used_proxy,
                                error=f"DNS_ERROR on redirect hop: {exc}",
                            )

                        next_norm = next_target.normalized_url
                        if next_norm in visited:
                            redirect_chain.append(next_norm)
                            return FetchResult(
                                requested_url=initial_target.normalized_url,
                                final_url=next_norm,
                                status_code=status_code,
                                headers=flat_headers,
                                raw_headers=raw_headers,
                                redirect_hops=hops + 1,
                                redirect_chain=redirect_chain,
                                redirect_loop=True,
                                used_proxy=used_proxy,
                                error=f"REDIRECT_LOOP: already visited {next_norm}",
                            )

                        visited.add(next_norm)
                        redirect_chain.append(next_norm)
                        hops += 1
                        current_url = next_norm
                        continue

                    # Non-redirect response: stream body up to max_bytes
                    buf = bytearray()
                    truncated = False
                    async for chunk in response.aiter_bytes():
                        remaining = max_bytes - len(buf)
                        if len(chunk) > remaining:
                            if remaining > 0:
                                buf.extend(chunk[:remaining])
                            truncated = True
                            break
                        buf.extend(chunk)

                    return FetchResult(
                        requested_url=initial_target.normalized_url,
                        final_url=current_url,
                        status_code=status_code,
                        headers=flat_headers,
                        raw_headers=raw_headers,
                        body=bytes(buf),
                        truncated=truncated,
                        redirect_hops=hops,
                        redirect_chain=redirect_chain,
                        used_proxy=used_proxy,
                    )

            except httpx.TimeoutException as exc:
                return FetchResult(
                    requested_url=initial_target.normalized_url,
                    final_url=current_url,
                    redirect_hops=hops,
                    redirect_chain=redirect_chain,
                    used_proxy=used_proxy,
                    error=f"TIMEOUT: {exc}",
                )
            except (httpx.HTTPError, OSError) as exc:
                return FetchResult(
                    requested_url=initial_target.normalized_url,
                    final_url=current_url,
                    redirect_hops=hops,
                    redirect_chain=redirect_chain,
                    used_proxy=used_proxy,
                    error=f"HTTP_ERROR: {type(exc).__name__}: {exc}",
                )
