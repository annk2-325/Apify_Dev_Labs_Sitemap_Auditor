"""RFC 9309 compliant ``robots.txt`` fetcher and parser powered by ``protego>=0.6.2``.

Fallback semantics (Skills.md §3.3):
- HTTP 2xx: parsed with ``protego.Protego.parse`` (``status="loaded"``).
- HTTP 4xx: treated as allow-all per RFC 9309 (``status="not_found_allow_all"``).
- HTTP 5xx / timeout / network error: treated as unknown without crashing the
  audit (``status="unavailable_unknown"``; callers record a warning).
- SSRF blocked: recorded as ``status="blocked_ssrf"``.

This module has zero dependency on ``apify``.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit, urlunsplit

from protego import Protego

from core.http_client import MAX_BYTES_ROBOTS, DomainHttpClient, FetchResult
from core.models import RobotsInfo
from core.ssrf import SSRFBlockedError, normalize_url


def build_robots_url(base_url: str) -> str:
    """Derive ``{scheme}://{netloc}/robots.txt`` from any valid HTTP(S) URL."""
    normalized = normalize_url(base_url)
    parts = urlsplit(normalized)
    return urlunsplit((parts.scheme, parts.netloc, "/robots.txt", "", ""))


def _extract_valid_sitemaps(raw_sitemaps: list[str], robots_url: str) -> list[str]:
    """Normalize and deduplicate ``Sitemap:`` directives while skipping invalid schemes."""
    seen: set[str] = set()
    cleaned: list[str] = []
    for raw in raw_sitemaps:
        candidate = raw.strip()
        if not candidate:
            continue
        resolved = urljoin(robots_url, candidate)
        try:
            norm = normalize_url(resolved, allow_bare_host=False)
        except SSRFBlockedError:
            continue
        if norm not in seen:
            seen.add(norm)
            cleaned.append(norm)
    return cleaned


class RobotsChecker:
    """Evaluates URL crawl permissions and exposes discovered ``Sitemap:`` URLs."""

    def __init__(
        self,
        info: RobotsInfo,
        parser: Protego | None = None,
    ) -> None:
        self.info = info
        self._parser = parser

    @property
    def sitemaps(self) -> list[str]:
        """Normalized ``Sitemap:`` URLs extracted from ``robots.txt``."""
        return list(self.info.sitemap_urls)

    def can_fetch(self, url: str, user_agent: str = "*") -> bool | None:
        """Return ``True`` (allowed), ``False`` (disallowed), or ``None`` (unknown).

        - ``status == "loaded"``: delegates to ``protego.can_fetch(url, user_agent)``.
        - ``status == "not_found_allow_all"``: returns ``True`` per RFC 9309.
        - ``status in ("unavailable_unknown", "blocked_ssrf")``: returns ``None``.
        """
        if self.info.status == "not_found_allow_all":
            return True
        if self.info.status != "loaded" or self._parser is None:
            return None
        return bool(self._parser.can_fetch(url, user_agent))

    @classmethod
    def from_text(
        cls,
        robots_url: str,
        content: str,
        *,
        http_status: int = 200,
        truncated: bool = False,
    ) -> RobotsChecker:
        """Construct a :class:`RobotsChecker` directly from raw ``robots.txt`` text."""
        cleaned_text = content.lstrip("\ufeff")
        parser = Protego.parse(cleaned_text)
        sitemap_urls = _extract_valid_sitemaps(list(parser.sitemaps), robots_url)
        info = RobotsInfo(
            url=robots_url,
            status="loaded",
            http_status=http_status,
            sitemap_urls=sitemap_urls,
            truncated=truncated,
        )
        return cls(info=info, parser=parser)

    @classmethod
    def from_fetch_result(cls, robots_url: str, result: FetchResult) -> RobotsChecker:
        """Construct a :class:`RobotsChecker` from a :class:`FetchResult`."""
        if result.ssrf_blocked:
            return cls(
                info=RobotsInfo(
                    url=robots_url,
                    status="blocked_ssrf",
                    http_status=result.status_code,
                    error=result.error,
                )
            )

        if result.error is not None or result.status_code is None:
            return cls(
                info=RobotsInfo(
                    url=robots_url,
                    status="unavailable_unknown",
                    http_status=result.status_code,
                    truncated=result.truncated,
                    error=result.error or "No HTTP status returned for robots.txt.",
                )
            )

        status_code = result.status_code
        if 200 <= status_code < 300:
            text = result.decode_text(default_encoding="utf-8")
            return cls.from_text(
                robots_url=robots_url,
                content=text,
                http_status=status_code,
                truncated=result.truncated,
            )

        if 400 <= status_code < 500:
            return cls(
                info=RobotsInfo(
                    url=robots_url,
                    status="not_found_allow_all",
                    http_status=status_code,
                    truncated=result.truncated,
                )
            )

        return cls(
            info=RobotsInfo(
                url=robots_url,
                status="unavailable_unknown",
                http_status=status_code,
                truncated=result.truncated,
                error=f"HTTP {status_code} returned for robots.txt.",
            )
        )


async def fetch_robots(
    http_client: DomainHttpClient,
    base_url: str,
) -> RobotsChecker:
    """Fetch and parse ``/robots.txt`` for the host of *base_url*."""
    robots_url = build_robots_url(base_url)
    result = await http_client.fetch(
        robots_url,
        max_bytes=MAX_BYTES_ROBOTS,
    )
    return RobotsChecker.from_fetch_result(robots_url=robots_url, result=result)
