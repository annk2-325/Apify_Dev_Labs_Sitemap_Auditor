"""AI search crawler differential reachability probing and ``/llms.txt`` diagnostics.

Implements Specification.md §3.4:
- Checks ``robots.txt`` permissions and live HTTP status for 5 major AI crawlers:
  ``OAI-SearchBot``, ``GPTBot``, ``ClaudeBot``, ``Claude-SearchBot``, ``PerplexityBot``.
- Compares each bot's HTTP status against a standard desktop browser UA on the
  domain's root URL; flags ``cdn_or_waf_diff_block = True`` when browser gets HTTP 200
  and the bot gets ``401 / 403 / 429 / 503``.
- Diagnoses ``/llms.txt`` (requires HTTP 200, non-HTML Content-Type & body, >= 20 bytes)
  and reports byte size, Markdown heading count, and Markdown link count.

This module has zero dependency on ``apify``.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit, urlunsplit

from core.http_client import (
    DEFAULT_BROWSER_USER_AGENT,
    MAX_BYTES_LLMS,
    DomainHttpClient,
    FetchResult,
)
from core.models import (
    AI_BOT_NAMES,
    AiAuditSummary,
    AiBotProbeResult,
    LlmsTxtResult,
)
from core.robots import RobotsChecker
from core.ssrf import normalize_url

DIFF_BLOCK_STATUS_CODES = frozenset({401, 403, 429, 503})
LLMS_TXT_MIN_BYTES = 20
_PROBE_MAX_BYTES = 64 * 1024  # 64 KB is plenty for differential status probing

# Official documented User-Agent strings for the 5 tracked AI crawlers
AI_BOT_USER_AGENTS: dict[str, str] = {
    "OAI-SearchBot": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); "
        "compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot"
    ),
    "GPTBot": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); "
        "compatible; GPTBot/1.2; +https://openai.com/gptbot"
    ),
    "ClaudeBot": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); "
        "compatible; ClaudeBot/1.0; +claudebot@anthropic.com"
    ),
    "Claude-SearchBot": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); "
        "compatible; Claude-SearchBot/1.0; +https://support.anthropic.com/"
    ),
    "PerplexityBot": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); "
        "compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot"
    ),
}

_HTML_BODY_PREFIXES = (
    b"<!doctype html",
    b"<html",
    b"<head",
    b"<body",
)
_MD_HEADING_RE = re.compile(r"^[ \t]{0,3}#{1,6}[ \t]+\S", re.MULTILINE)
_MD_LINK_RE = re.compile(r"(?<!\!)\[[^\]]+\]\([^)\s]+\)")


def build_origin_root_url(base_url: str) -> str:
    """Return ``{scheme}://{netloc}/`` for any valid HTTP(S) URL."""
    normalized = normalize_url(base_url)
    parts = urlsplit(normalized)
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def build_llms_txt_url(base_url: str) -> str:
    """Return ``{scheme}://{netloc}/llms.txt`` for any valid HTTP(S) URL."""
    normalized = normalize_url(base_url)
    parts = urlsplit(normalized)
    return urlunsplit((parts.scheme, parts.netloc, "/llms.txt", "", ""))


def is_differential_block(
    browser_status: int | None,
    bot_status: int | None,
) -> bool:
    """Return True if browser gets HTTP 200 while the AI bot gets 401/403/429/503."""
    return browser_status == 200 and bot_status in DIFF_BLOCK_STATUS_CODES


def _looks_like_html_payload(content_type: str | None, body: bytes) -> bool:
    ct_lower = (content_type or "").lower()
    if "text/html" in ct_lower or "application/xhtml+xml" in ct_lower:
        return True
    snippet = body[:512].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return snippet.startswith(_HTML_BODY_PREFIXES)


def analyze_llms_txt(url: str, fetch_result: FetchResult) -> LlmsTxtResult:
    """Evaluate a fetched ``/llms.txt`` response (with HTML soft-404 protection)."""
    content_type = fetch_result.headers.get("content-type")
    byte_size = len(fetch_result.body)

    if fetch_result.error is not None or fetch_result.status_code != 200:
        return LlmsTxtResult(
            url=url,
            http_status=fetch_result.status_code,
            content_type=content_type,
            llms_txt_present=False,
            byte_size=byte_size,
            truncated=fetch_result.truncated,
            error=fetch_result.error,
        )

    if byte_size < LLMS_TXT_MIN_BYTES or _looks_like_html_payload(
        content_type, fetch_result.body
    ):
        return LlmsTxtResult(
            url=url,
            http_status=fetch_result.status_code,
            content_type=content_type,
            llms_txt_present=False,
            byte_size=byte_size,
            truncated=fetch_result.truncated,
        )

    text = fetch_result.decode_text(default_encoding="utf-8").lstrip("\ufeff")
    heading_count = len(_MD_HEADING_RE.findall(text))
    link_count = len(_MD_LINK_RE.findall(text))

    return LlmsTxtResult(
        url=url,
        http_status=fetch_result.status_code,
        content_type=content_type,
        llms_txt_present=True,
        byte_size=byte_size,
        heading_count=heading_count,
        link_count=link_count,
        truncated=fetch_result.truncated,
    )


async def probe_ai_bots_and_llms(
    http_client: DomainHttpClient,
    base_url: str,
    *,
    robots_checker: RobotsChecker | None = None,
) -> AiAuditSummary:
    """Run browser-vs-AI-bot differential probing and ``/llms.txt`` diagnostics."""
    target_url = build_origin_root_url(base_url)
    llms_url = build_llms_txt_url(base_url)

    # Fetch browser baseline and /llms.txt first (or concurrently)
    browser_res, llms_res = await asyncio.gather(
        http_client.fetch(
            target_url,
            max_bytes=_PROBE_MAX_BYTES,
            user_agent=DEFAULT_BROWSER_USER_AGENT,
            allow_proxy_escalation=False,
        ),
        http_client.fetch(
            llms_url,
            max_bytes=MAX_BYTES_LLMS,
            user_agent=DEFAULT_BROWSER_USER_AGENT,
            allow_proxy_escalation=False,
        ),
    )
    browser_status = browser_res.status_code if browser_res.error is None else None
    llms_result = analyze_llms_txt(llms_url, llms_res)

    async def _probe_single_bot(bot_name: str) -> AiBotProbeResult:
        robots_allowed = (
            robots_checker.can_fetch(target_url, bot_name)
            if robots_checker is not None
            else None
        )
        bot_ua = AI_BOT_USER_AGENTS[bot_name]
        res = await http_client.fetch(
            target_url,
            max_bytes=_PROBE_MAX_BYTES,
            user_agent=bot_ua,
            allow_proxy_escalation=False,
        )
        bot_status = res.status_code if res.error is None else None
        return AiBotProbeResult(
            bot_name=bot_name,
            robots_allowed=robots_allowed,
            http_status=bot_status,
            cdn_or_waf_diff_block=is_differential_block(browser_status, bot_status),
            error=res.error,
            elapsed_ms=res.elapsed_ms,
        )

    bot_results = list(
        await asyncio.gather(*(_probe_single_bot(bot) for bot in AI_BOT_NAMES))
    )

    return AiAuditSummary(
        target_url=target_url,
        browser_http_status=browser_status,
        bots=bot_results,
        any_cdn_or_waf_diff_block=any(b.cdn_or_waf_diff_block for b in bot_results),
        llms_txt=llms_result,
    )
