"""Safe Sitemap discovery and parsing (XML urlset, nested sitemapindex, .xml.gz, Text).

Security & robustness guarantees (Specification.md §3.2, Skills.md §3.2):
- XXE defense: ``lxml.etree.XMLParser(resolve_entities=False, no_network=True)`` always.
- Strict XML parse first; ``recover=True`` fallback only on ``XMLSyntaxError`` with
  ``recovered_xml = True`` recorded.
- Gzip detection via magic bytes ``b"\\x1f\\x8b"`` with streaming decompression cap
  (30 MB default) to prevent gzip-bomb OOM in 512 MB containers.
- Plain-text sitemaps (1 URL per line), nested ``sitemapindex`` (max depth 5,
  cycle protection, max file count), duplicate/cross-host/50k-limit/lastmod checks.
- Zero dependency on ``apify``.
"""

from __future__ import annotations

import datetime
import gzip
import io
import re
import zlib
from collections import deque
from urllib.parse import urlsplit, urlunsplit

from lxml import etree
from pydantic import BaseModel, Field

from core.http_client import MAX_BYTES_SITEMAP, DomainHttpClient
from core.models import (
    DiscoveryMethod,
    SitemapDiscoveryStats,
    SitemapFileResult,
    SitemapUrlEntry,
)
from core.robots import RobotsChecker
from core.ssrf import SSRFBlockedError, extract_host, normalize_url

MAX_SITEMAP_DEPTH = 5
MAX_DECOMPRESSED_BYTES = 30 * 1024 * 1024  # 30 MB gzip bomb cap
SITEMAP_MAX_URLS_PER_FILE = 50_000
GZIP_MAGIC = b"\x1f\x8b"
_GZIP_CHUNK_SIZE = 64 * 1024

FALLBACK_SITEMAP_PATHS: tuple[str, ...] = (
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap.xml.gz",
)

# W3C Datetime (ISO 8601 subset used by sitemaps.org)
_LASTMOD_RE = re.compile(
    r"^(?P<year>\d{4})"
    r"(?:-(?P<month>\d{2})"
    r"(?:-(?P<day>\d{2})"
    r"(?:[Tt](?P<hour>\d{2}):(?P<minute>\d{2})"
    r"(?::(?P<second>\d{2})(?:\.\d+)?)?"
    r"(?P<tz>[Zz]|[+-]\d{2}:\d{2}))?)?)?$"
)


class GzipBombError(ValueError):
    """Raised when gzip decompression exceeds the configured safety limit."""


class GzipDecompressError(ValueError):
    """Raised when gzip bytes are corrupted or unreadable."""


class ParsedSitemapData(BaseModel):
    """Output of parsing a single Sitemap file payload."""

    file_result: SitemapFileResult
    urls: list[SitemapUrlEntry] = Field(default_factory=list)
    child_sitemaps: list[str] = Field(default_factory=list)


class SitemapDiscoveryResult(BaseModel):
    """Domain-wide Sitemap discovery result combining URL entries and structural stats."""

    entries: list[SitemapUrlEntry] = Field(default_factory=list)
    stats: SitemapDiscoveryStats = Field(default_factory=SitemapDiscoveryStats)


def is_valid_lastmod(value: str) -> bool:
    """Validate W3C Datetime format and calendar correctness for ``<lastmod>``."""
    cleaned = value.strip()
    match = _LASTMOD_RE.match(cleaned)
    if not match:
        return False

    year = int(match.group("year"))
    month_s = match.group("month")
    day_s = match.group("day")
    hour_s = match.group("hour")
    minute_s = match.group("minute")
    second_s = match.group("second")
    tz_s = match.group("tz")

    if year < 1900 or year > 9999:
        return False

    if month_s is not None:
        month = int(month_s)
        if not (1 <= month <= 12):
            return False
        if day_s is not None:
            day = int(day_s)
            try:
                datetime.date(year, month, day)
            except ValueError:
                return False

    if hour_s is not None:
        hour = int(hour_s)
        minute = int(minute_s)
        second = int(second_s) if second_s is not None else 0
        if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
            return False
        if tz_s and tz_s.upper() != "Z":
            tz_hour = int(tz_s[1:3])
            tz_min = int(tz_s[4:6])
            if not (0 <= tz_hour <= 23 and 0 <= tz_min <= 59):
                return False

    return True


def is_explicit_sitemap_url(url: str) -> bool:
    """Return True if *url* appears to point directly to a Sitemap file."""
    normalized = normalize_url(url)
    path_lower = urlsplit(normalized).path.lower()
    if path_lower in ("", "/"):
        return False
    if path_lower.endswith(("/robots.txt", "/llms.txt")):
        return False
    if path_lower.endswith((".xml", ".xml.gz", ".gz", ".txt")):
        return True
    last_segment = path_lower.rstrip("/").rsplit("/", 1)[-1]
    return "sitemap" in last_segment


def build_fallback_sitemap_urls(base_url: str) -> list[str]:
    """Build standard fallback Sitemap URLs for the origin of *base_url*."""
    normalized = normalize_url(base_url)
    parts = urlsplit(normalized)
    return [
        urlunsplit((parts.scheme, parts.netloc, path, "", ""))
        for path in FALLBACK_SITEMAP_PATHS
    ]


def safe_decompress_gzip(
    raw_bytes: bytes,
    *,
    max_out_bytes: int = MAX_DECOMPRESSED_BYTES,
) -> bytes:
    """Decompress gzip payload incrementally with a strict output byte cap."""
    out = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw_bytes)) as gz:
            while True:
                to_read = min(_GZIP_CHUNK_SIZE, max_out_bytes - len(out) + 1)
                chunk = gz.read(to_read)
                if not chunk:
                    break
                out.extend(chunk)
                if len(out) > max_out_bytes:
                    raise GzipBombError(
                        f"Decompressed sitemap exceeds {max_out_bytes} byte safety limit."
                    )
    except GzipBombError:
        raise
    except (gzip.BadGzipFile, EOFError, zlib.error, OSError) as exc:
        raise GzipDecompressError(f"Invalid gzip stream: {exc}") from exc

    return bytes(out)


def _localname(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    if tag.startswith("{"):
        idx = tag.find("}")
        return tag[idx + 1 :].lower() if idx != -1 else tag.lower()
    return tag.lower()


def _parse_priority(raw: str | None) -> float | None:
    if not raw:
        return None
    try:
        value = float(raw.strip())
    except ValueError:
        return None
    if 0.0 <= value <= 1.0:
        return value
    return None


def _parse_xml_root(
    payload: bytes,
) -> tuple[etree._Element | None, bool, str | None]:
    """Parse XML safely (XXE disabled). Falls back to ``recover=True`` on syntax error."""
    strict_parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        recover=False,
        huge_tree=False,
    )
    try:
        root = etree.fromstring(payload, parser=strict_parser)
        return root, False, None
    except etree.XMLSyntaxError as strict_exc:
        recovery_parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            recover=True,
            huge_tree=False,
        )
        try:
            recovered_root = etree.fromstring(payload, parser=recovery_parser)
        except etree.XMLSyntaxError as rec_exc:
            return None, False, f"XML_SYNTAX_ERROR: {rec_exc}"
        if recovered_root is None:
            return None, False, f"XML_SYNTAX_ERROR: {strict_exc}"
        return recovered_root, True, None


def _parse_plain_text_sitemap(
    payload: bytes,
    *,
    sitemap_url: str,
    target_host: str,
) -> list[SitemapUrlEntry]:
    text = payload.decode("utf-8", errors="replace").lstrip("\ufeff")
    entries: list[SitemapUrlEntry] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if not (lower.startswith("http://") or lower.startswith("https://")):
            continue
        try:
            norm = normalize_url(line, allow_bare_host=False)
        except SSRFBlockedError:
            continue
        entry_host = extract_host(norm)
        entries.append(
            SitemapUrlEntry(
                url=norm,
                raw_url=line,
                sitemap_source=sitemap_url,
                is_cross_host=(entry_host != target_host),
            )
        )
    return entries


def parse_sitemap_bytes(
    raw_bytes: bytes,
    *,
    sitemap_url: str,
    target_host: str,
    http_status: int | None = 200,
    final_url: str | None = None,
    http_truncated: bool = False,
    elapsed_ms: int = 0,
    max_decompressed_bytes: int = MAX_DECOMPRESSED_BYTES,
    max_urls_per_file: int = SITEMAP_MAX_URLS_PER_FILE,
) -> ParsedSitemapData:
    """Parse raw Sitemap bytes (XML urlset, sitemapindex, .xml.gz, or plain text)."""
    normalized_target_host = target_host.rstrip(".").lower()
    is_gzipped = raw_bytes.startswith(GZIP_MAGIC)
    payload = raw_bytes

    if is_gzipped:
        try:
            payload = safe_decompress_gzip(
                raw_bytes, max_out_bytes=max_decompressed_bytes
            )
        except GzipBombError as exc:
            return ParsedSitemapData(
                file_result=SitemapFileResult(
                    url=sitemap_url,
                    format="unknown",
                    http_status=http_status,
                    final_url=final_url or sitemap_url,
                    is_gzipped=True,
                    truncated=True,
                    error=f"GZIP_DECOMPRESSION_LIMIT_EXCEEDED: {exc}",
                    elapsed_ms=elapsed_ms,
                )
            )
        except GzipDecompressError as exc:
            return ParsedSitemapData(
                file_result=SitemapFileResult(
                    url=sitemap_url,
                    format="unknown",
                    http_status=http_status,
                    final_url=final_url or sitemap_url,
                    is_gzipped=True,
                    truncated=http_truncated,
                    error=f"GZIP_DECOMPRESS_ERROR: {exc}",
                    elapsed_ms=elapsed_ms,
                )
            )

    stripped = payload.lstrip(b"\xef\xbb\xbf \t\r\n")
    if not stripped:
        return ParsedSitemapData(
            file_result=SitemapFileResult(
                url=sitemap_url,
                format="unknown",
                http_status=http_status,
                final_url=final_url or sitemap_url,
                is_gzipped=is_gzipped,
                truncated=http_truncated,
                error="EMPTY_SITEMAP",
                elapsed_ms=elapsed_ms,
            )
        )

    # Attempt XML parsing when payload begins with '<'
    if stripped.startswith(b"<"):
        root, recovered_xml, parse_error = _parse_xml_root(stripped)
        if root is None:
            return ParsedSitemapData(
                file_result=SitemapFileResult(
                    url=sitemap_url,
                    format="unknown",
                    http_status=http_status,
                    final_url=final_url or sitemap_url,
                    is_gzipped=is_gzipped,
                    truncated=http_truncated,
                    error=parse_error or "XML_PARSE_FAILED",
                    elapsed_ms=elapsed_ms,
                )
            )

        root_name = _localname(root.tag)
        if root_name == "urlset":
            urls: list[SitemapUrlEntry] = []
            for child in root:
                if _localname(child.tag) != "url":
                    continue
                raw_loc: str | None = None
                lastmod: str | None = None
                changefreq: str | None = None
                priority_raw: str | None = None

                for field_el in child:
                    fname = _localname(field_el.tag)
                    text_val = (field_el.text or "").strip()
                    if not text_val:
                        continue
                    if fname == "loc" and raw_loc is None:
                        raw_loc = text_val
                    elif fname == "lastmod" and lastmod is None:
                        lastmod = text_val
                    elif fname == "changefreq" and changefreq is None:
                        changefreq = text_val
                    elif fname == "priority" and priority_raw is None:
                        priority_raw = text_val

                if not raw_loc:
                    continue
                try:
                    norm_loc = normalize_url(raw_loc, allow_bare_host=False)
                except SSRFBlockedError:
                    continue

                entry_host = extract_host(norm_loc)
                urls.append(
                    SitemapUrlEntry(
                        url=norm_loc,
                        raw_url=raw_loc,
                        sitemap_source=sitemap_url,
                        lastmod=lastmod,
                        lastmod_valid=is_valid_lastmod(lastmod) if lastmod is not None else None,
                        changefreq=changefreq,
                        priority=_parse_priority(priority_raw),
                        is_cross_host=(entry_host != normalized_target_host),
                    )
                )

            return ParsedSitemapData(
                file_result=SitemapFileResult(
                    url=sitemap_url,
                    format="xml_urlset",
                    http_status=http_status,
                    final_url=final_url or sitemap_url,
                    url_count=len(urls),
                    is_gzipped=is_gzipped,
                    recovered_xml=recovered_xml,
                    truncated=http_truncated,
                    exceeded_50k_limit=(len(urls) > max_urls_per_file),
                    elapsed_ms=elapsed_ms,
                ),
                urls=urls,
            )

        if root_name == "sitemapindex":
            child_sitemaps: list[str] = []
            seen_children: set[str] = set()
            for child in root:
                if _localname(child.tag) != "sitemap":
                    continue
                raw_loc = None
                for field_el in child:
                    if _localname(field_el.tag) == "loc":
                        val = (field_el.text or "").strip()
                        if val:
                            raw_loc = val
                            break
                if not raw_loc:
                    continue
                try:
                    norm_child = normalize_url(raw_loc, allow_bare_host=False)
                except SSRFBlockedError:
                    continue
                if norm_child not in seen_children:
                    seen_children.add(norm_child)
                    child_sitemaps.append(norm_child)

            return ParsedSitemapData(
                file_result=SitemapFileResult(
                    url=sitemap_url,
                    format="xml_index",
                    http_status=http_status,
                    final_url=final_url or sitemap_url,
                    child_sitemap_count=len(child_sitemaps),
                    is_gzipped=is_gzipped,
                    recovered_xml=recovered_xml,
                    truncated=http_truncated,
                    exceeded_50k_limit=(len(child_sitemaps) > max_urls_per_file),
                    elapsed_ms=elapsed_ms,
                ),
                child_sitemaps=child_sitemaps,
            )

        return ParsedSitemapData(
            file_result=SitemapFileResult(
                url=sitemap_url,
                format="unknown",
                http_status=http_status,
                final_url=final_url or sitemap_url,
                is_gzipped=is_gzipped,
                truncated=http_truncated,
                error=f"UNSUPPORTED_XML_ROOT: <{root_name}> is not a valid sitemap root.",
                elapsed_ms=elapsed_ms,
            )
        )

    # Plain-text sitemap fallback (1 URL per line; reject JSON objects/arrays)
    if not stripped.startswith((b"{", b"[")):
        text_entries = _parse_plain_text_sitemap(
            stripped,
            sitemap_url=sitemap_url,
            target_host=normalized_target_host,
        )
        if text_entries:
            return ParsedSitemapData(
                file_result=SitemapFileResult(
                    url=sitemap_url,
                    format="text",
                    http_status=http_status,
                    final_url=final_url or sitemap_url,
                    url_count=len(text_entries),
                    is_gzipped=is_gzipped,
                    truncated=http_truncated,
                    exceeded_50k_limit=(len(text_entries) > max_urls_per_file),
                    elapsed_ms=elapsed_ms,
                ),
                urls=text_entries,
            )

    return ParsedSitemapData(
        file_result=SitemapFileResult(
            url=sitemap_url,
            format="unknown",
            http_status=http_status,
            final_url=final_url or sitemap_url,
            is_gzipped=is_gzipped,
            truncated=http_truncated,
            error="UNRECOGNIZED_SITEMAP_FORMAT",
            elapsed_ms=elapsed_ms,
        )
    )


async def _fetch_and_parse_single_sitemap(
    http_client: DomainHttpClient,
    sitemap_url: str,
    *,
    target_host: str,
    max_decompressed_bytes: int,
    max_urls_per_file: int,
) -> ParsedSitemapData:
    fetch_res = await http_client.fetch(
        sitemap_url,
        max_bytes=MAX_BYTES_SITEMAP,
    )
    if fetch_res.error is not None:
        return ParsedSitemapData(
            file_result=SitemapFileResult(
                url=sitemap_url,
                format="unknown",
                http_status=fetch_res.status_code,
                final_url=fetch_res.final_url,
                truncated=fetch_res.truncated,
                error=fetch_res.error,
                elapsed_ms=fetch_res.elapsed_ms,
            )
        )

    if fetch_res.status_code is None or not (200 <= fetch_res.status_code < 300):
        return ParsedSitemapData(
            file_result=SitemapFileResult(
                url=sitemap_url,
                format="unknown",
                http_status=fetch_res.status_code,
                final_url=fetch_res.final_url,
                truncated=fetch_res.truncated,
                error=f"HTTP_{fetch_res.status_code or 'UNKNOWN'}",
                elapsed_ms=fetch_res.elapsed_ms,
            )
        )

    return parse_sitemap_bytes(
        fetch_res.body,
        sitemap_url=sitemap_url,
        target_host=target_host,
        http_status=fetch_res.status_code,
        final_url=fetch_res.final_url,
        http_truncated=fetch_res.truncated,
        elapsed_ms=fetch_res.elapsed_ms,
        max_decompressed_bytes=max_decompressed_bytes,
        max_urls_per_file=max_urls_per_file,
    )


async def discover_and_parse_sitemaps(
    http_client: DomainHttpClient,
    start_url: str,
    *,
    robots_checker: RobotsChecker | None = None,
    max_urls_per_domain: int = 500,
    max_sitemap_files: int = 30,
    max_depth: int = MAX_SITEMAP_DEPTH,
    max_decompressed_bytes: int = MAX_DECOMPRESSED_BYTES,
    max_urls_per_file: int = SITEMAP_MAX_URLS_PER_FILE,
) -> SitemapDiscoveryResult:
    """Discover, recursively expand, and validate all Sitemaps for *start_url*."""
    normalized_start = normalize_url(start_url)
    target_host = extract_host(normalized_start)

    discovery_method: DiscoveryMethod = "none"
    queue: deque[tuple[str, int]] = deque()
    visited_sitemaps: set[str] = set()
    sitemap_files: list[SitemapFileResult] = []
    files_fetched = 0
    files_failed = 0
    initial_fallback_parsed: ParsedSitemapData | None = None

    def _enqueue(url: str, depth: int) -> None:
        try:
            norm = normalize_url(url, allow_bare_host=False)
        except SSRFBlockedError:
            return
        if norm not in visited_sitemaps:
            visited_sitemaps.add(norm)
            queue.append((norm, depth))

    # Step 1: Explicit sitemap URL vs robots.txt vs fallback probing
    if is_explicit_sitemap_url(normalized_start):
        discovery_method = "explicit"
        _enqueue(normalized_start, 0)
    elif robots_checker is not None and robots_checker.sitemaps:
        discovery_method = "robots_txt"
        for sm_url in robots_checker.sitemaps:
            _enqueue(sm_url, 0)
    else:
        # Probe /sitemap.xml -> /sitemap_index.xml -> /sitemap.xml.gz sequentially
        for fallback_url in build_fallback_sitemap_urls(normalized_start):
            if files_fetched >= max_sitemap_files:
                break
            visited_sitemaps.add(fallback_url)
            files_fetched += 1
            parsed = await _fetch_and_parse_single_sitemap(
                http_client,
                fallback_url,
                target_host=target_host,
                max_decompressed_bytes=max_decompressed_bytes,
                max_urls_per_file=max_urls_per_file,
            )
            if parsed.file_result.final_url:
                visited_sitemaps.add(parsed.file_result.final_url)
            sitemap_files.append(parsed.file_result)

            if parsed.file_result.error is None and parsed.file_result.format != "unknown":
                discovery_method = "fallback"
                # Process this discovered sitemap's contents right below
                initial_fallback_parsed = parsed
                break
            files_failed += 1
        else:
            initial_fallback_parsed = None

    total_urls_found = 0
    duplicate_urls_count = 0
    cross_host_urls_count = 0
    lastmod_present_count = 0
    invalid_lastmod_count = 0
    recovered_xml_files_count = 0
    over_50k_files_count = 0

    seen_urls: set[str] = set()
    collected_entries: list[SitemapUrlEntry] = []

    def _accumulate(parsed: ParsedSitemapData, depth: int) -> None:
        nonlocal total_urls_found, duplicate_urls_count, cross_host_urls_count
        nonlocal lastmod_present_count, invalid_lastmod_count
        nonlocal recovered_xml_files_count, over_50k_files_count

        fres = parsed.file_result
        if fres.recovered_xml:
            recovered_xml_files_count += 1
        if fres.exceeded_50k_limit:
            over_50k_files_count += 1

        if fres.format == "xml_index" and depth < max_depth:
            for child_url in parsed.child_sitemaps:
                _enqueue(child_url, depth + 1)

        for entry in parsed.urls:
            total_urls_found += 1
            if entry.url in seen_urls:
                duplicate_urls_count += 1
                continue
            seen_urls.add(entry.url)
            if entry.is_cross_host:
                cross_host_urls_count += 1
            if entry.lastmod is not None:
                lastmod_present_count += 1
                if entry.lastmod_valid is False:
                    invalid_lastmod_count += 1
            if len(collected_entries) < max_urls_per_domain:
                collected_entries.append(entry)

    if discovery_method == "fallback" and initial_fallback_parsed is not None:
        _accumulate(initial_fallback_parsed, 0)

    while queue and files_fetched < max_sitemap_files:
        sm_url, depth = queue.popleft()
        files_fetched += 1
        parsed = await _fetch_and_parse_single_sitemap(
            http_client,
            sm_url,
            target_host=target_host,
            max_decompressed_bytes=max_decompressed_bytes,
            max_urls_per_file=max_urls_per_file,
        )
        if parsed.file_result.final_url:
            visited_sitemaps.add(parsed.file_result.final_url)
        sitemap_files.append(parsed.file_result)

        if parsed.file_result.error is not None or parsed.file_result.format == "unknown":
            files_failed += 1
            continue

        _accumulate(parsed, depth)

    unique_urls_count = len(seen_urls)
    lastmod_coverage_rate = (
        round(lastmod_present_count / unique_urls_count, 4)
        if unique_urls_count > 0
        else 0.0
    )

    stats = SitemapDiscoveryStats(
        discovery_method=discovery_method,
        sitemap_files_fetched=files_fetched,
        sitemap_files_failed=files_failed,
        total_urls_found=total_urls_found,
        unique_urls_count=unique_urls_count,
        duplicate_urls_count=duplicate_urls_count,
        cross_host_urls_count=cross_host_urls_count,
        recovered_xml_files_count=recovered_xml_files_count,
        over_50k_files_count=over_50k_files_count,
        lastmod_present_count=lastmod_present_count,
        lastmod_coverage_rate=lastmod_coverage_rate,
        invalid_lastmod_count=invalid_lastmod_count,
        sitemap_files=sitemap_files,
    )
    return SitemapDiscoveryResult(entries=collected_entries, stats=stats)
