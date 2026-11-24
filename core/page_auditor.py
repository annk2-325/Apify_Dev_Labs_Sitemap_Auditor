"""Page-level Indexability, Canonical 5-way classification, and HTML SEO/JSON-LD auditor.

Implements Specification.md §3.3:
- HTTP status (4xx/5xx/fetch errors) and redirect chain severity (1 hop warning, >=2/loop critical).
- Non-HTTPS Sitemap URL warning (``HTTP_NON_HTTPS``).
- ``robots.txt`` conflict detection (``DISALLOWED_BY_ROBOTS``).
- ``noindex`` detection from both ``X-Robots-Tag`` HTTP headers and ``<meta name="robots|googlebot">``.
- 5-way Canonical classification with PoC anti-false-positive handling for
  ``index_file_equivalent`` (trailing ``/`` vs ``/index.html``, ``/index.htm``, ``/index.php``).
- ``full_audit`` HTML SEO metadata (``title``, ``meta description``, ``h1`` count, visible text
  length < 200 chars ``SSR_THIN_CONTENT``) and ``application/ld+json`` syntax validation.

This module has zero dependency on ``apify``.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from lxml import html as lxml_html

from core.http_client import MAX_BYTES_HTML, DomainHttpClient, FetchResult
from core.models import (
    AuditIssue,
    AuditMode,
    CanonicalStatus,
    IssueCode,
    NoindexSource,
    SeoMetadata,
    SitemapUrlEntry,
    UrlAuditRecord,
)
from core.robots import RobotsChecker
from core.ssrf import SSRFBlockedError, extract_host, normalize_url

THIN_CONTENT_CHAR_THRESHOLD = 200

_INDEX_FILE_SUFFIXES = ("/index.html", "/index.htm", "/index.php")
_NON_VISIBLE_TAGS = frozenset({"script", "style", "noscript", "template", "svg"})
_LINK_CANONICAL_RE = re.compile(
    r"<([^>]+)>\s*;\s*([^,]*\brel\s*=\s*(?:\"[^\"]*\bcanonical\b[^\"]*\"|'[^']*\bcanonical\b[^']*'|canonical\b)[^,]*)",
    re.IGNORECASE,
)
_WHITESPACE_RE = re.compile(r"\s+")


def _strip_index_file(path: str) -> str:
    """Normalize trailing ``/index.html``, ``/index.htm``, ``/index.php`` to ``/``."""
    lower = path.lower()
    for suffix in _INDEX_FILE_SUFFIXES:
        if lower.endswith(suffix):
            prefix = path[: -len(suffix)]
            return f"{prefix}/" if prefix else "/"
    return path


def classify_canonical(
    page_url: str,
    raw_canonical: str | None,
    *,
    base_url: str | None = None,
) -> tuple[CanonicalStatus, str | None]:
    """Classify a page's canonical URL into one of the 5 specification categories.

    Returns ``(canonical_status, normalized_canonical_url_or_raw)``.
    """
    if raw_canonical is None or not raw_canonical.strip():
        return "missing", None

    page_norm = normalize_url(page_url)
    resolve_base = normalize_url(base_url) if base_url else page_norm
    resolved = urljoin(resolve_base, raw_canonical.strip())

    try:
        canon_norm = normalize_url(resolved, allow_bare_host=False)
    except SSRFBlockedError:
        # Unparseable or non-HTTP canonical href cannot match page URL
        return "cross_host", raw_canonical.strip()

    if canon_norm == page_norm:
        return "self", canon_norm

    page_parts = urlsplit(page_norm)
    canon_parts = urlsplit(canon_norm)

    page_host = extract_host(page_norm)
    canon_host = extract_host(canon_norm)

    if canon_host != page_host:
        return "cross_host", canon_norm

    # Check index_file_equivalent: same scheme, netloc, query; only path differs by / vs /index.*
    if (
        page_parts.scheme == canon_parts.scheme
        and page_parts.netloc == canon_parts.netloc
        and page_parts.query == canon_parts.query
        and _strip_index_file(page_parts.path) == _strip_index_file(canon_parts.path)
    ):
        return "index_file_equivalent", canon_norm

    return "cross_path_same_host", canon_norm


def _parse_robots_directives(directive_str: str) -> set[str]:
    tokens = re.split(r"[\s,;]+", directive_str.lower())
    return {tok.strip() for tok in tokens if tok.strip()}


def has_header_noindex(x_robots_headers: list[str]) -> bool:
    """Return True if any ``X-Robots-Tag`` header applies ``noindex``/``none`` to search indexing."""
    for header_val in x_robots_headers:
        for segment in header_val.split(","):
            part = segment.strip()
            if not part:
                continue
            if ":" in part:
                bot_part, directive_part = part.split(":", 1)
                bot_name = bot_part.strip().lower()
                # Only treat unscoped or googlebot-targeted directives as general noindex
                if bot_name not in ("*", "googlebot"):
                    continue
                directives = _parse_robots_directives(directive_part)
            else:
                directives = _parse_robots_directives(part)

            if "noindex" in directives or "none" in directives:
                return True
    return False


def _extract_link_header_canonical(link_headers: list[str]) -> str | None:
    for header_val in link_headers:
        match = _LINK_CANONICAL_RE.search(header_val)
        if match:
            href = match.group(1).strip()
            if href:
                return href
    return None


def _is_html_response(headers: dict[str, str], body: bytes) -> bool:
    content_type = headers.get("content-type", "").lower()
    if "text/html" in content_type or "application/xhtml+xml" in content_type:
        return True
    if not content_type and body:
        snippet = body[:512].lstrip().lower()
        return snippet.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))
    return False


def _parse_html_document(html_text: str) -> lxml_html.HtmlElement | None:
    if not html_text or not html_text.strip():
        return None
    try:
        parser = lxml_html.HTMLParser(recover=True)
        return lxml_html.fromstring(html_text, parser=parser)
    except Exception:
        return None


def _collapse_ws(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text).strip()


def _extract_visible_text(doc: lxml_html.HtmlElement) -> str:
    body_nodes = doc.xpath("//body")
    root = body_nodes[0] if body_nodes else doc
    parts: list[str] = []

    def _walk(node: Any) -> None:
        if not isinstance(node.tag, str):
            return
        tag = node.tag.lower()
        if tag in _NON_VISIBLE_TAGS:
            return
        if node.text:
            parts.append(node.text)
        for child in node:
            _walk(child)
            if child.tail:
                parts.append(child.tail)

    _walk(root)
    return _collapse_ws(" ".join(parts))


def _collect_jsonld_types(data: Any, out: list[str]) -> None:
    if isinstance(data, dict):
        raw_type = data.get("@type")
        if isinstance(raw_type, str) and raw_type.strip():
            out.append(raw_type.strip())
        elif isinstance(raw_type, list):
            for item in raw_type:
                if isinstance(item, str) and item.strip():
                    out.append(item.strip())
        graph = data.get("@graph")
        if isinstance(graph, list):
            for node in graph:
                _collect_jsonld_types(node, out)
    elif isinstance(data, list):
        for item in data:
            _collect_jsonld_types(item, out)


def parse_html_signals(
    html_text: str,
    *,
    extract_seo: bool,
) -> tuple[bool, str | None, str | None, SeoMetadata | None]:
    """Extract meta noindex, HTML canonical href, base href, and optional SEO/JSON-LD metadata."""
    doc = _parse_html_document(html_text)
    if doc is None:
        return False, None, None, SeoMetadata() if extract_seo else None

    # <base href="..."> if present
    base_href: str | None = None
    for base_el in doc.xpath("//base[@href]"):
        val = (base_el.get("href") or "").strip()
        if val:
            base_href = val
            break

    # <meta name="robots|googlebot" content="...">
    meta_noindex = False
    for meta_el in doc.xpath("//meta[@name and @content]"):
        name = (meta_el.get("name") or "").strip().lower()
        if name in ("robots", "googlebot"):
            directives = _parse_robots_directives(meta_el.get("content") or "")
            if "noindex" in directives or "none" in directives:
                meta_noindex = True
                break

    # <link rel="canonical" href="...">
    html_canonical: str | None = None
    for link_el in doc.xpath("//link[@rel and @href]"):
        rel_tokens = {
            tok.lower() for tok in (link_el.get("rel") or "").split() if tok.strip()
        }
        if "canonical" in rel_tokens:
            href = (link_el.get("href") or "").strip()
            if href:
                html_canonical = href
                break

    if not extract_seo:
        return meta_noindex, html_canonical, base_href, None

    # <title>
    title_val: str | None = None
    title_nodes = doc.xpath("//title")
    if title_nodes:
        raw_title = _collapse_ws("".join(title_nodes[0].itertext()))
        if raw_title:
            title_val = raw_title

    # <meta name="description" content="...">
    meta_desc: str | None = None
    for meta_el in doc.xpath("//meta[@name and @content]"):
        if (meta_el.get("name") or "").strip().lower() == "description":
            desc_val = _collapse_ws(meta_el.get("content") or "")
            if desc_val:
                meta_desc = desc_val
            break

    # <h1> count
    h1_count = len(doc.xpath("//h1"))

    # Visible body text length
    visible_text = _extract_visible_text(doc)
    text_char_count = len(visible_text)

    # JSON-LD blocks
    jsonld_count = 0
    jsonld_error_count = 0
    raw_types: list[str] = []
    for script_el in doc.xpath("//script[@type]"):
        script_type = (script_el.get("type") or "").split(";", 1)[0].strip().lower()
        if script_type != "application/ld+json":
            continue
        jsonld_count += 1
        raw_json = (script_el.text or "").strip()
        if not raw_json:
            jsonld_error_count += 1
            continue
        try:
            parsed_json = json.loads(raw_json)
        except json.JSONDecodeError:
            jsonld_error_count += 1
            continue
        _collect_jsonld_types(parsed_json, raw_types)

    seo = SeoMetadata(
        title=title_val,
        title_length=len(title_val) if title_val else 0,
        meta_description=meta_desc,
        meta_description_length=len(meta_desc) if meta_desc else 0,
        h1_count=h1_count,
        text_char_count=text_char_count,
        jsonld_count=jsonld_count,
        jsonld_types=list(dict.fromkeys(raw_types)),
        jsonld_error_count=jsonld_error_count,
    )
    return meta_noindex, html_canonical, base_href, seo


def audit_fetched_page(
    entry: SitemapUrlEntry,
    fetch_result: FetchResult,
    *,
    domain: str,
    mode: AuditMode,
    robots_checker: RobotsChecker | None = None,
) -> UrlAuditRecord:
    """Evaluate a fetched Sitemap URL and return a populated :class:`UrlAuditRecord`."""
    issues: list[AuditIssue] = []

    # Non-HTTPS check on the Sitemap URL itself
    if urlsplit(entry.url).scheme == "http":
        issues.append(
            AuditIssue(
                code=IssueCode.HTTP_NON_HTTPS,
                severity="warning",
                detail=f"Sitemap URL uses insecure http:// scheme: {entry.url}",
            )
        )

    # robots.txt conflict check (User-agent: *)
    robots_allowed: bool | None = None
    if robots_checker is not None:
        robots_allowed = robots_checker.can_fetch(entry.url, "*")
        if robots_allowed is not False and fetch_result.final_url and fetch_result.final_url != entry.url:
            final_allowed = robots_checker.can_fetch(fetch_result.final_url, "*")
            if final_allowed is False:
                robots_allowed = False

    if robots_allowed is False:
        issues.append(
            AuditIssue(
                code=IssueCode.DISALLOWED_BY_ROBOTS,
                severity="critical",
                detail="URL listed in Sitemap is disallowed by robots.txt (User-agent: *).",
            )
        )

    # Fetch / redirect error classification
    fatal_fetch = False
    if fetch_result.ssrf_blocked:
        fatal_fetch = True
        issues.append(
            AuditIssue(
                code=IssueCode.SSRF_BLOCKED,
                severity="critical",
                detail=fetch_result.error or "Blocked by SSRF protection.",
            )
        )
    elif fetch_result.redirect_loop:
        fatal_fetch = True
        issues.append(
            AuditIssue(
                code=IssueCode.REDIRECT_LOOP,
                severity="critical",
                detail=fetch_result.error or "Redirect loop detected.",
            )
        )
        issues.append(
            AuditIssue(
                code=IssueCode.REDIRECT_CHAIN,
                severity="critical",
                detail=f"Redirect loop across {fetch_result.redirect_hops} hops.",
            )
        )
    elif fetch_result.too_many_redirects:
        fatal_fetch = True
        issues.append(
            AuditIssue(
                code=IssueCode.TOO_MANY_REDIRECTS,
                severity="critical",
                detail=fetch_result.error or "Exceeded maximum redirect hops.",
            )
        )
        issues.append(
            AuditIssue(
                code=IssueCode.REDIRECT_CHAIN,
                severity="critical",
                detail=f"Redirect chain exceeded maximum ({fetch_result.redirect_hops} hops).",
            )
        )
    elif fetch_result.error is not None or fetch_result.status_code is None:
        fatal_fetch = True
        issues.append(
            AuditIssue(
                code=IssueCode.FETCH_ERROR,
                severity="critical",
                detail=fetch_result.error or "HTTP fetch failed with no status code.",
            )
        )

    status_code = fetch_result.status_code

    if not fatal_fetch and status_code is not None:
        # Redirect chain check on completed fetches
        if fetch_result.redirect_hops == 1:
            issues.append(
                AuditIssue(
                    code=IssueCode.REDIRECT_CHAIN,
                    severity="warning",
                    detail=(
                        f"Sitemap URL redirects (1 hop) to {fetch_result.final_url}."
                    ),
                )
            )
        elif fetch_result.redirect_hops >= 2:
            issues.append(
                AuditIssue(
                    code=IssueCode.REDIRECT_CHAIN,
                    severity="critical",
                    detail=(
                        f"Sitemap URL has a {fetch_result.redirect_hops}-hop redirect "
                        f"chain ending at {fetch_result.final_url}."
                    ),
                )
            )

        if 400 <= status_code < 500:
            issues.append(
                AuditIssue(
                    code=IssueCode.HTTP_4XX,
                    severity="critical",
                    detail=f"HTTP {status_code} client error returned for Sitemap URL.",
                )
            )
        elif 500 <= status_code < 600:
            issues.append(
                AuditIssue(
                    code=IssueCode.HTTP_5XX,
                    severity="critical",
                    detail=f"HTTP {status_code} server error returned for Sitemap URL.",
                )
            )
        elif not (200 <= status_code < 300):
            issues.append(
                AuditIssue(
                    code=IssueCode.FETCH_ERROR,
                    severity="critical",
                    detail=f"Unexpected non-2xx HTTP status {status_code}.",
                )
            )

    noindex: bool | None = None
    noindex_source: NoindexSource = None
    canonical_status: CanonicalStatus | None = None
    canonical_url: str | None = None
    seo_meta: SeoMetadata | None = None

    is_2xx = (not fatal_fetch) and (status_code is not None) and (200 <= status_code < 300)

    if is_2xx:
        header_noindex = has_header_noindex(
            fetch_result.get_header_values("x-robots-tag")
        )
        link_header_canonical = _extract_link_header_canonical(
            fetch_result.get_header_values("link")
        )

        meta_noindex = False
        html_canonical: str | None = None
        base_href: str | None = None
        is_html = _is_html_response(fetch_result.headers, fetch_result.body)

        if is_html:
            html_text = fetch_result.decode_text(default_encoding="utf-8")
            meta_noindex, html_canonical, base_href, seo_meta = parse_html_signals(
                html_text,
                extract_seo=(mode == "full_audit"),
            )

        if header_noindex and meta_noindex:
            noindex = True
            noindex_source = "both"
        elif header_noindex:
            noindex = True
            noindex_source = "header"
        elif meta_noindex:
            noindex = True
            noindex_source = "meta"
        else:
            noindex = False
            noindex_source = None

        if noindex:
            issues.append(
                AuditIssue(
                    code=IssueCode.NOINDEX_IN_SITEMAP,
                    severity="critical",
                    detail=f"Page listed in Sitemap is marked noindex (source: {noindex_source}).",
                )
            )

        # Canonical classification
        chosen_canonical = html_canonical or link_header_canonical
        resolve_base = fetch_result.final_url
        if base_href:
            candidate_base = urljoin(fetch_result.final_url, base_href)
            try:
                resolve_base = normalize_url(candidate_base, allow_bare_host=False)
            except SSRFBlockedError:
                resolve_base = fetch_result.final_url

        canonical_status, canonical_url = classify_canonical(
            fetch_result.final_url,
            chosen_canonical,
            base_url=resolve_base,
        )

        if canonical_status == "index_file_equivalent":
            issues.append(
                AuditIssue(
                    code=IssueCode.CANONICAL_INDEX_FILE_EQUIVALENT,
                    severity="info",
                    detail=(
                        f"Canonical differs only by trailing '/' vs index file: {canonical_url}"
                    ),
                )
            )
        elif canonical_status == "cross_path_same_host":
            issues.append(
                AuditIssue(
                    code=IssueCode.CANONICAL_MISMATCH_SAME_HOST,
                    severity="warning",
                    detail=(
                        f"Canonical points to a different path on the same host: {canonical_url}"
                    ),
                )
            )
        elif canonical_status == "cross_host":
            issues.append(
                AuditIssue(
                    code=IssueCode.CANONICAL_MISMATCH_CROSS_HOST,
                    severity="critical",
                    detail=f"Canonical points to a different host: {canonical_url}",
                )
            )
        elif canonical_status == "missing" and is_html:
            issues.append(
                AuditIssue(
                    code=IssueCode.CANONICAL_MISSING,
                    severity="info",
                    detail="No canonical link tag or Link header found.",
                )
            )

        # full_audit SEO & JSON-LD issues
        if mode == "full_audit" and seo_meta is not None:
            if seo_meta.title_length == 0:
                issues.append(
                    AuditIssue(
                        code=IssueCode.MISSING_TITLE,
                        severity="warning",
                        detail="Page is missing a non-empty <title> tag.",
                    )
                )
            if seo_meta.meta_description_length == 0:
                issues.append(
                    AuditIssue(
                        code=IssueCode.MISSING_META_DESCRIPTION,
                        severity="info",
                        detail="Page is missing a non-empty meta description.",
                    )
                )
            if seo_meta.h1_count == 0:
                issues.append(
                    AuditIssue(
                        code=IssueCode.H1_MISSING,
                        severity="warning",
                        detail="Page has no <h1> heading.",
                    )
                )
            elif seo_meta.h1_count > 1:
                issues.append(
                    AuditIssue(
                        code=IssueCode.H1_MULTIPLE,
                        severity="info",
                        detail=f"Page has {seo_meta.h1_count} <h1> headings.",
                    )
                )
            if seo_meta.text_char_count < THIN_CONTENT_CHAR_THRESHOLD:
                issues.append(
                    AuditIssue(
                        code=IssueCode.SSR_THIN_CONTENT,
                        severity="warning",
                        detail=(
                            f"Visible body text is {seo_meta.text_char_count} chars "
                            f"(< {THIN_CONTENT_CHAR_THRESHOLD}); possible thin content or CSR shell."
                        ),
                    )
                )
            if seo_meta.jsonld_error_count > 0:
                issues.append(
                    AuditIssue(
                        code=IssueCode.INVALID_JSONLD,
                        severity="warning",
                        detail=(
                            f"Found {seo_meta.jsonld_error_count} invalid "
                            "application/ld+json block(s)."
                        ),
                    )
                )

    indexable = bool(
        is_2xx
        and robots_allowed is not False
        and noindex is not True
        and canonical_status not in ("cross_host", "cross_path_same_host")
    )

    record = UrlAuditRecord(
        domain=domain,
        url=entry.url,
        sitemap_source=entry.sitemap_source,
        lastmod=entry.lastmod,
        audited=True,
        http_status=status_code,
        final_url=fetch_result.final_url,
        redirect_hops=fetch_result.redirect_hops,
        redirect_chain=list(fetch_result.redirect_chain),
        robots_allowed=robots_allowed,
        indexable=indexable,
        noindex=noindex,
        noindex_source=noindex_source,
        canonical_status=canonical_status,
        canonical_url=canonical_url,
        issues=issues,
        elapsed_ms=fetch_result.elapsed_ms,
        error=fetch_result.error,
    )
    if seo_meta is not None:
        record.apply_seo_metadata(seo_meta)

    return record


async def audit_page(
    http_client: DomainHttpClient,
    entry: SitemapUrlEntry,
    *,
    domain: str,
    mode: AuditMode,
    robots_checker: RobotsChecker | None = None,
) -> UrlAuditRecord:
    """Fetch *entry.url* with *http_client* and perform Indexability / SEO auditing."""
    fetch_result = await http_client.fetch(
        entry.url,
        max_bytes=MAX_BYTES_HTML,
    )
    return audit_fetched_page(
        entry,
        fetch_result,
        domain=domain,
        mode=mode,
        robots_checker=robots_checker,
    )
