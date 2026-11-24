# Sitemap Extractor & Indexability Auditor — Fast, No Proxy, Broken Links & AI Bots

Extract every URL from XML, nested `sitemap_index.xml`, `.xml.gz`, plain-text, and even malformed Sitemaps at **512 MB** with **no proxy required by default** — then run a **4-point Indexability audit** (HTTP status & redirect chains, `robots.txt` conflicts, `noindex`, 5-way Canonical checks), **HTML SEO & JSON-LD validation**, **AI search bot reachability differential checks** (`OAI-SearchBot`, `GPTBot`, `ClaudeBot`, `Claude-SearchBot`, `PerplexityBot`), and **`/llms.txt` diagnostics**.

---

## Why Use This Actor?

- **512 MB & No Proxy by Default:** Pure async HTTP/2 (`httpx` + `lxml` + `protego`) with zero headless browser overhead. Starts with direct HTTP and automatically escalates to Apify Proxy only when HTTP `403 / 429 / 503` or a WAF challenge is detected (`autoEscalateProxy: true`).
- **Complete Sitemap Format & Quality Coverage:**
  - Auto-discovers Sitemaps from `robots.txt` (`Sitemap:` directives) with automatic fallback to `/sitemap.xml` → `/sitemap_index.xml` → `/sitemap.xml.gz`, or accepts explicit Sitemap URLs directly.
  - Recursively expands nested `sitemapindex` files (up to depth 5 with cycle protection), decompresses `.xml.gz` via magic-byte detection (`1f 8b` with 30 MB decompression bomb cap), supports plain-text Sitemaps, and recovers broken XML (`recovered_xml: true`) with XXE disabled.
  - Flags duplicate URLs, cross-host URLs, files exceeding the 50,000-URL protocol limit, and invalid W3C `<lastmod>` dates.
- **4-Point Indexability Reconciliation:**
  - **HTTP & Redirects:** Detects `HTTP_4XX`, `HTTP_5XX`, `FETCH_ERROR`, `HTTP_NON_HTTPS`, 1-hop `REDIRECT_CHAIN` warnings, 2+ hop / `REDIRECT_LOOP` / `TOO_MANY_REDIRECTS` criticals.
  - **`robots.txt` Conflicts:** RFC 9309 compliant checks via `protego>=0.6.2` (`DISALLOWED_BY_ROBOTS`).
  - **`noindex` Conflicts:** Inspects both HTTP `X-Robots-Tag` headers and HTML `<meta name="robots|googlebot">` tags (`NOINDEX_IN_SITEMAP`).
  - **5-Way Canonical Classification:** `self`, `index_file_equivalent` (treats trailing `/` vs `/index.html`, `/index.htm`, `/index.php` as `info` without false-positive penalties), `cross_path_same_host` (`warning`), `cross_host` (`critical`), and `missing` (`info`).
- **AI Search Bot Differential Probing & `/llms.txt` Audit:**
  - Tests `OAI-SearchBot`, `GPTBot`, `ClaudeBot`, `Claude-SearchBot`, and `PerplexityBot` against both `robots.txt` and live HTTP status compared to a desktop browser UA — flagging unintended CDN/WAF differential blocks (`AI_BOT_CDN_BLOCK`).
  - Validates `/llms.txt` (requires HTTP 200, non-HTML payload, and `>= 20` bytes) and reports byte size, Markdown heading count, and link count.
- **Actionable 0–100 Health Score & Top Priority Fixes:** Capped per-category scoring prevents single issues from collapsing scores to 0, paired with up to 10 prioritized remediation items.

---

## Execution Modes

| Mode | What It Runs | Best For |
|---|---|---|
| `extract_only` | `robots.txt` discovery + recursive Sitemap extraction + Sitemap hygiene stats & score (0 page fetches, 0 AI probes) | Ultra-fast bulk URL extraction up to 50,000 URLs/domain |
| `indexability_audit` *(default)* | Sitemap extraction + HTTP/redirect/robots/noindex/canonical audit on up to `maxAuditPagesPerDomain` URLs + optional AI bot & `/llms.txt` audit | Broken link detection, redirect cleanup, indexability QA |
| `full_audit` | Everything in `indexability_audit` + HTML SEO (`title`, `meta description`, `h1`, `<200` char `SSR_THIN_CONTENT`) + `application/ld+json` syntax validation + 3-axis 0–100 health score | Complete technical SEO, AI search readiness, and monitoring |

---

## Input Example

```json
{
  "startUrls": [
    "https://docs.python.org",
    "https://docs.perplexity.ai"
  ],
  "mode": "full_audit",
  "maxUrlsPerDomain": 500,
  "maxAuditPagesPerDomain": 25,
  "includeAiBotAudit": true,
  "outputMode": "both",
  "onlyIssuesInDataset": false,
  "autoEscalateProxy": true,
  "proxyConfiguration": {
    "useApifyProxy": false
  }
}
```

> `startUrls` accepts both plain URL strings (`["https://example.com"]`) and Apify RequestList objects (`[{"url": "https://example.com"}]`).

---

## Output Format

The Actor writes flat JSON records to the **Default Dataset** (`record_type: "summary"` and `record_type: "url"`) and always persists the complete aggregated run payload to the **Key-Value Store** under key **`SUMMARY`**.

### Dataset `summary` Record Example

```json
{
  "record_type": "summary",
  "domain": "docs.perplexity.ai",
  "start_url": "https://docs.perplexity.ai/",
  "mode": "full_audit",
  "health_score": 100,
  "robots_status": "loaded",
  "sitemap_stats": {
    "discovery_method": "robots_txt",
    "sitemap_files_fetched": 1,
    "sitemap_files_failed": 0,
    "total_urls_found": 210,
    "unique_urls_count": 210,
    "duplicate_urls_count": 0,
    "cross_host_urls_count": 0,
    "recovered_xml_files_count": 0,
    "over_50k_files_count": 0,
    "lastmod_coverage_rate": 1.0
  },
  "pages_audited": 10,
  "indexable_count": 10,
  "non_indexable_count": 0,
  "canonical_breakdown": {
    "self": 10,
    "index_file_equivalent": 0,
    "cross_path_same_host": 0,
    "cross_host": 0,
    "missing": 0
  },
  "ai_audit": {
    "target_url": "https://docs.perplexity.ai/",
    "browser_http_status": 200,
    "any_cdn_or_waf_diff_block": false,
    "llms_txt": {
      "url": "https://docs.perplexity.ai/llms.txt",
      "http_status": 200,
      "llms_txt_present": true,
      "byte_size": 48435,
      "heading_count": 3,
      "link_count": 217
    }
  },
  "top_priority_fixes": [],
  "proxy_escalated": false,
  "elapsed_sec": 3.42
}
```

### Dataset `url` Record Example

```json
{
  "record_type": "url",
  "domain": "docs.python.org",
  "url": "https://docs.python.org/3/",
  "sitemap_source": "https://docs.python.org/sitemap.xml",
  "audited": true,
  "http_status": 200,
  "final_url": "https://docs.python.org/3/",
  "redirect_hops": 0,
  "robots_allowed": true,
  "indexable": true,
  "noindex": false,
  "canonical_status": "index_file_equivalent",
  "canonical_url": "https://docs.python.org/3/index.html",
  "issues": [
    {
      "code": "CANONICAL_INDEX_FILE_EQUIVALENT",
      "severity": "info",
      "detail": "Canonical differs only by trailing '/' vs index file: https://docs.python.org/3/index.html"
    }
  ],
  "issue_codes": ["CANONICAL_INDEX_FILE_EQUIVALENT"],
  "issue_severities": ["info"],
  "elapsed_ms": 148
}
```

---

## Pay-Per-Event Pricing (No Double-Charging)

- `sitemap-url-extracted`: Charged once per extracted-only (unaudited) URL row pushed to the Dataset.
- `page-indexability-audited`: Charged once per HTTP/HTML audited URL row pushed to the Dataset (never double-charged with `sitemap-url-extracted`).
- `domain-audit-summary`: Charged once per audited domain summary (with deterministic idempotency key and automatic safe stop when `maxTotalChargeUsd` is reached).

---

## MCP & AI Agent Prompt Examples

This Actor's flat JSON schema and Key-Value Store `SUMMARY` record are designed for direct tool invocation via the **Apify MCP Server**:

- **Technical SEO & Broken Links Check:**
  > "Run `ajisai-labs/sitemap-extractor-indexability-auditor` in `indexability_audit` mode on `https://example.com` with `onlyIssuesInDataset: true` and summarize all 4xx/5xx URLs, redirect chains, noindex conflicts, and canonical mismatches."
- **AI Search Readiness & `/llms.txt` Audit:**
  > "Audit `https://example.com` in `full_audit` mode (`maxAuditPagesPerDomain: 10`, `includeAiBotAudit: true`) and check whether `OAI-SearchBot`, `GPTBot`, `ClaudeBot`, `Claude-SearchBot`, or `PerplexityBot` are blocked by `robots.txt` or CDN/WAF rules, and report whether `/llms.txt` is valid."
- **Fast Bulk Sitemap Extraction:**
  > "Extract up to 2,000 URLs from `https://example.com` using `mode: extract_only` and report duplicate URLs, cross-host links, and broken XML files."
