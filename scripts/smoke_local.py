"""Local smoke-test CLI for live validation against public websites.

Usage:
    .venv\\Scripts\\python.exe scripts/smoke_local.py
    .venv\\Scripts\\python.exe scripts/smoke_local.py --urls https://www.sitemaps.org --max-audit-pages 10
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Allow running directly via `python scripts/smoke_local.py` without editable install
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.models import AuditConfig, AuditMode
from core.runner import RunAuditResult, run_audit

DEFAULT_URLS = [
    "https://www.sitemaps.org",
    "https://docs.python.org",
    "https://docs.perplexity.ai",
]


def format_markdown_report(result: RunAuditResult) -> str:
    """Format a RunAuditResult into a readable GitHub-flavored Markdown report."""
    payload = result.summary_payload
    lines: list[str] = []
    lines.append("## Local Smoke Audit Report")
    lines.append("")
    lines.append(
        f"- **Mode:** `{payload.mode}` | **Domains:** `{payload.total_domains}` "
        f"| **URLs Extracted:** `{payload.total_urls_extracted}` "
        f"| **Pages Audited:** `{payload.total_pages_audited}` "
        f"| **Total Elapsed:** `{payload.elapsed_sec:.2f}s` "
        f"| **Proxy Escalated:** `{payload.proxy_escalated}`"
    )
    lines.append("")

    # Overview table
    lines.append(
        "| Domain | Score | Discovery | Sitemaps (OK/Fail) | URLs (Found/Unique/Dup) "
        "| Audited (Idx/Non) | Canonical (self/idx_eq/same/cross/miss) | llms.txt | AI Diff Block | Elapsed |"
    )
    lines.append("|---|---:|---|---|---|---:|---|---|---|---|")

    for domain_res in result.domain_results:
        s = domain_res.summary
        sm = s.sitemap_stats
        cb = s.canonical_breakdown
        canon_str = (
            f"{cb['self']}/{cb['index_file_equivalent']}/"
            f"{cb['cross_path_same_host']}/{cb['cross_host']}/{cb['missing']}"
        )
        llms_str = "n/a"
        ai_block_str = "n/a"
        if s.ai_audit is not None:
            ai_block_str = "YES" if s.ai_audit.any_cdn_or_waf_diff_block else "NO"
            if s.ai_audit.llms_txt is not None:
                lt = s.ai_audit.llms_txt
                if lt.llms_txt_present:
                    llms_str = (
                        f"YES ({lt.byte_size}B, H:{lt.heading_count}, L:{lt.link_count})"
                    )
                else:
                    llms_str = f"NO (HTTP {lt.http_status})"

        ok_files = max(0, sm.sitemap_files_fetched - sm.sitemap_files_failed)
        lines.append(
            f"| `{s.domain}` | **{s.health_score}** | `{sm.discovery_method}` "
            f"| {ok_files}/{sm.sitemap_files_failed} "
            f"| {sm.total_urls_found}/{sm.unique_urls_count}/{sm.duplicate_urls_count} "
            f"| {s.pages_audited} ({s.indexable_count}/{s.non_indexable_count}) "
            f"| `{canon_str}` | {llms_str} | {ai_block_str} | {s.elapsed_sec:.2f}s |"
        )

    lines.append("")

    # Per-domain breakdown
    for domain_res in result.domain_results:
        s = domain_res.summary
        lines.append(f"### `{s.domain}` (Score: {s.health_score}/100, {s.elapsed_sec:.2f}s)")
        lines.append("")
        lines.append(
            f"- **robots.txt:** `{s.robots_status}` | **Discovery:** `{s.sitemap_stats.discovery_method}` "
            f"| **Cross-host URLs:** `{s.sitemap_stats.cross_host_urls_count}` "
            f"| **Recovered XML:** `{s.sitemap_stats.recovered_xml_files_count}` "
            f"| **lastmod coverage:** `{s.sitemap_stats.lastmod_coverage_rate:.0%}`"
        )
        if s.ai_audit is not None:
            bot_bits = [
                f"`{b.bot_name}`: robots={b.robots_allowed}, HTTP={b.http_status}"
                + (" [WAF_BLOCK]" if b.cdn_or_waf_diff_block else "")
                for b in s.ai_audit.bots
            ]
            lines.append(
                f"- **AI Bots (Browser HTTP {s.ai_audit.browser_http_status}):** "
                + "; ".join(bot_bits)
            )
            if s.ai_audit.llms_txt is not None:
                lt = s.ai_audit.llms_txt
                lines.append(
                    f"- **/llms.txt:** present=`{lt.llms_txt_present}`, HTTP=`{lt.http_status}`, "
                    f"content_type=`{lt.content_type}`, bytes=`{lt.byte_size}`, "
                    f"headings=`{lt.heading_count}`, links=`{lt.link_count}`"
                )

        if s.top_priority_fixes:
            lines.append("- **Top Priority Fixes:**")
            for fix in s.top_priority_fixes[:5]:
                sample = f" (e.g. `{fix.sample_urls[0]}`)" if fix.sample_urls else ""
                lines.append(
                    f"  - `[{fix.severity.upper()}]` `{fix.code}` x{fix.affected_count}{sample}: "
                    f"{fix.recommended_action}"
                )
        else:
            lines.append("- **Top Priority Fixes:** None (0 issues detected)")

        if s.errors:
            lines.append(f"- **Errors:** {', '.join(s.errors)}")
        lines.append("")

    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run live local smoke audit against public websites."
    )
    parser.add_argument(
        "--urls",
        nargs="+",
        default=DEFAULT_URLS,
        help="Target domain or Sitemap URLs (default: sitemaps.org, docs.python.org, docs.perplexity.ai).",
    )
    parser.add_argument(
        "--mode",
        choices=("extract_only", "indexability_audit", "full_audit"),
        default="full_audit",
        help="Audit mode (default: full_audit).",
    )
    parser.add_argument(
        "--max-urls",
        type=int,
        default=500,
        help="Max URLs extracted per domain (default: 500).",
    )
    parser.add_argument(
        "--max-audit-pages",
        type=int,
        default=10,
        help="Max pages audited per domain (default: 10).",
    )
    parser.add_argument(
        "--max-sitemap-files",
        type=int,
        default=30,
        help="Max sitemap files per domain (default: 30).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Concurrent HTTP connections per domain (default: 5).",
    )
    parser.add_argument(
        "--no-ai-bot-audit",
        action="store_true",
        help="Disable AI search bot differential probing & /llms.txt check.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to save full JSON RunSummaryPayload.",
    )
    return parser.parse_args(argv)


async def _main_async(args: argparse.Namespace) -> int:
    mode: AuditMode = args.mode
    config = AuditConfig(
        start_urls=args.urls,
        mode=mode,
        max_urls_per_domain=args.max_urls,
        max_audit_pages_per_domain=args.max_audit_pages,
        max_sitemap_files=args.max_sitemap_files,
        concurrency=args.concurrency,
        include_ai_bot_audit=not args.no_ai_bot_audit,
        auto_escalate_proxy=False,
    )
    result = await run_audit(config)
    report = format_markdown_report(result)
    print(report)

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(result.summary_payload.model_dump(mode="json"), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = parse_args(argv)
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
