"""
JSPECTER CLI Entry Point
Autonomous JS Recon, Secret Discovery & Vulnerability Intelligence Engine.

Usage:
    jspecter -u https://target.com [options]
"""

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Dict, List, Optional

from . import __version__
from .config import ScanConfig, DEFAULT_DEPTH, DEFAULT_THREADS, DEFAULT_TIMEOUT, RESUME_STATE_FILE
from .crawler import Crawler
from .cve_engine import CVEEngine
from .js_analyzer import JSAnalyzer
from .reporter import (
    build_html_report, build_json_report, build_txt_report, print_cli_report
)
from .secrets_engine import SecretsEngine
from .tester import EndpointTester
from .utils import (
    BANNER, Icon, BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW,
    classify_risk, current_ts, logger, normalize_url, print_section,
    safe_write, save_json_state, load_json_state, setup_logger
)


# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jspecter",
        description="JSPECTER — Autonomous JS Recon & Vulnerability Intelligence Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  jspecter -u https://target.com
  jspecter -u https://target.com --depth 5 --cve-scan --format html -o report.html
  jspecter -u https://target.com --subs --threads 20 --timeout 30
  jspecter -u https://target.com --headers '{"Authorization": "Bearer TOKEN"}'
  jspecter -u https://target.com --no-test --format json -o output.json
  jspecter -u https://target.com --proxy http://127.0.0.1:8080
  jspecter -u https://target.com --react2shell
  jspecter --git /path/to/repo

React2Shell (CVE-2025-55182):
  jspecter -u https://target.com --react2shell
  jspecter -u https://target.com --react2shell --format json -o r2s.json
  jspecter -u https://target.com --react2shell --verbose

⚠️  For authorized security research and bug bounty only.
""",
    )

    # Required
    parser.add_argument(
        "-u", "--url",
        help="Target URL (e.g. https://target.com)",
        metavar="URL",
    )

    # Crawl options
    crawl_group = parser.add_argument_group("Crawl Options")
    crawl_group.add_argument(
        "--depth",
        type=int,
        default=DEFAULT_DEPTH,
        help=f"Crawl depth (default: {DEFAULT_DEPTH})",
    )
    crawl_group.add_argument(
        "--subs",
        action="store_true",
        default=False,
        help="Include subdomains in crawl scope",
    )
    crawl_group.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Concurrent request threads (default: {DEFAULT_THREADS})",
    )
    crawl_group.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    crawl_group.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Seconds between requests for rate limiting (default: 0 = no limit)",
    )

    # Request options
    req_group = parser.add_argument_group("Request Options")
    req_group.add_argument(
        "--headers",
        help='Custom headers as JSON string: \'{"Cookie": "session=abc"}\'',
        metavar="JSON",
    )
    req_group.add_argument(
        "--token",
        help="Auth token (added as Authorization: Bearer <token>)",
        metavar="TOKEN",
    )
    req_group.add_argument(
        "--proxy",
        help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)",
        metavar="URL",
    )

    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--no-test",
        action="store_true",
        default=False,
        help="Skip endpoint probing phase",
    )
    scan_group.add_argument(
        "--cve-scan",
        action="store_true",
        default=False,
        help="Enable live CVE correlation via NVD API",
    )
    scan_group.add_argument(
        "--git",
        metavar="REPO_PATH",
        help="Scan a local git repository for historical secrets",
    )
    scan_group.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help="Resume interrupted scan (loads state from .jspecter_state.json)",
    )

    # Output options
    out_group = parser.add_argument_group("Output Options")
    out_group.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output file path",
    )
    out_group.add_argument(
        "--format",
        choices=["json", "html", "txt"],
        default="json",
        help="Output format: json | html | txt (default: json)",
    )
    out_group.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose/debug output",
    )
    out_group.add_argument(
        "--version",
        action="version",
        version=f"JSPECTER {__version__}",
    )

    return parser


# ─── Custom Headers Parser ────────────────────────────────────────────────────

def parse_headers(header_str: Optional[str]) -> Dict[str, str]:
    """Parse custom headers from JSON string or key:value format."""
    if not header_str:
        return {}
    try:
        return json.loads(header_str)
    except json.JSONDecodeError:
        # Try key:value format
        headers = {}
        for part in header_str.split(";"):
            if ":" in part:
                k, v = part.split(":", 1)
                headers[k.strip()] = v.strip()
        return headers


# ─── Main Orchestrator ────────────────────────────────────────────────────────

async def run_scan(config: ScanConfig) -> int:
    """Execute the full JSPECTER scan pipeline."""
    start_time = time.time()

    # ── Phase 1: Crawl ────────────────────────────────────────────────────────
    print_section("Phase 1 · Web Crawl")
    crawler = Crawler(config)
    crawl_result = await crawler.run()

    # ── Phase 2: JS Analysis ──────────────────────────────────────────────────
    print_section("Phase 2 · JavaScript Intelligence Engine")
    analyzer = JSAnalyzer(target_url=config.url, verbose=config.verbose)
    js_analysis = analyzer.analyze_all(
        crawl_result.js_contents,
        crawl_result.inline_scripts,
    )

    # ── Phase 3: Secret Discovery ─────────────────────────────────────────────
    print_section("Phase 3 · Secret Discovery Engine")
    secrets_engine = SecretsEngine(verbose=config.verbose)
    secrets = secrets_engine.scan_all(
        crawl_result.js_contents,
        crawl_result.inline_scripts,
    )

    # ── Phase 4: CVE Correlation ──────────────────────────────────────────────
    print_section("Phase 4 · CVE Intelligence Engine")
    cve_engine = CVEEngine(config)
    cves = await cve_engine.correlate(js_analysis.endpoints, js_analysis.libraries)

    # ── Phase 5: Endpoint Testing ─────────────────────────────────────────────
    probes = []
    if not config.no_test and js_analysis.endpoints:
        print_section("Phase 5 · Endpoint Intelligence Tester")
        tester = EndpointTester(config, config.url)
        probes = await tester.probe_all(js_analysis.endpoints)
    else:
        print_section("Phase 5 · Endpoint Intelligence Tester")
        if config.no_test:
            print(f"  {Icon.INFO} Endpoint testing skipped (--no-test)")
        else:
            print(f"  {Icon.INFO} No endpoints to probe.")

    # ── Phase 6a: React2Shell CVE-2025-55182 (optional dedicated scan) ──────────
    r2s_result = None
    if getattr(config, "react2shell", False):
        print_section("Phase 6a · React2Shell Scanner (CVE-2025-55182)")
        try:
            from .react2shell import React2ShellScanner
            r2s = React2ShellScanner(
                target_url=config.url,
                threads=config.threads,
                timeout=config.timeout,
                headers=config.headers,
                proxy=config.proxy,
                verbose=config.verbose,
            )
            r2s_result = await r2s.scan()
            if r2s_result.vulnerable:
                all_findings_for_risk_r2s = [{"severity": "CRITICAL"}]
        except Exception as e:
            print(f"  {Icon.ERROR} React2Shell scan error: {e}")
            if config.verbose:
                import traceback; traceback.print_exc()

    # ── Phase 6b: Git Scan (optional) ─────────────────────────────────────────
    if config.git_scan:
        print_section("Phase 6b · Git Intelligence Module")
        try:
            from .git_module import GitIntelligence
            git_intel = GitIntelligence(config.git_scan, verbose=config.verbose)
            git_findings = git_intel.scan()
            if git_findings:
                print(f"  {Icon.SECRET} Found {len(git_findings)} issues in git history.")
        except ImportError as e:
            print(f"  {Icon.WARN} Git module unavailable: {e}")
        except Exception as e:
            print(f"  {Icon.ERROR} Git scan error: {e}")

    # ── Phase 7: Reporting ────────────────────────────────────────────────────
    print_section("Phase 7 · Report Generation")

    all_findings_for_risk = (
        [{"severity": s.severity} for s in secrets]
        + [{"severity": c.severity} for c in cves]
        + [{"severity": p.severity} for p in probes if p.interesting]
        + ([{"severity": "CRITICAL"}] if r2s_result and r2s_result.vulnerable else [])
    )
    overall_risk = classify_risk(all_findings_for_risk)

    duration = round(time.time() - start_time, 2)
    scan_meta = {
        "duration": duration,
        "overall_risk": overall_risk,
        "config": {
            "depth": config.depth,
            "threads": config.threads,
            "timeout": config.timeout,
            "include_subs": config.include_subs,
            "cve_scan": config.cve_scan,
        },
    }

    # Print CLI summary
    print_cli_report(
        config.url,
        crawl_result.js_urls,
        js_analysis,
        secrets,
        cves,
        probes,
        scan_meta,
    )

    print(
        f"  {Icon.SUCCESS} {GREEN}Scan completed in {duration}s{RESET}"
    )

    # File output
    if config.output:
        report_content = ""
        if config.output_format == "json":
            report_content = build_json_report(
                config.url, crawl_result.js_urls, js_analysis,
                secrets, cves, probes, scan_meta
            )
        elif config.output_format == "html":
            report_content = build_html_report(
                config.url, crawl_result.js_urls, js_analysis,
                secrets, cves, probes, scan_meta
            )
        elif config.output_format == "txt":
            report_content = build_txt_report(
                config.url, crawl_result.js_urls, js_analysis,
                secrets, cves, probes, scan_meta
            )

        if safe_write(config.output, report_content):
            print(
                f"  {Icon.SUCCESS} Report saved: "
                f"{CYAN}{os.path.abspath(config.output)}{RESET}"
            )
        else:
            print(f"  {Icon.ERROR} Failed to write report to {config.output}")

    return 0 if not secrets and not cves else 1


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main() -> None:
    """JSPECTER CLI entry point."""
    print(BANNER)

    parser = build_parser()
    args = parser.parse_args()

    # Validate required args
    if not args.url and not args.git:
        parser.error("Either --url or --git is required.")

    # Setup logger
    setup_logger(verbose=args.verbose)

    # Build config
    from .config import DEFAULT_HEADERS
    headers = dict(DEFAULT_HEADERS)

    # Apply custom headers
    custom_headers = parse_headers(args.headers)
    headers.update(custom_headers)

    # Apply auth token
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    config = ScanConfig(
        url=normalize_url(args.url) if args.url else "",
        depth=args.depth,
        include_subs=args.subs,
        threads=args.threads,
        timeout=args.timeout,
        headers=headers,
        output=args.output,
        output_format=args.format,
        no_test=args.no_test,
        cve_scan=args.cve_scan,
        verbose=args.verbose,
        proxy=getattr(args, "proxy", None),
        resume=args.resume,
        rate_limit=getattr(args, "rate_limit", 0.0),
        git_scan=getattr(args, "git", None),
        auth_token=getattr(args, "token", None),
    )
    # Attach extra flags not in ScanConfig dataclass
    config.react2shell = getattr(args, "react2shell", False)  # type: ignore[attr-defined]

    # Disclaimer
    print(f"{DIM}  ⚠  For authorized security research and bug bounty only.{RESET}")
    print(f"{DIM}  ⚠  Ensure you have explicit permission to test the target.{RESET}\n")

    # Run
    try:
        exit_code = asyncio.run(run_scan(config))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n  {Icon.WARN} {YELLOW}Scan interrupted by user.{RESET}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
