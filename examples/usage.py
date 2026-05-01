#!/usr/bin/env python3
"""
JSPECTER Usage Examples
Run these to understand JSPECTER's capabilities.
"""

# ─── Example 1: Basic Scan ────────────────────────────────────────────────────
# jspecter -u https://example.com

# ─── Example 2: Deep Scan with CVE Correlation ────────────────────────────────
# jspecter -u https://target.com --depth 5 --cve-scan --format html -o report.html

# ─── Example 3: Authenticated Scan ───────────────────────────────────────────
# jspecter -u https://app.target.com \
#     --token "eyJhbGciOiJSUzI1NiIsInR..." \
#     --headers '{"Cookie": "session=abc123"}' \
#     --depth 3

# ─── Example 4: Through Burp Proxy ───────────────────────────────────────────
# jspecter -u https://target.com --proxy http://127.0.0.1:8080

# ─── Example 5: Subdomain + High Concurrency ──────────────────────────────────
# jspecter -u https://target.com --subs --threads 30 --timeout 20

# ─── Example 6: Skip Probing, JSON Output ─────────────────────────────────────
# jspecter -u https://target.com --no-test --format json -o findings.json

# ─── Example 7: Git Repo Scan ─────────────────────────────────────────────────
# jspecter --git /path/to/local/repo

# ─── Example 8: Rate Limited Scan ─────────────────────────────────────────────
# jspecter -u https://target.com --rate-limit 0.5 --threads 5

# ─── Example 9: Programmatic Usage ───────────────────────────────────────────
import asyncio
import sys

async def programmatic_example():
    """Use JSPECTER as a Python library."""
    try:
        from jspecter.config import ScanConfig, DEFAULT_HEADERS
        from jspecter.crawler import Crawler
        from jspecter.js_analyzer import JSAnalyzer
        from jspecter.secrets_engine import SecretsEngine
        from jspecter.cve_engine import CVEEngine
    except ImportError:
        print("Install JSPECTER first: pip install .")
        return

    config = ScanConfig(
        url="https://httpbin.org",
        depth=1,
        threads=5,
        timeout=10,
        no_test=True,
        cve_scan=False,
        verbose=False,
    )

    # Crawl
    crawler = Crawler(config)
    crawl_result = await crawler.run()

    print(f"Found {len(crawl_result.js_urls)} JS files")
    print(f"Found {len(crawl_result.inline_scripts)} inline scripts")

    # Analyze
    analyzer = JSAnalyzer()
    analysis = analyzer.analyze_all(
        crawl_result.js_contents,
        crawl_result.inline_scripts,
    )

    print(f"Extracted {len(analysis.endpoints)} endpoints")
    print(f"Detected libraries: {list(analysis.libraries.keys())}")

    # Secrets
    engine = SecretsEngine()
    secrets = engine.scan_all(
        crawl_result.js_contents,
        crawl_result.inline_scripts,
    )

    print(f"Secrets found: {len(secrets)}")
    for s in secrets:
        print(f"  [{s.severity}] {s.secret_type}: {s.redacted_value()}")


if __name__ == "__main__":
    asyncio.run(programmatic_example())
