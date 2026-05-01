<div align="center">

<img width="607" height="348" alt="Screenshot 2026-05-01 124622" src="https://github.com/user-attachments/assets/04d6e3a4-400d-4f8a-bf4b-4961fa2cd896" />

# JSPECTER

**Autonomous JavaScript Recon, Secret Discovery & Vulnerability Intelligence Engine**

> *"Hunting what JavaScript tries to hide."*

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-red?style=for-the-badge)](CHANGELOG.md)
[![CVE](https://img.shields.io/badge/CVE--2025--55182-React2Shell-critical?style=for-the-badge&color=darkred)](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
[![Author](https://img.shields.io/badge/Author-abhi04anon-cyan?style=for-the-badge)](https://github.com/abhi04anon)

</div>

---

## What is JSPECTER?

JSPECTER is a next-generation **offensive security recon framework** built for bug bounty hunters and security researchers. It autonomously crawls a target web application, extracts every piece of intelligence hidden inside JavaScript files, and produces a prioritised, actionable report — all in a single command.

It combines the power of:
- **LinkFinder** — endpoint extraction from JS
- **truffleHog** — secret and credential discovery
- **Nuclei** — CVE-based vulnerability correlation
- **React2Shell Scanner** — dedicated CVE-2025-55182 detection (CVSS 10.0)

Every finding is anchored to the **exact URL on your target**. Nothing outside your defined scope is ever touched.

---

## Feature Overview

| Module | Capability |
|--------|-----------|
| 🌐 **Intelligent Crawler** | Async recursive crawl with depth control, subdomain scope, inline script extraction. CDNs and third-party JS are automatically blocked. |
| 🔒 **ScopeGuard Engine** | Port-aware, hostname-exact scope enforcement. Every URL — pages, JS files, links, probes, endpoint findings — validated before any network contact. |
| 🧩 **JS Intelligence Engine** | REST, GraphQL, WebSocket endpoint extraction from minified and obfuscated JS. Library detection, version fingerprinting, source map exposure. |
| 🔑 **Secrets Discovery** | 30+ regex signatures (AWS, Stripe, GitHub, Firebase, JWT, Discord, Azure...) + Shannon entropy analysis for unlabelled credentials. |
| 🧪 **Endpoint Tester** | Non-destructive HTTP probing for CORS misconfigs, open admin panels, server disclosure, auth anomalies, missing security headers. |
| 🧠 **CVE Intelligence Engine** | Built-in heuristic map of 20+ vulnerability classes + live NIST NVD API correlation with CVSS scores and exploitation guidance. |
| ⚡ **React2Shell Scanner** | Dedicated CVE-2025-55182 scanner. Zero-false-positive weighted evidence model. Auto-generates step-by-step PoC on confirmed findings. |
| 📂 **Git Intelligence** | Scans local git repositories across full commit history for historical secrets and exposed credentials. |
| 📊 **Multi-Format Reports** | Colourised terminal output, structured JSON, styled HTML, plain-text. Every CVE finding includes manual PoC verification steps. |

---

## React2Shell — CVE-2025-55182

<div align="center">

```
┌─────────────────────────────────────────────────────────────┐
│  CVE-2025-55182  ·  React2Shell  ·  CVSS 10.0 (Maximum)    │
│  Pre-Authentication Remote Code Execution                    │
│  React Server Components Flight Protocol                    │
│  CISA KEV Listed  ·  Actively Exploited in the Wild        │
└─────────────────────────────────────────────────────────────┘
```

</div>

**What it is:** A critical deserialization vulnerability (CWE-502) in the React Server Components (RSC) Flight protocol. Affects the packages `react-server-dom-webpack`, `react-server-dom-parcel`, and `react-server-dom-turbopack` in versions `19.0.0`, `19.1.0`, `19.1.1`, and `19.2.0`. Default configurations are vulnerable with near-100% exploit reliability.

**Affected frameworks:** Next.js, react-router (RSC preview), waku, @parcel/rsc, @vitejs/plugin-rsc, rwsdk

**Patched versions:** `react-server-dom-* 19.0.1 / 19.1.2 / 19.2.1+`, Next.js `≥ 15.5.7 / 16.0.7`

**How JSPECTER detects it:**

JSPECTER uses a **weighted evidence model** — no single signal can trigger a finding. A target is only flagged `VULNERABLE` when all three conditions are met:

1. RSC runtime code is confirmed inside a JS bundle (`createFromReadableStream`, `ReactFlightClientConfigBundlerWebpack`, etc.)
2. RSC Flight payload is active in the HTML (`self.__next_f.push(`)
3. Package version is extracted and confirmed in the affected range

A patched version (`19.2.1`) immediately clears the vulnerable flag even if RSC is detected.

```bash
jspecter -u https://target.com --react2shell
```

---

## Installation

### Requirements
- Python 3.9 or later
- pip

### Quick Install

```bash
# Clone
git clone https://github.com/abhi04anon/jspecter.git
cd jspecter

# Upgrade pip first (prevents setuptools errors)
pip install --upgrade pip setuptools wheel

# Install
pip install .

# Verify
jspecter --version
```

### Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

pip install --upgrade pip setuptools wheel
pip install .
jspecter --version
```

### With Git Scanning Support

```bash
pip install ".[git]"
```

### Kali / Debian / Ubuntu (system Python)

```bash
pip install . --break-system-packages
```

### Windows

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install .

# If jspecter command not found:
python -m jspecter.cli -u https://target.com
```

---

## CLI Reference

```
jspecter -u <URL> [options]

TARGET
  -u, --url URL             Target URL  (e.g. https://target.com)

CRAWL OPTIONS
  --depth N                 Crawl depth  (default: 3)
  --subs                    Include all subdomains in scope
  --threads N               Concurrent async workers  (default: 10)
  --timeout N               Per-request timeout in seconds  (default: 15)
  --rate-limit SECONDS      Delay between requests  (default: 0)

REQUEST OPTIONS
  --headers JSON            Custom HTTP headers as JSON string
  --token TOKEN             Auth token → sent as Authorization: Bearer <token>
  --proxy URL               HTTP/HTTPS proxy  (e.g. http://127.0.0.1:8080)

SCAN OPTIONS
  --react2shell             Run CVE-2025-55182 React2Shell detection scan
  --cve-scan                Enable live NVD CVE correlation
  --no-test                 Skip endpoint probing phase
  --git REPO_PATH           Scan a local git repository for secrets
  --resume                  Resume an interrupted scan

OUTPUT OPTIONS
  -o, --output FILE         Write report to file
  --format FORMAT           json | html | txt  (default: json)
  --verbose                 Debug output + scope block logs
  --version                 Show version and exit
```

---

## Usage Examples

### Basic Recon

```bash
# Quick scan — all 7 phases, CLI output only
jspecter -u https://target.com
```

### React2Shell — CVE-2025-55182 Detection

```bash
# Dedicated React2Shell scan
jspecter -u https://target.com --react2shell

# React2Shell + save JSON report
jspecter -u https://target.com --react2shell --format json -o r2s.json

# React2Shell + verbose (see every indicator checked)
jspecter -u https://target.com --react2shell --verbose

# React2Shell on authenticated app
jspecter -u https://app.target.com --react2shell --token "eyJhbGci..."

# React2Shell + full pipeline together
jspecter -u https://target.com --react2shell --cve-scan --depth 3 --format html -o report.html
```

### Full Pipeline with CVE Correlation

```bash
# Full scan with live NVD CVE lookup + HTML report
jspecter -u https://target.com --depth 5 --cve-scan --format html -o report.html

# Full scan with all phases + verbose debug
jspecter -u https://target.com --depth 4 --cve-scan --verbose --format json -o full.json
```

### Authenticated Scans

```bash
# JWT token auth
jspecter -u https://app.target.com \
    --token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
    --depth 4 --cve-scan

# Session cookie + custom headers
jspecter -u https://app.target.com \
    --headers '{"Cookie": "session=abc123; csrf=xyz789"}' \
    --depth 3

# Multiple custom headers
jspecter -u https://app.target.com \
    --token "YOUR_JWT" \
    --headers '{"Cookie": "session=abc", "X-API-Key": "key123"}' \
    --cve-scan --format html -o authenticated_report.html
```

### Scope Control

```bash
# Include all subdomains (api.target.com, auth.target.com, etc.)
jspecter -u https://target.com --subs --depth 3

# Subdomain scope + CVE scan
jspecter -u https://target.com --subs --cve-scan --format json -o subdomains.json

# Debug what is being blocked out of scope
jspecter -u https://target.com --verbose 2>&1 | grep OOS
```

### Through Burp Suite

```bash
# Intercept all traffic in Burp
jspecter -u https://target.com --proxy http://127.0.0.1:8080

# Burp + full scan
jspecter -u https://target.com \
    --proxy http://127.0.0.1:8080 \
    --cve-scan --depth 4 --format html -o burp_assisted.html
```

### Rate Limiting & Stealth

```bash
# Slow scan — 1 second between requests, 3 threads
jspecter -u https://target.com --rate-limit 1.0 --threads 3

# Very polite scan
jspecter -u https://target.com --rate-limit 2.0 --threads 1 --depth 2
```

### Analysis Only (No Probing)

```bash
# Skip endpoint testing — just extract and analyse
jspecter -u https://target.com --no-test --format json -o analysis.json

# No-test + deep crawl
jspecter -u https://target.com --no-test --depth 6 --format html -o deep.html
```

### Git Repository Scan

```bash
# Scan a cloned repo for historical secrets
jspecter --git /path/to/cloned/repo

# With git support installed
pip install ".[git]"
jspecter --git /home/user/target-repo
```

### Output Formats

```bash
# JSON — structured, machine-readable
jspecter -u https://target.com --format json -o report.json

# HTML — styled, shareable with program triage
jspecter -u https://target.com --format html -o report.html

# Plain text — clean, paste-friendly
jspecter -u https://target.com --format txt -o report.txt

# No file — terminal only
jspecter -u https://target.com
```

### High-Concurrency Large Apps

```bash
# 30 threads, 20s timeout, include subs
jspecter -u https://target.com \
    --threads 30 \
    --timeout 20 \
    --subs \
    --depth 5 \
    --cve-scan \
    --format html -o large_app.html
```

---

## Sample Output

### Terminal Summary

```
  __| |______________________________________________________| |__
__   ______________________________________________________   __
  | |                                                      | |
  | |        _ ____  ____  _____ ____ _____ _____ ____     | |
  | |       | / ___||  _ \| ____/ ___|_   _| ____|  _ \    | |
  | |    _  | \___ \| |_) |  _|| |     | | |  _| | |_) |   | |
  | |   | |_| |___) |  __/| |__| |___  | | | |___|  _ <    | |
  | |    \___/|____/|_|   |_____\____| |_| |_____|_| \_\   | |
  | |                                                      | |
__| |______________________________________________________| |__

            [ JSPECTER — Autonomous JS Recon & Vulnerability Intelligence Engine ]
              "Hunting what JavaScript tries to hide."

              Author  : abhi04anon
              Version : 1.0.0

══════════════════════════════════════════════════════════════
  JSPECTER SCAN RESULTS  —  https://target.com
══════════════════════════════════════════════════════════════
  Overall Risk: CRITICAL

  [S] SECRETS (3)
    →  [CRITICAL] AWS Access Key ID: AKIAI***EXAMPLE
         Source: https://target.com/static/js/main.chunk.js
    →  [HIGH] JSON Web Token: eyJhbGci***redacted
         Source: <inline:2>
    →  [HIGH] Stripe Secret Key: sk_live_***redacted
         Source: https://target.com/js/checkout.js

  [C] CVE CORRELATIONS (5)

    [!] CRITICAL CVE-2025-55182: React2Shell — Next.js RSC Application Detected
        Target: https://target.com/_next/static/chunks/webpack.js
        PoC Steps:
          Step 1 — Confirm endpoint reachable
            curl -s -o /dev/null -w '%{http_code}' 'https://target.com/'
          Step 2 — Confirm RSC Flight payload active
            curl -s https://target.com/ | grep -c '__next_f'

    [!] CRITICAL CVE-2017-5638: Unrestricted File Upload
        Target: https://target.com/api/upload
        Parameter: file

    [!] HIGH CVE-2021-27358: GraphQL Introspection Exposure
        Target: https://target.com/graphql

  [E] INTERESTING ENDPOINTS (12)
    → /graphql [GraphQL]
    → /admin/users [REST]
    → /api/v1/export?id= [REST]
    → /api/download?file= [REST]

  [*] LIBRARIES DETECTED:
    • react-server-dom-webpack v19.1.0  ← VULNERABLE (CVE-2025-55182)
    • lodash v4.17.4
    • jquery v2.1.4

──────────────────────────────────────────────────────────────
  JS Files: 18 | Endpoints: 47 | Secrets: 3 | CVEs: 5
──────────────────────────────────────────────────────────────
  Scan completed in 28.4s
```

### React2Shell Detection Output

```
  [C] React2Shell Scanner — CVE-2025-55182
      CVSS 10.0 | Pre-auth RCE | react-server-dom-* 19.0–19.2.0
      Target: https://target.com

  ──────────────────────────────────────────────────────────────
  ⚠  VULNERABLE — CVE-2025-55182 CONFIRMED
  ──────────────────────────────────────────────────────────────

  React-server-dom : 19.1.0
  Next.js version  : 15.2.3
  RSC runtime      : YES
  Evidence weight  : 8  (threshold = 7)
  Confidence       : HIGH

  Evidence (4 signals)

    [CONFIRMED  ] RSC runtime API in bundle
          Detail : createFromReadableStream(
          Source : https://target.com/_next/static/chunks/webpack.js

    [STRONG     ] RSC Flight payload (self.__next_f)
          Detail : self.__next_f.push([
          Source : https://target.com/

    [STRONG     ] react-server-dom-* package reference
          Detail : "react-server-dom-webpack"
          Source : https://target.com/_next/static/chunks/webpack.js

    [SUPPORTING ] __NEXT_DATA__ script tag
          Detail : __NEXT_DATA__
          Source : https://target.com/

  PoC Verification Steps — CVE-2025-55182
  ────────────────────────────────────────
  Target: https://target.com

  Step 1 — Confirm endpoint is reachable
    curl -s -o /dev/null -w '%{http_code}' 'https://target.com/'
    Expected: 200 OK

  Step 2 — Confirm RSC Flight payload is active
    curl -s https://target.com/ | grep -c '__next_f'
    Expected: a number > 0

  Step 3 — Verify react-server-dom-* package version
    curl -s https://target.com/package.json | grep react-server-dom
    Expected: version in 19.0.0 / 19.1.0 / 19.1.1 / 19.2.0

  Step 4 — Locate a Server Action endpoint
    curl -s https://target.com/ | grep -oE '\$ACTION[_A-Z0-9:]+'

  Step 5 — Confirm RSC endpoint accepts POST
    curl -s -X POST \
      -H 'Content-Type: text/plain;charset=UTF-8' \
      -H 'Next-Action: <action-id-from-step-4>' \
      -d '' \
      https://target.com/
    Expected: HTTP 200

  Recommendation:
    PATCH IMMEDIATELY — Pre-auth RCE (CVSS 10.0) — CISA KEV
    npm install react-server-dom-webpack@19.2.1
    npm install next@latest  (>= 15.5.7 or >= 16.0.7)
```

---

## Architecture

```
JSPECTER/
├── jspecter/
│   ├── __init__.py              Package metadata
│   ├── cli.py                   Argument parser + 7-phase pipeline orchestrator
│   ├── config.py                All constants, CVE maps, library vuln DB, ScanConfig
│   ├── utils.py                 ScopeGuard, ANSI colours, logging, Shannon entropy
│   ├── crawler.py               Async recursive crawler — ScopeGuard at every step
│   ├── js_analyzer.py           Endpoint extraction, library detection, source maps
│   ├── secrets_engine.py        30+ regex signatures + entropy-based secret discovery
│   ├── cve_engine.py            CVE heuristics + live NVD API + PoC step generator
│   ├── react2shell.py           CVE-2025-55182 zero-FP weighted evidence scanner
│   ├── tester.py                Non-destructive HTTP prober (scope-gated)
│   ├── git_module.py            Git commit history scanner (optional)
│   └── reporter.py              JSON / HTML / TXT / CLI report generation
│
├── tests/
│   ├── test_scope.py            20 ScopeGuard tests
│   └── test_react2shell.py      11 zero-FP model tests
│
├── .github/
│   ├── workflows/ci.yml         CI — Python 3.9–3.12 × Linux/Mac/Win
│   ├── workflows/codeql.yml     Weekly CodeQL security scan
│   ├── ISSUE_TEMPLATE/          Bug report + CVE request templates
│   └── PULL_REQUEST_TEMPLATE.md FP testing checklist
│
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── pyproject.toml
├── setup.py
├── requirements.txt
└── LICENSE
```

### Seven-Phase Pipeline

```
jspecter -u https://target.com
         │
         ▼
Phase 1 ─── Web Crawler
         Async recursive crawl · ScopeGuard at every URL decision
         CDNs, analytics, off-domain links → blocked and logged
         │
         ▼
Phase 2 ─── JS Intelligence Engine
         Endpoint extraction (REST / GraphQL / WebSocket)
         Library + version detection · Source map exposure
         External URLs → filtered from findings
         │
         ▼
Phase 3 ─── Secret Discovery Engine
         30+ regex signatures · Shannon entropy analysis
         AWS / Stripe / GitHub / Firebase / JWT / Discord / Azure...
         │
         ▼
Phase 4 ─── CVE Intelligence Engine
         Local heuristic map (20+ vulnerability classes)
         Live NIST NVD API (with --cve-scan)
         PoC verification steps for every finding
         │
         ▼
Phase 5 ─── Endpoint Intelligence Tester
         Non-destructive HTTP probing
         CORS · Auth · Headers · Redirects
         Only contacts in-scope URLs
         │
         ▼
Phase 6a ── React2Shell Scanner (with --react2shell)
         CVE-2025-55182 · CVSS 10.0
         Weighted evidence model · Zero false positives
         Auto-generates PoC on confirmed findings
         │
Phase 6b ── Git Intelligence (with --git)
         Full commit history scan · .env file scan
         │
         ▼
Phase 7 ─── Report Generation
         JSON · HTML · TXT · CLI
         Risk-classified · Target-anchored findings
```

---

## Scope Enforcement

JSPECTER never touches anything outside your defined scope.

```
Every URL passes through ScopeGuard before any network contact:

  Crawler._crawl_page()     →  in_scope()           (page visits)
  Crawler._fetch()          →  in_scope() on redirect (post-redirect check)
  Crawler._extract_js_urls()→  in_scope_js()        (JS file fetching)
  Crawler._extract_links()  →  in_scope()           (link following)
  JSAnalyzer._add_endpoint()→  in_scope_endpoint()  (findings)
  EndpointTester.probe_all()→  in_scope_probe()     (probing)

In scope  →  proceed
OOS       →  discard + log (--verbose shows each block)
```

**Scope modes:**

```bash
# Default: exact hostname only
jspecter -u https://target.com

# Include all subdomains
jspecter -u https://target.com --subs

# See what was blocked
jspecter -u https://target.com --verbose 2>&1 | grep OOS
```

---

## Secret Detection Coverage

| Secret | Severity |
|--------|----------|
| AWS Access Key ID + Secret | CRITICAL |
| Google API Key / OAuth | HIGH |
| Firebase Config + Database URL | HIGH |
| Stripe Secret / Publishable Key | CRITICAL / MEDIUM |
| GitHub PAT / OAuth Token | CRITICAL |
| GitLab Personal Token | HIGH |
| Slack Token / Webhook URL | HIGH / MEDIUM |
| Twilio SID / Auth Token | HIGH / CRITICAL |
| SendGrid API Key | HIGH |
| Mailchimp API Key | HIGH |
| Discord Bot Token | HIGH |
| Telegram Bot Token | HIGH |
| JWT Tokens | HIGH |
| HTTP Bearer / Basic Auth | HIGH |
| Azure Storage Connection String | CRITICAL |
| PEM Private Key Block | CRITICAL |
| Shopify Admin Token | HIGH |
| NPM Auth Token | HIGH |
| Mapbox Token | MEDIUM |
| Heroku API Key | HIGH |
| DigitalOcean Token | HIGH |
| Braintree / Square / PayPal | CRITICAL |
| High-Entropy Strings | MEDIUM |
| Generic Secret Variables | MEDIUM |

---

## CVE Coverage

### React2Shell — CVE-2025-55182 (Dedicated Scanner)

```bash
jspecter -u https://target.com --react2shell
```

| Detail | Value |
|--------|-------|
| CVE ID | CVE-2025-55182 |
| CVSS | 10.0 (Maximum) |
| Type | Pre-auth RCE |
| CWE | CWE-502 Deserialization |
| Status | CISA KEV — Actively Exploited |
| Affected | react-server-dom-* 19.0.0 / 19.1.0 / 19.1.1 / 19.2.0 |
| Patched | 19.0.1 / 19.1.2 / 19.2.1+ |
| Frameworks | Next.js, react-router, waku, @parcel/rsc |

### Built-in Endpoint Heuristics

| Endpoint | Vulnerability Class |
|----------|---------------------|
| `/graphql` | Introspection exposure, batch attack |
| `/admin` | Unauthenticated admin access |
| `/swagger`, `/api-docs` | API schema exposure |
| `/actuator` | Spring Boot / Spring4Shell (CVE-2022-22965) |
| `/jolokia` | JMX RCE via HTTP |
| `/.env` | Environment file exposure |
| `/.git` | Source code extraction |
| `/upload` | Unrestricted file upload |
| `/download` | Path traversal |
| `/shell`, `/system-information` | react2shell npm RCE (CVE-2021-21315) |
| `/oauth` | Open redirect / token theft |
| `/webhook` | SSRF via URL registration |
| `/debug`, `/metrics` | Information disclosure |
| `/wp-admin`, `/xmlrpc` | WordPress attacks |

### Vulnerable Library Detection

| Library | CVE | Severity |
|---------|-----|----------|
| react-server-dom-* 19.0–19.2.0 | CVE-2025-55182 | CRITICAL |
| systeminformation ≤ 5.3.1 | CVE-2021-21315 | CRITICAL |
| lodash < 4.17.21 | CVE-2021-23337 | HIGH |
| next.js < 14.1.1 | CVE-2024-34351 | HIGH |
| express | CVE-2022-24999 | HIGH |
| ejs < 3.1.7 | CVE-2022-29078 | CRITICAL |
| pug < 3.0.1 | CVE-2021-21353 | CRITICAL |
| handlebars < 4.7.7 | CVE-2021-23369 | CRITICAL |
| socket.io < 4.5.3 | CVE-2022-2421 | CRITICAL |
| minimist < 1.2.6 | CVE-2021-44906 | CRITICAL |
| nuxt < 3.6.1 | CVE-2023-3224 | CRITICAL |
| moment.js < 2.29.2 | CVE-2022-24785 | HIGH |
| axios < 1.6.0 | CVE-2023-45857 | MEDIUM |
| jquery < 3.4.0 | CVE-2019-11358 | MEDIUM |
| webpack (source maps) | CVE-2023-28154 | CRITICAL |

---

## Programmatic Usage

```python
import asyncio
from jspecter.config import ScanConfig
from jspecter.crawler import Crawler
from jspecter.js_analyzer import JSAnalyzer
from jspecter.secrets_engine import SecretsEngine
from jspecter.cve_engine import CVEEngine
from jspecter.react2shell import React2ShellScanner

async def run(url: str):
    config = ScanConfig(url=url, depth=2, threads=10, cve_scan=False)

    # Phase 1: Crawl (scope-enforced)
    crawler = Crawler(config)
    crawl = await crawler.run()

    # Phase 2: Analyse JS
    analyzer = JSAnalyzer(target_url=url)
    analysis = analyzer.analyze_all(crawl.js_contents, crawl.inline_scripts)

    # Phase 3: Secrets
    engine = SecretsEngine()
    secrets = engine.scan_all(crawl.js_contents, crawl.inline_scripts)

    # Phase 4: CVE correlation
    cve_engine = CVEEngine(config)
    cves = await cve_engine.correlate(analysis.endpoints, analysis.libraries)

    # React2Shell scan
    r2s = React2ShellScanner(target_url=url, timeout=15)
    r2s_result = await r2s.scan()

    print(f"Secrets : {len(secrets)}")
    print(f"CVEs    : {len(cves)}")
    print(f"React2Shell vulnerable: {r2s_result.vulnerable}")
    if r2s_result.poc_steps:
        print(r2s_result.poc_steps)

asyncio.run(run("https://target.com"))
```

---

## Bug Bounty Workflow

```bash
# 1. Quick recon — no noise, analysis only
jspecter -u https://target.com --no-test --depth 2

# 2. Check for React2Shell (CVE-2025-55182)
jspecter -u https://target.com --react2shell

# 3. Full authenticated scan with CVE lookup
jspecter -u https://target.com \
    --token "YOUR_JWT" \
    --depth 5 --cve-scan \
    --format html -o report.html

# 4. Subdomain sweep
jspecter -u https://target.com --subs --depth 3 --cve-scan

# 5. Through Burp for manual review
jspecter -u https://target.com \
    --proxy http://127.0.0.1:8080 \
    --cve-scan --format html -o burp.html
```

---

## Running Tests

```bash
pip install ".[dev]"
pytest tests/ -v
```

```
tests/test_scope.py::TestBasicScope::test_same_domain          PASSED
tests/test_scope.py::TestBasicScope::test_cdn_blocked          PASSED
tests/test_scope.py::TestBasicScope::test_suffix_attack_blocked PASSED
tests/test_scope.py::TestPortAwareness::test_wrong_port_blocked PASSED
tests/test_react2shell.py::TestZeroFP::test_plain_nextjs_pages_router_not_flagged  PASSED
tests/test_react2shell.py::TestZeroFP::test_patched_version_blocks_vulnerable       PASSED
tests/test_react2shell.py::TestZeroFP::test_vulnerable_version_with_rsc_flagged    PASSED
tests/test_react2shell.py::TestPoCSteps::test_poc_generated_only_when_vulnerable   PASSED

31 passed in 0.40s
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding CVE rules, secret signatures, and React2Shell detection signals.

**False positive policy:** Every detection rule must be tested against at least 3 non-vulnerable targets before a PR is accepted.

---

## Legal Disclaimer

> **JSPECTER is strictly for authorized security research, bug bounty programs, and ethical penetration testing.**
>
> Only use against targets you have **explicit written permission** to test. Unauthorized scanning may violate the Computer Fraud and Abuse Act (USA), Computer Misuse Act (UK), and equivalent laws in your jurisdiction.
>
> The author assumes no liability for misuse. Always follow responsible disclosure practices.

---

## References

- [CVE-2025-55182 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [React Security Blog — CVE-2025-55182](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CVE-2021-21315 — systeminformation npm](https://nvd.nist.gov/vuln/detail/CVE-2021-21315)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

<div align="center">

**Made with ❤️ by [abhi04anon](https://github.com/abhi04anon)**

*For authorized security research only*

</div>
