# Changelog

All notable changes to JSPECTER are documented here.

## [1.0.0] — Initial Release

### Added
- Seven-phase autonomous pipeline: Crawl → JS Analysis → Secret Discovery → CVE Correlation → Endpoint Testing → Git Scan → Reporting
- **ScopeGuard** — centralised scope enforcement at every URL decision point
  - Exact hostname + port matching
  - Subdomain mode (`--subs`)
  - Post-redirect scope checking
  - Third-party JS/CDN blocking
- **React2Shell Scanner** (`--react2shell`) — dedicated CVE-2025-55182 detection
  - Zero-false-positive weighted evidence model (weight threshold = 7)
  - Four independent signal categories: RSC runtime, HTML Flight payload, HTTP headers, version
  - Patched version auto-clears vulnerable flag
  - Step-by-step PoC verification guide on confirmed findings
- **CVE-2025-55182** added to:
  - `ENDPOINT_CVE_MAP` — `/_next`, `/__next`, `/api/action` patterns
  - `JS_LIBRARY_VULNS` — `react-server-dom-webpack/turbopack/parcel`, `react-server`, `react-router-rsc`
  - `JS library detector` — `createServerReference`, `registerServerReference`, RSC package imports
- **CVE-2021-21315** (systeminformation / react2shell npm) — full coverage
- **NVD Full Database** integration with pagination, caching, direct CVE ID lookup
- **PoC step generator** — every CVE finding includes manual verification steps anchored to the actual target URL
- **30+ secret signatures** with entropy-based fallback detection
- JSON, HTML, and TXT report generation

### False Positive Hardening
- Removed `"use server"` as RSC signal (too common in docs/comments)
- Removed `server-timing` header as RSC signal (used by all CDNs)
- Removed `action=` HTML attribute match (matches every form)
- Tightened Generic Secret Variable pattern: minimum 24 chars, excludes placeholders
- Heroku UUID pattern now requires keyword context
- Narrowed SQLi params: removed `sort`, `limit`, `offset`, `page`
- Narrowed SSTI params: removed `page`, `render`
- Narrowed command injection params: removed `host`, `query`
- Narrowed XXE params: removed `body`, `content`, `input`
