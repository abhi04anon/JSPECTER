"""
JSPECTER Configuration Module
Centralized settings and constants for the entire framework.\n"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ─── Default Settings ────────────────────────────────────────────────────────

DEFAULT_DEPTH: int = 3
DEFAULT_THREADS: int = 10
DEFAULT_TIMEOUT: int = 15
DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
DEFAULT_OUTPUT_FORMAT: str = "json"
MAX_RETRIES: int = 3
RETRY_DELAY: float = 1.0
MAX_JS_FILE_SIZE: int = 10 * 1024 * 1024  # 10 MB

# NVD API
NVD_API_BASE: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY: float = 0.6        # seconds between NVD API calls
NVD_PAGE_SIZE: int = 20                   # results per NVD page request
NVD_MAX_PAGES: int = 5                    # cap to avoid runaway API usage
NVD_CACHE_TTL: int = 3600                 # seconds to cache NVD results


# ─── HTTP Headers ─────────────────────────────────────────────────────────────

DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


# ─── Endpoint Intelligence Patterns ───────────────────────────────────────────

INTERESTING_ENDPOINTS: List[str] = [
    "/admin", "/api", "/graphql", "/swagger", "/swagger-ui",
    "/api-docs", "/openapi", "/.env", "/config", "/debug",
    "/metrics", "/health", "/status", "/v1", "/v2", "/v3",
    "/internal", "/private", "/secret", "/backup", "/test",
    "/console", "/dashboard", "/login", "/auth", "/oauth",
    "/token", "/reset", "/upload", "/download", "/export",
    "/actuator", "/jolokia", "/heapdump", "/trace", "/env",
    "/shell", "/exec", "/run", "/cmd", "/rpc", "/soap",
    "/xmlrpc", "/.git", "/.svn", "/wp-admin", "/phpmyadmin",
    "/server-status", "/server-info", "/elmah.axd",
    "/react", "/react-shell", "/system-information",
]

INTERESTING_PARAMS: List[str] = [
    "file", "path", "dir", "folder", "url", "redirect",
    "return", "next", "ref", "referrer", "target", "dest",
    "destination", "source", "src", "page", "id", "user",
    "username", "email", "token", "key", "secret", "password",
    "pass", "pwd", "cmd", "command", "exec", "execute", "query",
    "search", "q", "s", "input", "data", "payload", "callback",
    "host", "port", "server", "endpoint", "api", "action",
    "name", "info", "type", "format", "lang", "locale",
    "template", "view", "layout", "include", "require",
    "load", "fetch", "import", "module", "plugin",
    "from", "to", "subject", "body", "content", "message",
    "upload", "download", "export", "import", "backup",
    "debug", "verbose", "trace", "log", "level",
]


# ─── CVE Keyword Mapping ──────────────────────────────────────────────────────

CVE_KEYWORD_MAP: Dict[str, List[str]] = {
    "/graphql": ["graphql injection", "graphql introspection", "graphql denial"],
    "/admin": ["admin panel exposure", "unauthorized admin access"],
    "/api/v1": ["api authentication bypass", "api information disclosure"],
    "/swagger": ["swagger ui exposure", "api documentation exposure"],
    "/actuator": ["spring boot actuator exposure", "actuator information disclosure"],
    "/shell": ["react2shell", "systeminformation rce", "shell injection"],
    "/system-information": ["systeminformation rce", "CVE-2021-21315"],
    "file": ["path traversal", "local file inclusion", "directory traversal"],
    "redirect": ["open redirect", "url redirection"],
    "url": ["server-side request forgery", "open redirect"],
    "cmd": ["command injection", "remote code execution"],
    "query": ["sql injection", "nosql injection"],
    "callback": ["jsonp injection", "cross-site request forgery"],
    "token": ["jwt misconfiguration", "token exposure"],
    "upload": ["file upload vulnerability", "unrestricted file upload"],
    "download": ["path traversal", "insecure direct object reference"],
    "template": ["server-side template injection", "ssti"],
    "host": ["ssrf", "server-side request forgery"],
}


# ─── JS Library CVE Database ─────────────────────────────────────────────────
# Comprehensive library → CVE mapping with NVD-verified data

JS_LIBRARY_VULNS: Dict[str, Dict] = {

    # ── CVE-2025-55182 React Server Components (React2Shell) ─────────────────
    # CVSS 10.0 | Pre-auth RCE | Actively exploited | CISA KEV
    "react-server-dom-webpack": {
        "cve": "CVE-2025-55182",
        "severity": "CRITICAL",
        "description": (
            "react-server-dom-webpack is one of the affected packages in CVE-2025-55182 (React2Shell). "
            "Versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 allow pre-authentication RCE via "
            "insecure deserialization of React Server Components Flight protocol payloads. "
            "CISA KEV listed. Actively exploited by nation-state actors."
        ),
        "hint": (
            "Run: jspecter -u <TARGET> --react2shell for dedicated detection.\n"
            "Check response headers for x-nextjs-cache, x-nextjs-matched-path.\n"
            "Look for __NEXT_DATA__ or self.__next_f in HTML source.\n"
            "Patch: npm install react-server-dom-webpack@19.2.1 (or 19.0.1 / 19.1.2)."
        ),
        "nvd_keyword": "CVE-2025-55182 react server components",
        "affected_versions": "19.0.0, 19.1.0, 19.1.1, 19.2.0",
    },
    "react-server-dom-turbopack": {
        "cve": "CVE-2025-55182",
        "severity": "CRITICAL",
        "description": (
            "react-server-dom-turbopack affected by CVE-2025-55182 (React2Shell). "
            "Insecure deserialization in RSC Flight protocol enables pre-auth RCE. CVSS 10.0."
        ),
        "hint": (
            "Run: jspecter -u <TARGET> --react2shell\n"
            "Patch: npm install react-server-dom-turbopack@19.2.1"
        ),
        "nvd_keyword": "CVE-2025-55182",
        "affected_versions": "19.0.0, 19.1.0, 19.1.1, 19.2.0",
    },
    "react-server-dom-parcel": {
        "cve": "CVE-2025-55182",
        "severity": "CRITICAL",
        "description": (
            "react-server-dom-parcel affected by CVE-2025-55182 (React2Shell). "
            "Pre-auth RCE via malformed RSC Flight multipart POST. CVSS 10.0. CISA KEV."
        ),
        "hint": (
            "Run: jspecter -u <TARGET> --react2shell\n"
            "Patch: npm install react-server-dom-parcel@19.2.1"
        ),
        "nvd_keyword": "CVE-2025-55182",
        "affected_versions": "19.0.0, 19.1.0, 19.1.1, 19.2.0",
    },
    "react-server": {
        "cve": "CVE-2025-55182",
        "severity": "CRITICAL",
        "description": (
            "React Server runtime package detected — a core component of CVE-2025-55182. "
            "createServerReference/registerServerReference APIs are present, indicating "
            "RSC Server Functions are enabled. Default configurations are vulnerable."
        ),
        "hint": (
            "RSC Server Functions confirmed in JS bundle.\n"
            "Run: jspecter -u <TARGET> --react2shell for full assessment.\n"
            "Patch: Upgrade all react-server-dom-* packages to 19.0.1 / 19.1.2 / 19.2.1."
        ),
        "nvd_keyword": "CVE-2025-55182 react server",
        "affected_versions": "19.0.0, 19.1.0, 19.1.1, 19.2.0",
    },
    "react-router-rsc": {
        "cve": "CVE-2025-55182",
        "severity": "CRITICAL",
        "description": (
            "react-router RSC preview APIs detected. React Router's unstable RSC implementation "
            "uses the same vulnerable react-server-dom-* packages affected by CVE-2025-55182."
        ),
        "hint": (
            "React Router RSC detected. Verify react-server-dom-* dependency versions.\n"
            "Run: jspecter -u <TARGET> --react2shell\n"
            "Upgrade react-router to latest and pin react-server-dom-* to patched version."
        ),
        "nvd_keyword": "CVE-2025-55182 react-router",
        "affected_versions": "RSC preview builds",
    },
    # ── React ecosystem ───────────────────────────────────────────────────────
    "react": {
        "cve": "CVE-2018-6341",
        "severity": "HIGH",
        "description": "React DOM XSS via dangerouslySetInnerHTML in server-side rendering with user-controlled data.",
        "hint": "Search JS for dangerouslySetInnerHTML. Confirm no user input flows into it without sanitization.",
        "nvd_keyword": "react xss",
        "affected_versions": "< 16.0.0",
    },
    "react-dom": {
        "cve": "CVE-2018-6341",
        "severity": "HIGH",
        "description": "ReactDOM server-side rendering XSS via user-controlled attribute values.",
        "hint": "Check SSR render paths. Test attribute injection: pass ><script>alert(1)</script> in rendered props.",
        "nvd_keyword": "react-dom xss server rendering",
        "affected_versions": "< 16.0.0",
    },

    # ── react2shell / systeminformation (react-shell) ─────────────────────────
    # CVE-2021-21315: systeminformation npm package RCE
    # react2shell is a React-based UI that wraps systeminformation and exposes
    # shell command execution via its /api endpoint — a critical pre-auth RCE
    # commonly found on Node.js admin dashboards and internal monitoring panels.
    "react-shell": {
        "cve": "CVE-2021-21315",
        "severity": "CRITICAL",
        "description": (
            "react2shell uses systeminformation (npm) <= 5.3.1 which is vulnerable to "
            "CVE-2021-21315. Prototype pollution via crafted input to system info functions "
            "leads to remote command execution. An attacker can pass shell metacharacters "
            "through the 'name' or similar parameters to achieve unauthenticated RCE."
        ),
        "hint": (
            "Look for /api/system, /api/shell, /system-information endpoints. "
            "PoC: GET /api/cpu?name=$(id) or POST with {\"name\":\"$(whoami)\"}. "
            "Also test: {\"name\":\"test;id\"} and {\"name\":\"test`id`\"}. "
            "Check package.json or package-lock.json for systeminformation <= 5.3.1."
        ),
        "nvd_keyword": "systeminformation CVE-2021-21315",
        "affected_versions": "<= 5.3.1",
    },
    "systeminformation": {
        "cve": "CVE-2021-21315",
        "severity": "CRITICAL",
        "description": (
            "systeminformation npm package <= 5.3.1 has a command injection vulnerability. "
            "User-supplied input passed to system information functions is not properly sanitized, "
            "allowing shell metacharacter injection leading to arbitrary OS command execution."
        ),
        "hint": (
            "Test all endpoints accepting 'name', 'iface', 'drive', 'mount' parameters. "
            "PoC payloads: name=$(id), name=`id`, name=test;id;#, name=test||id. "
            "Check Node.js version and package-lock.json for systeminformation entry. "
            "Unauthenticated endpoints are critical — report immediately."
        ),
        "nvd_keyword": "systeminformation npm command injection",
        "affected_versions": "<= 5.3.1",
    },

    # ── jQuery ────────────────────────────────────────────────────────────────
    "jquery": {
        "cve": "CVE-2019-11358",
        "severity": "MEDIUM",
        "description": "jQuery < 3.4.0 prototype pollution via jQuery.extend(true, {}, ...) with a crafted object.",
        "hint": "Confirm version via jQuery.fn.jquery in console. Test: $.extend(true,{},(JSON.parse('{\"__proto__\":{\"polluted\":1}}'))).",
        "nvd_keyword": "jquery prototype pollution",
        "affected_versions": "< 3.4.0",
    },

    # ── Angular / AngularJS ───────────────────────────────────────────────────
    "angular": {
        "cve": "CVE-2023-26118",
        "severity": "MEDIUM",
        "description": "AngularJS XSS bypass via usemap attribute allows bypassing AngularJS sanitizer.",
        "hint": "Inject: <img usemap='\" ng-app>'. Verify if AngularJS processes the attribute unsanitized.",
        "nvd_keyword": "angularjs xss bypass",
        "affected_versions": "< 1.8.3",
    },
    "angularjs": {
        "cve": "CVE-2022-25844",
        "severity": "HIGH",
        "description": "AngularJS ReDoS via currency filter with crafted input string.",
        "hint": "Send long crafted strings to currency-formatted fields. Check for timeout/CPU spike indicating ReDoS.",
        "nvd_keyword": "angularjs redos currency",
        "affected_versions": ">= 1.0.0, < 1.8.3",
    },

    # ── Vue.js ────────────────────────────────────────────────────────────────
    "vue": {
        "cve": "CVE-2023-39699",
        "severity": "MEDIUM",
        "description": "Vue.js XSS via v-html directive when user-controlled data is rendered without sanitization.",
        "hint": "Search JS/templates for v-html. Test: pass <img src=x onerror=alert(1)> through user-controlled fields bound to v-html.",
        "nvd_keyword": "vue.js xss v-html",
        "affected_versions": "< 3.3.4",
    },

    # ── Lodash ────────────────────────────────────────────────────────────────
    "lodash": {
        "cve": "CVE-2021-23337",
        "severity": "HIGH",
        "description": "Lodash template function command injection via __proto__ pollution and template evaluation.",
        "hint": "Test: _.template('<%=process.mainModule.require(\"child_process\").execSync(\"id\")%>')(). Requires template() call with user input.",
        "nvd_keyword": "lodash command injection template",
        "affected_versions": "< 4.17.21",
    },

    # ── Moment.js ────────────────────────────────────────────────────────────
    "moment": {
        "cve": "CVE-2022-24785",
        "severity": "HIGH",
        "description": "Moment.js path traversal via locale loading — attacker can load arbitrary locale files from filesystem.",
        "hint": "Test: moment.locale('../../../etc/passwd'). Check if server loads locale files from user input.",
        "nvd_keyword": "moment.js path traversal locale",
        "affected_versions": "< 2.29.2",
    },

    # ── Axios ────────────────────────────────────────────────────────────────
    "axios": {
        "cve": "CVE-2023-45857",
        "severity": "MEDIUM",
        "description": "Axios CSRF token leaked to third-party origins via cross-origin requests in certain configurations.",
        "hint": "Check if XSRF-TOKEN cookie is sent to cross-origin requests. Confirm axios baseURL and withCredentials settings.",
        "nvd_keyword": "axios csrf token exposure",
        "affected_versions": ">= 0.8.1, < 1.6.0",
    },

    # ── Socket.io ────────────────────────────────────────────────────────────
    "socket.io": {
        "cve": "CVE-2022-2421",
        "severity": "CRITICAL",
        "description": "Socket.io prototype pollution via object deserialization — can lead to RCE in certain Node.js configurations.",
        "hint": "Send WebSocket message: {\"__proto__\":{\"polluted\":\"yes\"}}. Verify pollution with Object.prototype.polluted in console.",
        "nvd_keyword": "socket.io prototype pollution",
        "affected_versions": "< 4.5.3",
    },

    # ── Bootstrap ────────────────────────────────────────────────────────────
    "bootstrap": {
        "cve": "CVE-2019-8331",
        "severity": "MEDIUM",
        "description": "Bootstrap XSS via data-template attribute in tooltip/popover components.",
        "hint": "Inject: data-template='<div><a href=\"ja vascript:alert(1)\">'. Test tooltip/popover components for XSS.",
        "nvd_keyword": "bootstrap xss tooltip",
        "affected_versions": ">= 3.0.0, < 3.4.1 or >= 4.0.0, < 4.3.1",
    },

    # ── Webpack ───────────────────────────────────────────────────────────────
    "webpack": {
        "cve": "CVE-2023-28154",
        "severity": "CRITICAL",
        "description": "Webpack misconfiguration exposes source maps (.map files), revealing original source code, internal paths, and secrets.",
        "hint": "Fetch: <js-file-url>.map — if it returns JSON with 'sources' array, source code is exposed. Also check //# sourceMappingURL= comments.",
        "nvd_keyword": "webpack source map exposure",
        "affected_versions": "misconfigured devtool setting",
    },

    # ── Next.js ───────────────────────────────────────────────────────────────
    "next.js": {
        "cve": "CVE-2024-34351",
        "severity": "HIGH",
        "description": "Next.js SSRF via Host header manipulation in server actions.",
        "hint": "Send requests with Host: internal.corp:8080. Check if Next.js fetches attacker-controlled host in server actions.",
        "nvd_keyword": "next.js ssrf host header",
        "affected_versions": "< 14.1.1",
    },

    # ── Express ───────────────────────────────────────────────────────────────
    "express": {
        "cve": "CVE-2022-24999",
        "severity": "HIGH",
        "description": "Express.js qs prototype pollution via URL query string parsing.",
        "hint": "Test: GET /?__proto__[polluted]=1 or /?constructor[prototype][polluted]=1. Verify via Object.prototype.polluted.",
        "nvd_keyword": "express qs prototype pollution",
        "affected_versions": "< 4.17.3",
    },

    # ── Nuxt ─────────────────────────────────────────────────────────────────
    "nuxt": {
        "cve": "CVE-2023-3224",
        "severity": "CRITICAL",
        "description": "Nuxt.js path traversal via malformed URL allows reading arbitrary files from server.",
        "hint": "Test: GET /_nuxt/../../../etc/passwd or /__nuxt/../etc/passwd. Check Nuxt version in nuxt.config.js.",
        "nvd_keyword": "nuxt.js path traversal",
        "affected_versions": "< 3.6.1",
    },

    # ── Svelte ────────────────────────────────────────────────────────────────
    "svelte": {
        "cve": "CVE-2021-23346",
        "severity": "MEDIUM",
        "description": "Svelte XSS via {@html} tag with unsanitized user input.",
        "hint": "Search .svelte files for {@html}. Test user-controlled inputs bound to {@html} for XSS.",
        "nvd_keyword": "svelte xss html",
        "affected_versions": "< 3.29.5",
    },

    # ── Handlebars ────────────────────────────────────────────────────────────
    "handlebars": {
        "cve": "CVE-2021-23369",
        "severity": "CRITICAL",
        "description": "Handlebars.js prototype pollution and RCE via template compilation with user-controlled templates.",
        "hint": "Test: Handlebars.compile('{{#with (lookup (lookup this \"__proto__\") \"polluted\")}}{{/with}}')({'__proto__': {'polluted': 'yes'}}). If server renders user-supplied templates, escalate to RCE.",
        "nvd_keyword": "handlebars prototype pollution RCE",
        "affected_versions": "< 4.7.7",
    },

    # ── highlight.js ──────────────────────────────────────────────────────────
    "highlight.js": {
        "cve": "CVE-2021-23346",
        "severity": "MEDIUM",
        "description": "highlight.js ReDoS via crafted source strings causing catastrophic backtracking.",
        "hint": "Send very long strings to code highlighting endpoints. Check for timeout indicating ReDoS.",
        "nvd_keyword": "highlight.js redos",
        "affected_versions": "< 10.4.1",
    },

    # ── marked ────────────────────────────────────────────────────────────────
    "marked": {
        "cve": "CVE-2022-21681",
        "severity": "HIGH",
        "description": "marked.js ReDoS via crafted markdown input — leads to denial of service.",
        "hint": "POST extremely long markdown strings to any endpoint that renders markdown. Check response time for anomaly.",
        "nvd_keyword": "marked.js redos markdown",
        "affected_versions": "< 4.0.10",
    },

    # ── minimist ─────────────────────────────────────────────────────────────
    "minimist": {
        "cve": "CVE-2021-44906",
        "severity": "CRITICAL",
        "description": "minimist prototype pollution via '--__proto__' CLI arguments.",
        "hint": "Test query params: ?__proto__[admin]=true. Used in many Node.js CLI tools — check package-lock.json.",
        "nvd_keyword": "minimist prototype pollution",
        "affected_versions": "< 1.2.6",
    },

    # ── node-fetch ────────────────────────────────────────────────────────────
    "node-fetch": {
        "cve": "CVE-2022-0235",
        "severity": "HIGH",
        "description": "node-fetch exposure of sensitive headers to third-party redirect destinations.",
        "hint": "Test server-side fetch endpoints with redirect to attacker-controlled URL. Check if auth headers are forwarded.",
        "nvd_keyword": "node-fetch redirect headers",
        "affected_versions": "< 2.6.7 or < 3.1.1",
    },

    # ── ejs ───────────────────────────────────────────────────────────────────
    "ejs": {
        "cve": "CVE-2022-29078",
        "severity": "CRITICAL",
        "description": "EJS (Embedded JavaScript) template injection via __proto__ or settings object — leads to RCE.",
        "hint": "Test: pass opts.outputFunctionName=x;process.mainModule.require('child_process').exec('id')//. Check any EJS rendering endpoints.",
        "nvd_keyword": "ejs template injection RCE",
        "affected_versions": "< 3.1.7",
    },

    # ── pug (jade) ────────────────────────────────────────────────────────────
    "pug": {
        "cve": "CVE-2021-21353",
        "severity": "CRITICAL",
        "description": "Pug template engine code injection via user-supplied template strings.",
        "hint": "Test: #{process.mainModule.require('child_process').execSync('id')}. If server renders user-controlled Pug templates, full RCE is possible.",
        "nvd_keyword": "pug template injection",
        "affected_versions": "< 3.0.1",
    },
}


# ─── Scan State File ───────────────────────────────────────────────────────────

RESUME_STATE_FILE: str = ".jspecter_state.json"


# ─── Risk Thresholds ───────────────────────────────────────────────────────────

RISK_LEVELS: Dict[str, str] = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[96m",
    "INFO":     "\033[94m",
}


@dataclass
class ScanConfig:
    """Runtime scan configuration container."""
    url: str
    depth: int = DEFAULT_DEPTH
    include_subs: bool = False
    threads: int = DEFAULT_THREADS
    timeout: int = DEFAULT_TIMEOUT
    headers: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_HEADERS))
    output: Optional[str] = None
    output_format: str = DEFAULT_OUTPUT_FORMAT
    no_test: bool = False
    cve_scan: bool = False
    verbose: bool = False
    proxy: Optional[str] = None
    resume: bool = False
    rate_limit: float = 0.0
    git_scan: Optional[str] = None
    auth_token: Optional[str] = None

# ─── CVE-2025-55182 (React2Shell) ─────────────────────────────────────────────

REACT2SHELL_CVE = {
    "cve_id":          "CVE-2025-55182",
    "alias":           "React2Shell",
    "cvss":            10.0,
    "cvss_vector":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cwe":             "CWE-502: Deserialization of Untrusted Data",
    "severity":        "CRITICAL",
    "published":       "2025-12-03",
    "cisa_kev":        True,
    "exploited_wild":  True,
    "description": (
        "Pre-authentication remote code execution in React Server Components "
        "Flight protocol. Insecure deserialization of RSC payloads allows "
        "unauthenticated attackers to execute arbitrary server-side code via "
        "a single crafted HTTP POST request. Default Next.js configurations "
        "are vulnerable with near-100% exploit reliability."
    ),
    "affected_packages": [
        "react-server-dom-webpack",
        "react-server-dom-parcel",
        "react-server-dom-turbopack",
    ],
    "vulnerable_versions": ["19.0.0", "19.0", "19.1.0", "19.1.1", "19.2.0"],
    "patched_versions":    ["19.0.1", "19.1.2", "19.2.1", "19.2.2", "19.2.3"],
    "affected_frameworks": {
        "next":               "< 15.5.7 / < 16.0.7",
        "react-router":       "RSC preview builds",
        "waku":               "RSC-enabled versions",
        "@parcel/rsc":        "all",
        "@vitejs/plugin-rsc": "all",
        "rwsdk":              "all",
    },
    "remediation": (
        "Upgrade react-server-dom-* to 19.0.1, 19.1.2, or 19.2.1+. "
        "For Next.js: npm install next@latest (≥ 15.5.7 / 16.0.7+). "
        "Deploy WAF rules to block suspicious multipart RSC payloads as compensating control."
    ),
    "references": [
        "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-55182",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://www.microsoft.com/en-us/security/blog/2025/12/15/defending-against-the-cve-2025-55182-react2shell-vulnerability-in-react-server-components/",
        "https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182",
        "https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/",
    ],
}
