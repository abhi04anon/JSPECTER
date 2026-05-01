"""
JSPECTER JavaScript Intelligence Engine
Extracts REST/GraphQL/WebSocket endpoints from JS source code.
Supports minified and lightly obfuscated JavaScript.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from .config import INTERESTING_ENDPOINTS, INTERESTING_PARAMS
from .utils import (
    Icon, CYAN, DIM, GREEN, MAGENTA, RESET, YELLOW,
    ScopeGuard, deduplicate, logger, print_status, truncate
)

# ─── Regex Patterns ───────────────────────────────────────────────────────────

# REST API paths — broad coverage for bug bounty targets
_RE_API_PATH = re.compile(
    r"""(?:["'`])(/(?:api|v\d+|rest|graphql|admin|internal|private|auth|oauth|
    token|user|users|account|accounts|profile|settings|config|configuration|
    upload|uploads|download|downloads|export|exports|import|imports|
    search|query|data|service|services|webhook|webhooks|callback|callbacks|
    ws|wss|socket|sockets|stream|streams|health|status|metrics|debug|
    console|swagger|openapi|docs|documentation|dashboard|dashboards|
    actuator|jolokia|heapdump|trace|env|beans|mappings|
    shell|exec|system|system-information|system-info|react-shell|
    wp-admin|wp-json|xmlrpc|phpmyadmin|adminer|server-status|
    git|svn|backup|backups|log|logs|report|reports|
    reset|invite|verify|confirm|activate|deactivate|
    payment|payments|order|orders|invoice|invoices|
    file|files|media|images|assets|static|public|
    [a-z0-9_-]+/[a-z0-9_/:-]+)[^"'`\s]*)["'`]""",
    re.IGNORECASE | re.VERBOSE,
)

# URLs with scheme
_RE_FULL_URL = re.compile(
    r"""["'`](https?://[^\s"'`<>{}|\\^`\[\]]+)["'`]""",
    re.IGNORECASE,
)

# GraphQL queries/mutations/subscriptions
_RE_GRAPHQL = re.compile(
    r"""(?:query|mutation|subscription)\s+\w+|gql`[^`]+`|graphql\s*\(""",
    re.IGNORECASE | re.DOTALL,
)

# WebSocket URLs
_RE_WEBSOCKET = re.compile(
    r"""["'`](wss?://[^\s"'`<>{}]+)["'`]""",
    re.IGNORECASE,
)

# fetch/axios/XMLHttpRequest calls
_RE_FETCH_CALL = re.compile(
    r"""(?:fetch|axios(?:\.[a-z]+)?|\.(?:get|post|put|delete|patch|request))\s*\(
    \s*["'`]([^"'`\s]+)["'`]""",
    re.IGNORECASE | re.VERBOSE,
)

# URL template literals with variables
_RE_TEMPLATE_URL = re.compile(
    r"""`([^`]*(?:/api|/v\d+|/rest|/graphql|/admin)[^`]*)`""",
    re.IGNORECASE,
)

# Path parameters pattern e.g. "${userId}/profile"
_RE_PATH_PARAMS = re.compile(
    r"/\$\{[^}]+\}/|/:[a-zA-Z_]+/|/\{[a-zA-Z_]+\}/",
)

# Import/require with external URLs
_RE_IMPORT_URL = re.compile(
    r"""(?:import|require)\s*\(\s*["'`](https?://[^"'`\s]+)["'`]\s*\)""",
    re.IGNORECASE,
)

# JS library detection patterns
_RE_LIBRARIES = {
    # ── CVE-2025-55182 React Server Components packages (CRITICAL — CVSS 10.0) ──
    # Detecting these in JS bundles triggers React2Shell scanner
    "react-server-dom-webpack": re.compile(
        r'react-server-dom-webpack[/-]([\d.]+)|"react-server-dom-webpack"', re.I),
    "react-server-dom-turbopack": re.compile(
        r'react-server-dom-turbopack[/-]([\d.]+)|"react-server-dom-turbopack"', re.I),
    "react-server-dom-parcel": re.compile(
        r'react-server-dom-parcel[/-]([\d.]+)|"react-server-dom-parcel"', re.I),
    "react-server": re.compile(
        r'createServerReference|registerServerReference|'
        r'encodeReply\s*\(|decodeReply\s*\(|'
        r'react-server[/-]([\d.]+)', re.I),
    "react-router-rsc": re.compile(
        r'unstable_rsc|RSCStaticRouter|ServerRouter', re.I),
    # Core frameworks
    "jquery":           re.compile(r'jQuery\s+v?([\d.]+)|jquery[/-]([\d.]+)', re.I),
    "react":            re.compile(r'React\s+v?([\d.]+)|react[/-]([\d.]+)', re.I),
    "react-dom":        re.compile(r'ReactDOM|react-dom[/-]([\d.]+)', re.I),
    "angular":          re.compile(r'Angular(?:JS)?\s+v?([\d.]+)|angular[/-]([\d.]+)', re.I),
    "angularjs":        re.compile(r'AngularJS\s+v?([\d.]+)|angularjs[/-]([\d.]+)', re.I),
    "vue":              re.compile(r'Vue\.js\s+v?([\d.]+)|vue[/-]([\d.]+)', re.I),
    "svelte":           re.compile(r'Svelte\s+v?([\d.]+)|svelte[/-]([\d.]+)', re.I),
    "next.js":          re.compile(r'Next\.js\s+v?([\d.]+)|next[/-]([\d.]+)', re.I),
    "nuxt":             re.compile(r'Nuxt\.js\s+v?([\d.]+)|nuxt[/-]([\d.]+)', re.I),
    # Utilities
    "lodash":           re.compile(r'Lodash\s+v?([\d.]+)|lodash[/-]([\d.]+)', re.I),
    "moment":           re.compile(r'moment\.js\s+v?([\d.]+)|moment[/-]([\d.]+)', re.I),
    "axios":            re.compile(r'axios\s+v?([\d.]+)|axios[/-]([\d.]+)', re.I),
    "node-fetch":       re.compile(r'node-fetch[/-]([\d.]+)', re.I),
    "marked":           re.compile(r'marked\s+v?([\d.]+)|marked[/-]([\d.]+)', re.I),
    "highlight.js":     re.compile(r'highlight\.js\s+v?([\d.]+)|highlight[/-]([\d.]+)', re.I),
    "handlebars":       re.compile(r'Handlebars\s+v?([\d.]+)|handlebars[/-]([\d.]+)', re.I),
    "minimist":         re.compile(r'minimist[/-]([\d.]+)', re.I),
    # Infrastructure
    "webpack":          re.compile(r'webpack\s+v?([\d.]+)|webpack[/-]([\d.]+)', re.I),
    "express":          re.compile(r'Express\s+v?([\d.]+)|express[/-]([\d.]+)', re.I),
    "socket.io":        re.compile(r'socket\.io\s+v?([\d.]+)|socket\.io[/-]([\d.]+)', re.I),
    "bootstrap":        re.compile(r'Bootstrap\s+v?([\d.]+)|bootstrap[/-]([\d.]+)', re.I),
    # Template engines (high-risk)
    "ejs":              re.compile(r'EJS\s+v?([\d.]+)|ejs[/-]([\d.]+)', re.I),
    "pug":              re.compile(r'Pug\s+v?([\d.]+)|pug[/-]([\d.]+)', re.I),
    # ── react2shell / systeminformation (CVE-2021-21315) ─────────────────────
    # These are detected by their JS fingerprints in source / bundle comments
    "react-shell":      re.compile(
        r'react-shell|react2shell|ReactShell|'
        r'systeminformation[/-]([\d.]+)|'
        r'si\s*\.\s*cpu\s*\(|si\s*\.\s*mem\s*\(|si\s*\.\s*disk\s*\(',
        re.I
    ),
    "systeminformation": re.compile(
        r'systeminformation[/-]([\d.]+)|'
        r'require\s*\(\s*["\']systeminformation["\']\s*\)|'
        r'from\s+["\']systeminformation["\']|'
        r'si\s*\.\s*(?:cpu|mem|disk|network|os|system)\s*\(',
        re.I
    ),
}

# Source map exposure
_RE_SOURCE_MAP = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(.+)', re.I)

# Interesting comment patterns
_RE_TODO_FIXME = re.compile(
    r'//\s*(?:TODO|FIXME|HACK|XXX|BUG|NOTE)[:\s]+(.+)',
    re.I,
)


@dataclass
class EndpointFinding:
    """A discovered endpoint."""
    url: str
    source_js: str = ""
    endpoint_type: str = "REST"   # REST | GraphQL | WebSocket | Unknown
    method: str = "UNKNOWN"
    params: List[str] = field(default_factory=list)
    interesting: bool = False
    notes: List[str] = field(default_factory=list)


@dataclass
class JSAnalysisResult:
    """Full analysis output for all JS files."""
    endpoints: List[EndpointFinding] = field(default_factory=list)
    libraries: Dict[str, str] = field(default_factory=dict)   # name → version
    source_maps: List[str] = field(default_factory=list)
    todos: List[str] = field(default_factory=list)
    graphql_operations: List[str] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _looks_like_code(path: str) -> bool:
    """Filter out things that look like code strings not paths."""
    noise_patterns = [
        r'\.\w{2,5}$',          # file extensions handled separately
        r'[<>{}]',              # template/HTML fragments
        r'^\d',                  # starts with digit
        r'\\n|\\t|\\r',         # escape sequences
    ]
    for pat in noise_patterns:
        if re.search(pat, path):
            return False
    return True


def _is_interesting_endpoint(path: str) -> bool:
    """Flag endpoints that commonly have security issues."""
    path_lower = path.lower()
    for ep in INTERESTING_ENDPOINTS:
        if ep in path_lower:
            return True
    return False


def _extract_params_from_path(path: str) -> List[str]:
    """Extract parameter names from endpoint path."""
    found = []
    # Query string params
    if "?" in path:
        qs = path.split("?", 1)[1]
        for part in qs.split("&"):
            if "=" in part:
                found.append(part.split("=")[0])
            else:
                found.append(part)
    # Path params like :id or {id}
    for match in re.finditer(r'[:{]([a-zA-Z_][a-zA-Z0-9_]*)[}]?', path):
        found.append(match.group(1))
    return [p for p in found if p]


def _flag_interesting_params(params: List[str]) -> List[str]:
    """Return params that appear in the interesting params list."""
    return [p for p in params if p.lower() in INTERESTING_PARAMS]


# ─── JS Analyzer ──────────────────────────────────────────────────────────────

class JSAnalyzer:
    """
    JavaScript intelligence engine.
    Parses JS/inline scripts to extract endpoints, libraries, and more.

    All extracted endpoints are scope-filtered: only paths and URLs
    belonging to the target host are included in findings.
    """

    def __init__(self, target_url: str = "", verbose: bool = False) -> None:
        self.verbose = verbose
        self._seen_endpoints: Set[str] = set()
        # Build scope guard if a target is provided
        self._scope: Optional[ScopeGuard] = None
        if target_url:
            try:
                self._scope = ScopeGuard(target_url)
            except Exception:
                pass

    def _add_endpoint(
        self,
        path: str,
        source_js: str,
        ep_type: str = "REST",
        method: str = "UNKNOWN",
    ) -> Optional[EndpointFinding]:
        """
        Deduplicate, scope-check, and create an EndpointFinding.

        Scope rule:
          - Bare paths (/api/...) → always accepted (relative to target)
          - Full URLs (https://...) → only accepted if they belong to the target
          - External CDN / third-party API URLs → rejected silently
        """
        path = path.strip().rstrip("/")
        if not path or path in self._seen_endpoints:
            return None
        if len(path) > 512:
            return None

        # Scope gate for absolute URLs
        if self._scope and path.startswith(("http://", "https://", "ws://", "wss://")):
            if not self._scope.in_scope_endpoint(path):
                if self.verbose:
                    logger.debug(f"Endpoint OOS filtered: {truncate(path, 70)}")
                return None

        self._seen_endpoints.add(path)
        params = _extract_params_from_path(path)
        interesting = _is_interesting_endpoint(path)
        flagged = _flag_interesting_params(params)
        notes = []
        if flagged:
            notes.append(f"Interesting params: {', '.join(flagged)}")

        ep = EndpointFinding(
            url=path,
            source_js=source_js,
            endpoint_type=ep_type,
            method=method,
            params=params,
            interesting=interesting,
            notes=notes,
        )
        return ep

    def _analyze_single(self, js_content: str, source: str) -> List[EndpointFinding]:
        """Analyze a single JS string and return endpoint findings."""
        findings: List[EndpointFinding] = []

        # 1. fetch/axios/XHR calls (highest confidence)
        for match in _RE_FETCH_CALL.finditer(js_content):
            path = match.group(1)
            method = "GET"
            ctx = js_content[max(0, match.start()-30):match.start()].lower()
            if "post" in ctx:
                method = "POST"
            elif "put" in ctx:
                method = "PUT"
            elif "delete" in ctx:
                method = "DELETE"
            ep = self._add_endpoint(path, source, "REST", method)
            if ep:
                findings.append(ep)

        # 2. API path strings
        for match in _RE_API_PATH.finditer(js_content):
            path = match.group(1)
            if _looks_like_code(path):
                ep = self._add_endpoint(path, source, "REST")
                if ep:
                    findings.append(ep)

        # 3. Full HTTP URLs
        for match in _RE_FULL_URL.finditer(js_content):
            url = match.group(1)
            try:
                parsed = urlparse(url)
                path = parsed.path
                if path and path != "/" and len(path) > 1:
                    ep = self._add_endpoint(url, source, "REST")
                    if ep:
                        findings.append(ep)
            except Exception:
                pass

        # 4. WebSocket URLs
        for match in _RE_WEBSOCKET.finditer(js_content):
            ws_url = match.group(1)
            ep = self._add_endpoint(ws_url, source, "WebSocket")
            if ep:
                findings.append(ep)

        # 5. Template literal URLs
        for match in _RE_TEMPLATE_URL.finditer(js_content):
            path = match.group(1)
            # Normalize: replace ${...} with :param
            normalized = re.sub(r'\$\{[^}]+\}', ':param', path)
            ep = self._add_endpoint(normalized, source, "REST")
            if ep:
                findings.append(ep)

        return findings

    def _detect_libraries(self, js_content: str) -> Dict[str, str]:
        """Detect JavaScript library names and versions."""
        found: Dict[str, str] = {}
        for lib_name, pattern in _RE_LIBRARIES.items():
            match = pattern.search(js_content)
            if match:
                version = match.group(1) or match.group(2) or "unknown"
                found[lib_name] = version
        return found

    def _detect_source_maps(self, js_content: str) -> List[str]:
        """Detect exposed source maps."""
        maps = []
        for match in _RE_SOURCE_MAP.finditer(js_content):
            maps.append(match.group(1).strip())
        return maps

    def _detect_graphql(self, js_content: str) -> List[str]:
        """Detect GraphQL operation names."""
        ops = []
        for match in _RE_GRAPHQL.finditer(js_content):
            ops.append(match.group(0).strip()[:80])
        return list(set(ops))

    def _detect_todos(self, js_content: str) -> List[str]:
        """Extract TODO/FIXME/HACK comments."""
        todos = []
        for match in _RE_TODO_FIXME.finditer(js_content):
            todos.append(match.group(0).strip()[:120])
        return todos

    def analyze_all(
        self,
        js_contents: Dict[str, str],
        inline_scripts: List[str],
    ) -> JSAnalysisResult:
        """
        Analyze all JS files and inline scripts.

        Args:
            js_contents: dict of {url: js_source}
            inline_scripts: list of raw inline script strings

        Returns:
            JSAnalysisResult
        """
        result = JSAnalysisResult()
        all_endpoints: List[EndpointFinding] = []
        all_libraries: Dict[str, str] = {}
        all_source_maps: List[str] = []
        all_todos: List[str] = []
        all_graphql: List[str] = []

        total = len(js_contents) + len(inline_scripts)
        processed = 0

        for url, content in js_contents.items():
            endpoints = self._analyze_single(content, url)
            all_endpoints.extend(endpoints)
            all_libraries.update(self._detect_libraries(content))
            all_source_maps.extend(self._detect_source_maps(content))
            all_todos.extend(self._detect_todos(content))
            all_graphql.extend(self._detect_graphql(content))
            processed += 1
            if self.verbose:
                logger.debug(
                    f"Analyzed [{processed}/{total}]: {truncate(url, 60)} "
                    f"→ {len(endpoints)} endpoints"
                )

        for i, inline in enumerate(inline_scripts):
            source = f"<inline:{i}>"
            endpoints = self._analyze_single(inline, source)
            all_endpoints.extend(endpoints)
            all_libraries.update(self._detect_libraries(inline))
            all_graphql.extend(self._detect_graphql(inline))
            all_todos.extend(self._detect_todos(inline))

        result.endpoints = deduplicate(all_endpoints)
        result.libraries = all_libraries
        result.source_maps = list(set(all_source_maps))
        result.todos = list(set(all_todos))
        result.graphql_operations = list(set(all_graphql))
        result.stats = {
            "total_endpoints": len(result.endpoints),
            "interesting_endpoints": sum(1 for e in result.endpoints if e.interesting),
            "websocket_endpoints": sum(1 for e in result.endpoints if e.endpoint_type == "WebSocket"),
            "graphql_endpoints": sum(1 for e in result.endpoints if e.endpoint_type == "GraphQL"),
            "libraries_detected": len(result.libraries),
            "source_maps_exposed": len(result.source_maps),
        }

        print_status(
            f"{GREEN}JS analysis complete.{RESET} "
            f"Endpoints: {len(result.endpoints)} | "
            f"Interesting: {result.stats['interesting_endpoints']} | "
            f"Libraries: {len(result.libraries)}",
            Icon.SUCCESS,
        )

        if result.source_maps:
            for sm in result.source_maps:
                print_status(
                    f"{YELLOW}Exposed source map:{RESET} {sm}",
                    Icon.WARN,
                )

        return result
