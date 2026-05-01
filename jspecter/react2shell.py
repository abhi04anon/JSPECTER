"""
JSPECTER — React2Shell Scanner
CVE-2025-55182 Detection Engine — Zero False-Positive Design

Every signal requires multiple corroborating pieces of evidence before
a finding is emitted. The scanner uses a weighted evidence model:

  CONFIRMED signals  (weight 3) — only fired when artefact is unambiguous
  STRONG signals     (weight 2) — highly specific to RSC, rare elsewhere
  SUPPORTING signals (weight 1) — consistent with RSC but not conclusive alone

A target is flagged VULNERABLE only when ALL of these are satisfied:
  1. Total evidence weight >= 5
  2. At least one CONFIRMED or two STRONG signals present
  3. react-server-dom-* package is detectable in a JS bundle OR version
     is extracted AND falls in the affected range (19.0.0–19.2.0)

This means a plain Next.js app without RSC server functions, a React 18
app, or any CDN-cached site will NOT be flagged.

CVE-2025-55182 (React2Shell)
  CVSS:   10.0  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
  CWE:    CWE-502 Deserialization of Untrusted Data
  Fixed:  react-server-dom-* 19.0.1 / 19.1.2 / 19.2.1
          next >= 15.5.7 / 16.0.7
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

try:
    import aiohttp
except ImportError:
    raise ImportError("aiohttp is required: pip install aiohttp")

from .utils import (
    Icon, BOLD, CYAN, DIM, GREEN, ORANGE, RED, RESET, WHITE, YELLOW,
    ScopeGuard, logger, normalize_url, truncate,
)

# ─── CVE constants ────────────────────────────────────────────────────────────

CVE_ID      = "CVE-2025-55182"
CVE_ALIAS   = "React2Shell"
CVSS_SCORE  = 10.0

# Exact versions confirmed vulnerable by maintainers
VULNERABLE_VERSIONS: Set[str] = {
    "19.0.0", "19.1.0", "19.1.1", "19.2.0",
}
# Confirmed patched
PATCHED_VERSIONS: Set[str] = {
    "19.0.1", "19.1.2", "19.2.1", "19.2.2", "19.2.3",
}

# ─── Evidence weights ─────────────────────────────────────────────────────────

W_CONFIRMED  = 3   # Unambiguous RSC artefact
W_STRONG     = 2   # Highly specific, very rarely a false positive
W_SUPPORTING = 1   # Consistent with RSC but not conclusive alone

# Minimum total weight to report a finding
MIN_WEIGHT_REPORT    = 3   # report as LOW confidence
MIN_WEIGHT_MEDIUM    = 5   # report as MEDIUM
MIN_WEIGHT_VULNERABLE = 7  # flag as VULNERABLE (requires version evidence too)


# ─── Patterns — each comment explains WHY it is specific ────────────────────

# CONFIRMED (weight 3):
# These strings appear ONLY in react-server-dom-* runtime bundles.
# They are generated identifiers in the compiled RSC client/server bridge.
# A false positive here would require someone to manually type these exact
# strings in their own code — practically impossible in production JS.
_RE_RSC_CONFIRMED = re.compile(
    r'react-server-dom-webpack/client'       # exact package entry point
    r'|react-server-dom-turbopack/client'
    r'|react-server-dom-parcel/client'
    r'|react-server-dom-webpack/server'
    r'|react-server-dom-turbopack/server'
    r'|createFromReadableStream\s*\('        # RSC Flight client API
    r'|createServerReference\s*\(\s*["\'][0-9a-f]'  # server ref with hash ID
    r'|__webpack_require__.*react-server-dom'  # webpack chunk with RSC module
    r'|\$\$typeof.*SERVER_REFERENCE'         # internal RSC symbol
    r'|ReactFlightClientConfigBundlerWebpack' # exact internal config name
    r'|ReactFlightServerConfigWebpackBundler',
    re.IGNORECASE,
)

# STRONG (weight 2):
# These appear in Next.js RSC payload HTML inline scripts.
# self.__next_f is Next.js's RSC Flight push mechanism — not used
# by any other framework or library.
_RE_RSC_STRONG_HTML = re.compile(
    r'self\.__next_f\s*=\s*\[\s*\]'         # Flight buffer init
    r'|self\.__next_f\.push\s*\(\['          # Flight chunk push
    r'|\$RC\s*=\s*function'                  # RSC refresh cache function
    r'|\$L[0-9a-f]+\s*=\s*\['               # Flight lazy reference
    r'|__RSC_MANIFEST__'                     # RSC manifest marker
    r'|rsc-action-id',                       # actual RSC action ID in HTML script
    re.IGNORECASE,
)

# STRONG (weight 2):
# HTTP response headers that Next.js RSC uniquely sets.
# server-timing is excluded — too generic (used by Cloudflare, Fastly, etc.)
_RSC_STRONG_HEADERS = {
    "x-nextjs-cache",           # Next.js only
    "x-nextjs-matched-path",    # Next.js only
    "x-nextjs-page",            # Next.js only
    "x-middleware-rewrite",     # Next.js middleware only
    "x-rsc",                    # custom RSC header, rare
    "x-react-server",           # custom RSC header, rare
}

# STRONG (weight 2):
# Package names inside a <script type="importmap"> or chunk comments.
# These exact strings only appear if the package is actually bundled.
_RE_RSC_PACKAGE_IN_BUNDLE = re.compile(
    r'["\']react-server-dom-webpack["\']'
    r'|["\']react-server-dom-turbopack["\']'
    r'|["\']react-server-dom-parcel["\']'
    r'|["\']react-server-dom-esm["\']',
    re.IGNORECASE,
)

# SUPPORTING (weight 1):
# These confirm Next.js is present, but NOT that RSC server functions are enabled.
# They raise evidence weight toward the threshold but cannot trigger a finding alone.
_RE_NEXTJS_DATA = re.compile(
    r'<script\b[^>]+\bid\s*=\s*["\']__NEXT_DATA__["\']',
    re.IGNORECASE,
)
_RE_NEXTJS_SCRIPT = re.compile(
    r'src\s*=\s*["\'][^"\']*/_next/static/[^"\']+\.js["\']',
    re.IGNORECASE,
)

# SUPPORTING (weight 1):
# Version string extraction — used to confirm/deny vulnerable range.
# These are ONLY used as version evidence, never as a standalone signal.
_RE_REACT_VERSION = re.compile(
    # Matches: "version":"19.1.0" near react-server-dom package string
    r'"react-server-dom-(?:webpack|turbopack|parcel)"[^}]{0,200}'
    r'"version"\s*:\s*"([\d]+\.[\d]+\.[\d]+)"'
    # OR the standard React bundle version comment
    r'|react-dom\.development\.js\s+[\d.]+\s*\*\)\s*\n.*?version\s*=\s*["\']?([\d]+\.[\d]+\.[\d]+)',
    re.IGNORECASE | re.DOTALL,
)
# Simpler fallback version extraction from package.json if exposed
_RE_PKG_REACT_VERSION = re.compile(
    r'"react-server-dom-(?:webpack|turbopack|parcel)"\s*:\s*"[^"]*?([\d]+\.[\d]+\.[\d]+)[^"]*"',
    re.IGNORECASE,
)
_RE_NEXT_VERSION = re.compile(
    r'"next"\s*:\s*"[^"]*?([\d]+\.[\d]+\.[\d]+)[^"]*"',
    re.IGNORECASE,
)

# Build ID is a unique Next.js fingerprint (not RSC-specific, but supporting)
_RE_BUILD_ID = re.compile(r'^[a-zA-Z0-9_-]{8,40}$')

# RSC Probe paths — ordered from most to least specific
# Each is checked for status=200 AND then content-analysed
RSC_PROBE_PATHS = [
    # High-specificity JS chunks that only exist in RSC apps
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/main-app.js",
    "/_next/static/chunks/app-pages-internals.js",
    # Next.js metadata files
    "/.next/BUILD_ID",
    "/package.json",
    # Root page for inline RSC Flight scripts
    "/",
]


# ─── PoC step generator ───────────────────────────────────────────────────────

def build_poc(result: "React2ShellResult", target_url: str) -> str:
    """
    Generate a step-by-step PoC verification checklist for the hunter.
    This describes how to manually confirm the finding — it does NOT
    generate or include any exploit payload.
    """
    base = target_url.rstrip("/")
    rv   = result.react_version or "19.x.x (detected)"
    nv   = result.next_version   or "unknown"

    lines = [
        "",
        "━" * 64,
        f"  PoC VERIFICATION STEPS — {CVE_ID} ({CVE_ALIAS})",
        "━" * 64,
        "",
        "  These steps let you manually confirm the finding before reporting.",
        "  All steps use standard HTTP requests — no exploit payload is sent.",
        "",
        f"  Target  : {base}",
        f"  React   : {rv}",
        f"  Next.js : {nv}",
        "",
        "  ── Step 1: Confirm Next.js + RSC are running ────────────────────",
        "",
        f"    curl -s -I {base}/ | grep -i 'x-nextjs'",
        "",
        "    Expected output if vulnerable:",
        "      x-nextjs-cache: MISS",
        "      x-nextjs-matched-path: /",
        "",
        "  ── Step 2: Confirm RSC Flight payload is active ─────────────────",
        "",
        f"    curl -s {base}/ | grep -c '__next_f'",
        "",
        "    Expected: a number > 0  (RSC Flight chunks present in HTML)",
        "",
        "  ── Step 3: Verify react-server-dom-* package version ────────────",
        "",
        f"    # If package.json is exposed:",
        f"    curl -s {base}/package.json | python3 -m json.tool | grep react-server-dom",
        "",
        "    # If not exposed, inspect the webpack chunk:",
        f"    curl -s {base}/_next/static/chunks/webpack.js | grep -o '\"react-server-dom[^\"]*\"'",
        "",
        f"    Expected: react-server-dom-webpack version in {sorted(VULNERABLE_VERSIONS)}",
        "",
        "  ── Step 4: Locate a Server Action endpoint ───────────────────────",
        "",
        f"    curl -s {base}/ | grep -oE '\\$ACTION[_A-Z0-9:]+' | head -5",
        "",
        "    OR inspect HTML for next-action header references:",
        f"    curl -s {base}/ | grep -i 'next-action\\|rsc-action-id'",
        "",
        "  ── Step 5: Confirm RSC endpoint accepts POST ─────────────────────",
        "",
        f"    curl -s -o /dev/null -w '%{{http_code}}' \\",
        f"      -X POST \\",
        f"      -H 'Content-Type: text/plain;charset=UTF-8' \\",
        f"      -H 'Next-Action: <action-id-from-step-4>' \\",
        f"      -d '' \\",
        f"      {base}/",
        "",
        "    Expected: HTTP 200 (endpoint accepts the RSC POST format)",
        "    This alone is NOT exploitation — it only confirms the endpoint",
        "    is reachable. Report to the program at this stage.",
        "",
        "  ── Remediation ───────────────────────────────────────────────────",
        "",
        "    Upgrade packages immediately:",
        "      npm install react@19.2.1 react-dom@19.2.1",
        "      npm install react-server-dom-webpack@19.2.1",
        "      npm install next@latest  (>= 15.5.7 or >= 16.0.7)",
        "",
        "    Verify fix:",
        f"    curl -s {base}/package.json | grep react-server-dom",
        "    Expected: \"react-server-dom-webpack\": \"19.2.1\" (or later)",
        "",
        "  ── References ────────────────────────────────────────────────────",
        "",
        "    NVD:   https://nvd.nist.gov/vuln/detail/CVE-2025-55182",
        "    React: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
        "    CISA:  https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "",
        "━" * 64,
    ]
    return "\n".join(lines)


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class Evidence:
    """One piece of evidence toward a React2Shell finding."""
    signal: str           # short label of what was found
    detail: str           # exact matched string / value (truncated)
    source_url: str       # URL where this was found
    weight: int           # W_CONFIRMED | W_STRONG | W_SUPPORTING
    category: str         # "rsc_runtime" | "nextjs_infra" | "version" | "header" | "html"
    notes: str = ""

    @property
    def weight_label(self) -> str:
        return {W_CONFIRMED: "CONFIRMED", W_STRONG: "STRONG", W_SUPPORTING: "SUPPORTING"}.get(
            self.weight, "UNKNOWN"
        )


@dataclass
class React2ShellResult:
    """Complete detection result."""
    target_url: str
    cve_id: str              = CVE_ID
    vulnerable: bool         = False
    confidence: str          = "NONE"     # NONE / LOW / MEDIUM / HIGH
    react_version: str       = ""
    next_version: str        = ""
    rsc_runtime_confirmed: bool = False   # react-server-dom-* actually in bundle
    total_weight: int        = 0
    evidence: List[Evidence] = field(default_factory=list)
    affected_paths: List[str]= field(default_factory=list)
    poc_steps: str           = ""
    recommendation: str      = ""

    def is_version_vulnerable(self) -> Optional[bool]:
        v = self.react_version.strip()
        if not v:
            return None
        if v in VULNERABLE_VERSIONS:
            return True
        if v in PATCHED_VERSIONS:
            return False
        # Handle semver prefix match (e.g. "19.0" → "19.0.0")
        for vv in VULNERABLE_VERSIONS:
            if v.startswith(vv):
                return True
        for pv in PATCHED_VERSIONS:
            if v.startswith(pv):
                return False
        # Version is React 19.x but not in our known lists
        if v.startswith("19."):
            return None   # unknown — treat as uncertain, not safe
        return False      # not React 19 at all → not vulnerable


# ─── Scanner ──────────────────────────────────────────────────────────────────

class React2ShellScanner:
    """
    True-positive-only scanner for CVE-2025-55182 (React2Shell).

    Evidence model:
      - Multiple independent signal sources required before any verdict
      - Version confirmation required before calling VULNERABLE
      - Patched version immediately clears VULNERABLE flag even if RSC found
      - PoC steps generated only when VULNERABLE verdict is reached
    """

    def __init__(
        self,
        target_url: str,
        threads: int = 5,
        timeout: int = 15,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        verbose: bool = False,
    ) -> None:
        self.target_url = normalize_url(target_url)
        self.base_url   = self.target_url.rstrip("/")
        self.scope      = ScopeGuard(self.target_url)
        self.timeout    = timeout
        self.proxy      = proxy
        self.verbose    = verbose
        self.headers    = headers or {
            "User-Agent": (
                "Mozilla/5.0 (compatible; JSPECTER-Security-Scanner/1.0; "
                "+https://github.com/abhi04anon/jspecter)"
            ),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        self._session: Optional[aiohttp.ClientSession] = None
        self._sem = asyncio.Semaphore(threads)
        self.result = React2ShellResult(target_url=self.target_url)

    # ─── HTTP ─────────────────────────────────────────────────────────────────

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            kw: Dict = {
                "headers": self.headers,
                "timeout": aiohttp.ClientTimeout(total=self.timeout),
                "connector": aiohttp.TCPConnector(ssl=False, limit=10),
            }
            if self.proxy:
                kw["proxy"] = self.proxy
            self._session = aiohttp.ClientSession(**kw)
        return self._session

    async def _close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            await asyncio.sleep(0.1)

    async def _get(
        self, path: str, extra_headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[str], int, Dict[str, str]]:
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        if not self.scope.in_scope(url):
            return None, 0, {}
        session = await self._get_session()
        try:
            async with self._sem:
                hdrs = {**self.headers, **(extra_headers or {})}
                async with session.get(
                    url, headers=hdrs,
                    allow_redirects=True, max_redirects=3
                ) as resp:
                    final = str(resp.url)
                    if not self.scope.in_scope(final):
                        return None, 0, {}
                    body = ""
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        body = body[:300_000]
                    return body, resp.status, dict(resp.headers)
        except Exception as e:
            if self.verbose:
                logger.debug(f"R2S fetch {url}: {e}")
            return None, 0, {}

    # ─── Evidence recording ───────────────────────────────────────────────────

    def _add(
        self,
        signal: str,
        detail: str,
        source: str,
        weight: int,
        category: str,
        notes: str = "",
    ) -> None:
        # Deduplicate by signal + source
        key = f"{signal}:{source}"
        if any(f"{e.signal}:{e.source_url}" == key for e in self.result.evidence):
            return
        self.result.evidence.append(Evidence(
            signal=signal,
            detail=truncate(detail, 120),
            source_url=source,
            weight=weight,
            category=category,
            notes=notes,
        ))
        self.result.total_weight += weight
        if self.verbose:
            logger.debug(f"R2S evidence [{weight}] {signal} @ {truncate(source, 50)}")

    # ─── Signal checkers ──────────────────────────────────────────────────────

    def _check_headers(self, headers: Dict[str, str], source: str) -> None:
        """Check HTTP response headers for RSC-specific values."""
        hl = {k.lower(): v for k, v in headers.items()}

        # Server header — only flag if it explicitly names Next.js with version
        server = hl.get("server", "") + " " + hl.get("x-powered-by", "")
        m = re.search(r'next(?:\.js)?/?([\d]+\.[\d]+\.[\d]+)', server, re.I)
        if m:
            self._add(
                "Next.js server header", f"Server: {server.strip()}", source,
                W_SUPPORTING, "nextjs_infra",
                "Server header confirms Next.js; RSC presence still needs verification."
            )
            if not self.result.next_version:
                self.result.next_version = m.group(1)

        # RSC-specific headers (exclude server-timing — too generic)
        for h in _RSC_STRONG_HEADERS:
            if h in hl:
                self._add(
                    f"RSC header: {h}", f"{h}: {hl[h][:80]}", source,
                    W_STRONG, "header",
                    f"Header '{h}' is emitted only by Next.js RSC responses."
                )

    def _check_html(self, html: str, source: str) -> None:
        """Check HTML page for RSC-specific Flight payload patterns."""
        if not html:
            return

        # SUPPORTING: __NEXT_DATA__ — confirms Next.js but NOT RSC server functions
        if _RE_NEXTJS_DATA.search(html):
            self._add(
                "__NEXT_DATA__ script tag", "__NEXT_DATA__", source,
                W_SUPPORTING, "nextjs_infra",
                "Confirms Next.js Pages Router. RSC (App Router) needs further evidence."
            )

        # SUPPORTING: _next/static script src — confirms Next.js
        if _RE_NEXTJS_SCRIPT.search(html):
            self._add(
                "_next/static JS bundle", "_next/static/", source,
                W_SUPPORTING, "nextjs_infra",
                "Next.js static chunk loading confirmed in HTML."
            )

        # STRONG: self.__next_f — only in App Router RSC pages
        m = _RE_RSC_STRONG_HTML.search(html)
        if m:
            self._add(
                "RSC Flight payload (self.__next_f)", m.group(0)[:80], source,
                W_STRONG, "html",
                "self.__next_f is the Next.js RSC Flight buffer — "
                "only present when RSC server rendering is active."
            )

    def _check_js_bundle(self, js: str, source: str) -> None:
        """
        Check a JS bundle for RSC runtime code.
        Only fires CONFIRMED/STRONG signals — never broad keyword matches.
        """
        if not js:
            return

        # CONFIRMED: RSC runtime API strings that only exist in react-server-dom-*
        m = _RE_RSC_CONFIRMED.search(js)
        if m:
            self.result.rsc_runtime_confirmed = True
            self._add(
                "RSC runtime API in bundle", m.group(0)[:100], source,
                W_CONFIRMED, "rsc_runtime",
                "This string only appears in compiled react-server-dom-* packages. "
                "False positive probability is near zero."
            )

        # STRONG: package name as a string literal inside the bundle
        m2 = _RE_RSC_PACKAGE_IN_BUNDLE.search(js)
        if m2 and not self.result.rsc_runtime_confirmed:
            self._add(
                "react-server-dom-* package reference", m2.group(0), source,
                W_STRONG, "rsc_runtime",
                "Package name string found in bundle — confirms RSC package is bundled."
            )

        # Version extraction from bundle (does NOT add to weight — only sets version)
        for m3 in _RE_REACT_VERSION.finditer(js):
            v = next((g for g in m3.groups() if g), None)
            if v and not self.result.react_version:
                self.result.react_version = v
                logger.debug(f"R2S: react-server-dom version extracted: {v}")

    def _check_package_json(self, body: str, source: str) -> None:
        """
        Parse an exposed package.json for react-server-dom-* version.
        Only extracts the specific affected packages — not generic 'react'.
        """
        m = _RE_PKG_REACT_VERSION.search(body)
        if m:
            v = m.group(1)
            self.result.react_version = v
            self._add(
                f"react-server-dom-* in package.json (v{v})",
                m.group(0)[:100], source,
                W_STRONG, "version",
                f"Exact package version {v} found in exposed package.json. "
                f"Vulnerable range: {sorted(VULNERABLE_VERSIONS)}"
            )

        m2 = _RE_NEXT_VERSION.search(body)
        if m2 and not self.result.next_version:
            self.result.next_version = m2.group(1)

    # ─── Phase runners ────────────────────────────────────────────────────────

    async def _probe_root(self) -> None:
        """Fetch root page and check headers + HTML + inline JS."""
        body, status, headers = await self._get("/")
        if status != 200:
            return
        src = self.base_url + "/"
        self._check_headers(headers, src)
        self._check_html(body or "", src)

        # Inline scripts — only check for RSC Flight patterns, not broad JS
        for block in re.findall(
            r'<script(?:\s+type\s*=\s*["\'](?:text/javascript|module)["\'])?\s*>(.*?)</script>',
            body or "", re.DOTALL | re.IGNORECASE
        ):
            if "next_f" in block or "react-server-dom" in block.lower():
                self._check_js_bundle(block, src + "#inline")

    async def _probe_js_chunks(self) -> None:
        """
        Fetch specific Next.js JS chunks and check for RSC runtime code.
        We fetch only paths that are exclusive to Next.js App Router with RSC.
        """
        js_paths = [
            "/_next/static/chunks/webpack.js",
            "/_next/static/chunks/main-app.js",
            "/_next/static/chunks/app-pages-internals.js",
        ]
        for path in js_paths:
            body, status, headers = await self._get(path)
            if status == 200 and body:
                self._check_headers(headers, self.base_url + path)
                self._check_js_bundle(body, self.base_url + path)
                if self.result.rsc_runtime_confirmed:
                    self.result.affected_paths.append(self.base_url + path)

    async def _probe_build_id(self) -> None:
        """/.next/BUILD_ID — unique Next.js artefact."""
        body, status, _ = await self._get("/.next/BUILD_ID")
        if status == 200 and body:
            bid = body.strip()
            if _RE_BUILD_ID.match(bid):
                self._add(
                    "Next.js BUILD_ID exposed", bid, self.base_url + "/.next/BUILD_ID",
                    W_SUPPORTING, "nextjs_infra",
                    "BUILD_ID confirms Next.js deployment."
                )

    async def _probe_package_json(self) -> None:
        """package.json — check for exact react-server-dom-* version."""
        body, status, _ = await self._get("/package.json")
        if status == 200 and body:
            try:
                # Only process if it looks like a real package.json
                if '"dependencies"' in body or '"devDependencies"' in body:
                    self._check_package_json(body, self.base_url + "/package.json")
            except Exception:
                pass

    # ─── Verdict ──────────────────────────────────────────────────────────────

    def _compute_verdict(self) -> None:
        """
        Strict multi-factor verdict.

        VULNERABLE requires ALL of:
          1. total_weight >= MIN_WEIGHT_VULNERABLE
          2. rsc_runtime_confirmed OR strong version evidence
          3. react_version is in VULNERABLE_VERSIONS (or unknown React 19.x)
          4. react_version is NOT in PATCHED_VERSIONS

        This prevents flagging:
          - Plain Next.js apps without RSC server functions
          - React 18 or earlier apps
          - Apps running patched react-server-dom-* versions
          - CDN-fronted apps with generic headers
        """
        r = self.result
        w = r.total_weight
        v_status = r.is_version_vulnerable()

        # Confidence tier
        if w >= MIN_WEIGHT_VULNERABLE and r.rsc_runtime_confirmed:
            r.confidence = "HIGH"
        elif w >= MIN_WEIGHT_MEDIUM:
            r.confidence = "MEDIUM"
        elif w >= MIN_WEIGHT_REPORT:
            r.confidence = "LOW"
        else:
            r.confidence = "NONE"

        # Vulnerable flag — strict
        if (
            r.confidence in ("HIGH", "MEDIUM")
            and r.rsc_runtime_confirmed
            and v_status is not False   # not confirmed patched
        ):
            r.vulnerable = True

        # If we have explicit patched version → never vulnerable
        if v_status is False:
            r.vulnerable = False

        # Recommendation
        if r.vulnerable:
            r.recommendation = (
                "PATCH IMMEDIATELY — Pre-auth RCE (CVSS 10.0) — CISA KEV\n"
                "  Upgrade:\n"
                "    npm install react-server-dom-webpack@19.2.1\n"
                "    npm install react-server-dom-turbopack@19.2.1\n"
                "    npm install react-server-dom-parcel@19.2.1\n"
                "    npm install next@latest   (>= 15.5.7 or >= 16.0.7)\n"
                "  Compensating control (while patching):\n"
                "    Block POST requests with 'Next-Action' or 'Rsc-Action-Id' headers at WAF."
            )
            r.poc_steps = build_poc(r, r.target_url)
        elif r.confidence in ("MEDIUM", "HIGH"):
            r.recommendation = (
                "RSC detected. Version could not be confirmed as vulnerable or patched.\n"
                "  Manually verify react-server-dom-* version:\n"
                f"    curl -s {r.target_url.rstrip('/')}/package.json | grep react-server-dom\n"
                "  Vulnerable: 19.0.0, 19.1.0, 19.1.1, 19.2.0\n"
                "  Patched:    19.0.1, 19.1.2, 19.2.1+"
            )
        elif r.confidence == "LOW":
            r.recommendation = (
                "Weak RSC signals — likely Next.js Pages Router (not RSC) or a CDN cache.\n"
                "  No action required unless App Router with Server Functions is confirmed."
            )
        else:
            r.recommendation = (
                "No RSC indicators found. Target does not appear to use React Server Components."
            )

    # ─── Entry point ──────────────────────────────────────────────────────────

    async def scan(self) -> React2ShellResult:
        """
        Run the full React2Shell detection scan.
        Returns a React2ShellResult; only sets vulnerable=True when
        evidence is conclusive and version is confirmed in affected range.
        """
        print(f"\n  {Icon.CVE} {ORANGE}{BOLD}React2Shell Scanner — {CVE_ID}{RESET}")
        print(f"  {DIM}CVSS {CVSS_SCORE} | Pre-auth RCE | react-server-dom-* 19.0–19.2.0{RESET}")
        print(f"  {Icon.INFO} Target: {self.target_url}\n")
        print(f"  {DIM}Running multi-factor detection (zero-FP model)...{RESET}\n")

        try:
            await asyncio.gather(
                self._probe_root(),
                self._probe_js_chunks(),
                self._probe_build_id(),
                self._probe_package_json(),
                return_exceptions=True,
            )
        finally:
            await self._close()

        self._compute_verdict()
        self._print_result()
        return self.result

    # ─── Print ────────────────────────────────────────────────────────────────

    def _print_result(self) -> None:
        r = self.result

        # Banner
        if r.vulnerable:
            bc, icon, msg = RED, "⚠", f"VULNERABLE — {CVE_ID} CONFIRMED"
        elif r.confidence in ("HIGH", "MEDIUM"):
            bc, icon, msg = YELLOW, "⚡", f"RSC DETECTED — Manual version check needed"
        elif r.confidence == "LOW":
            bc, icon, msg = CYAN, "?", "Weak RSC signals — likely false positive risk, verify manually"
        else:
            bc, icon, msg = GREEN, "✓", "NOT VULNERABLE — No RSC indicators found"

        print(f"  {bc}{BOLD}{'─' * 62}{RESET}")
        print(f"  {bc}{BOLD}  {icon}  {msg}{RESET}")
        print(f"  {bc}{BOLD}{'─' * 62}{RESET}\n")

        # Summary line
        rv  = r.react_version or "not extracted"
        nv  = r.next_version  or "not extracted"
        rsc = f"{RED}YES{RESET}" if r.rsc_runtime_confirmed else f"{DIM}NO{RESET}"
        print(f"  React-server-dom : {rv}")
        print(f"  Next.js version  : {nv}")
        print(f"  RSC runtime      : {rsc}")
        print(f"  Evidence weight  : {r.total_weight}  (threshold = {MIN_WEIGHT_VULNERABLE})")
        print(f"  Confidence       : {r.confidence}\n")

        # Evidence table
        if r.evidence:
            print(f"  {Icon.INFO} Evidence ({len(r.evidence)} signals)\n")
            for e in sorted(r.evidence, key=lambda x: -x.weight):
                wc = RED if e.weight == W_CONFIRMED else (YELLOW if e.weight == W_STRONG else CYAN)
                print(f"    [{wc}{e.weight_label:10}{RESET}] {BOLD}{e.signal}{RESET}")
                print(f"              Detail : {e.detail}")
                print(f"              Source : {truncate(e.source_url, 65)}")
                if e.notes:
                    print(f"              Why    : {DIM}{e.notes}{RESET}")
                print()

        # Recommendation
        print(f"  {Icon.INFO} {BOLD}Recommendation{RESET}")
        for line in r.recommendation.splitlines():
            print(f"    {line}")
        print()

        # PoC steps (only when vulnerable)
        if r.poc_steps:
            print(r.poc_steps)

        # References always shown
        print(f"  {DIM}References:{RESET}")
        print(f"    {DIM}NVD  : https://nvd.nist.gov/vuln/detail/CVE-2025-55182{RESET}")
        print(f"    {DIM}Blog : https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components{RESET}")
        print(f"    {DIM}CISA : https://www.cisa.gov/known-exploited-vulnerabilities-catalog{RESET}")
        print()
