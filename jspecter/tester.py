"""
JSPECTER Endpoint Intelligence Tester
Non-destructive probing of discovered endpoints for security misconfigurations.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:
    raise ImportError("aiohttp is required: pip install aiohttp")

from .config import INTERESTING_ENDPOINTS, ScanConfig
from .js_analyzer import EndpointFinding
from .utils import (
    Icon, CYAN, DIM, GREEN, MAGENTA, RED, RESET, YELLOW, BOLD, ORANGE,
    colorize_severity, logger, normalize_url, truncate
)


@dataclass
class ProbeResult:
    """Result of probing a single endpoint."""
    url: str
    status_code: int
    content_type: str = ""
    response_length: int = 0
    redirect_url: str = ""
    server_header: str = ""
    interesting: bool = False
    flags: List[str] = field(default_factory=list)
    severity: str = "INFO"
    notes: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)

    def status_color(self) -> str:
        if self.status_code == 200:
            return GREEN
        elif self.status_code in (301, 302, 307, 308):
            return YELLOW
        elif self.status_code == 403:
            return CYAN
        elif self.status_code == 401:
            return MAGENTA
        elif self.status_code >= 500:
            return RED
        return DIM


# ─── Security Analysis Helpers ────────────────────────────────────────────────

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def _analyze_response(
    url: str,
    status: int,
    headers: Dict[str, str],
    body: str,
    endpoint: EndpointFinding,
) -> ProbeResult:
    """Analyze HTTP response for security issues."""
    flags: List[str] = []
    notes: List[str] = []
    severity = "INFO"
    interesting = False

    ct = headers.get("Content-Type", "")
    server = headers.get("Server", "") or headers.get("X-Powered-By", "")
    redirect = headers.get("Location", "")
    content_len = len(body)

    # ── Status-based analysis ──────────────────────────────────────────────
    if status == 200 and endpoint.interesting:
        flags.append("OPEN_INTERESTING")
        notes.append(f"Interesting endpoint returned 200 OK — verify authorization required.")
        severity = "HIGH"
        interesting = True

    if status == 200 and "admin" in url.lower():
        flags.append("ADMIN_OPEN")
        notes.append("Admin panel accessible without observed authentication challenge.")
        severity = "CRITICAL"
        interesting = True

    if status in (301, 302) and redirect:
        if redirect.startswith("http") and urlparse(redirect).netloc != urlparse(url).netloc:
            flags.append("OPEN_REDIRECT")
            notes.append(f"Cross-origin redirect to: {redirect}")
            severity = "MEDIUM"
            interesting = True

    if status == 403:
        flags.append("FORBIDDEN_403")
        notes.append("403 Forbidden — may be bypassable with different methods/headers.")

    if status >= 500:
        flags.append("SERVER_ERROR_5XX")
        notes.append(f"Server error {status} — may indicate unhandled exception or stack trace.")
        severity = "MEDIUM"
        interesting = True

    # ── Missing security headers ───────────────────────────────────────────
    missing = [h for h in SECURITY_HEADERS if h.lower() not in {k.lower() for k in headers}]
    if missing and status == 200:
        flags.append("MISSING_SECURITY_HEADERS")
        notes.append(f"Missing security headers: {', '.join(missing[:3])}")

    # ── Information disclosure ─────────────────────────────────────────────
    if server:
        flags.append("SERVER_VERSION_DISCLOSURE")
        notes.append(f"Server/framework version disclosed: {server}")
        severity = max(severity, "LOW", key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "INFO": -1}.get(s, -1))

    # ── Sensitive content in response ─────────────────────────────────────
    sensitive_patterns = {
        "error": ("stack trace" in body.lower() or "traceback" in body.lower()),
        "env":   (".env" in url.lower() and content_len > 0),
        "debug": ("debug" in url.lower() and status == 200),
        "api_key_in_response": ("api_key" in body.lower() or "apikey" in body.lower()),
        "password_in_response": ('"password"' in body.lower() and status == 200),
    }

    for flag, condition in sensitive_patterns.items():
        if condition:
            flags.append(flag.upper())
            if flag == "env":
                notes.append("Possible .env file exposure — check response body for secrets.")
                severity = "CRITICAL"
                interesting = True
            elif flag == "error":
                notes.append("Stack trace detected in response — information disclosure.")
                severity = "MEDIUM"
                interesting = True
            elif flag == "password_in_response":
                notes.append("Password field in JSON response — check if over-exposure.")
                severity = "HIGH"
                interesting = True

    # ── CORS misconfiguration ─────────────────────────────────────────────
    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao == "*" and status == 200:
        flags.append("CORS_WILDCARD")
        notes.append("CORS wildcard (*) — any origin can make cross-origin requests.")
        if not severity or severity == "INFO":
            severity = "MEDIUM"

    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao and acao != "*" and acac.lower() == "true":
        flags.append("CORS_WITH_CREDENTIALS")
        notes.append(f"CORS allows credentials from origin: {acao} — verify if intended.")
        severity = "HIGH"
        interesting = True

    return ProbeResult(
        url=url,
        status_code=status,
        content_type=ct,
        response_length=content_len,
        redirect_url=redirect,
        server_header=server,
        interesting=interesting,
        flags=flags,
        severity=severity if flags else "INFO",
        notes=notes,
        headers=dict(headers),
    )


# ─── Endpoint Tester ──────────────────────────────────────────────────────────

class EndpointTester:
    """
    Non-destructive endpoint prober.
    Tests each discovered endpoint for common security misconfigurations.

    Only probes URLs that resolve to the target host via ScopeGuard.
    Absolute URLs pointing to third parties are silently skipped.
    """

    def __init__(self, config: ScanConfig, base_url: str) -> None:
        self.config = config
        self.base_url = normalize_url(base_url)
        from .utils import ScopeGuard
        self.scope = ScopeGuard(self.base_url, include_subs=config.include_subs)
        self._semaphore = asyncio.Semaphore(config.threads)
        self._session: Optional[aiohttp.ClientSession] = None
        self._tested: Set[str] = set()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=False, limit=self.config.threads)
            self._session = aiohttp.ClientSession(
                headers=self.config.headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                connector=connector,
            )
        return self._session

    async def _close_session(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            await asyncio.sleep(0.25)

    def _resolve_and_scope_check(self, endpoint_url: str) -> Optional[str]:
        """
        Resolve an endpoint URL to an absolute URL on the target,
        then verify it passes ScopeGuard before returning.

        Rules:
          - Bare paths (/api/v1/...) → prepend target origin, always in scope
          - Absolute http(s):// URLs → scope-checked; returns None if external
          - ws/wss URLs → converted to http/https for probing, scope-checked
          - Anything else → rejected
        """
        url = endpoint_url.strip()

        # Bare path — always belongs to the target
        if url.startswith("/"):
            absolute = self.scope.make_absolute(url)
            return absolute  # make_absolute guarantees it's on target

        # Absolute HTTP(S) URL
        if url.startswith(("http://", "https://")):
            if self.scope.in_scope_probe(url):
                return url
            logger.debug(f"Tester OOS skipped: {truncate(url, 70)}")
            return None

        # WebSocket URL — convert to HTTP for probing
        if url.startswith("ws://"):
            http_url = "http://" + url[5:]
            if self.scope.in_scope_probe(http_url):
                return http_url
            return None
        if url.startswith("wss://"):
            https_url = "https://" + url[6:]
            if self.scope.in_scope_probe(https_url):
                return https_url
            return None

        # Relative path without leading slash (e.g. "api/users")
        if not url.startswith(("//", "data:", "javascript:")):
            absolute = self.scope.make_absolute("/" + url)
            return absolute

        return None

    async def _probe_url(
        self, url: str, endpoint: EndpointFinding
    ) -> Optional[ProbeResult]:
        """Send a single HEAD/GET probe and analyze the response."""
        if url in self._tested:
            return None
        self._tested.add(url)

        session = await self._get_session()
        # Try HEAD first, fall back to GET for analysis
        for method in ("GET",):
            try:
                async with self._semaphore:
                    if self.config.rate_limit > 0:
                        await asyncio.sleep(self.config.rate_limit)
                    async with session.request(
                        method,
                        url,
                        allow_redirects=False,
                        max_redirects=0,
                    ) as resp:
                        # Read limited body for analysis
                        try:
                            body = await resp.text(errors="replace")
                            body = body[:4096]  # Only read first 4KB
                        except Exception:
                            body = ""
                        headers = dict(resp.headers)
                        result = _analyze_response(
                            url, resp.status, headers, body, endpoint
                        )
                        return result
            except aiohttp.ClientConnectorError:
                return None
            except asyncio.TimeoutError:
                logger.debug(f"Timeout probing: {url}")
                return None
            except Exception as e:
                logger.debug(f"Probe error [{url}]: {e}")
                return None
        return None

    async def probe_all(
        self, endpoints: List[EndpointFinding]
    ) -> List[ProbeResult]:
        """
        Probe all discovered endpoints.

        Args:
            endpoints: list of EndpointFinding objects

        Returns:
            List of ProbeResult objects
        """
        results: List[ProbeResult] = []

        # Build probe list — only in-scope, resolvable URLs
        probe_targets: List[Tuple[str, EndpointFinding]] = []
        skipped_oos = 0
        for ep in endpoints:
            resolved = self._resolve_and_scope_check(ep.url)
            if resolved and resolved not in self._tested:
                probe_targets.append((resolved, ep))
            elif not resolved:
                skipped_oos += 1

        total = len(probe_targets)
        if total == 0:
            msg = f"No in-scope endpoints to probe."
            if skipped_oos:
                msg += f" ({skipped_oos} external URLs skipped)"
            print(f"  {Icon.INFO} {msg}")
            return results

        print(f"  {Icon.INFO} Probing {total} in-scope endpoints"
              + (f" ({skipped_oos} external skipped)" if skipped_oos else "")
              + " (non-destructive)...")

        # Run probes concurrently
        tasks = [self._probe_url(url, ep) for url, ep in probe_targets]
        raw = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter and print interesting results
        interesting_count = 0
        for result in raw:
            if isinstance(result, ProbeResult):
                results.append(result)
                if result.interesting or result.status_code == 200:
                    color = result.status_color()
                    status_str = f"{color}{result.status_code}{RESET}"
                    severity_str = colorize_severity(result.severity)
                    print(
                        f"    {Icon.ENDPOINT} [{status_str}] "
                        f"{truncate(result.url, 55)} "
                        f"[{severity_str}]"
                    )
                    for note in result.notes[:2]:
                        print(f"      {DIM}→ {note}{RESET}")
                    if result.interesting:
                        interesting_count += 1

        try:
            await self._close_session()
        except Exception:
            pass

        open_count = sum(1 for r in results if r.status_code == 200)
        print(
            f"\n  {Icon.SUCCESS} {GREEN}Probe complete.{RESET} "
            f"Open: {open_count} | Interesting: {interesting_count} | "
            f"Total: {len(results)}"
        )
        return results
