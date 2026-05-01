"""
JSPECTER Crawler Module
Async recursive web crawler that discovers JS files and inline scripts.

Scope is enforced by ScopeGuard at EVERY decision point:
  - Pages to crawl
  - JS files to fetch
  - Links to follow
Nothing outside the target host is ever fetched or queued.
"""

import asyncio
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:
    raise ImportError("aiohttp is required. Run: pip install aiohttp")

from .config import MAX_JS_FILE_SIZE, ScanConfig
from .utils import (
    Icon, GREEN, YELLOW, CYAN, DIM, RESET, MAGENTA,
    ScopeGuard, logger, normalize_url, print_status, resolve_url,
    truncate
)

# ─── URL Extraction Patterns ──────────────────────────────────────────────────

_RE_SCRIPT_SRC = re.compile(
    r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_RE_SRC_HREF = re.compile(
    r'(?:src|href|action)\s*=\s*["\']([^"\']+\.js[^"\']*)["\']',
    re.IGNORECASE,
)
_RE_INLINE_SCRIPT = re.compile(
    r'<script(?:[^>]*)>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
_RE_ANCHOR = re.compile(
    r'<a[^>]+href\s*=\s*["\']([^"\'#?][^"\']*)["\']',
    re.IGNORECASE,
)
# Only bare relative paths — never full http:// URLs (those get scope-checked explicitly)
_RE_LAZY_JS = re.compile(
    r'["\']([a-zA-Z0-9_/.-]+\.js(?:\?[^"\']*)?)["\']',
)


class CrawlResult:
    """Container for crawl output."""

    def __init__(self) -> None:
        self.js_urls: List[str] = []
        self.js_contents: Dict[str, str] = {}
        self.inline_scripts: List[str] = []
        self.visited_pages: List[str] = []
        self.skipped_oos: List[str] = []
        self.errors: List[str] = []
        self.stats: Dict = {
            "pages_crawled": 0,
            "js_files_found": 0,
            "inline_scripts_found": 0,
            "out_of_scope_skipped": 0,
            "errors": 0,
        }


class Crawler:
    """
    Async recursive web crawler with strict scope enforcement.

    Every URL — pages, JS files, links — is validated through ScopeGuard
    before any network request is made. Third-party CDNs, analytics scripts,
    and external services are silently skipped and logged.
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.base_url = normalize_url(config.url)
        self.scope = ScopeGuard(self.base_url, include_subs=config.include_subs)
        self.result = CrawlResult()

        self._visited_pages: Set[str] = set()
        self._queued_js: Set[str] = set()
        self._semaphore = asyncio.Semaphore(config.threads)
        self._session: Optional[aiohttp.ClientSession] = None

        if config.verbose:
            logger.debug(f"Scope guard: {self.scope}")

    # ─── Session Management ───────────────────────────────────────────────────

    def _build_session_kwargs(self) -> Dict:
        kwargs: Dict = {
            "headers": self.config.headers,
            "timeout": aiohttp.ClientTimeout(total=self.config.timeout),
            "connector": aiohttp.TCPConnector(
                ssl=False,
                limit=self.config.threads * 2,
            ),
        }
        if self.config.proxy:
            kwargs["proxy"] = self.config.proxy
        return kwargs

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(**self._build_session_kwargs())
        return self._session

    async def _close_session(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            await asyncio.sleep(0.25)

    # ─── Scope Logging ────────────────────────────────────────────────────────

    def _record_oos(self, url: str, reason: str = "") -> None:
        """Record and count an out-of-scope URL that was blocked."""
        self.result.stats["out_of_scope_skipped"] += 1
        self.result.skipped_oos.append(url)
        if self.config.verbose:
            logger.debug(f"OOS blocked ({reason}): {truncate(url, 70)}")

    # ─── Core Fetch ───────────────────────────────────────────────────────────

    async def _fetch(self, url: str) -> Tuple[Optional[str], int]:
        """
        Fetch URL content. Callers must scope-check before calling.
        Also checks post-redirect URL to catch redirect-to-external attacks.
        """
        session = await self._get_session()
        for attempt in range(1, 4):
            try:
                async with self._semaphore:
                    if self.config.rate_limit > 0:
                        await asyncio.sleep(self.config.rate_limit)
                    async with session.get(
                        url, allow_redirects=True, max_redirects=5
                    ) as resp:
                        status = resp.status
                        if status == 200:
                            content_length = int(
                                resp.headers.get("Content-Length", 0)
                            )
                            if content_length > MAX_JS_FILE_SIZE:
                                logger.warning(
                                    f"Skipping large file "
                                    f"({content_length // 1024}KB): {truncate(url, 55)}"
                                )
                                return None, status

                            # Post-redirect scope check: if we were redirected
                            # to a different domain, abort and record OOS.
                            final_url = str(resp.url)
                            if (
                                final_url != url
                                and not self.scope.in_scope(final_url)
                            ):
                                self._record_oos(
                                    final_url,
                                    f"redirect from {truncate(url, 40)}"
                                )
                                return None, 0

                            text = await resp.text(errors="replace")
                            return text, status
                        return None, status

            except aiohttp.ClientConnectorError as e:
                if attempt == 3:
                    logger.debug(f"Connection failed [{url}]: {e}")
                    self.result.errors.append(f"Connection failed: {url}")
                    self.result.stats["errors"] += 1
            except asyncio.TimeoutError:
                if attempt == 3:
                    logger.debug(f"Timeout: {truncate(url, 60)}")
                    self.result.errors.append(f"Timeout: {url}")
                    self.result.stats["errors"] += 1
            except Exception as e:
                if attempt == 3:
                    logger.debug(f"Fetch error [{url}]: {e}")
                    self.result.errors.append(f"Error: {url} — {e}")
                    self.result.stats["errors"] += 1
            await asyncio.sleep(0.5 * attempt)
        return None, 0

    # ─── JS File Fetching ─────────────────────────────────────────────────────

    async def _fetch_js(self, url: str) -> None:
        """
        Fetch a JS file — scope MUST be verified by caller first.
        """
        if url in self._queued_js:
            return
        self._queued_js.add(url)

        content, status = await self._fetch(url)
        if content:
            self.result.js_urls.append(url)
            self.result.js_contents[url] = content
            self.result.stats["js_files_found"] += 1
            if self.config.verbose:
                print_status(
                    f"{MAGENTA}JS{RESET} {truncate(url, 70)}", Icon.JS
                )

    # ─── HTML Parsing ─────────────────────────────────────────────────────────

    def _is_js_url(self, url: str) -> bool:
        """Quick check: does this URL point to a JS file?"""
        path = urlparse(url).path.lower()
        return path.endswith((".js", ".mjs")) or ".js?" in path

    def _extract_js_urls_from_html(self, html: str, page_url: str) -> List[str]:
        """
        Extract JS file URLs from HTML — scope-checked before returning.

        Strategy:
          1. Collect candidates from <script src>, src/href attrs, lazy refs
          2. Resolve each against the current page URL
          3. ScopeGuard.in_scope_js() gates every single one
          4. Non-JS URLs and out-of-scope URLs are discarded
        """
        candidates: List[str] = []

        for pattern in [_RE_SCRIPT_SRC, _RE_SRC_HREF]:
            for match in pattern.finditer(html):
                raw = match.group(1).strip()
                if raw.startswith("data:"):
                    continue
                resolved = resolve_url(page_url, raw)
                if resolved:
                    candidates.append(resolved)

        # Bare relative paths from lazy loading (e.g. "/chunk.abc.js")
        # _RE_LAZY_JS only matches paths without a scheme, so resolving
        # them always produces a URL on the current page's origin.
        for match in _RE_LAZY_JS.finditer(html):
            raw = match.group(1).strip()
            resolved = resolve_url(page_url, raw)
            if resolved:
                candidates.append(resolved)

        # Scope gate + JS type filter
        in_scope: List[str] = []
        seen: Set[str] = set()
        for url in candidates:
            if url in seen:
                continue
            seen.add(url)
            if not self._is_js_url(url):
                continue
            if self.scope.in_scope_js(url):
                in_scope.append(url)
            else:
                self._record_oos(url, "third-party JS")

        return in_scope

    def _extract_inline_scripts(self, html: str) -> List[str]:
        """Extract inline <script> block content from HTML."""
        scripts = []
        for match in _RE_INLINE_SCRIPT.finditer(html):
            content = match.group(1).strip()
            if len(content) > 20:
                scripts.append(content)
        return scripts

    def _extract_page_links(self, html: str, page_url: str) -> List[str]:
        """
        Extract internal page links for recursive crawling.
        Only returns URLs that pass ScopeGuard.in_scope().
        """
        links: List[str] = []
        seen: Set[str] = set()
        for match in _RE_ANCHOR.finditer(html):
            raw = match.group(1).strip()
            if raw.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
                continue
            resolved = resolve_url(page_url, raw)
            if not resolved or resolved in seen:
                continue
            seen.add(resolved)

            if self.scope.in_scope(resolved):
                links.append(resolved)
            else:
                self._record_oos(resolved, "off-domain link")
        return links

    # ─── Recursive Crawler ────────────────────────────────────────────────────

    async def _crawl_page(self, url: str, depth: int) -> None:
        """Recursively crawl a page up to max depth."""
        url = url.split("#")[0]   # strip fragment

        # ── Primary scope gate ───────────────────────────────────────────────
        if not self.scope.in_scope(url):
            self._record_oos(url, "page out of scope")
            return

        if url in self._visited_pages or depth < 0:
            return

        self._visited_pages.add(url)
        self.result.visited_pages.append(url)
        self.result.stats["pages_crawled"] += 1

        if self.config.verbose:
            print_status(
                f"{DIM}Crawling (depth={depth}):{RESET} {truncate(url, 65)}",
                Icon.INFO,
            )

        content, status = await self._fetch(url)
        if not content:
            return

        # Extract in-scope JS files
        js_urls = self._extract_js_urls_from_html(content, url)
        js_tasks = [
            self._fetch_js(ju)
            for ju in js_urls
            if ju not in self._queued_js
        ]

        # Inline scripts
        inline = self._extract_inline_scripts(content)
        if inline:
            self.result.inline_scripts.extend(inline)
            self.result.stats["inline_scripts_found"] += len(inline)

        # In-scope page links
        page_links: List[str] = []
        if depth > 0:
            page_links = self._extract_page_links(content, url)

        if js_tasks:
            await asyncio.gather(*js_tasks, return_exceptions=True)

        link_tasks = [
            self._crawl_page(link, depth - 1)
            for link in page_links
            if link not in self._visited_pages
        ]
        if link_tasks:
            await asyncio.gather(*link_tasks, return_exceptions=True)

    # ─── Public Entry Point ───────────────────────────────────────────────────

    async def run(self) -> CrawlResult:
        """Execute the full crawl and return results."""
        scope_label = self.scope.target_host
        if self.scope.include_subs:
            scope_label += " (+ subdomains)"

        print_status(
            f"Target scope: {CYAN}{scope_label}{RESET} | "
            f"depth={self.config.depth} | threads={self.config.threads}",
            Icon.INFO,
        )

        try:
            await self._crawl_page(self.base_url, self.config.depth)
        finally:
            await self._close_session()

        oos = self.result.stats["out_of_scope_skipped"]
        print_status(
            f"{GREEN}Crawl complete.{RESET} "
            f"Pages: {self.result.stats['pages_crawled']} | "
            f"JS files: {self.result.stats['js_files_found']} | "
            f"Inline scripts: {self.result.stats['inline_scripts_found']}"
            + (f" | {YELLOW}OOS blocked: {oos}{RESET}" if oos else ""),
            Icon.SUCCESS,
        )
        return self.result
