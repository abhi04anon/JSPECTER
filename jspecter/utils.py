"""
JSPECTER Utility Module
Helper functions, logging setup, color output, and common utilities.
"""

import hashlib
import json
import logging
import math
import os
import re
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

# ─── ANSI Color Codes ─────────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
ORANGE = "\033[38;5;208m"
DARK_GREEN = "\033[38;5;22m"

# Disable colors on Windows if not supported
if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        # Fallback: strip colors on Windows
        RESET = BOLD = DIM = RED = GREEN = YELLOW = BLUE = ""
        MAGENTA = CYAN = WHITE = ORANGE = DARK_GREEN = ""


# ─── Status Icons ─────────────────────────────────────────────────────────────

class Icon:
    INFO    = f"{CYAN}[*]{RESET}"
    SUCCESS = f"{GREEN}[+]{RESET}"
    WARN    = f"{YELLOW}[!]{RESET}"
    ERROR   = f"{RED}[-]{RESET}"
    SECRET  = f"{RED}[S]{RESET}"
    CVE     = f"{ORANGE}[C]{RESET}"
    ENDPOINT= f"{BLUE}[E]{RESET}"
    JS      = f"{MAGENTA}[J]{RESET}"
    ARROW   = f"{DIM}  →{RESET}"


# ─── ASCII Banner ─────────────────────────────────────────────────────────────

BANNER = f"""{CYAN}{BOLD}
     ██╗███████╗██████╗ ███████╗███████╗████████╗███████╗██████╗ 
     ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
     ██║█████╗  ██████╔╝█████╗  █████╗     ██║   █████╗  ██████╔╝
██   ██║██╔══╝  ██╔═══╝ ██╔══╝  ██╔══╝     ██║   ██╔══╝  ██╔══██╗
╚█████╔╝███████╗██║     ███████╗███████╗   ██║   ███████╗██║  ██║
 ╚════╝ ╚══════╝╚═╝     ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{RESET}
{DIM}  [ {CYAN}JSPECTER{RESET}{DIM} - Autonomous JS Recon & Vulnerability Intelligence Engine ]{RESET}
{DIM}  {DARK_GREEN}"Hunting what JavaScript tries to hide."{RESET}
"""


# ─── Logging Setup ─────────────────────────────────────────────────────────────

class ColorFormatter(logging.Formatter):
    """Custom log formatter with color support."""

    FORMATS = {
        logging.DEBUG:    f"{DIM}[DBG]{{RESET}} %(message)s",
        logging.INFO:     f"{BLUE}[INF]{RESET} %(message)s",
        logging.WARNING:  f"{YELLOW}[WRN]{RESET} %(message)s",
        logging.ERROR:    f"{RED}[ERR]{RESET} %(message)s",
        logging.CRITICAL: f"{RED}{BOLD}[CRT]{RESET} %(message)s",
    }

    def format(self, record: logging.LogRecord) -> str:
        fmt = self.FORMATS.get(record.levelno, "%(message)s")
        formatter = logging.Formatter(fmt)
        return formatter.format(record)


def setup_logger(verbose: bool = False) -> logging.Logger:
    """Configure and return the JSPECTER logger."""
    logger = logging.getLogger("jspecter")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(ColorFormatter())
        logger.addHandler(handler)

    return logger


logger = logging.getLogger("jspecter")


# ─── URL Utilities ─────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure URL has a scheme and normalize it."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    # Remove fragment
    return parsed._replace(fragment="").geturl()


def get_base_domain(url: str) -> str:
    """Extract hostname (without port) from URL."""
    return urlparse(url).hostname or ""


def _strip_port(netloc: str) -> str:
    """Return hostname without port number."""
    # urlparse.hostname already handles this, but for raw netloc strings:
    return netloc.split(":")[0].lower()


def is_same_domain(url: str, base: str, include_subs: bool = False) -> bool:
    """Check if URL belongs to the same domain as base (port-aware)."""
    try:
        url_host  = urlparse(url).hostname or ""
        base_host = urlparse(base).hostname or ""
        url_host  = url_host.lower()
        base_host = base_host.lower()
        if include_subs:
            return url_host == base_host or url_host.endswith("." + base_host)
        return url_host == base_host
    except Exception:
        return False


def resolve_url(base: str, relative: str) -> Optional[str]:
    """Safely resolve relative URL against base."""
    try:
        resolved = urljoin(base, relative)
        parsed = urlparse(resolved)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return resolved
    except Exception:
        pass
    return None


# ─── Scope Guard ──────────────────────────────────────────────────────────────

class ScopeGuard:
    """
    Central, authoritative scope enforcer for all JSPECTER modules.

    Every URL decision — crawling, JS fetching, endpoint probing,
    endpoint reporting — must pass through in_scope() before acting.

    Rules:
      • Only http/https/ws/wss schemes are permitted.
      • The hostname must exactly match the target hostname, OR
        be a subdomain of it when include_subs=True.
      • Ports are compared correctly (target.com:8080 ≠ target.com).
      • No third-party CDNs, analytics, or external services pass.
    """

    def __init__(self, target_url: str, include_subs: bool = False) -> None:
        parsed = urlparse(normalize_url(target_url))
        self.target_host: str = (parsed.hostname or "").lower()
        self.target_port: Optional[int] = parsed.port   # None means default
        self.target_scheme: str = parsed.scheme.lower()
        self.include_subs: bool = include_subs

        if not self.target_host:
            raise ValueError(f"Cannot determine target host from: {target_url}")

    # ── Public API ────────────────────────────────────────────────────────────

    def in_scope(self, url: str) -> bool:
        """
        Return True only if `url` is in scope.
        This is the single gating function used everywhere.
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return False

        # Scheme must be http/https (or ws/wss for websockets)
        if parsed.scheme not in ("http", "https", "ws", "wss"):
            return False

        candidate_host = (parsed.hostname or "").lower()
        if not candidate_host:
            return False

        # Host must match
        if not self._host_matches(candidate_host):
            return False

        # Port must match (when target has an explicit non-default port)
        if self.target_port is not None:
            candidate_port = parsed.port
            if candidate_port is None:
                # Infer default port from scheme
                candidate_port = 443 if parsed.scheme in ("https", "wss") else 80
            if candidate_port != self.target_port:
                return False

        return True

    def in_scope_js(self, url: str) -> bool:
        """
        Gate for JS file fetching.
        Same as in_scope() — JS from CDNs is NOT fetched.
        """
        return self.in_scope(url)

    def in_scope_probe(self, url: str) -> bool:
        """
        Gate for endpoint probing.
        Only probes URLs on the exact target host/port.
        Never probes third-party services extracted from JS.
        """
        return self.in_scope(url)

    def in_scope_endpoint(self, url: str) -> bool:
        """
        Gate for including an endpoint in reports.
        Allows absolute target URLs AND bare paths (starting with /).
        Rejects full URLs pointing to external hosts.
        """
        if url.startswith("/"):
            return True          # bare path — always target-relative
        if url.startswith(("ws://", "wss://", "http://", "https://")):
            return self.in_scope(url)
        # Relative paths with no scheme — accept
        if not url.startswith(("//",)):
            return True
        # Protocol-relative //cdn.example.com/... — check host
        try:
            parsed = urlparse("https:" + url)
            return self._host_matches((parsed.hostname or "").lower())
        except Exception:
            return False

    def make_absolute(self, path_or_url: str) -> str:
        """
        Convert a path or URL into an absolute URL on the target.
        If it's already an absolute URL on the target, return as-is.
        """
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        # Build base
        port_part = f":{self.target_port}" if self.target_port else ""
        base = f"{self.target_scheme}://{self.target_host}{port_part}"
        return urljoin(base, path_or_url)

    def filter_endpoints(self, urls: List[str]) -> List[str]:
        """Bulk-filter a list of URL strings, returning only in-scope ones."""
        return [u for u in urls if self.in_scope_endpoint(u)]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _host_matches(self, candidate: str) -> bool:
        if self.include_subs:
            return (
                candidate == self.target_host
                or candidate.endswith("." + self.target_host)
            )
        return candidate == self.target_host

    def __repr__(self) -> str:
        return (
            f"ScopeGuard(host={self.target_host!r}, "
            f"port={self.target_port}, subs={self.include_subs})"
        )


def url_fingerprint(url: str) -> str:
    """Generate a short fingerprint for deduplication."""
    return hashlib.md5(url.encode()).hexdigest()[:8]


def is_js_url(url: str) -> bool:
    """Check if URL points to a JavaScript file."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    return path.endswith(".js") or ".js?" in path


# ─── Entropy ──────────────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (used for secret detection)."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


# ─── Risk Classification ──────────────────────────────────────────────────────

SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     BLUE,
    "NONE":     DIM,
}

def colorize_severity(severity: str) -> str:
    """Return colored severity string."""
    color = SEVERITY_COLORS.get(severity.upper(), RESET)
    return f"{color}{severity}{RESET}"


def classify_risk(findings: List[Dict]) -> str:
    """Determine overall risk level from all findings."""
    severities = [f.get("severity", "LOW").upper() for f in findings]
    if "CRITICAL" in severities:
        return "CRITICAL"
    elif "HIGH" in severities:
        return "HIGH"
    elif "MEDIUM" in severities:
        return "MEDIUM"
    elif "LOW" in severities:
        return "LOW"
    return "NONE"


# ─── File Utilities ───────────────────────────────────────────────────────────

def safe_write(path: str, content: str) -> bool:
    """Write content to file safely."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception as e:
        logger.error(f"Failed to write {path}: {e}")
        return False


def load_json_state(path: str) -> Optional[Dict]:
    """Load JSON state file for scan resumption."""
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return None


def save_json_state(path: str, state: Dict) -> None:
    """Save JSON state file for scan resumption."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, default=str)
    except Exception as e:
        logger.warning(f"Could not save state: {e}")


# ─── Progress Display ─────────────────────────────────────────────────────────

def print_section(title: str) -> None:
    """Print a styled section header."""
    width = 70
    print(f"\n{CYAN}{BOLD}{'─' * width}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'─' * width}{RESET}")


def print_finding(icon: str, label: str, value: str, color: str = WHITE) -> None:
    """Print a single finding line."""
    print(f"  {icon} {DIM}{label}:{RESET} {color}{value}{RESET}")


def print_status(msg: str, icon: str = Icon.INFO) -> None:
    """Print a status message."""
    print(f"{icon} {msg}")


def timestamp() -> str:
    """Return current timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def current_ts() -> str:
    return datetime.now().isoformat()


# ─── String Helpers ────────────────────────────────────────────────────────────

def truncate(s: str, max_len: int = 80) -> str:
    """Truncate string to max_len with ellipsis."""
    return s if len(s) <= max_len else s[:max_len - 3] + "..."


def deduplicate(items: List[Any]) -> List[Any]:
    """Deduplicate a list while preserving order."""
    seen: Set = set()
    result = []
    for item in items:
        key = str(item)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
