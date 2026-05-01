"""Tests for React2Shell zero-FP evidence model."""
import pytest
from jspecter.utils import ScopeGuard
from jspecter.react2shell import (
    React2ShellScanner, React2ShellResult,
    W_CONFIRMED, W_STRONG, W_SUPPORTING,
    MIN_WEIGHT_VULNERABLE, VULNERABLE_VERSIONS, PATCHED_VERSIONS,
)


def make_scanner(url="https://test.com") -> React2ShellScanner:
    s = React2ShellScanner.__new__(React2ShellScanner)
    s.target_url = url
    s.base_url = url.rstrip("/")
    s.scope = ScopeGuard(url)
    s.verbose = False
    s.result = React2ShellResult(target_url=url)
    return s


class TestVersionCheck:
    def test_vulnerable_versions(self):
        for v in VULNERABLE_VERSIONS:
            r = React2ShellResult(target_url="https://t.com", react_version=v)
            assert r.is_version_vulnerable() is True, f"{v} should be vulnerable"

    def test_patched_versions(self):
        for v in PATCHED_VERSIONS:
            r = React2ShellResult(target_url="https://t.com", react_version=v)
            assert r.is_version_vulnerable() is False, f"{v} should be patched"

    def test_react_18_not_vulnerable(self):
        r = React2ShellResult(target_url="https://t.com", react_version="18.3.1")
        assert r.is_version_vulnerable() is False

    def test_unknown_version_returns_none(self):
        r = React2ShellResult(target_url="https://t.com", react_version="")
        assert r.is_version_vulnerable() is None


class TestZeroFP:
    def test_plain_nextjs_pages_router_not_flagged(self):
        """__NEXT_DATA__ alone (Pages Router) must never flag VULNERABLE."""
        s = make_scanner()
        s._add("__NEXT_DATA__", "__NEXT_DATA__", "https://test.com/", W_SUPPORTING, "nextjs_infra")
        s._add("_next/static", "_next/static/", "https://test.com/", W_SUPPORTING, "nextjs_infra")
        s._compute_verdict()
        assert not s.result.vulnerable
        assert s.result.confidence == "NONE"

    def test_headers_only_not_vulnerable(self):
        """RSC headers alone cannot trigger VULNERABLE."""
        s = make_scanner()
        s._add("x-nextjs-cache", "x-nextjs-cache: HIT", "https://test.com/", W_STRONG, "header")
        s._compute_verdict()
        assert not s.result.vulnerable

    def test_patched_version_blocks_vulnerable(self):
        """Confirmed patched version must clear VULNERABLE even with RSC runtime."""
        s = make_scanner()
        s.result.react_version = "19.2.1"
        s.result.rsc_runtime_confirmed = True
        s._add("RSC runtime", "createFromReadableStream", "https://test.com/app.js", W_CONFIRMED, "rsc_runtime")
        s._add("RSC Flight", "self.__next_f", "https://test.com/", W_STRONG, "html")
        s._add("RSC package", '"react-server-dom-webpack"', "https://test.com/", W_STRONG, "rsc_runtime")
        s._add("__NEXT_DATA__", "__NEXT_DATA__", "https://test.com/", W_SUPPORTING, "nextjs_infra")
        s._compute_verdict()
        assert not s.result.vulnerable, "Patched 19.2.1 must never be VULNERABLE"

    def test_vulnerable_version_with_rsc_flagged(self):
        """RSC runtime + vulnerable version must flag VULNERABLE."""
        s = make_scanner()
        s.result.react_version = "19.1.0"
        s.result.rsc_runtime_confirmed = True
        s._add("RSC runtime", "createFromReadableStream", "https://test.com/app.js", W_CONFIRMED, "rsc_runtime")
        s._add("RSC Flight", "self.__next_f", "https://test.com/", W_STRONG, "html")
        s._add("RSC package", '"react-server-dom-webpack"', "https://test.com/", W_STRONG, "rsc_runtime")
        s._add("__NEXT_DATA__", "__NEXT_DATA__", "https://test.com/", W_SUPPORTING, "nextjs_infra")
        s._compute_verdict()
        assert s.result.vulnerable
        assert s.result.poc_steps  # PoC steps generated

    def test_rsc_without_version_medium_confidence_only(self):
        """RSC confirmed but no version extracted → MEDIUM confidence, not VULNERABLE."""
        s = make_scanner()
        s.result.rsc_runtime_confirmed = True
        # Only 5 weight, below MIN_WEIGHT_VULNERABLE=7
        s._add("RSC runtime", "createFromReadableStream", "https://test.com/app.js", W_CONFIRMED, "rsc_runtime")
        s._add("__NEXT_DATA__", "__NEXT_DATA__", "https://test.com/", W_SUPPORTING, "nextjs_infra")
        s._compute_verdict()
        # Weight = 3+1 = 4, below MIN_WEIGHT_MEDIUM=5
        assert s.result.confidence in ("NONE", "LOW")
        assert not s.result.vulnerable


class TestPoCSteps:
    def test_poc_generated_only_when_vulnerable(self):
        s = make_scanner()
        s.result.react_version = "19.1.0"
        s.result.rsc_runtime_confirmed = True
        s._add("RSC runtime", "createFromReadableStream", "https://test.com/app.js", W_CONFIRMED, "rsc_runtime")
        s._add("RSC Flight", "self.__next_f", "https://test.com/", W_STRONG, "html")
        s._add("RSC package", '"react-server-dom-webpack"', "https://test.com/", W_STRONG, "rsc_runtime")
        s._add("__NEXT_DATA__", "__NEXT_DATA__", "https://test.com/", W_SUPPORTING, "nextjs_infra")
        s._compute_verdict()
        assert "Step 1" in s.result.poc_steps
        assert "curl" in s.result.poc_steps
        assert "https://test.com" in s.result.poc_steps

    def test_no_poc_when_not_vulnerable(self):
        s = make_scanner()
        s._add("__NEXT_DATA__", "__NEXT_DATA__", "https://test.com/", W_SUPPORTING, "nextjs_infra")
        s._compute_verdict()
        assert not s.result.poc_steps
