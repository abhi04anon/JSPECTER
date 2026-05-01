"""Tests for ScopeGuard — zero scope-leak guarantee."""
import pytest
from jspecter.utils import ScopeGuard


def sg(url, subs=False):
    return ScopeGuard(url, include_subs=subs)


class TestBasicScope:
    def test_same_domain(self):
        s = sg("https://target.com")
        assert s.in_scope("https://target.com/api/v1")

    def test_root(self):
        assert sg("https://target.com").in_scope("https://target.com/")

    def test_external_blocked(self):
        assert not sg("https://target.com").in_scope("https://evil.com/")

    def test_cdn_blocked(self):
        assert not sg("https://target.com").in_scope("https://cdn.jsdelivr.net/npm/jquery.js")

    def test_analytics_blocked(self):
        assert not sg("https://target.com").in_scope("https://www.google-analytics.com/analytics.js")

    def test_suffix_attack_blocked(self):
        assert not sg("https://target.com").in_scope("https://target.com.evil.com/")

    def test_partial_match_blocked(self):
        assert not sg("https://target.com").in_scope("https://notarget.com/")


class TestSubdomains:
    def test_sub_blocked_by_default(self):
        assert not sg("https://target.com").in_scope("https://sub.target.com/")

    def test_sub_allowed_with_flag(self):
        assert sg("https://target.com", subs=True).in_scope("https://sub.target.com/")

    def test_deep_sub_allowed(self):
        assert sg("https://target.com", subs=True).in_scope("https://a.b.target.com/")

    def test_unrelated_still_blocked_with_subs(self):
        assert not sg("https://target.com", subs=True).in_scope("https://evil.com/")


class TestPortAwareness:
    def test_correct_port(self):
        assert sg("https://target.com:8443").in_scope("https://target.com:8443/api")

    def test_wrong_port_blocked(self):
        assert not sg("https://target.com:8443").in_scope("https://target.com/api")

    def test_different_port_blocked(self):
        assert not sg("https://target.com:8443").in_scope("https://target.com:9000/api")


class TestEndpointScope:
    def test_bare_path_always_ok(self):
        assert sg("https://target.com").in_scope_endpoint("/api/v1")

    def test_target_absolute_ok(self):
        assert sg("https://target.com").in_scope_endpoint("https://target.com/download")

    def test_external_absolute_blocked(self):
        assert not sg("https://target.com").in_scope_endpoint("https://cdn.example.com/jquery.js")


class TestMakeAbsolute:
    def test_path(self):
        assert sg("https://target.com").make_absolute("/api/v1") == "https://target.com/api/v1"

    def test_already_absolute(self):
        assert sg("https://target.com").make_absolute("https://target.com/x") == "https://target.com/x"

    def test_port_preserved(self):
        assert sg("https://target.com:8443").make_absolute("/api") == "https://target.com:8443/api"
