"""Scope 校验测试（红线 5：授权前置）。"""

import pytest

from proofhound.compliance.scope import (
    Scope,
    Target,
    check_scope,
    extract_targets,
)


class TestExtractTargets:
    def test_url_with_port(self):
        targets = extract_targets(["-u", "https://sub.example.com:8443/path?q=1"])
        assert targets == [Target(host="sub.example.com", port=8443, is_ip=False)]

    def test_bare_ip_and_host_port(self):
        targets = extract_targets(["10.0.1.5", "example.com:8080"])
        assert Target(host="10.0.1.5", is_ip=True) in targets
        assert Target(host="example.com", port=8080) in targets

    def test_flags_and_values_skipped(self):
        assert extract_targets(["-silent", "-rate-limit", "100"]) == []

    def test_dedupe_keeps_order(self):
        targets = extract_targets(["a.example.com", "b.example.com", "a.example.com"])
        assert [t.host for t in targets] == ["a.example.com", "b.example.com"]

    def test_invalid_port_ignored(self):
        assert extract_targets(["example.com:99999"]) == []


class TestCheckScope:
    scope = Scope(
        domains=["example.com"], networks=["10.0.0.0/8"], ports=[80, 443, 8443]
    )

    def test_exact_domain_and_subdomain(self):
        assert check_scope(self.scope, ["example.com"]).allowed
        assert check_scope(self.scope, ["https://api.example.com/"]).allowed

    def test_domain_not_in_scope(self):
        decision = check_scope(self.scope, ["https://evil.com/"])
        assert not decision.allowed
        assert any("evil.com" in v for v in decision.violations)

    def test_ip_in_cidr(self):
        assert check_scope(self.scope, ["10.9.9.9"]).allowed

    def test_ip_out_of_cidr(self):
        decision = check_scope(self.scope, ["192.168.1.1"])
        assert not decision.allowed

    def test_port_restriction(self):
        assert check_scope(self.scope, ["https://example.com:443/"]).allowed
        assert check_scope(self.scope, ["https://example.com:8443/"]).allowed
        decision = check_scope(self.scope, ["https://example.com:22/"])
        assert not decision.allowed
        assert any("端口 22" in v for v in decision.violations)

    def test_empty_ports_means_no_restriction(self):
        scope = Scope(domains=["example.com"])
        assert check_scope(scope, ["https://example.com:12345/"]).allowed

    def test_one_violation_fails_whole_command(self):
        decision = check_scope(
            self.scope, ["example.com", "https://evil.com/"]
        )
        assert not decision.allowed

    def test_no_targets_rejected_by_default(self):
        """M2a 起：未识别出目标默认拒绝（消除 no_targets 放行口子）。"""
        decision = check_scope(self.scope, ["-silent", "-json"])
        assert not decision.allowed
        assert decision.no_targets

    def test_no_targets_allowed_only_when_explicit(self):
        decision = check_scope(
            self.scope, ["-silent", "-json"], allow_no_targets=True
        )
        assert decision.allowed
        assert decision.no_targets


def test_scope_from_file(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text(
        "domains: [example.com]\nnetworks: ['10.0.0.0/8']\nports: [80]\n",
        encoding="utf-8",
    )
    scope = Scope.from_file(path)
    assert scope.domains == ["example.com"]
    assert check_scope(scope, ["http://example.com:80/"]).allowed
    assert not check_scope(scope, ["http://example.com:8080/"]).allowed
