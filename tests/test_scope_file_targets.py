"""Scope 文件目标解析与 no_targets 默认拒绝（M2a，红线 5）。

覆盖验收硬指标：``-l`` 目标文件含越界目标必拒；未识别出目标默认拒绝。
"""

import pytest

from proofhound.compliance.scope import (
    Scope,
    Target,
    check_scope,
)


@pytest.fixture
def scope():
    return Scope(domains=["example.com"], networks=["10.0.0.0/8"])


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


class TestTargetFile:
    def test_file_all_in_scope_allowed(self, scope, tmp_path):
        f = _write(
            tmp_path,
            "targets.txt",
            "https://a.example.com/\n10.1.2.3\n# 注释行\n\nexample.com:443\n",
        )
        decision = check_scope(scope, ["httpx", "-l", str(f)])
        assert decision.allowed
        hosts = {t.host for t in decision.targets}
        assert hosts == {"a.example.com", "10.1.2.3", "example.com"}
        assert decision.file_targets == [str(f)]

    def test_file_with_out_of_scope_line_rejected(self, scope, tmp_path):
        """验收硬指标：目标文件任一行越界即整命令拒绝。"""
        f = _write(
            tmp_path,
            "targets.txt",
            "https://a.example.com/\nhttps://evil.com/\n",
        )
        decision = check_scope(scope, ["httpx", "-l", str(f)])
        assert not decision.allowed
        assert any("evil.com" in v for v in decision.violations)

    def test_file_missing_rejected(self, scope, tmp_path):
        decision = check_scope(scope, ["httpx", "-l", str(tmp_path / "nope.txt")])
        assert not decision.allowed
        assert any("不可读" in v for v in decision.violations)

    def test_file_unparseable_line_rejected(self, scope, tmp_path):
        f = _write(tmp_path, "targets.txt", "a.example.com\n???\n")
        decision = check_scope(scope, ["httpx", "-l", str(f)])
        assert not decision.allowed
        assert any("无法解析" in v for v in decision.violations)

    def test_empty_file_rejected_as_no_targets(self, scope, tmp_path):
        f = _write(tmp_path, "targets.txt", "# 只有注释\n\n")
        decision = check_scope(scope, ["httpx", "-l", str(f)])
        assert not decision.allowed
        assert decision.no_targets

    def test_equals_form(self, scope, tmp_path):
        f = _write(tmp_path, "targets.txt", "a.example.com\n")
        decision = check_scope(scope, ["httpx", f"--list={f}"])
        assert decision.allowed
        assert [t.host for t in decision.targets] == ["a.example.com"]

    def test_relative_path_resolved_against_base_dir(self, scope, tmp_path):
        _write(tmp_path, "targets.txt", "a.example.com\n")
        decision = check_scope(
            scope, ["httpx", "-l", "targets.txt"], base_dir=tmp_path
        )
        assert decision.allowed
        assert decision.file_targets == [str(tmp_path / "targets.txt")]

    def test_filename_not_misparsed_as_domain(self, scope, tmp_path):
        """被 -l 消费的文件名不再被裸域名正则误判为目标。"""
        f = _write(tmp_path, "targets.txt", "a.example.com\n")
        decision = check_scope(scope, ["httpx", "-l", str(f)])
        assert decision.allowed
        hosts = {t.host for t in decision.targets}
        assert hosts == {"a.example.com"}
        assert "targets.txt" not in hosts

    def test_output_filename_still_fail_closed(self, scope, tmp_path):
        """已知限制：``-o out.json`` 这类输出文件名仍会被误判为域名目标
        （fail-closed 方向，最多误拒，不会误放）。"""
        f = _write(tmp_path, "targets.txt", "a.example.com\n")
        decision = check_scope(scope, ["httpx", "-l", str(f), "-o", "out.json"])
        assert not decision.allowed
        assert any("out.json" in v for v in decision.violations)

    def test_mixed_file_and_cli_targets(self, scope, tmp_path):
        f = _write(tmp_path, "targets.txt", "10.1.1.1\n")
        decision = check_scope(
            scope, ["httpx", "-l", str(f), "-u", "https://b.example.com/"]
        )
        assert decision.allowed
        assert {t.host for t in decision.targets} == {"10.1.1.1", "b.example.com"}

    def test_custom_file_flags(self, scope, tmp_path):
        f = _write(tmp_path, "ips.txt", "10.1.1.1\n")
        decision = check_scope(
            scope, ["nmap", "-iL", str(f)], target_file_flags=("-iL",)
        )
        assert decision.allowed
        assert [t.host for t in decision.targets] == ["10.1.1.1"]

    def test_port_violation_in_file(self, tmp_path):
        scope = Scope(domains=["example.com"], ports=[443])
        f = _write(tmp_path, "targets.txt", "https://example.com:22/\n")
        decision = check_scope(scope, ["httpx", "-l", str(f)])
        assert not decision.allowed
        assert any("端口 22" in v for v in decision.violations)

    def test_proxy_flag_value_not_a_target(self, scope):
        """-proxy 的值是基础设施端点（白名单代理），不参与目标提取。"""
        decision = check_scope(
            scope,
            ["httpx", "-u", "https://a.example.com/", "-proxy", "http://172.18.0.1:18080"],
        )
        assert decision.allowed
        assert {t.host for t in decision.targets} == {"a.example.com"}


class TestNoTargetsPolicy:
    def test_no_targets_rejected_by_default(self, scope):
        decision = check_scope(scope, ["httpx", "-silent", "-json"])
        assert not decision.allowed
        assert decision.no_targets
        assert any("no_targets" in v for v in decision.violations)

    def test_no_targets_allowed_when_explicit(self, scope):
        decision = check_scope(
            scope, ["httpx", "-silent", "-json"], allow_no_targets=True
        )
        assert decision.allowed
        assert decision.no_targets
        assert decision.targets == []
