"""预置会话与凭据脱敏测试（M3b，§5.3 认证旁路第①条 + 脱敏纪律）。

核心断言：Cookie 值在审计、state、任何日志中只记 sha256 前 8 位——
全审计链（含 command_rejected / command_executed）不得出现 Cookie 原文。
"""

from __future__ import annotations

import json

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope, check_scope
from proofhound.compliance.session import (
    SessionConfig,
    redact_argv,
    redact_text,
    secret_marker,
)
from proofhound.tools.egress import EgressPolicy
from proofhound.tools.sandbox import SandboxConfig, SandboxRunner

COOKIE = "PHPSESSID=df6a4b9c0e1f2a3b4c5d6e7f890abcde; security=low"
SESSION = SessionConfig(
    cookies={"PHPSESSID": "df6a4b9c0e1f2a3b4c5d6e7f890abcde", "security": "low"},
    headers={"Authorization": "Bearer tok-secret-123"},
)


def test_cookie_header_rendering():
    assert SESSION.cookie_header() == COOKIE


def test_secret_values_cover_rendered_and_parts():
    values = SESSION.secret_values()
    assert COOKIE in values  # 完整 Cookie 头
    assert "PHPSESSID=df6a4b9c0e1f2a3b4c5d6e7f890abcde" in values  # k=v 对形态
    assert "security=low" in values
    assert "df6a4b9c0e1f2a3b4c5d6e7f890abcde" in values  # 长裸值
    assert "Bearer tok-secret-123" in values
    assert "Authorization: Bearer tok-secret-123" in values
    assert "low" not in values  # 短裸值豁免（防 collateral damage）
    assert "" not in values


def test_short_cookie_value_no_collateral_damage():
    """实靶回归：security=low 的裸值 low 不得替换坏 "following" 等正常单词。"""
    text = "sqlmap identified the following injection point(s) with a total of 182"
    assert redact_text(text, SESSION.secret_values()) == text
    # 但 k=v 对形态与完整 Cookie 头仍脱敏
    echoed = f"Cookie: {COOKIE}"
    redacted = redact_text(echoed, SESSION.secret_values())
    assert "df6a4b9c0e1f2a3b4c5d6e7f890abcde" not in redacted
    assert "security=low" not in redacted


def test_secret_marker_is_sha256_prefix8():
    marker = secret_marker(COOKIE)
    assert marker.startswith("sha256:")
    assert len(marker) == len("sha256:") + 8


def test_redact_text_replaces_all_forms():
    text = f"cmd --cookie '{COOKIE}' -H 'Authorization: Bearer tok-secret-123'"
    redacted = redact_text(text, SESSION.secret_values())
    assert "df6a4b9c0e1f2a3b4c5d6e7f890abcde" not in redacted
    assert "tok-secret-123" not in redacted
    assert "sha256:" in redacted


def test_redact_argv_does_not_mutate_input():
    argv = ["sqlmap", "--cookie", COOKIE]
    redacted = redact_argv(argv, SESSION.secret_values())
    assert argv[2] == COOKIE  # 原列表不变
    assert redacted[2].startswith("sha256:")


def test_scope_yaml_with_session_loads(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "domains: [example.com]\n"
        "session:\n"
        "  cookies: {PHPSESSID: abc, security: low}\n"
        "  headers: {X-Token: t1}\n",
        encoding="utf-8",
    )
    scope = Scope.from_file(scope_file)
    assert scope.session.cookie_header() == "PHPSESSID=abc; security=low"
    assert scope.session.headers == {"X-Token": "t1"}


def test_scope_yaml_without_session_still_loads(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("domains: [example.com]\n", encoding="utf-8")
    assert Scope.from_file(scope_file).session is None


def test_secret_flags_stripped_from_target_extraction():
    """cookie 值中的域名形态子串不得被误判为目标（fail-closed 再收紧）。"""
    scope = Scope(domains=["example.com"])
    argv = [
        "-u", "http://example.com/",
        "--cookie", "sessionid=track.evil.com; theme=dark",
        "-H", "Cookie: sid=another.bad.io",
    ]
    decision = check_scope(scope, argv)
    hosts = [t.host for t in decision.targets]
    assert hosts == ["example.com"]
    assert decision.allowed


def _runner(scope, audit, tmp_path, client):
    return SandboxRunner(
        scope,
        audit,
        evidence_dir=tmp_path / "evidence",
        tools_dir=tmp_path / "tools.d",
        config=SandboxConfig(egress=EgressPolicy(mode="none")),
        client=client,
    )


def test_rejected_command_audit_has_no_cookie(tmp_path):
    """拒径（不启动容器，无需 Docker）：审计中的命令必须脱敏。"""
    scope = Scope(domains=["example.com"], session=SESSION)
    audit = AuditLog(tmp_path / "audit.jsonl")
    runner = _runner(scope, audit, tmp_path, client=object())
    result = runner.run(
        "sqlmap",
        ["-u", "http://out-of-scope.example/", "--cookie", COOKIE, "--batch"],
    )
    assert result.rejected

    raw = audit.path.read_text(encoding="utf-8")
    assert "df6a4b9c0e1f2a3b4c5d6e7f890abcde" not in raw
    assert "security=low" not in raw
    assert "sha256:" in raw
    # 返回值中的命令同样脱敏
    assert all("df6a4b9c" not in token for token in result.command)


@pytest.mark.docker
def test_executed_command_audit_has_no_cookie(tmp_path, docker_client, sandbox_image, fake_tools_dir):
    """执行径（docker）：command_executed 审计中的命令必须脱敏。"""
    scope = Scope(networks=["127.0.0.0/8"], session=SESSION)
    audit = AuditLog(tmp_path / "audit.jsonl")
    runner = SandboxRunner(
        scope,
        audit,
        evidence_dir=tmp_path / "evidence",
        tools_dir=fake_tools_dir,
        config=SandboxConfig(image=sandbox_image, egress=EgressPolicy(mode="none")),
        client=docker_client,
    )
    result = runner.run(
        "echo-tool",
        ["http://127.0.0.1:8080/", "--cookie", COOKIE],
    )
    assert not result.rejected
    assert result.exit_code == 0

    raw = audit.path.read_text(encoding="utf-8")
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    executed = [e for e in events if e["event"] == "command_executed"]
    assert len(executed) == 1
    command_text = " ".join(executed[0]["command"])
    assert "df6a4b9c0e1f2a3b4c5d6e7f890abcde" not in command_text
    assert "sha256:" in command_text

    # 证据落盘同样脱敏（echo-tool 会把 --cookie 参数回显进 stdout）
    evidence = result.stdout_path.read_bytes()
    assert b"df6a4b9c0e1f2a3b4c5d6e7f890abcde" not in evidence
    assert b"sha256:" in evidence
    # 审计哈希与落盘内容一致（证据链不断裂）
    import hashlib

    assert executed[0]["stdout_sha256"] == hashlib.sha256(evidence).hexdigest()
