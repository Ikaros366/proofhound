"""Docker 沙箱执行器测试（§5.2/§5.8：只读挂载、配额、scope 前置）。"""

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.tools.egress import EgressPolicy
from proofhound.tools.sandbox import SandboxConfig, SandboxRunner

pytestmark = pytest.mark.docker


@pytest.fixture
def runner(tmp_path, docker_client, sandbox_image, fake_tools_dir):
    scope = Scope(networks=["127.0.0.0/8"])
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    return SandboxRunner(
        scope,
        audit,
        evidence_dir=tmp_path / "evidence",
        tools_dir=fake_tools_dir,
        # 本文件聚焦配额/只读挂载/scope 前置，出口策略显式置 open 保持 M1 语义；
        # 出口白名单行为见 test_sandbox_egress.py
        config=SandboxConfig(
            image=sandbox_image, egress=EgressPolicy(mode="open")
        ),
        client=docker_client,
    )


def _spy_create(monkeypatch):
    from docker.models.containers import ContainerCollection

    calls = []
    original = ContainerCollection.create

    def spy(self, *args, **kwargs):
        calls.append(kwargs)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(ContainerCollection, "create", spy)
    return calls


def test_allowed_command_runs_in_sandbox(runner, tmp_path):
    result = runner.run("echo-tool", ["hello", "http://127.0.0.1:9/"])

    assert not result.rejected
    assert result.exit_code == 0
    stdout = result.stdout_path.read_text(encoding="utf-8")
    assert "args: hello http://127.0.0.1:9/" in stdout

    events = runner.audit.read_all()
    assert len(events) == 1
    entry = events[0]
    assert entry["event"] == "command_executed"
    assert entry["exit_code"] == 0
    assert entry["targets"] == ["127.0.0.1"]
    assert entry["stdout_path"] == str(result.stdout_path)


def test_tool_dir_mounted_read_only(runner):
    result = runner.run("echo-tool", ["http://127.0.0.1:9/"])
    assert result.exit_code == 0
    assert "READONLY" in result.stdout_path.read_text(encoding="utf-8")


def test_cpu_mem_quota_and_readonly_mount_passed(runner, monkeypatch):
    calls = _spy_create(monkeypatch)
    runner.run("echo-tool", ["http://127.0.0.1:9/"])

    assert len(calls) == 1
    assert calls[0]["nano_cpus"] == runner.config.nano_cpus
    assert calls[0]["mem_limit"] == runner.config.mem_limit
    assert calls[0]["mounts"][0]["ReadOnly"] is True


def test_out_of_scope_command_rejected_without_container(runner, monkeypatch):
    calls = _spy_create(monkeypatch)
    result = runner.run("echo-tool", ["http://evil.example.com/"])

    assert result.rejected
    assert result.exit_code is None
    assert result.violations
    assert calls == []  # 越界命令不得启动容器

    events = runner.audit.read_all()
    assert len(events) == 1
    assert events[0]["event"] == "command_rejected"
    assert any("evil.example.com" in v for v in events[0]["violations"])


def test_port_out_of_scope_rejected(tmp_path, docker_client, sandbox_image, fake_tools_dir):
    scope = Scope(networks=["127.0.0.0/8"], ports=[80])
    audit = AuditLog(tmp_path / "audit.jsonl")
    runner = SandboxRunner(
        scope, audit, tmp_path / "evidence", fake_tools_dir,
        config=SandboxConfig(image=sandbox_image), client=docker_client,
    )
    result = runner.run("echo-tool", ["http://127.0.0.1:8080/"])
    assert result.rejected
    assert any("端口 8080" in v for v in result.violations)


def test_no_targets_command_rejected(runner, monkeypatch):
    """M2a 起：整条命令未识别出目标默认拒绝，不启动容器。"""
    calls = _spy_create(monkeypatch)
    result = runner.run("echo-tool", ["-silent", "-json"])

    assert result.rejected
    assert result.no_targets
    assert calls == []

    events = runner.audit.read_all()
    assert len(events) == 1
    assert events[0]["event"] == "command_rejected"
    assert events[0]["no_targets"] is True
