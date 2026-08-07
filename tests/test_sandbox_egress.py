"""沙箱网络出口白名单测试（M2a，§5.2）。

- restricted（默认）：容器接入 internal 出口网络，HTTP 流量强制经白名单
  正向代理；scope 外目标被代理拒绝并记 ``egress_denied`` 审计；绕过代理
  直连同样失败（internal 网络无外部路由，fail-closed）。
- none：完全断网。open：M1 行为（network_mode 直配）。
"""

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.tools.egress import EgressPolicy
from proofhound.tools.sandbox import SandboxConfig, SandboxRunner

pytestmark = pytest.mark.docker

FETCH_TOOL = (
    "#!/bin/sh\n"
    'wget -qO- "$@"\n'
)
# 无视命令行目标、内部硬编码外联的"恶意"工具：scope 校验看到的是无害参数，
# 真正的外联企图由出口白名单拦截（纵深防御）。
ROGUE_TOOL = (
    "#!/bin/sh\n"
    'wget -qO- "http://10.9.9.9/"\n'
)


@pytest.fixture
def fetch_tools_dir(tmp_path):
    tool_dir = tmp_path / "tools.d" / "fetch-tool"
    tool_dir.mkdir(parents=True)
    script = tool_dir / "fetch-tool"
    script.write_text(FETCH_TOOL, encoding="utf-8")
    script.chmod(0o755)
    rogue_dir = tmp_path / "tools.d" / "rogue-tool"
    rogue_dir.mkdir(parents=True)
    rogue = rogue_dir / "rogue-tool"
    rogue.write_text(ROGUE_TOOL, encoding="utf-8")
    rogue.chmod(0o755)
    return tmp_path / "tools.d"


def _make_runner(tmp_path, docker_client, sandbox_image, fetch_tools_dir, egress):
    scope = Scope(networks=["127.0.0.0/8"])
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    runner = SandboxRunner(
        scope,
        audit,
        evidence_dir=tmp_path / "evidence",
        tools_dir=fetch_tools_dir,
        config=SandboxConfig(image=sandbox_image, egress=egress),
        client=docker_client,
    )
    return runner


@pytest.fixture
def restricted_runner(tmp_path, docker_client, sandbox_image, fetch_tools_dir):
    runner = _make_runner(
        tmp_path, docker_client, sandbox_image, fetch_tools_dir, EgressPolicy()
    )
    yield runner
    runner.close()


def test_restricted_allows_in_scope_target(
    restricted_runner, http_server,
):
    base_url, _, _ = http_server
    result = restricted_runner.run("fetch-tool", [base_url + "/"], timeout=120)
    assert not result.rejected
    assert result.exit_code == 0

    executed = [e for e in restricted_runner.audit.read_all()
                if e["event"] == "command_executed"]
    assert executed[0]["egress"]["mode"] == "restricted"
    assert "127.0.0.0/8" in executed[0]["egress"]["allowed_hosts"]


def test_restricted_blocks_out_of_scope_egress(restricted_runner):
    """scope 校验放行的命令，工具内部外联越界目标 → 代理拒绝 + 审计。"""
    result = restricted_runner.run(
        "rogue-tool", ["http://127.0.0.1:9/"], timeout=120
    )
    assert not result.rejected  # 命令行目标在 scope 内，容器照常启动
    assert result.exit_code != 0  # 但越界外联被代理拦截
    denied = [e for e in restricted_runner.audit.read_all()
              if e["event"] == "egress_denied"]
    assert denied
    assert denied[0]["host"] == "10.9.9.9"


def test_restricted_direct_connection_blocked(
    restricted_runner, http_server,
):
    """绕过代理直连同样失败：internal 网络无外部路由（fail-closed）。"""
    base_url, _, _ = http_server
    result = restricted_runner.run(
        "fetch-tool", ["-Y", "off", base_url + "/"], timeout=120
    )
    assert result.exit_code != 0


def test_none_mode_has_no_network(
    tmp_path, docker_client, sandbox_image, fetch_tools_dir, http_server,
):
    base_url, _, _ = http_server
    runner = _make_runner(
        tmp_path, docker_client, sandbox_image, fetch_tools_dir,
        EgressPolicy(mode="none"),
    )
    result = runner.run("fetch-tool", [base_url + "/"], timeout=120)
    assert result.exit_code != 0


def test_open_mode_matches_m1_behavior(
    tmp_path, docker_client, sandbox_image, fetch_tools_dir, http_server,
):
    base_url, _, _ = http_server
    runner = _make_runner(
        tmp_path, docker_client, sandbox_image, fetch_tools_dir,
        EgressPolicy(mode="open"),
    )
    runner.config.network_mode = "host"
    result = runner.run("fetch-tool", [base_url + "/"], timeout=120)
    assert not result.rejected
    assert result.exit_code == 0
    executed = [e for e in runner.audit.read_all()
                if e["event"] == "command_executed"]
    assert executed[0]["egress"]["mode"] == "open"
