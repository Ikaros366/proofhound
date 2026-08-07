"""httpx 工具链端到端验收（M1）：安装 → scope 校验 → 沙箱执行 → 证据落盘。"""

from pathlib import Path

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.tools.egress import EgressPolicy
from proofhound.tools.installer import InstallError, ToolInstaller
from proofhound.tools.manifest import load_manifest
from proofhound.tools.sandbox import SandboxConfig, SandboxRunner

pytestmark = pytest.mark.docker

MANIFEST_PATH = (
    Path(__file__).parent.parent / "proofhound" / "tools" / "manifests" / "httpx.yaml"
)


@pytest.fixture(scope="session")
def httpx_tool(tmp_path_factory):
    """通过安装器获取真实 httpx（binary 配方，GitHub 白名单源 + SHA256）。

    session 级共享：整个测试会话只下载一次（对齐"绝不重复下载"纪律，
    也避免 GitHub 网络抖动导致反复安装）；失败时重试一次后 skip。
    """
    manifest = load_manifest(MANIFEST_PATH)
    tools_dir = tmp_path_factory.mktemp("tools") / "tools.d"
    installer = ToolInstaller(tools_dir)
    for attempt in (1, 2):
        try:
            installer.ensure(manifest)
            break
        except InstallError as exc:
            if attempt == 2:
                pytest.skip(f"httpx 安装失败（网络受限？）: {exc}")
    return tools_dir


def test_httpx_full_chain(tmp_path, docker_client, sandbox_image, http_server, httpx_tool):
    base_url, _, _ = http_server
    port = int(base_url.rsplit(":", 1)[1])

    scope = Scope(networks=["127.0.0.0/8"], ports=[port])
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    runner = SandboxRunner(
        scope,
        audit,
        evidence_dir=tmp_path / "evidence",
        tools_dir=httpx_tool,
        config=SandboxConfig(
            image=sandbox_image,
            network_mode="host",
            egress=EgressPolicy(mode="open"),
        ),
        client=docker_client,
    )

    # 1. scope 内目标：完整链路
    result = runner.run(
        "httpx",
        ["-u", base_url, "-status-code", "-silent", "-no-color"],
        timeout=120,
    )
    assert not result.rejected
    assert result.exit_code == 0
    stdout = result.stdout_path.read_text(encoding="utf-8")
    assert base_url in stdout
    assert "[200]" in stdout

    # 2. scope 外目标：拒绝且不执行
    rejected = runner.run("httpx", ["-u", "https://www.example.com", "-silent"])
    assert rejected.rejected

    # 3. 审计证据链完整：一条 executed + 一条 rejected
    events = audit.read_all()
    assert [e["event"] for e in events] == ["command_executed", "command_rejected"]
    executed = events[0]
    assert executed["tool"] == "httpx"
    assert executed["targets"] == ["127.0.0.1"]
    assert executed["exit_code"] == 0
    assert Path(executed["stdout_path"]).is_file()
    assert len(executed["stdout_sha256"]) == 64


def test_httpx_reinstall_skipped(httpx_tool):
    """同版本重复安装必须跳过（验收标准）。"""
    manifest = load_manifest(MANIFEST_PATH)
    installer = ToolInstaller(httpx_tool)
    result = installer.ensure(manifest)
    assert result.status == "skipped"


def test_httpx_full_chain_restricted_egress(
    tmp_path, docker_client, sandbox_image, http_server, httpx_tool
):
    """M2a：restricted 出口白名单下的 httpx 完整链路（经白名单代理出站）。"""
    base_url, _, _ = http_server
    port = int(base_url.rsplit(":", 1)[1])

    scope = Scope(networks=["127.0.0.0/8"], ports=[port])
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    runner = SandboxRunner(
        scope,
        audit,
        evidence_dir=tmp_path / "evidence",
        tools_dir=httpx_tool,
        config=SandboxConfig(image=sandbox_image),  # egress 默认 restricted
        client=docker_client,
    )
    try:
        # scope 内目标：经白名单代理正常完成
        # （httpx 不读 proxy 环境变量，须显式传 -proxy；代理地址是基础设施
        # 端点，scope 校验会剔除它，实际外联由代理白名单强制）
        result = runner.run(
            "httpx",
            [
                "-u", base_url,
                "-proxy", runner.egress_proxy_url,
                "-status-code", "-silent", "-no-color",
            ],
            timeout=120,
        )
        assert not result.rejected
        assert result.exit_code == 0
        assert "[200]" in result.stdout_path.read_text(encoding="utf-8")

        # scope 外目标：命令层拒绝，不启动容器
        rejected = runner.run("httpx", ["-u", "https://www.example.com", "-silent"])
        assert rejected.rejected
    finally:
        runner.close()

    executed = [e for e in audit.read_all() if e["event"] == "command_executed"]
    assert executed[0]["egress"]["mode"] == "restricted"
