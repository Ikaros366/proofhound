"""M3b DVWA 实靶端到端验收（docker，可选）：真 DVWA + 真 sqlmap，mock T2。

链路：DVWA 容器就绪（create_db + 确定性登录）→ 种子 sqli Hypothesis →
run_verify_phase（带会话 baseline → 沙箱 sqlmap → 证据门 → Verifier mock
confirm）→ Confirmed。DVWA 镜像/守护进程/工具安装任一不可用即自动 skip；
Verifier 用 mock T2（pytest 不打真实 LLM）。
"""

from __future__ import annotations

import importlib.util
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings import FindingState
from proofhound.llm.router import ModelRouter, Tier
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.egress import EgressPolicy
from proofhound.tools.installer import InstallError, ToolInstaller
from proofhound.tools.manifest import load_manifest
from proofhound.tools.sandbox import SandboxConfig, SandboxRunner

pytestmark = pytest.mark.docker

REPO_ROOT = Path(__file__).parent.parent
MANIFESTS = REPO_ROOT / "proofhound" / "tools" / "manifests"


def _load_demo():
    """按路径加载 scripts/demo_verify_dvwa.py（复用其 DVWA 就绪/登录助手）。"""
    spec = importlib.util.spec_from_file_location(
        "demo_verify_dvwa", REPO_ROOT / "scripts" / "demo_verify_dvwa.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _ConfirmRouter(ModelRouter):
    """mock T2：固定 confirm（不进真实 LLM）。"""

    def __init__(self):
        self.configs = {Tier.T2: SimpleNamespace(model="verifier-mock")}

    def complete(self, tier, messages):
        return '{"verdict": "confirm", "reason": "e2e mock：证据链完整", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'


@pytest.fixture(scope="session")
def tools_dir():
    """仓库 tools.d（安装即缓存）；缺失且装不上则 skip。"""
    installer = ToolInstaller(REPO_ROOT / "tools.d")
    for tool in ("httpx", "sqlmap"):
        try:
            installer.ensure(load_manifest(MANIFESTS / f"{tool}.yaml"))
        except InstallError as exc:
            pytest.skip(f"{tool} 安装失败（网络受限？）: {exc}")
    return REPO_ROOT / "tools.d"


def test_verify_phase_e2e_dvwa(docker_client, sandbox_image, tools_dir, tmp_path):
    demo = _load_demo()
    for image in ("python:3.12-alpine", demo.DVWA_IMAGE):
        try:
            docker_client.images.get(image)
        except Exception:
            try:
                docker_client.images.pull(image)
            except Exception as exc:
                pytest.skip(f"镜像 {image} 不可用: {exc}")

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    try:
        dvwa, container = demo.ensure_dvwa(docker_client, base_url, port)
    except Exception as exc:
        pytest.skip(f"DVWA 就绪失败: {exc}")
    try:
        evidence_dir = tmp_path / "evidence"
        audit = AuditLog(evidence_dir / "audit.jsonl")
        scope = Scope(
            networks=["127.0.0.0/8"],
            ports=[port],
            session=SessionConfig(cookies=dvwa.session_cookies()),
        )
        runner = SandboxRunner(
            scope,
            audit,
            evidence_dir=evidence_dir,
            tools_dir=tools_dir,
            config=SandboxConfig(
                image=sandbox_image,
                network_mode="host",
                egress=EgressPolicy(mode="open"),
            ),
            client=docker_client,
        )
        registry = SkillRegistry(REPO_ROOT / "skills", audit).discover()
        orch = Orchestrator(registry, runner, _ConfirmRouter(), audit, evidence_dir)

        demo.seed_finding.main([
            "--dir", str(evidence_dir),
            "--asset", f"{base_url}/vulnerabilities/sqli/?id=1&Submit=Submit",
            "--vuln-type", "sqli", "--param", "id",
        ])
        processed = orch.run_verify_phase(skill_name="verify-sqli")

        assert len(processed) == 1
        finding = processed[0]
        assert finding.state is FindingState.CONFIRMED
        assert finding.verification.method == "sqlmap-confirmed"
        assert "behavioral" in finding.evidence_kinds
        # 审计链无 Cookie 原文
        raw = audit.path.read_text(encoding="utf-8")
        assert dvwa.session_cookies()["PHPSESSID"] not in raw
    finally:
        if container is not None:
            container.stop()
