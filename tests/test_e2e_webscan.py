"""M2b 最小链路端到端验收（docker）：

加载 web-scan skill → 规划器产计划（mock LLM）→ 沙箱执行 httpx →
结构化 Signal 落盘 → 全链路审计。靶标为本地 HTTP 服务（conftest
http_server fixture），LLM 全程 mock，不发真实请求。
"""

import json
from pathlib import Path

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.core.orchestrator import Orchestrator
from proofhound.core.tasks import TaskStatus
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.egress import EgressPolicy
from proofhound.tools.installer import InstallError, ToolInstaller
from proofhound.tools.manifest import load_manifest
from proofhound.tools.sandbox import SandboxConfig, SandboxRunner

pytestmark = pytest.mark.docker

MANIFEST_PATH = (
    Path(__file__).parent.parent / "proofhound" / "tools" / "manifests" / "httpx.yaml"
)
SKILLS_DIR = Path(__file__).parent.parent / "skills"


@pytest.fixture(scope="session")
def httpx_tool(tmp_path_factory):
    """真实 httpx（binary 配方，白名单源 + SHA256）；会话级只装一次。"""
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


class CannedLLM:
    """返回固定计划的 mock LLM（e2e 不打真实 LLM 请求）。"""

    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def complete(self, messages):
        self.calls.append(messages)
        return self.reply


def test_webscan_minimal_chain(tmp_path, docker_client, sandbox_image, http_server, httpx_tool):
    base_url, _, _ = http_server
    port = int(base_url.rsplit(":", 1)[1])

    scope = Scope(networks=["127.0.0.0/8"], ports=[port])
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    registry = SkillRegistry(SKILLS_DIR, audit).discover()
    skill = registry.get("web-scan")
    assert skill is not None and skill.enabled

    llm = CannedLLM(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "run_tool",
                        "skill": "web-scan",
                        "tool": "httpx",
                        "params": {"target": base_url},
                        "expected_output": "signals",
                    }
                ]
            }
        )
    )
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
    orch = Orchestrator(
        registry, runner, llm, audit, evidence_dir=tmp_path / "evidence"
    )

    phase = orch.run_scan_phase([base_url])

    # 1. 任务树：阶段与子任务均 done
    assert phase.status == TaskStatus.DONE
    assert [c.status for c in phase.children] == [TaskStatus.DONE]

    # 2. 规划器确实被调用，且 prompt 含 skill SOP 正文与结构化状态
    assert len(llm.calls) == 1
    prompt = llm.calls[0][1]["content"]
    assert "httpx Web 探活与指纹采集" in prompt
    assert base_url in prompt

    # 3. Signal 落盘且字段齐全（含证据引用）
    signals_files = list((tmp_path / "evidence").glob("*.signals.jsonl"))
    assert len(signals_files) == 1
    signals = [
        json.loads(line)
        for line in signals_files[0].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert signals, "httpx 应至少产出一行 Signal"
    hit = [s for s in signals if s["asset"].rstrip("/") == base_url]
    assert hit, f"Signal 资产应覆盖靶标: {signals}"
    assert hit[0]["status_code"] == 200
    assert hit[0]["skill"] == "web-scan"
    ref = hit[0]["evidence_ref"]
    ref_path, _, lineno = ref.rpartition("#L")
    assert Path(ref_path).is_file() and int(lineno) >= 1

    # 4. 全链路审计：skill 注册 → 计划 → 状态迁移 → 命令执行 → Signal
    events = [e["event"] for e in audit.read_all()]
    assert "skill_registered" in events
    assert "plan_generated" in events
    assert "command_executed" in events
    assert "signals_recorded" in events
    executed = next(e for e in audit.read_all() if e["event"] == "command_executed")
    assert executed["tool"] == "httpx"
    assert executed["exit_code"] == 0
    # 命令由构造器产出：固定旗标齐全，不含 LLM 自由文本
    cmd = executed["command"]
    assert cmd[:2] == ["httpx", "-u"]
    assert base_url in cmd and "-json" in cmd and "-status-code" in cmd
