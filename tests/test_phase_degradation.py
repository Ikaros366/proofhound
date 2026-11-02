"""M27：``with_session`` 按实际会话派生 + 阶段失败必须可观测。

两条回归都来自同一个真实现象——"控制台点一下，5 秒全绿跑完，0 个发现"：

1. ``skills/recon-crawl/SKILL.md`` 把 ``with_session`` 写成固定 ``true``，而构造器
   对"声明 true 却无会话"是 fail-closed 的。M9a 之后"只填 target 就建任务"是默认
   路径（cookie 是可选框），于是默认路径上爬行面 100% 在命令构造处挂掉。
2. ``EngagementRunner._scan()`` 失败不抛异常，engagement 照样
   ``DONE("全部阶段完成")``，详情接口只回 state —— 控制台五段全绿。

不碰 Docker、不调真模型：编排器用 FakeRunner，API 用 FakePhases 替身。
"""

from __future__ import annotations

import json
import shutil
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core.orchestrator import Orchestrator
from proofhound.core.plan import PlanAction
from proofhound.core.tasks import TaskNode, TaskStatus
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.sandbox import RunResult

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET = "http://127.0.0.1:8000"
COOKIE_VALUE = "deadbeefcafe1234"


# ---- 编排器层：with_session 由实际会话派生 ----


class FakeRunner:
    """沙箱 runner 替身：不启容器，只记录 argv。"""

    egress_proxy_url = None

    def __init__(self, evidence_dir, scope=None):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.scope = scope
        self.calls: list[list[str]] = []

    def run(self, tool, args, timeout=300, image=None):
        self.calls.append([tool, *args])
        uid = uuid.uuid4().hex[:12]
        stdout_path = self.evidence_dir / f"{uid}.stdout.log"
        stderr_path = self.evidence_dir / f"{uid}.stderr.log"
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        return RunResult(
            rejected=False,
            command=[tool, *args],
            exit_code=0,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )


class _NoLLM:
    """本测试走不到规划层；被调用即说明测试写错了。"""

    def complete(self, messages):
        raise AssertionError("本测试不应触发 LLM 调用")


class _SkillStub:
    name = "recon-crawl"


@pytest.fixture
def registry(make_skill_dir):
    return SkillRegistry(make_skill_dir()).discover()


def _orch(registry, tmp_path, scope=None):
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    runner = FakeRunner(tmp_path / "evidence", scope=scope)
    orch = Orchestrator(
        registry, runner, _NoLLM(), audit, evidence_dir=tmp_path / "evidence"
    )
    return orch, runner, audit


def _katana_action() -> PlanAction:
    """SOP 里的原样动作：``with_session`` 固定 true（模板文字）。"""
    return PlanAction(
        action="run_tool",
        skill="recon-crawl",
        tool="katana",
        params={"target": TARGET, "with_session": True},
        expected_output="param-endpoint Signals",
    )


def _running_node() -> TaskNode:
    node = TaskNode(name=f"scan:{TARGET}", meta={"target": TARGET})
    node.transition(TaskStatus.RUNNING, reason="子任务启动")
    return node


def test_with_session_downgraded_to_anonymous_when_no_session(registry, tmp_path):
    """声明 true 但 scope 无会话：降级匿名执行，**不再**整个子任务失败。"""
    orch, runner, audit = _orch(registry, tmp_path, scope=Scope(networks=["127.0.0.0/8"]))
    node = _running_node()

    outcome = orch._exec_run_tool(node, _katana_action(), skill=_SkillStub())

    assert outcome == "ok"
    assert node.status is TaskStatus.RUNNING  # 未被判 failed
    argv = runner.calls[0]
    assert argv[0] == "katana"
    assert "-H" not in argv  # 没有凭空注入凭据
    assert TARGET in argv

    events = [event["event"] for event in audit.read_all()]
    assert "session_injection_skipped" in events


def test_with_session_kept_when_session_configured(registry, tmp_path):
    """有会话时原样透传：构造器注入 ``-H Cookie``，且不记降级事件。"""
    scope = Scope(
        networks=["127.0.0.0/8"],
        session=SessionConfig(cookies={"sid": COOKIE_VALUE}),
    )
    orch, runner, audit = _orch(registry, tmp_path, scope=scope)
    node = _running_node()

    assert orch._exec_run_tool(node, _katana_action(), skill=_SkillStub()) == "ok"

    argv = runner.calls[0]
    assert "-H" in argv
    joined = " ".join(argv)
    assert "sid=" in joined
    # 凭据原文只在 argv 里交给沙箱，审计里只允许出现脱敏标记
    events = [event["event"] for event in audit.read_all()]
    assert "session_injection_skipped" not in events
    assert COOKIE_VALUE not in json.dumps(audit.read_all(), ensure_ascii=False)


def test_without_session_declaration_is_untouched(registry, tmp_path):
    """规划器没声明 with_session：一个字节都不改，也不记审计噪音。"""
    orch, runner, audit = _orch(registry, tmp_path)
    action = _katana_action()
    action.params.pop("with_session")
    node = _running_node()

    assert orch._exec_run_tool(node, action, skill=_SkillStub()) == "ok"

    assert "-H" not in runner.calls[0]
    assert "session_injection_skipped" not in [
        event["event"] for event in audit.read_all()
    ]


# ---- API 层：阶段失败必须冒到详情与终态理由 ----


class DegradedPhases:
    """scan 阶段固定失败（复刻 with_session fail-closed 那条失败形态）。"""

    scan_skill = "web-scan"
    scan_risk_level = "L1"
    verify_skill = "verify-sqli"
    verify_risk_level = "L2"

    def __init__(self, runtime):
        self.dir = runtime.engagement.dir
        self.target = runtime.engagement.target
        self.audit = runtime.audit

    def scan(self, targets: list[str]) -> TaskNode:
        phase = TaskNode(name="phase:scan", kind="phase")
        phase.transition(TaskStatus.RUNNING, reason="scan 阶段启动")
        child = TaskNode(name=f"scan:{self.target}", meta={"target": self.target})
        child.transition(TaskStatus.RUNNING, reason="子任务启动")
        child.transition(
            TaskStatus.FAILED,
            reason="命令构造失败（规划缺陷）: with_session=True 要求 scope 配置预置会话",
        )
        phase.children.append(child)
        phase.transition(TaskStatus.FAILED, reason="阶段聚合")
        return phase

    def triage(self) -> list:
        return []

    def verify_covered_vuln_types(self) -> frozenset[str]:
        return frozenset()

    def verify(self) -> list:
        return []


class CleanPhases(DegradedPhases):
    """旧式 phases：scan 返回 None（拿不到节点）——不得凭空造降级态。"""

    def scan(self, targets: list[str]):
        return None


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "scope.yaml").write_text("networks: [127.0.0.0/8]\n", encoding="utf-8")
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    shutil.copyfile(
        REPO_ROOT / "templates" / "default_template.docx",
        templates_dir / "default_template.docx",
    )
    return tmp_path


def _run_to_done(client, workspace) -> str:
    resp = client.post(
        "/api/engagements",
        json={"target": "http://127.0.0.1:8080", "scope_paths": ["scope.yaml"]},
    )
    assert resp.status_code == 201, resp.text
    eng_id = resp.json()["id"]
    assert client.post(f"/api/engagements/{eng_id}/run").status_code == 202

    deadline = time.monotonic() + 15.0
    state = None
    while time.monotonic() < deadline:
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state in {"done", "failed"}:
            return eng_id
        time.sleep(0.05)
    raise AssertionError(f"等待终态超时，当前状态: {state}")


def test_scan_failure_surfaces_as_degraded(workspace):
    app = create_app(
        workspace,
        phases_factory=lambda runtime: DegradedPhases(runtime),
        confirm_timeout=30.0,
    )
    with TestClient(app) as client:
        eng_id = _run_to_done(client, workspace)
        detail = client.get(f"/api/engagements/{eng_id}").json()

        assert detail["state"] == "done"  # 主链路仍走完
        assert detail["degraded"] is True  # 但不再是"干净完成"
        scan = [r for r in detail["phases"] if r["phase"] == "scan"]
        assert len(scan) == 1
        assert scan[0]["status"] == "failed"
        assert "with_session" in scan[0]["reason"]

        events = client.get(f"/api/engagements/{eng_id}/audit").json()["events"]
        done = [
            event
            for event in events
            if event["event"] == "engagement_state" and event["to"] == "done"
        ]
        assert done and "降级" in done[-1]["reason"]
        assert any(event["event"] == "engagement_degraded" for event in events)


def test_clean_run_stays_not_degraded(workspace):
    app = create_app(
        workspace,
        phases_factory=lambda runtime: CleanPhases(runtime),
        confirm_timeout=30.0,
    )
    with TestClient(app) as client:
        eng_id = _run_to_done(client, workspace)
        detail = client.get(f"/api/engagements/{eng_id}").json()

        assert detail["state"] == "done"
        assert detail["degraded"] is False
        assert [r["status"] for r in detail["phases"] if r["phase"] == "scan"] == ["done"]
        events = client.get(f"/api/engagements/{eng_id}/audit").json()["events"]
        assert not any(event["event"] == "engagement_degraded" for event in events)


def test_phases_survive_restart(workspace):
    """阶段终态落在 api.json：重建 app 后仍读得到（不依赖内存态）。"""
    factory = lambda runtime: DegradedPhases(runtime)  # noqa: E731
    app = create_app(workspace, phases_factory=factory, confirm_timeout=30.0)
    with TestClient(app) as client:
        eng_id = _run_to_done(client, workspace)

    app2 = create_app(workspace, phases_factory=factory, confirm_timeout=30.0)
    with TestClient(app2) as client:
        detail = client.get(f"/api/engagements/{eng_id}").json()
        assert detail["degraded"] is True
        assert any(r["status"] == "failed" for r in detail["phases"])
