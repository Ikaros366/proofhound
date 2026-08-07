"""最小编排器单元测试（M2b）：fake runner（不碰 Docker）+ mock LLM。

覆盖验收点：
- 全链路：计划 → 构造 argv → 执行 → Signal 落盘 → 审计链完整；
- 失败预算命中 → 子任务 blocked 且不再重试（runner 调用次数 == 2）；
- scope 拒绝 / 计划非法 → failed 且不重试。
"""

import json
import uuid
from pathlib import Path

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.orchestrator import Orchestrator
from proofhound.core.tasks import TaskStatus
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.sandbox import RunResult

TARGET = "http://127.0.0.1:8000"


class FakeLLM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = 0

    def complete(self, messages):
        self.calls += 1
        return self.replies.pop(0)


class FakeRunner:
    """SandboxRunner 的替身：不写容器，把给定输出写进 evidence 文件。"""

    egress_proxy_url = None

    def __init__(self, evidence_dir, handler):
        self.evidence_dir = Path(evidence_dir)
        self.handler = handler  # (tool, args) -> (exit_code, stdout, stderr) | "reject"
        self.calls = []

    def run(self, tool, args, timeout=300):
        self.calls.append([tool, *args])
        outcome = self.handler(tool, args)
        if outcome == "reject":
            return RunResult(
                rejected=True, command=[tool, *args], violations=["越界目标"]
            )
        exit_code, stdout, stderr = outcome
        uid = uuid.uuid4().hex[:12]
        stdout_path = self.evidence_dir / f"{uid}.stdout.log"
        stderr_path = self.evidence_dir / f"{uid}.stderr.log"
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        return RunResult(
            rejected=False,
            command=[tool, *args],
            exit_code=exit_code,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )


def _run_tool_plan(target=TARGET):
    return json.dumps(
        {
            "actions": [
                {
                    "action": "run_tool",
                    "skill": "web-scan",
                    "tool": "httpx",
                    "params": {"target": target},
                    "expected_output": "signals",
                }
            ]
        }
    )


HTTPX_JSONL = (
    '{"url":"http://127.0.0.1:8000","status_code":200,"title":"Index",'
    '"tech":["nginx"]}\n'
)


@pytest.fixture
def registry(make_skill_dir):
    return SkillRegistry(make_skill_dir()).discover()


def _make_orchestrator(registry, tmp_path, replies, handler):
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    runner = FakeRunner(tmp_path / "evidence", handler)
    llm = FakeLLM(replies)
    orch = Orchestrator(
        registry,
        runner,
        llm,
        audit,
        evidence_dir=tmp_path / "evidence",
    )
    return orch, runner, llm, audit


def test_full_chain(registry, tmp_path):
    orch, runner, llm, audit = _make_orchestrator(
        registry,
        tmp_path,
        [_run_tool_plan()],
        lambda tool, args: (0, HTTPX_JSONL, ""),
    )
    phase = orch.run_scan_phase([TARGET])

    assert phase.status == TaskStatus.DONE
    assert len(phase.children) == 1
    node = phase.children[0]
    assert node.status == TaskStatus.DONE
    assert node.attempts == 1

    # argv 由构造器产出（红线 1），不是 LLM 文本
    assert runner.calls == [
        [
            "httpx", "-u", TARGET,
            "-status-code", "-title", "-tech-detect", "-follow-redirects",
            "-rate-limit", "50", "-json", "-silent", "-no-color",
        ]
    ]

    # Signal 落盘
    signals_files = list((tmp_path / "evidence").glob("*.signals.jsonl"))
    assert len(signals_files) == 1
    lines = signals_files[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    signal = json.loads(lines[0])
    assert signal["asset"] == TARGET
    assert signal["status_code"] == 200
    assert signal["tech"] == ["nginx"]
    assert signal["skill"] == "web-scan"
    assert "#L1" in signal["evidence_ref"]

    # 审计链：阶段/子任务状态迁移 + 计划 + signals
    events = [e["event"] for e in audit.read_all()]
    assert "plan_generated" in events
    assert "signals_recorded" in events
    states = [
        (e["name"], e["to"])
        for e in audit.read_all()
        if e["event"] == "task_state"
    ]
    assert ("phase:scan", "running") in states
    assert (f"scan:{TARGET}", "running") in states
    assert (f"scan:{TARGET}", "done") in states
    assert ("phase:scan", "done") in states


def test_failure_budget_blocks_and_stops(registry, tmp_path):
    """同类失败 2 次后 blocked，不再发起第 3 次执行。"""
    orch, runner, llm, audit = _make_orchestrator(
        registry,
        tmp_path,
        [_run_tool_plan(), _run_tool_plan(), _run_tool_plan()],
        lambda tool, args: (1, "", "429 Too Many Requests"),
    )
    phase = orch.run_scan_phase([TARGET])

    node = phase.children[0]
    assert node.status == TaskStatus.BLOCKED
    assert phase.status == TaskStatus.BLOCKED
    assert runner.calls and len(runner.calls) == 2  # 预算上限，无第 3 次
    assert node.failure_counts == {"ratelimit": 2}

    events = audit.read_all()
    blocked = [e for e in events if e["event"] == "task_blocked"]
    assert len(blocked) == 1
    assert blocked[0]["category"] == "ratelimit"
    attempts = [e for e in events if e["event"] == "attempt_failed"]
    assert [e["count"] for e in attempts] == [1, 2]


def test_scope_rejection_fails_without_retry(registry, tmp_path):
    orch, runner, llm, audit = _make_orchestrator(
        registry, tmp_path, [_run_tool_plan()], lambda tool, args: "reject"
    )
    phase = orch.run_scan_phase([TARGET])

    node = phase.children[0]
    assert node.status == TaskStatus.FAILED
    assert len(runner.calls) == 1  # 规划缺陷不重试
    assert llm.calls == 1


def test_invalid_plan_fails_without_execution(registry, tmp_path):
    orch, runner, _, audit = _make_orchestrator(
        registry, tmp_path, ["根本不是 JSON"], lambda tool, args: (0, "", "")
    )
    phase = orch.run_scan_phase([TARGET])

    assert phase.children[0].status == TaskStatus.FAILED
    assert runner.calls == []
    assert any(e["event"] == "plan_rejected" for e in audit.read_all())


def test_multi_target_parallel(registry, tmp_path):
    targets = ["http://127.0.0.1:8000", "http://127.0.0.1:8001"]
    orch, runner, _, _ = _make_orchestrator(
        registry,
        tmp_path,
        [_run_tool_plan(t) for t in targets],
        lambda tool, args: (0, HTTPX_JSONL, ""),
    )
    phase = orch.run_scan_phase(targets)

    assert phase.status == TaskStatus.DONE
    assert [c.status for c in phase.children] == [TaskStatus.DONE] * 2
    assert len(runner.calls) == 2
    ran_targets = {call[call.index("-u") + 1] for call in runner.calls}
    assert ran_targets == set(targets)


def test_unknown_skill_raises(registry, tmp_path):
    orch, _, _, _ = _make_orchestrator(
        registry, tmp_path, [], lambda tool, args: (0, "", "")
    )
    with pytest.raises(KeyError):
        orch.run_scan_phase([TARGET], skill_name="ghost")
