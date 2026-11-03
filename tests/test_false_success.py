"""M31-e：退出码 0 的**假成功**不得被记成成功（web-dirsearch 级回归）。

实测（eng-20261102T093506Z-aac47e3a）：dirsearch 走受限出口代理时打印

    Cannot establish the proxy connection          （stdout 全文，39 字节）

然后**仍以 exit 0 退出**。旧逻辑只看退出码 ⇒ ``signals_recorded count=0`` +
``phases: web-dirsearch=done`` + ``degraded=False`` + 终态理由"全部阶段完成"，
任务 26 秒"跑完"，而实际一次目录爆破请求都没发出去。

本文件在编排器层锁住三件事：

1. 命中致命签名 ⇒ 走**失败预算**（retry/blocked），不记 ok、不记信号；
2. 记一条 ``false_success_detected`` 审计（留证据，不静默）；
3. 健康的 dirsearch 输出（含 ``--max-time`` 到点的正常收尾）**不得**被误判。
"""

from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.core.orchestrator import Orchestrator
from proofhound.core.plan import PlanAction
from proofhound.core.tasks import TaskNode, TaskStatus
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.sandbox import RunResult

TARGET = "https://127.0.0.1:8443/login"

#: 实测原文：它长得像"一句提示"，但意味着整轮没跑起来。
PROXY_FAILURE = "Cannot establish the proxy connection\n"


class FakeRunner:
    """可配退出码的假 runner：stdout 由 ``stdout`` 决定，证据照常落盘。"""

    egress_proxy_url = None

    def __init__(self, evidence_dir, scope, *, stdout: str, exit_code: int):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.scope = scope
        self.stdout = stdout
        self.exit_code = exit_code
        self.calls: list[list[str]] = []

    def run(self, tool, args, timeout=300, image=None):
        self.calls.append([tool, *args])
        uid = uuid.uuid4().hex[:12]
        stdout_path = self.evidence_dir / f"{uid}.stdout.log"
        stderr_path = self.evidence_dir / f"{uid}.stderr.log"
        stdout_path.write_text(self.stdout, encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        return RunResult(
            rejected=False,
            command=[tool, *args],
            exit_code=self.exit_code,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )


@pytest.fixture
def registry(make_skill_dir):
    return SkillRegistry(make_skill_dir()).discover()


def _orch(tmp_path, registry, *, stdout: str, exit_code: int = 0):
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    runner = FakeRunner(
        tmp_path / "evidence", Scope(networks=["127.0.0.0/8"]),
        stdout=stdout, exit_code=exit_code,
    )
    orch = Orchestrator(
        registry,
        runner,
        SimpleNamespace(complete=lambda messages: "{}"),
        audit,
        evidence_dir=tmp_path / "evidence",
    )
    return orch, runner, audit


def _action() -> PlanAction:
    return PlanAction(
        action="run_tool",
        skill="web-dirsearch",
        tool="dirsearch",
        params={"target": TARGET},
        expected_output="signals",
    )


def _running_node() -> TaskNode:
    node = TaskNode(name="scan:test", meta={"target": TARGET})
    node.transition(TaskStatus.RUNNING, reason="子任务启动")
    return node


def _skill() -> SimpleNamespace:
    return SimpleNamespace(name="web-dirsearch")


def test_exit_zero_with_proxy_error_is_not_success(tmp_path, registry):
    """核心回归：exit 0 + ``Cannot establish the proxy connection`` ⇒ 失败。"""
    orch, _runner, audit = _orch(tmp_path, registry, stdout=PROXY_FAILURE, exit_code=0)
    node = _running_node()

    outcome = orch._exec_run_tool(node, _action(), _skill())

    assert outcome == "retry", "假成功必须走失败预算，不得返回 ok"
    assert node.status is TaskStatus.RUNNING  # 未迁移到 done
    assert node.failure_counts == {"tool_broken": 1}

    events = audit.read_all()
    assert [e for e in events if e["event"] == "signals_recorded"] == []
    detected = [e for e in events if e["event"] == "false_success_detected"]
    assert detected and detected[0]["tool"] == "dirsearch"
    assert detected[0]["signature"] == "Cannot establish the proxy connection"
    failed = [e for e in events if e["event"] == "attempt_failed"]
    assert failed[0]["category"] == "tool_broken"
    assert failed[0]["exit_code"] == 0


def test_budget_exhaustion_after_repeated_false_success_blocks(tmp_path, registry):
    """连挂两次后 blocked —— 与其它失败类别共用同一套失败预算。"""
    orch, _runner, audit = _orch(tmp_path, registry, stdout=PROXY_FAILURE, exit_code=0)
    node = _running_node()

    assert orch._exec_run_tool(node, _action(), _skill()) == "retry"
    assert orch._exec_run_tool(node, _action(), _skill()) == "blocked"
    assert node.status is TaskStatus.BLOCKED
    blocked = [e for e in audit.read_all() if e["event"] == "task_blocked"]
    assert blocked[0]["category"] == "tool_broken"


def test_tool_missing_exit_code_is_classified(tmp_path, registry):
    """§4.2：exit 127（工具缺失）不得再落到 unknown（那会把锅甩给规划器）。"""
    orch, _runner, audit = _orch(
        tmp_path, registry, stdout="sh: dirsearch: not found\n", exit_code=127
    )
    node = _running_node()

    assert orch._exec_run_tool(node, _action(), _skill()) == "retry"
    assert node.failure_counts == {"tool_missing": 1}
    failed = [e for e in audit.read_all() if e["event"] == "attempt_failed"]
    assert failed[0]["category"] == "tool_missing"


def test_healthy_dirsearch_output_still_succeeds(tmp_path, registry):
    """不得误判：有真结果行 + ``--max-time`` 正常收尾 ⇒ 仍然是 ok。"""
    healthy = (
        "[09:44:21] 404 -    19B - https://127.0.0.1:8443/login/aa\n"
        "[09:44:24] 200 -   27B - https://127.0.0.1:8443/admin\n"
        "\nRuntime exceeded the maximum set by the user\n"
    )
    orch, _runner, audit = _orch(tmp_path, registry, stdout=healthy, exit_code=0)
    node = _running_node()

    assert orch._exec_run_tool(node, _action(), _skill()) == "ok"
    assert node.failure_counts == {}
    events = audit.read_all()
    assert [e for e in events if e["event"] == "false_success_detected"] == []
    # 成功路径照常记一次 signals_recorded（哪怕本批 0 条）
    assert [e for e in events if e["event"] == "signals_recorded"]
