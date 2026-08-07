"""预算硬闸的编排集成测试（M2c）：真实 ModelRouter + mock urllib（零网络）。

覆盖验收点：
- 0 预算 → 首次规划前即被闸：子任务 blocked、记 llm_budget_exceeded、
  不发 HTTP、不写 llm_call，且超限后 router 调用次数不再增长；
- 预算恰够一轮 → 第一轮规划成功（记 llm_call），执行失败 retry，第二轮
  规划前被闸 → blocked，llm_call 恰 1 条。
"""

import json
import uuid
from pathlib import Path

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.orchestrator import Orchestrator
from proofhound.core.tasks import TaskStatus
from proofhound.llm.router import ModelRouter, Tier, TierConfig
from proofhound.llm.usage import TokenBudget, UsageTracker
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.sandbox import RunResult

TARGET = "http://127.0.0.1:8000"


class FakeRunner:
    """SandboxRunner 的替身：不写容器，把给定输出写进 evidence 文件。"""

    egress_proxy_url = None

    def __init__(self, evidence_dir, handler):
        self.evidence_dir = Path(evidence_dir)
        self.handler = handler
        self.calls = []

    def run(self, tool, args, timeout=300):
        self.calls.append([tool, *args])
        exit_code, stdout, stderr = self.handler(tool, args)
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


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self) -> bytes:
        return self._body


def _run_tool_plan() -> str:
    return json.dumps(
        {
            "actions": [
                {
                    "action": "run_tool",
                    "skill": "web-scan",
                    "tool": "httpx",
                    "params": {"target": TARGET},
                    "expected_output": "signals",
                }
            ]
        }
    )


def _router(budget: TokenBudget, tracker: UsageTracker, audit: AuditLog) -> ModelRouter:
    configs = {
        Tier.T1: TierConfig(base_url="https://t1.example/v1", api_key="k1", model="m1")
    }
    return ModelRouter(configs, audit=audit, tracker=tracker, budget=budget)


def _counting_spy(router: ModelRouter):
    calls = []
    original = router.complete

    def spy(tier, messages):
        calls.append(tier)
        return original(tier, messages)

    router.complete = spy  # 实例属性遮蔽类方法
    return calls


@pytest.fixture
def registry(make_skill_dir):
    return SkillRegistry(make_skill_dir()).discover()


def test_zero_budget_blocks_before_any_call(registry, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout=None: (_ for _ in ()).throw(
            AssertionError("预算 0 不应发起 HTTP")
        ),
    )
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    tracker = UsageTracker()
    router = _router(TokenBudget(max_total=0), tracker, audit)
    router_calls = _counting_spy(router)
    runner = FakeRunner(tmp_path / "evidence", lambda tool, args: (0, "", ""))
    orch = Orchestrator(registry, runner, router, audit, evidence_dir=tmp_path / "evidence")

    phase = orch.run_scan_phase([TARGET])

    node = phase.children[0]
    assert node.status == TaskStatus.BLOCKED
    assert phase.status == TaskStatus.BLOCKED
    assert router_calls == [Tier.T1]  # 闸后不再增长
    assert runner.calls == []  # 未执行任何工具
    assert tracker.records == []

    events = audit.read_all()
    (exceeded,) = [e for e in events if e["event"] == "llm_budget_exceeded"]
    assert exceeded["node_id"] == node.id
    assert exceeded["tier"] == "t1"
    assert exceeded["used"] == 0 and exceeded["limit"] == 0
    assert exceeded["scope"] == "run"
    assert not [e for e in events if e["event"] == "llm_call"]


def test_budget_allows_exactly_one_round(registry, tmp_path, monkeypatch):
    """预算 100：第一轮规划耗 100 tokens；执行失败 retry；第二轮规划前被闸。"""
    body = json.dumps(
        {
            "choices": [{"message": {"content": _run_tool_plan()}}],
            "usage": {"prompt_tokens": 60, "completion_tokens": 40},
        }
    ).encode()
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda req, timeout=None: _FakeResponse(body)
    )
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    tracker = UsageTracker()
    router = _router(TokenBudget(max_total=100), tracker, audit)
    router_calls = _counting_spy(router)
    runner = FakeRunner(
        tmp_path / "evidence", lambda tool, args: (1, "", "connection refused")
    )
    orch = Orchestrator(registry, runner, router, audit, evidence_dir=tmp_path / "evidence")

    phase = orch.run_scan_phase([TARGET])

    node = phase.children[0]
    assert node.status == TaskStatus.BLOCKED
    assert router_calls == [Tier.T1, Tier.T1]  # 第二次规划调用被闸在 HTTP 之前
    assert len(runner.calls) == 1  # 工具只执行了一轮
    assert tracker.total_tokens() == 100

    events = audit.read_all()
    llm_calls = [e for e in events if e["event"] == "llm_call"]
    assert len(llm_calls) == 1
    assert llm_calls[0]["prompt_tokens"] == 60
    (exceeded,) = [e for e in events if e["event"] == "llm_budget_exceeded"]
    assert exceeded["used"] == 100 and exceeded["limit"] == 100
    assert node.failure_counts == {"network": 1}  # 失败计数完整保留
