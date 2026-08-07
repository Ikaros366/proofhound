"""上下文治理单元测试（M2c）：确定性压缩 + prompt 字符硬上限。

覆盖：未超阈值不压缩、压缩确定性（同输入同输出）、每类最新 K 条 +
total/by_kind 计数不丢、attempts/failure_counts 原样保留、原 state 不被
修改；planner 层：触发压缩记 context_compressed、超硬上限抛
ContextOverflowError（不发 LLM 调用）；orchestrator 层：overflow → 节点
failed + 记 context_overflow 审计、不执行工具。
"""

import json

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.context import (
    ContextOverflowError,
    ContextPolicy,
    compress_state,
    messages_chars,
)
from proofhound.core.orchestrator import Orchestrator
from proofhound.core.planner import Planner
from proofhound.core.tasks import TaskStatus
from proofhound.skills.registry import SkillRegistry


def _signals(*specs: tuple[str, int]) -> list[dict]:
    """按 (kind, 条数) 生成摘要：asset 携带全局序号以便验证保留的是最新条。"""
    out = []
    n = 0
    for kind, count in specs:
        for _ in range(count):
            n += 1
            out.append(
                {
                    "asset": f"http://t/{n}",
                    "status_code": 200,
                    "kind": kind,
                    "evidence_ref": f"e.log#L{n}",
                }
            )
    return out


def _state(signals) -> dict:
    return {
        "target": "http://127.0.0.1:8000",
        "attempts": 3,
        "failure_counts": {"network": 2},
        "signals": signals,
    }


def test_no_compress_under_threshold():
    state = _state(_signals(("web-probe", 5)))
    new_state, info = compress_state(state, ContextPolicy())
    assert new_state is state
    assert info is None


def test_compress_deterministic():
    state = _state(_signals(("web-probe", 15), ("dir", 10)))
    policy = ContextPolicy(max_signals=20, keep_latest=4)
    assert compress_state(state, policy) == compress_state(state, policy)


def test_compress_keeps_latest_per_kind_and_counts():
    state = _state(_signals(("web-probe", 15), ("dir", 10)))
    new_state, info = compress_state(state, ContextPolicy(max_signals=20, keep_latest=4))

    assert info == {
        "total": 25,
        "kept": 8,
        "by_kind": {"web-probe": 15, "dir": 10},
    }
    kept = new_state["signals"]
    # 每类保留最新 4 条：web-probe 序号为 12~15，dir 为 22~25（asset 尾号）
    assert [s["asset"] for s in kept if s["kind"] == "web-probe"] == [
        f"http://t/{n}" for n in range(12, 16)
    ]
    assert [s["asset"] for s in kept if s["kind"] == "dir"] == [
        f"http://t/{n}" for n in range(22, 26)
    ]
    # 保持原相对顺序（web-probe 在前，dir 在后）
    assert [s["kind"] for s in kept] == ["web-probe"] * 4 + ["dir"] * 4
    # 计数与尝试次数完整保留
    assert new_state["attempts"] == 3
    assert new_state["failure_counts"] == {"network": 2}
    assert new_state["signals_summary"] == {
        "total": 25,
        "by_kind": {"web-probe": 15, "dir": 10},
        "kept": 8,
    }
    # 原 state 不被修改
    assert len(state["signals"]) == 25
    assert "signals_summary" not in state


def test_compress_unknown_kind_fallback():
    signals = [{"asset": "http://t/1"}] * 3  # 无 kind 字段
    state = _state(signals)
    _, info = compress_state(state, ContextPolicy(max_signals=2, keep_latest=1))
    assert info["by_kind"] == {"unknown": 3}


def test_messages_chars():
    messages = [{"role": "system", "content": "abcd"}, {"role": "user", "content": "ef"}]
    assert messages_chars(messages) == 6


# ---- planner 集成（mock LLM，零网络） ----


class FakeLLM:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def complete(self, messages):
        self.calls.append(messages)
        return self.reply


def _plan_json():
    return json.dumps(
        {
            "actions": [
                {
                    "action": "run_tool",
                    "skill": "web-scan",
                    "tool": "httpx",
                    "params": {"target": "http://127.0.0.1:8000"},
                    "expected_output": "signals",
                }
            ]
        }
    )


@pytest.fixture
def registry(make_skill_dir):
    return SkillRegistry(make_skill_dir()).discover()


def test_planner_compresses_and_audits(registry, tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    llm = FakeLLM(_plan_json())
    planner = Planner(
        llm,
        registry,
        {"httpx"},
        audit,
        context_policy=ContextPolicy(max_signals=2, keep_latest=1),
    )
    state = _state(_signals(("web-probe", 2), ("dir", 1)))
    plan = planner.plan(state, registry.get("web-scan"))
    assert plan.actions[0].tool == "httpx"

    # LLM 收到的 prompt：每类只留最新 1 条 + 汇总计数
    prompt = llm.calls[0][1]["content"]
    assert '"total": 3' in prompt
    assert "http://t/2" in prompt and "http://t/3" in prompt
    assert "http://t/1" not in prompt

    events = [e["event"] for e in audit.read_all()]
    assert events == ["context_compressed", "plan_generated"]
    compressed = audit.read_all()[0]
    assert compressed["total"] == 3 and compressed["kept"] == 2


def test_planner_overflow_raises_without_llm_call(registry, tmp_path):
    llm = FakeLLM(_plan_json())
    planner = Planner(
        llm,
        registry,
        {"httpx"},
        AuditLog(tmp_path / "audit.jsonl"),
        context_policy=ContextPolicy(max_chars=10),
    )
    with pytest.raises(ContextOverflowError) as excinfo:
        planner.plan(_state([]), registry.get("web-scan"))
    assert excinfo.value.limit == 10
    assert excinfo.value.chars > 10
    assert llm.calls == []  # 超限不发 LLM 调用


# ---- orchestrator 集成：overflow → failed + 审计 ----


class _ForbiddenRunner:
    """溢出路径不应执行任何工具。"""

    egress_proxy_url = None

    def run(self, tool, args, timeout=300):
        raise AssertionError("上下文超限不应执行工具")


def test_orchestrator_overflow_fails_and_audits(registry, tmp_path):
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    orch = Orchestrator(
        registry,
        _ForbiddenRunner(),
        FakeLLM(_plan_json()),
        audit,
        evidence_dir=tmp_path / "evidence",
        context_policy=ContextPolicy(max_chars=10),
    )
    phase = orch.run_scan_phase(["http://127.0.0.1:8000"])

    node = phase.children[0]
    assert node.status == TaskStatus.FAILED
    assert phase.status == TaskStatus.FAILED
    (event,) = [e for e in audit.read_all() if e["event"] == "context_overflow"]
    assert event["node_id"] == node.id
    assert event["chars"] > event["limit"] == 10
