"""结构化输出修复重试测试（M6a）：三调用点 + 预算/计量 + 原失败语义不变。

覆盖验收点：
- planner/narrative/verifier 三处：首轮垃圾 → 次轮合法（修复成功，
  记 llm_repair_attempt{result=success}）；两轮均非法 → 原失败语义
  （PlanValidationError + plan_rejected / NarrativeError 零落盘 /
  VerifierError fail-closed，记 result=failed）；
- 重试 token 照常计入 UsageTracker；预算中途耗尽照旧 BudgetExceededError；
- 修复消息超 max_chars → skipped_overflow + 抛首次错误；首轮 LLMError
  不触发重试；修复调用本身异常 → 回退首次错误（不多记审计）。
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.plan import PlanValidationError
from proofhound.core.planner import Planner
from proofhound.findings.finding import (
    Finding,
    FindingState,
    FindingStore,
    Verification,
)
from proofhound.llm.client import CompletionResult, LLMError
from proofhound.llm.repair import complete_structured
from proofhound.llm.router import ModelRouter, Tier, TierConfig
from proofhound.llm.usage import (
    BudgetExceededError,
    TokenBudget,
    UsageRecord,
    UsageTracker,
)
from proofhound.report.narrative import NarrativeError, NarrativeGenerator
from proofhound.skills.registry import SkillRegistry
from proofhound.verify.verifier import Verifier, VerifierError

GARBAGE = "随便说点什么，没有 JSON"


class SeqRouter:
    """按队列返回罐头回复的路由替身；带 tracker 时逐次模拟计量。"""

    def __init__(self, replies, tracker: UsageTracker | None = None):
        self.replies = list(replies)
        self.calls: list[tuple] = []
        self.tracker = tracker
        self.configs = {
            Tier.T1: SimpleNamespace(model="t1-mock"),
            Tier.T2: SimpleNamespace(model="t2-mock"),
        }

    def complete(self, *args):
        # 兼容两种签名：router 式 complete(tier, messages) 与旧式 complete(messages)
        # （Planner 的 ensure_router 会把非 ModelRouter 包成单参适配器）
        if len(args) == 2:
            tier, messages = args
        else:
            tier, messages = Tier.T1, args[0]
        self.calls.append((tier, messages))
        if not self.replies:
            raise AssertionError("回复队列已空")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if self.tracker is not None:
            self.tracker.record(
                UsageRecord(
                    tier=tier.value,
                    model="mock",
                    prompt_tokens=10,
                    completion_tokens=6,
                    latency_ms=1.0,
                    estimated=False,
                )
            )
        return reply


def _plan_json() -> str:
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


VALID_NARRATIVE = json.dumps(
    {
        "paragraphs": {
            "F-2026-0001": "该 SQL 注入可致数据泄漏。",
            "overview": "本次测试共确认 2 个漏洞。",
            "remediation": "建议使用参数化查询。",
        }
    },
    ensure_ascii=False,
)

VALID_VERDICT = '{"verdict": "confirm", "reason": "证据链完整，方法认可", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'


@pytest.fixture
def registry(make_skill_dir):
    return SkillRegistry(make_skill_dir()).discover()


def _make_planner(registry, tmp_path, replies):
    audit = AuditLog(tmp_path / "audit.jsonl")
    router = SeqRouter(replies)
    return Planner(router, registry, {"httpx"}, audit), router, audit


def _verifier_finding() -> Finding:
    return Finding(
        id="F-2026-0001",
        state=FindingState.REPRODUCED,
        vuln_type="sqli",
        severity="high",
        asset="http://127.0.0.1:8080/vulnerabilities/sqli/?id=1",
        param="id",
        evidence_kinds=["status-code", "behavioral"],
        verification=Verification(
            method="sqlmap-confirmed",
            evidence_refs=["evidence/a.log#L1"],
            reproduction_steps=["步骤一"],
            verified_by="verify-sqli@1.0.0",
            verified_at="2026-08-07T00:00:00.000+00:00",
        ),
        dedup_key="sha256:deadbeef",
        created_at="2026-08-07T00:00:00.000+00:00",
        updated_at="2026-08-07T00:00:00.000+00:00",
    )


def _repair_events(audit: AuditLog) -> list[dict]:
    return [e for e in audit.read_all() if e["event"] == "llm_repair_attempt"]


# ---- planner（T1 规划）----


def test_planner_repair_success(registry, tmp_path):
    planner, router, audit = _make_planner(registry, tmp_path, [GARBAGE, _plan_json()])
    plan = planner.plan({}, registry.get("web-scan"))

    assert plan.actions[0].tool == "httpx"
    assert len(router.calls) == 2
    # 修复追问携带原始输出（assistant 轮次）+ 错误描述（user 轮次）
    repair_messages = router.calls[1][1]
    assert repair_messages[-2] == {"role": "assistant", "content": GARBAGE}
    assert "未通过校验" in repair_messages[-1]["content"]
    assert "仅输出修正后的 JSON" in repair_messages[-1]["content"]
    attempts = _repair_events(audit)
    assert len(attempts) == 1
    assert attempts[0]["caller"] == "planner"
    assert attempts[0]["tier"] == "t1"
    assert attempts[0]["result"] == "success"
    assert attempts[0]["error_type"] == "PlanValidationError"
    assert any(e["event"] == "plan_generated" for e in audit.read_all())


def test_planner_repair_double_failure_keeps_semantics(registry, tmp_path):
    planner, _, audit = _make_planner(registry, tmp_path, [GARBAGE, GARBAGE])
    with pytest.raises(PlanValidationError):
        planner.plan({}, registry.get("web-scan"))

    events = audit.read_all()
    assert _repair_events(audit)[0]["result"] == "failed"
    # 原失败语义不变：plan_rejected 照旧落盘
    assert any(e["event"] == "plan_rejected" for e in events)


def test_planner_repair_call_error_falls_back(registry, tmp_path):
    """修复调用本身异常（替身队列耗尽）：回退抛首次错误，不多记审计。"""
    planner, router, audit = _make_planner(registry, tmp_path, [GARBAGE])
    with pytest.raises(PlanValidationError):
        planner.plan({}, registry.get("web-scan"))

    assert len(router.calls) == 2  # 确实追问过一次
    assert _repair_events(audit) == []
    assert [e["event"] for e in audit.read_all()] == ["plan_rejected"]


# ---- narrative（T1 叙述）----


def test_narrative_repair_success(report_evidence_dir, tmp_path):
    tracker = UsageTracker()
    router = SeqRouter([GARBAGE, VALID_NARRATIVE], tracker=tracker)
    audit = AuditLog(tmp_path / "audit.jsonl")
    store = FindingStore(report_evidence_dir / "findings.jsonl")
    paragraphs = NarrativeGenerator(router, audit).generate(
        store.load_all(), store=store, evidence_dir=report_evidence_dir
    )

    assert paragraphs["F-2026-0001"] == "该 SQL 注入可致数据泄漏。"
    attempts = _repair_events(audit)
    assert len(attempts) == 1 and attempts[0]["caller"] == "narrative"
    assert attempts[0]["result"] == "success"
    # 重试 token 照常计入：两次调用各 16，narrative_generated 事件 tokens 为总量
    assert tracker.total_tokens() == 32
    narrative_events = [
        e for e in audit.read_all() if e["event"] == "narrative_generated"
    ]
    assert narrative_events and all(e["tokens"] == 32 for e in narrative_events)


def test_narrative_repair_double_failure_zero_write(report_evidence_dir, tmp_path):
    store = FindingStore(report_evidence_dir / "findings.jsonl")
    lines_before = len(store.path.read_text(encoding="utf-8").splitlines())
    router = SeqRouter([GARBAGE, '{"paragraphs": {}}'])
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(NarrativeError):
        NarrativeGenerator(router, audit).generate(
            store.load_all(), store=store, evidence_dir=report_evidence_dir
        )

    assert (
        len(store.path.read_text(encoding="utf-8").splitlines()) == lines_before
    )
    assert not (report_evidence_dir / "narrative_sections.json").exists()
    assert _repair_events(audit)[0]["result"] == "failed"


# ---- verifier（T2 终审）----


def test_verifier_repair_success(tmp_path):
    router = SeqRouter(['{"verdict": "maybe", "reason": "x"}', VALID_VERDICT])
    audit = AuditLog(tmp_path / "audit.jsonl")
    finding = _verifier_finding()
    verdict = Verifier(router, audit).review(finding, evidence_index=[])

    assert verdict.verdict == "confirm"
    assert finding.verifier is not None
    attempts = _repair_events(audit)
    assert len(attempts) == 1
    assert attempts[0]["caller"] == "verifier"
    assert attempts[0]["tier"] == "t2"
    assert attempts[0]["result"] == "success"


def test_verifier_repair_double_failure(tmp_path):
    router = SeqRouter([GARBAGE, '{"verdict": "downgrade", "reason": "x"}'])
    audit = AuditLog(tmp_path / "audit.jsonl")
    finding = _verifier_finding()
    with pytest.raises(VerifierError):
        Verifier(router, audit).review(finding, evidence_index=[])

    assert finding.verifier is None  # fail-closed：非法裁定不落盘
    assert _repair_events(audit)[0]["result"] == "failed"
    assert not any(
        e["event"] == "verifier_verdict" for e in audit.read_all()
    )


# ---- 助手层：计量 / 预算 / 上下文 / 首轮异常 ----


def _real_router(replies, tracker, budget=None):
    """真实 ModelRouter（计量/预算硬闸真实生效），HTTP 客户端打桩。"""
    router = ModelRouter(
        {Tier.T1: TierConfig(base_url="http://x", api_key="k", model="m1")},
        tracker=tracker,
        budget=budget,
    )
    contents = list(replies)

    def fake_complete(_messages):
        return CompletionResult(
            content=contents.pop(0),
            usage={"prompt_tokens": 100, "completion_tokens": 50},
            latency_ms=1.0,
        )

    router._clients[Tier.T1].complete_with_usage = fake_complete
    return router


def test_repair_tokens_counted_in_tracker(tmp_path):
    tracker = UsageTracker()
    router = _real_router([GARBAGE, '{"a": 1}'], tracker)
    audit = AuditLog(tmp_path / "audit.jsonl")
    result = complete_structured(
        router, Tier.T1, [{"role": "user", "content": "x"}], json.loads,
        audit=audit, caller="unit",
    )

    assert result == {"a": 1}
    assert len(tracker.records) == 2  # 首轮 + 修复轮均计量
    assert tracker.total_tokens() == 300
    assert _repair_events(audit)[0]["result"] == "success"


def test_repair_budget_exceeded_midway(tmp_path):
    tracker = UsageTracker()
    # 首轮 150 tokens 放行（0 < 150），修复轮被闸（150 >= 150）
    router = _real_router(
        [GARBAGE, '{"a": 1}'], tracker, budget=TokenBudget(max_total=150)
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(BudgetExceededError):
        complete_structured(
            router, Tier.T1, [{"role": "user", "content": "x"}], json.loads,
            audit=audit, caller="unit",
        )
    assert len(tracker.records) == 1  # 硬闸调用不计用量
    assert _repair_events(audit) == []  # 预算事件由编排层记，助手不记


def test_repair_skipped_on_context_overflow(tmp_path):
    router = SeqRouter([GARBAGE])
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(json.JSONDecodeError):
        complete_structured(
            router, Tier.T1, [{"role": "user", "content": "x"}], json.loads,
            audit=audit, caller="unit", max_chars=5,
        )
    assert len(router.calls) == 1  # 未发起修复调用
    assert _repair_events(audit)[0]["result"] == "skipped_overflow"


def test_first_call_llm_error_no_repair(tmp_path):
    router = SeqRouter([LLMError("连接失败")])
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(LLMError):
        complete_structured(
            router, Tier.T1, [{"role": "user", "content": "x"}], json.loads,
            audit=audit, caller="unit",
        )
    assert len(router.calls) == 1  # 首轮调用异常不触发重试
    assert _repair_events(audit) == []


def test_repair_call_llm_error_falls_back_with_audit(tmp_path):
    router = SeqRouter([GARBAGE, LLMError("HTTP 500")])
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(json.JSONDecodeError):  # 回退抛首次校验错误
        complete_structured(
            router, Tier.T1, [{"role": "user", "content": "x"}], json.loads,
            audit=audit, caller="unit",
        )
    assert len(router.calls) == 2
    assert _repair_events(audit)[0]["result"] == "error"
