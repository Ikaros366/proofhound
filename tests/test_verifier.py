"""Verifier Agent 测试（M3b，§5.4.4）：T2 对抗校验。

mock T2 路由（不进真实 LLM）：confirm/reject 落 Finding.verifier + 审计；
坏 JSON / 非法 verdict / 空 reason 一律 VerifierError（非法 verdict 拒收）；
prompt 只含结构化摘要与证据索引（红线 3：无原始输出、无凭据原文）。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.findings import Finding, FindingState, Verification
from proofhound.llm.router import Tier
from proofhound.llm.usage import BudgetExceededError
from proofhound.verify.verifier import Verifier, VerifierError

COOKIE_VALUE = "df6a4b9c0e1f2a3b4c5d6e7f890abcde"


class MockRouter:
    """罐头 T2 路由：记录调用，返回预设文本。"""

    def __init__(self, reply: str | Exception):
        self.reply = reply
        self.calls: list[tuple] = []
        self.configs = {Tier.T2: SimpleNamespace(model="kimi-k3-test")}

    def complete(self, tier, messages):
        self.calls.append((tier, messages))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def _finding() -> Finding:
    return Finding(
        id="F-2026-0001",
        state=FindingState.REPRODUCED,
        vuln_type="sqli",
        asset="http://127.0.0.1:8080/vulnerabilities/sqli/?id=1",
        param="id",
        evidence_kinds=["status-code", "behavioral"],
        verification=Verification(
            method="sqlmap-confirmed",
            evidence_refs=["evidence/a.log#L1", "evidence/b.log#L24"],
            baseline_diff="带会话 baseline 200；sqlmap 确认 id（GET）boolean-based blind",
            reproduction_steps=["以预置会话（Cookie sha256:2ef2affa）GET ..."],
            verified_by="verify-sqli@1.0.0",
            verified_at="2026-08-07T00:00:00.000+00:00",
        ),
        dedup_key="sha256:deadbeef",
        created_at="2026-08-07T00:00:00.000+00:00",
        updated_at="2026-08-07T00:00:00.000+00:00",
    )


def _evidence_index() -> list[dict]:
    return [
        {"file": "a-aaaaaaaa.log", "sha256": "a" * 64, "source_ref": "evidence/a.log#L1", "line_anchor": 1},
        {"file": "b-bbbbbbbb.log", "sha256": "b" * 64, "source_ref": "evidence/b.log#L24", "line_anchor": 24},
    ]


def test_confirm_verdict_lands(tmp_path):
    router = MockRouter('{"verdict": "confirm", "reason": "证据链完整，方法认可", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}')
    audit = AuditLog(tmp_path / "audit.jsonl")
    finding = _finding()
    verdict = Verifier(router, audit).review(
        finding, evidence_index=_evidence_index(), diff_summary="diff"
    )
    assert verdict.verdict == "confirm"
    assert verdict.model == "kimi-k3-test"
    assert finding.verifier is not None
    assert finding.verifier.verdict == "confirm"

    tier, _ = router.calls[0]
    assert tier is Tier.T2  # 必须走 T2 档
    events = [e for e in audit.read_all() if e["event"] == "verifier_verdict"]
    assert len(events) == 1
    assert events[0]["verdict"] == "confirm"
    assert events[0]["model"] == "kimi-k3-test"
    assert events[0]["finding_id"] == finding.id


def test_reject_verdict_lands(tmp_path):
    router = MockRouter('{"verdict": "reject", "reason": "存在更平凡解释：WAF 拦截页"}')
    finding = _finding()
    verdict = Verifier(router, AuditLog(tmp_path / "audit.jsonl")).review(
        finding, evidence_index=_evidence_index()
    )
    assert verdict.verdict == "reject"
    assert "WAF" in verdict.reason


def test_code_fenced_json_accepted(tmp_path):
    router = MockRouter('```json\n{"verdict": "confirm", "reason": "ok", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}\n```')
    verdict = Verifier(router).review(_finding(), evidence_index=[])
    assert verdict.verdict == "confirm"


def test_bad_json_rejected():
    router = MockRouter("我觉得应该是 confirm 吧")
    with pytest.raises(VerifierError):
        Verifier(router).review(_finding(), evidence_index=[])


def test_illegal_verdict_rejected():
    """非法 verdict（maybe/downgrade/...）一律拒收。"""
    for bad in ('{"verdict": "maybe", "reason": "x"}',
                '{"verdict": "downgrade", "reason": "x"}',
                '{"verdict": "CONFIRM", "reason": "x"}'):
        with pytest.raises(VerifierError):
            Verifier(MockRouter(bad)).review(_finding(), evidence_index=[])


def test_empty_reason_rejected():
    with pytest.raises(VerifierError):
        Verifier(MockRouter('{"verdict": "confirm"}')).review(
            _finding(), evidence_index=[]
        )
    with pytest.raises(VerifierError):
        Verifier(MockRouter('{"verdict": "confirm", "reason": ""}')).review(
            _finding(), evidence_index=[]
        )


def test_prompt_boundary_no_raw_output_no_cookie():
    """红线 3：prompt 只含结构化摘要 + 索引；不得出现凭据原文。"""
    router = MockRouter('{"verdict": "confirm", "reason": "ok", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}')
    finding = _finding()
    Verifier(router).review(finding, evidence_index=_evidence_index())
    _, messages = router.calls[0]
    prompt = "\n".join(str(m["content"]) for m in messages)
    assert COOKIE_VALUE not in prompt
    assert "evidence_pack_index" in prompt
    assert "b-bbbbbbbb.log" in prompt  # 证据包索引在内
    assert "sqlmap identified the following" not in prompt  # 原始输出不进


def test_budget_exceeded_propagates():
    router = MockRouter(
        BudgetExceededError(tier="t2", used=100, limit=100, scope="run")
    )
    with pytest.raises(BudgetExceededError):
        Verifier(router).review(_finding(), evidence_index=[])


def test_context_overflow_when_prompt_too_large():
    from proofhound.core.context import ContextOverflowError, ContextPolicy

    router = MockRouter('{"verdict": "confirm", "reason": "ok"}')
    verifier = Verifier(router, context_policy=ContextPolicy(max_chars=10))
    with pytest.raises(ContextOverflowError):
        verifier.review(_finding(), evidence_index=_evidence_index())
    assert router.calls == []  # 超限即抛，未发起调用


# ---- M6b：CVSS 向量契约（LLM 只产向量字符串，confirm 必须带合法向量） ----

VECTOR_98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 critical


def test_confirm_without_vector_rejected():
    """confirm 缺 cvss_vector = 整个 verdict 非法（fail-closed 无降级）。"""
    router = MockRouter('{"verdict": "confirm", "reason": "证据链完整"}')
    with pytest.raises(VerifierError):
        Verifier(router).review(_finding(), evidence_index=[])


def test_confirm_with_invalid_vector_rejected():
    """confirm 向量非法（坏指标值/缺指标）= 非法裁决。"""
    for bad in (
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 非法值
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # 缺指标
        "9.8",  # 根本不是向量
    ):
        reply = (
            '{"verdict": "confirm", "reason": "ok", "cvss_vector": "%s"}' % bad
        )
        with pytest.raises(VerifierError):
            Verifier(MockRouter(reply)).review(_finding(), evidence_index=[])


def test_confirm_verdict_carries_vector_and_rationale(tmp_path):
    """confirm 带合法向量：落 Finding.verifier 与审计（含 rationale）。"""
    reply = (
        '{"verdict": "confirm", "reason": "证据链完整", '
        f'"cvss_vector": "{VECTOR_98}", "cvss_rationale": "sqlmap 已拖出库名，C:H"}}'
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    finding = _finding()
    verdict = Verifier(MockRouter(reply), audit).review(finding, evidence_index=[])
    assert verdict.cvss_vector == VECTOR_98
    assert verdict.cvss_rationale and "C:H" in verdict.cvss_rationale
    assert finding.verifier.cvss_vector == VECTOR_98
    event = [e for e in audit.read_all() if e["event"] == "verifier_verdict"][0]
    assert event["cvss_vector"] == VECTOR_98
    assert event["cvss_rationale"] == verdict.cvss_rationale


def test_reject_needs_no_vector_and_must_not_carry_one(tmp_path):
    """reject 无需向量（正常落盘）；携带向量即非法（fail-closed 宁严勿宽）。"""
    finding = _finding()
    verdict = Verifier(MockRouter('{"verdict": "reject", "reason": "WAF 拦截页"}')).review(
        finding, evidence_index=[]
    )
    assert verdict.verdict == "reject"
    assert verdict.cvss_vector is None

    reply = (
        '{"verdict": "reject", "reason": "x", "cvss_vector": "%s"}' % VECTOR_98
    )
    with pytest.raises(VerifierError):
        Verifier(MockRouter(reply)).review(_finding(), evidence_index=[])


def test_fake_score_fields_ignored():
    """红线：LLM 不产数字——verdict 塞假分数字段被忽略（不入模型、零生效）。"""
    reply = (
        '{"verdict": "confirm", "reason": "ok", '
        f'"cvss_vector": "{VECTOR_98}", "cvss_score": 0.1, "score": 999}}'
    )
    verdict = Verifier(MockRouter(reply)).review(_finding(), evidence_index=[])
    assert verdict.cvss_vector == VECTOR_98
    dumped = verdict.model_dump()
    assert "cvss_score" not in dumped  # 契约无分数字段：假分数零落盘
    assert "score" not in dumped
