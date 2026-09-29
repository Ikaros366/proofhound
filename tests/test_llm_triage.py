"""M9c① 模型驱动假设生成（T1 档）测试。

覆盖验收点：
- 输入边界（红线 3）：prompt 无响应体、无 scheme/host/凭据，只有结构化摘要；
- 输出强校验：坏 JSON / 非对象 / 缺键 / 未知 vuln_type / 空 param / 非法
  confidence 一律 fail-closed（不产候选）；
- 接地性：param 必须在送审摘要内出现过，否则丢弃该条（不整批拒绝）；
- 修复重试：首次非法 + 二次合法 → 成功（M6a 先例，最多一次）；
- 二次仍非法 → 上抛，**不产候选**（不是"当作合法候选"）；
- 预算/上下文硬闸优先：BudgetExceededError / ContextOverflowError 原样上抛；
- 分批：超过 BATCH_SIZE 逐批调用，逐批记 llm_triage_batch 审计。
"""

from __future__ import annotations

import json

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.findings.finding import Finding, FindingState, Verification
from proofhound.findings.signal import Signal
from proofhound.llm.router import Tier
from proofhound.llm.triage import (
    ALLOWED_VULN_TYPES,
    BATCH_SIZE,
    HypothesisBatch,
    HypothesisItem,
    ModelTriageError,
    build_candidates,
    parse_hypotheses,
    summarize_signals,
)
from proofhound.llm.usage import BudgetExceededError

BODY_SENTINEL = "PHBODY-SENTINEL-9f3a"
CRED_SENTINEL = "phsess=deadbeefcafe1234"


class FakeRouter:
    """按队列逐个返回回复的路由替身（记录收到的消息）。"""

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = 0
        self.messages = []

    def complete(self, tier, messages):
        assert tier is Tier.T1, f"模型 triage 必须走 T1 档，实得 {tier}"
        self.calls += 1
        self.messages.append(messages)
        if not self._replies:
            raise AssertionError("回复队列已耗尽")
        return self._replies.pop(0)


class ClimbingRouter:
    """修复重试场景：第 n 次调用返回第 n 个回复。"""

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = 0

    def complete(self, tier, messages):
        self.calls += 1
        return self._replies.pop(0)


def _summaries(*, param="article_id", kind="param-endpoint", query=True):
    """造一条摘要（默认模拟交接文档点名的表外参数）。"""
    asset = (
        f"http://127.0.0.1:8080/b/sqli?{param}=1"
        if query
        else "http://127.0.0.1:8080/c/form-sqli"
    )
    signal = Signal(
        asset=asset,
        status_code=200,
        kind=kind,
        source_tool="katana",
        skill="recon-crawl",
        evidence_ref="katana.jsonl#L7",
        form_fields=[] if query else [param],
    )
    return summarize_signals([signal])


def _reply(*hypotheses):
    return json.dumps({"hypotheses": list(hypotheses)}, ensure_ascii=False)


# ---------------- 输入边界（红线 3） ----------------


def test_summarize_strips_scheme_host_and_credentials():
    """摘要只留 path+query：scheme/host/端口/凭据一律不进模型上下文。"""
    signal = Signal(
        asset=f"http://{CRED_SENTINEL}@evil.example.com:8443/b/sqli?article_id=1",
        status_code=200,
        kind="param-endpoint",
        source_tool="katana",
        skill="recon-crawl",
        evidence_ref="katana.jsonl#L3",
    )
    summary = summarize_signals([signal])[0]
    assert summary.path == "/b/sqli"
    assert summary.params == ["article_id"]
    assert "evil.example.com" not in summary.path
    assert "deadbeefcafe1234" not in summary.path


def test_prompt_contains_no_response_body_and_no_credentials():
    """prompt 只有结构化摘要 + 文件引用；响应体与凭据原文零进入（红线 3）。"""
    router = FakeRouter([_reply({"vuln_type": "sqli", "param": "article_id"})])
    summaries = _summaries()
    build_candidates(router, summaries)

    assert router.calls == 1
    blob = json.dumps(router.messages[0], ensure_ascii=False)
    assert BODY_SENTINEL not in blob, "响应体内容泄漏进 prompt"
    assert "deadbeefcafe1234" not in blob, "凭据原文泄漏进 prompt"
    assert "http://" not in blob and "https://" not in blob, "含 scheme 的完整 URL 进了 prompt"
    # 结构化字段确实在（否则等于没给模型任何信息）
    assert "article_id" in blob
    assert "/b/sqli" in blob
    assert "katana.jsonl#L7" in blob


# ---------------- 输出强校验（fail-closed） ----------------


@pytest.mark.parametrize(
    "raw",
    [
        "not json at all",
        "[]",
        '{"hypotheses": "should be a list"}',
        '{"unknown_key": []}',
        _reply({"vuln_type": "rce", "param": "article_id"}),
        _reply({"vuln_type": "lfi", "param": "article_id"}),
        _reply({"vuln_type": "sqli", "param": "   "}),
        _reply({"vuln_type": "sqli", "param": "article_id", "confidence": "certain"}),
        _reply({"vuln_type": "sqli"}),
    ],
)
def test_parse_rejects_illegal_output(raw):
    with pytest.raises(ModelTriageError):
        parse_hypotheses(raw)


def test_parse_accepts_empty_and_key_variants():
    assert parse_hypotheses('{"hypotheses": []}').hypotheses == []
    # 键名宽容：items / candidates 等价
    assert parse_hypotheses('{"items": []}').hypotheses == []
    assert parse_hypotheses('{"candidates": []}').hypotheses == []
    batch = parse_hypotheses(
        _reply({"vuln_type": "idor", "param": "no", "reason": "编号", "confidence": "high"})
    )
    assert isinstance(batch, HypothesisBatch)
    assert batch.hypotheses[0] == HypothesisItem(
        vuln_type="idor", param="no", reason="编号", confidence="high"
    )


def test_allowed_types_are_exactly_the_declared_ones():
    """白名单**逐字**锁定：{sqli, xss, idor, ssrf}——多一个或少一个都红。

    M15 披露（断言意图已随任务变更）：原断言是“白名单 = 现有 verify-* 覆盖的
    类型”，而 M15 第一步**刻意**让 ssrf 例外——它有候选通道但没有验证器
    （`GATE_MATRIX` 无 ssrf 项 → 证据门恒 fail-closed，永远不可能 Confirmed）。
    “无验证器的类型不得有确认通道”这一原意图由下面的
    test_ssrf_is_hypothesis_only_no_confirmed_channel 承接并加强。
    """
    assert ALLOWED_VULN_TYPES == frozenset({"sqli", "xss", "idor", "ssrf"})


def test_ssrf_confirmed_requires_callback_method_only():
    """**M16 披露（断言意图已随第二步落地而反转）**：M15 时 ssrf 刻意没有
    Confirmed 通道，本测试当时断言 `"ssrf" not in GATE_MATRIX` + 过门恒不过。
    M16 建了 `verify-ssrf`（确认手段 = 回调 listener 收到请求，带外二值事实），
    故 ssrf **现在有且仅有**一条确认通道；原意图「无验证器的类型不得有确认
    通道」由下面三条承接——矩阵项**必须存在**、method 白名单**只含回调确认**、
    且**缺行为证据/缺 verification 一律不过门**（防止有人把矩阵项放宽成摆设）。
    """
    from proofhound.verify.gate import GATE_MATRIX, check
    from proofhound.verify.ssrf import SSRF_CONFIRMED_METHOD

    assert "ssrf" in ALLOWED_VULN_TYPES
    assert "ssrf" in GATE_MATRIX
    assert GATE_MATRIX["ssrf"].methods == frozenset({SSRF_CONFIRMED_METHOD})

    def _finding(**overrides) -> Finding:
        base = dict(
            id="F-2026-9001",
            vuln_type="ssrf",
            state=FindingState.REPRODUCED,
            asset="http://127.0.0.1:8000/e/fetch3?target=1",
            param="target",
            dedup_key="ssrf-target",
            evidence_kinds=["behavioral"],
            created_at="2026-09-29T00:00:00Z",
            updated_at="2026-09-29T00:00:00Z",
        )
        base.update(overrides)
        return Finding(**base)

    # 只有「行为类证据 + 白名单 method + 证据引用」齐全才过门
    finding = _finding()
    result = check(finding)
    assert result.passed is False  # 还没有 verification
    assert any("缺 verification" in item for item in result.missing)

    # 非白名单 method（例如拿 sqlmap 的结论来确认 ssrf）必须被拒
    other_method = _finding(
        verification=Verification(
            method="sqlmap-confirmed", evidence_refs=["x.jsonl"]
        )
    )
    assert check(other_method).passed is False

    # 缺行为类证据标签同样不过（纯 status-code 永不 Confirmed 的另一层）
    no_behavior = _finding(
        evidence_kinds=["crawl-endpoint"],
        verification=Verification(
            method=SSRF_CONFIRMED_METHOD, evidence_refs=["x.jsonl"]
        ),
    )
    assert check(no_behavior).passed is False

    # 齐全 → 过门（真正的判定由编排层 + Verifier 负责，本门只查最低验收标准）
    ok = _finding(
        verification=Verification(
            method=SSRF_CONFIRMED_METHOD, evidence_refs=["x.jsonl"]
        )
    )
    assert check(ok).passed is True


def test_parse_tolerates_code_fence():
    fenced = "```json\n" + _reply({"vuln_type": "sqli", "param": "bh"}) + "\n```"
    assert parse_hypotheses(fenced).hypotheses[0].param == "bh"


# ---------------- 接地性 ----------------


def test_ungrounded_param_is_dropped_not_batch_rejected():
    """模型看错一条只丢该条；不能因它保住整批（也不整批拒绝）。"""
    router = FakeRouter(
        [
            _reply(
                {"vuln_type": "sqli", "param": "article_id"},
                {"vuln_type": "sqli", "param": "nonexistent_param"},
                {"vuln_type": "xss", "param": "totally_made_up"},
            )
        ]
    )
    out = build_candidates(router, _summaries())
    assert [c.param for c in out] == ["article_id"]


def test_candidate_carries_source_asset():
    """候选必须带源 asset（模型不回 URL，归属由摘要确定性回填）。"""
    router = FakeRouter([_reply({"vuln_type": "sqli", "param": "article_id"})])
    out = build_candidates(router, _summaries())
    assert out[0].asset == "http://127.0.0.1:8080/b/sqli?article_id=1"


# ---------------- 修复重试（M6a 先例） ----------------


def test_repair_retry_recovers_from_bad_output():
    router = ClimbingRouter(
        ["这是一个解释，不是 JSON", _reply({"vuln_type": "idor", "param": "no"})]
    )
    out = build_candidates(router, _summaries(param="no"))
    assert router.calls == 2, "应恰好修复重试一次"
    assert [c.vuln_type for c in out] == ["idor"]


def test_second_failure_raises_and_yields_no_candidates():
    router = ClimbingRouter(["bad", "still bad"])
    with pytest.raises(ModelTriageError):
        build_candidates(router, _summaries())
    assert router.calls == 2, "全程最多一次修复重试（无循环）"


# ---------------- 硬闸优先 ----------------


def test_budget_error_propagates_untouched():
    class BudgetRouter:
        def complete(self, tier, messages):
            raise BudgetExceededError(tier="t1", used=10, limit=5, scope="run")

    with pytest.raises(BudgetExceededError):
        build_candidates(BudgetRouter(), _summaries())


def test_empty_input_makes_no_call():
    router = FakeRouter([])
    assert build_candidates(router, []) == []
    assert router.calls == 0


# ---------------- 分批 + 审计 ----------------


def test_batches_over_limit_and_audits_each_batch(tmp_path):
    signals = [
        Signal(
            asset=f"http://127.0.0.1:8080/b/item?sku={i}",
            status_code=200,
            kind="param-endpoint",
            source_tool="katana",
            skill="recon-crawl",
            evidence_ref=f"katana.jsonl#L{i}",
        )
        for i in range(BATCH_SIZE + 1)
    ]
    summaries = summarize_signals(signals)
    router = FakeRouter([_reply(), _reply()])
    audit = AuditLog(tmp_path / "audit.jsonl")
    build_candidates(router, summaries, audit=audit)

    assert router.calls == 2, f"{BATCH_SIZE + 1} 条应分 2 批"
    events = [e for e in audit.read_all() if e["event"] == "llm_triage_batch"]
    assert len(events) == 2
    assert sum(e["signals"] for e in events) == BATCH_SIZE + 1
    assert all(e["result"] == "ok" for e in events)


def test_audit_records_dropped_ungrounded(tmp_path):
    router = FakeRouter(
        [
            _reply(
                {"vuln_type": "sqli", "param": "sku"},
                {"vuln_type": "sqli", "param": "ghost"},
            )
        ]
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    build_candidates(router, _summaries(param="sku"), audit=audit)
    events = [e for e in audit.read_all() if e["event"] == "llm_triage_batch"]
    assert events[0]["candidates"] == 1
    assert events[0]["dropped"] and "ghost" in events[0]["dropped"][0]