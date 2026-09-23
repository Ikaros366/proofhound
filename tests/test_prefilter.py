"""M9c② 廉价粗筛层测试（纯函数 + 编排接线）。

覆盖验收点：
- 判定表逐格：只有「两个语义不同取值产出逐字节等长响应」才判 UNLIKELY；
- 一切含糊情形（基准不可达/非 2xx/响应过短/探测非 2xx）一律 UNKNOWN 放行；
- 参数取值有可观测影响 → PROMISING；
- `passed` 语义：UNKNOWN 与 PROMISING 都放行（宁漏勿滥）；
- param 为空 → UNKNOWN（无廉价差分可做）；
- 编排接线：UNLIKELY 不进贵验证档且 Finding **保持 Hypothesis（不 Rejected）**；
- 贵验证档 cap 生效，超出记 verify_capped 且不驳回；
- 关闭粗筛时 `_prefilter_or_cap` 不被调用（默认零行为差，由旧测试保证）。
"""

from __future__ import annotations

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings.finding import Finding, FindingState
from proofhound.skills.registry import SkillRegistry
from proofhound.verify.prefilter import (
    MIN_COMPARABLE_BYTES,
    Probe,
    ScreenDecision,
    decide,
    screen,
    with_query_param,
)

URL = "http://127.0.0.1:8080/b/sqli?article_id=1&lang=zh"


def _long(n=MIN_COMPARABLE_BYTES + 10):
    return Probe(status=200, length=n)


# ---------------- with_query_param ----------------


def test_replace_query_param_keeps_other_params():
    out = with_query_param(URL, "article_id", "999999")
    assert "article_id=999999" in out
    assert "lang=zh" in out


def test_replace_appends_when_param_absent():
    out = with_query_param("http://h/p?a=1", "sku", "2")
    assert "a=1" in out and "sku=2" in out


# ---------------- decide：判定表逐格 ----------------


def test_unreachable_baseline_is_unknown():
    r = decide(Probe(None, 0, error="TimeoutError"), (_long(), _long()))
    assert r.decision is ScreenDecision.UNKNOWN
    assert r.passed


def test_non_2xx_baseline_is_unknown():
    r = decide(Probe(403, 500), (_long(), _long()))
    assert r.decision is ScreenDecision.UNKNOWN


def test_short_baseline_is_unknown():
    r = decide(Probe(200, MIN_COMPARABLE_BYTES - 1), (_long(), _long()))
    assert r.decision is ScreenDecision.UNKNOWN


def test_non_2xx_probe_is_unknown():
    """探测打到错误页：可能是漏洞也可能是错误——含糊，放行。"""
    r = decide(_long(), (Probe(500, 400), Probe(500, 400)))
    assert r.decision is ScreenDecision.UNKNOWN


def test_unreachable_probe_is_unknown():
    r = decide(_long(), (Probe(None, 0, error="URLError"), _long()))
    assert r.decision is ScreenDecision.UNKNOWN


def test_differing_lengths_are_promising():
    r = decide(_long(500), (Probe(200, 700), Probe(200, 900)))
    assert r.decision is ScreenDecision.PROMISING
    assert r.length_deltas == (200, 400)
    assert r.passed


def test_identical_length_probes_are_unlikely():
    """唯一判 UNLIKELY 的格子：两个语义不同取值产出逐字节等长响应。"""
    r = decide(_long(500), (Probe(200, 500), Probe(200, 500)))
    assert r.decision is ScreenDecision.UNLIKELY
    assert r.advisory is True, "给出「不值得优先验证」的建议"
    assert r.passed is True, "但**绝不丢弃候选**（M9c② 实测：丢弃是负收益）"
    assert "无可观测影响力" in r.reason


def test_one_differing_length_is_promising_not_unlikely():
    r = decide(_long(500), (Probe(200, 500), Probe(200, 501)))
    assert r.decision is ScreenDecision.PROMISING


def test_result_serializes_judgement_basis():
    r = decide(_long(500), (Probe(200, 500), Probe(200, 500)))
    data = r.to_dict()
    assert data["decision"] == "unlikely"
    assert data["baseline_length"] == 500
    assert data["probe_lengths"] == [500, 500]
    assert data["thresholds"]["min_comparable_bytes"] == MIN_COMPARABLE_BYTES


# ---------------- screen ----------------


def test_screen_without_param_is_unknown():
    called = []

    def fetcher(url):
        called.append(url)
        return _long()

    r = screen(URL, None, fetcher=fetcher)
    assert r.decision is ScreenDecision.UNKNOWN
    assert called == [], "无参数时不应发任何请求"


def test_screen_issues_baseline_plus_two_probes():
    seen = []

    def fetcher(url):
        seen.append(url)
        return Probe(200, 500)

    r = screen("http://h/p?sku=1", "sku", fetcher=fetcher)
    assert len(seen) == 3, "基准 1 次 + 探测 2 次"
    assert r.decision is ScreenDecision.UNLIKELY
    assert r.advisory is True


def test_post_form_candidate_is_unknown_not_unlikely():
    """POST 表单候选 asset 无 query：GET 差分不适用 → UNKNOWN（不是"无影响力"）。"""
    seen = []

    def fetcher(url):
        seen.append(url)
        return Probe(200, 500)

    r = screen("http://h/c/form-sqli", "bh", fetcher=fetcher)
    assert r.decision is ScreenDecision.UNKNOWN
    assert seen == [], "方法不适用时不应发任何请求"


# ---------------- 编排接线 ----------------


def _hypothesis(vuln_type="sqli", param="article_id", asset=URL):
    return Finding(
        id="F-2026-0001",
        state=FindingState.SIGNAL,
        vuln_type=vuln_type,
        severity="medium",
        asset=asset,
        param=param,
        confidence="low",
        evidence_kinds=["crawl-endpoint"],
        dedup_key="sha256:deadbeef",
        source_signal_refs=["katana.jsonl#L1"],
        created_at="2026-09-22T00:00:00+00:00",
        updated_at="2026-09-22T00:00:00+00:00",
    )


def _promising_fetch():
    """可复用的取数替身：基准 500 字节、两个探测 900 字节 → PROMISING。"""
    seq = iter(
        [
            Probe(200, 500),
            Probe(200, 900),
            Probe(200, 900),
            Probe(200, 500),
            Probe(200, 900),
            Probe(200, 900),
        ]
    )
    return lambda url: next(seq)


@pytest.fixture
def orch(tmp_path, make_skill_dir):
    audit = AuditLog(tmp_path / "audit.jsonl")
    o = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=None,
        llm=None,
        audit=audit,
        evidence_dir=tmp_path,
        verify_prefilter=True,
        prefilter_fetch=lambda url: Probe(200, 500),
    )
    return o, audit


def test_prefilter_never_drops_candidate_only_advises(orch, tmp_path):
    """M9c② 实测结论锁死：粗筛**不丢弃**候选，只产出排序建议。

    初版把 UNLIKELY 当作"不进贵验证档"，实测为负收益（发现率被砍、误报率不降）
    ——"两个取值等长"同样出现在 blind 注入与定长模板里，不是漏洞的负面证据。
    """
    o, audit = orch
    finding = _hypothesis()
    finding.audit = audit
    # 放行到贵验证档（不丢弃），但"不值得优先"的建议被记下
    assert o._prefilter_or_cap(finding, "verify-sqli") is None
    assert finding.state is FindingState.SIGNAL  # 状态不变：粗筛不是判定
    events = [
        e for e in audit.read_all() if e["event"] == "verify_prefilter_unlikely"
    ]
    assert len(events) == 1
    assert events[0]["finding_id"] == finding.id
    assert events[0]["decision"] == "unlikely"  # 建议值如实记录
    assert "thresholds" in events[0]  # 判定依据可离线复核
    assert o._prefilter_advisory == 1  # 计入汇总
    assert o._expensive_spent == 1  # 但仍进贵验证档


def test_prefilter_promising_passes_and_records(orch):
    o, audit = orch
    o._prefilter_fetch = _promising_fetch()
    finding = _hypothesis()
    finding.audit = audit
    assert o._prefilter_or_cap(finding, "verify-sqli") is None
    assert o._expensive_spent == 1
    assert [e["event"] for e in audit.read_all()] == ["verify_prefilter_passed"]
    assert o._prefilter_advisory == 0  # PROMISING 不是"不建议"


def test_prefilter_failure_does_not_block(orch):
    """粗筛自身抛错 → 记审计但不阻塞，仍放行到贵验证档。"""
    o, audit = orch

    def boom(url):
        raise RuntimeError("网络栈炸了")

    o._prefilter_fetch = boom
    finding = _hypothesis()
    finding.audit = audit
    assert o._prefilter_or_cap(finding, "verify-sqli") is None
    events = [e["event"] for e in audit.read_all()]
    assert "verify_prefilter_error" in events


def test_expensive_cap_stops_without_rejecting(tmp_path, make_skill_dir):
    audit = AuditLog(tmp_path / "audit.jsonl")
    o = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=None,
        llm=None,
        audit=audit,
        evidence_dir=tmp_path,
        verify_prefilter=True,
        expensive_cap=1,
        prefilter_fetch=_promising_fetch(),
    )
    first, second = _hypothesis(), _hypothesis()
    first.audit = second.audit = audit
    assert o._prefilter_or_cap(first, "verify-sqli") is None  # 用掉唯一配额
    assert o._prefilter_or_cap(second, "verify-sqli") == "capped"
    assert second.state is FindingState.SIGNAL  # cap 不驳回
    capped = [e for e in audit.read_all() if e["event"] == "verify_capped"]
    assert len(capped) == 1 and capped[0]["limit"] == 1


def test_prefilter_disabled_by_default(tmp_path, make_skill_dir):
    """默认关闭：构造器不开启粗筛（旧链路零行为差）。"""
    o = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=None,
        llm=None,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        evidence_dir=tmp_path,
    )
    assert o.verify_prefilter is False
    assert o.triage_model is False
    assert o.triage_rules is True