"""叙事事实守卫测试（M6c，§5.7）：确定性守卫 + reasons_cn + 修复重试集成。

覆盖验收点：
- 状态词共现矩阵（Confirmed/Rejected/Reproduced/Hypothesis/Signal × 四类词
  × 一致/矛盾）、否定前缀豁免、中性列举放行、幻觉 F-ID 拒；
- 计数断言（确认/误报三形态、阿拉伯+中文数字、一致/不一致、否定豁免）；
- reasons_cn schema（多余键拒/空值拒/缺失容忍）+ 落盘恒写 + data 层透传
  + 默认模板附录 B（reason_cn 优先、None 回退原文）；
- 守卫接入 M6a 修复重试：首轮失真→次轮修正→落盘；双失败零写入；
- prompt 携带 state_roster 全量状态清单与措辞纪律。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.findings.finding import FindingState, FindingStore
from proofhound.llm.router import Tier
from proofhound.report.data import build_context
from proofhound.report.factguard import check_narrative_facts
from proofhound.report.narrative import NarrativeError, NarrativeGenerator
from proofhound.report.render import render_docx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import make_default_template  # noqa: E402


class SeqRouter:
    """按队列返回罐头回复的 T1 路由替身。"""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls: list[tuple] = []
        self.configs = {Tier.T1: SimpleNamespace(model="t1-mock")}

    def complete(self, tier, messages):
        self.calls.append((tier, messages))
        return self.replies.pop(0)


def _reply(overview="本次测试共确认 2 个漏洞。", reasons=None):
    payload = {
        "paragraphs": {
            "F-2026-0001": "该 SQL 注入可致数据泄漏。",
            "F-2026-0005": "该 RCE 可直接执行命令。",
            "overview": overview,
            "remediation": "建议使用参数化查询。",
        }
    }
    if reasons is not None:
        payload["reasons_cn"] = reasons
    return json.dumps(payload, ensure_ascii=False)


def _generate(report_evidence_dir, router, audit=None):
    store = FindingStore(report_evidence_dir / "findings.jsonl")
    generator = NarrativeGenerator(router, audit)
    return generator.generate(
        store.load_all(), store=store, evidence_dir=report_evidence_dir
    )


def _states(**id_to_state):
    return {fid: FindingState(state) for fid, state in id_to_state.items()}


# ---- ① 状态词共现守卫 ----

#: (状态词, 允许的真实状态集合)
WORD_CASES = [
    ("确认", {"confirmed"}),
    ("证实", {"confirmed"}),
    ("Confirmed", {"confirmed"}),
    ("误报", {"rejected"}),
    ("排除", {"rejected"}),
    ("Rejected", {"rejected"}),
    ("假设", {"signal", "hypothesis"}),
    ("待验证", {"signal", "hypothesis"}),
    ("hypothesis", {"signal", "hypothesis"}),
    ("有效验证", {"reproduced"}),
    ("行为复现", {"reproduced"}),
    ("Reproduced", {"reproduced"}),
]


@pytest.mark.parametrize("word,allowed", WORD_CASES)
@pytest.mark.parametrize(
    "state", ["confirmed", "rejected", "reproduced", "hypothesis", "signal"]
)
def test_state_word_cooccurrence(word, allowed, state):
    """句中状态词与真实状态一致放行、矛盾违规（4 词类 × 全状态矩阵）。"""
    states = _states(**{"F-2026-0001": state})
    text = f"F-2026-0001 经 {word} 判定。"
    violations = check_narrative_facts(
        [text], states, confirmed_count=0, rejected_count=0
    )
    if state in allowed:
        assert violations == []
    else:
        assert any("F-2026-0001" in v for v in violations), violations


def test_negation_prefix_exempts():
    """否定前缀（未/不/无法/未能/没有）修饰的状态词不计入共现。"""
    states = _states(**{"F-2026-0002": "rejected"})
    for text in (
        "F-2026-0002 经复核未确认注入。",
        "F-2026-0002 无法证实可利用。",
        "F-2026-0002 未能确认注入点。",
        "F-2026-0002 没有确认可利用性。",
    ):
        assert (
            check_narrative_facts(
                [text], states, confirmed_count=0, rejected_count=1
            )
            == []
        ), text
    # 对照：去掉否定前缀即违规
    violations = check_narrative_facts(
        ["F-2026-0002 经复核确认注入。"], states, confirmed_count=0, rejected_count=1
    )
    assert violations and "F-2026-0002" in violations[0]


def test_neutral_enumeration_passes():
    """无状态词的中性列举放行。"""
    states = _states(**{"F-2026-0004": "reproduced", "F-2026-0005": "reproduced"})
    text = "本次测试涉及 F-2026-0004、F-2026-0005 等 3 个候选。"
    assert (
        check_narrative_facts([text], states, confirmed_count=0, rejected_count=0)
        == []
    )


def test_hallucinated_fid_rejected():
    """引用不存在的 F-ID → 幻觉违规。"""
    violations = check_narrative_facts(
        ["F-9999-0001 经有效验证。"],
        _states(**{"F-2026-0001": "confirmed"}),
        confirmed_count=1,
        rejected_count=0,
    )
    assert violations and "幻觉" in violations[0] and "F-9999-0001" in violations[0]


# ---- ② 计数断言守卫 ----


@pytest.mark.parametrize(
    "text,expected,ok",
    [
        ("本次测试共确认 2 个漏洞。", 2, True),
        ("本次测试确认 2 个漏洞。", 2, True),
        ("2 个漏洞被确认。", 2, True),
        ("本次测试共发现确认（confirmed）1项。", 1, True),
        ("确认 2 项。", 2, True),
        ("本次测试共确认 3 个漏洞。", 2, False),
        ("确认 3 个漏洞。", 2, False),
        ("确认（confirmed）3项。", 2, False),
        ("3 个漏洞被确认。", 2, False),
        ("未确认 3 个候选仍待复测。", 2, True),  # 否定豁免
    ],
)
def test_count_guard_confirm_forms(text, expected, ok):
    violations = check_narrative_facts(
        [text], {}, confirmed_count=expected, rejected_count=0
    )
    assert (violations == []) == ok, (text, violations)


@pytest.mark.parametrize(
    "text,expected,ok",
    [
        ("已排除误报 5 个候选。", 5, True),
        ("误报 5 个。", 5, True),
        ("误报（rejected）5项。", 5, True),
        ("共排除 5 个候选。", 5, True),
        ("5 个候选经复核判定为误报。", 5, True),
        ("误报 4 个。", 5, False),
        ("误报（rejected）4项。", 5, False),
        ("共排除 3 个。", 5, False),
    ],
)
def test_count_guard_reject_forms(text, expected, ok):
    violations = check_narrative_facts(
        [text], {}, confirmed_count=0, rejected_count=expected
    )
    assert (violations == []) == ok, (text, violations)


@pytest.mark.parametrize(
    "text,confirmed,rejected,ok",
    [
        ("本次测试共确认一个漏洞。", 1, 0, True),
        ("本次测试共确认三个漏洞。", 1, 0, False),
        ("已排除误报十个候选。", 0, 10, True),
        ("确认二个漏洞。", 2, 0, True),
    ],
)
def test_count_guard_chinese_numerals(text, confirmed, rejected, ok):
    violations = check_narrative_facts(
        [text], {}, confirmed_count=confirmed, rejected_count=rejected
    )
    assert (violations == []) == ok, (text, violations)


def test_violation_message_details():
    """违规描述写明 F-ID/声称词/真实状态；计数违规写明声称与真实。"""
    states = _states(**{"F-2026-0004": "reproduced"})
    violations = check_narrative_facts(
        ["共确认 3 个漏洞。F-2026-0004 已确认可利用。"],
        states,
        confirmed_count=1,
        rejected_count=0,
    )
    state_hit = next(v for v in violations if "F-2026-0004" in v)
    assert "确认" in state_hit and "reproduced" in state_hit
    count_hit = next(v for v in violations if "计数" in v)
    assert "3" in count_hit and "= 1" in count_hit


# ---- ③ reasons_cn schema 与落盘 ----


def test_reasons_cn_unknown_key_rejected(report_evidence_dir):
    """reasons_cn 键超出 Rejected 集合 → 无锚归因拒收。"""
    reply = _reply(reasons={"F-2026-0001": "confirmed 不是 rejected"})
    with pytest.raises(NarrativeError, match="无锚归因"):
        _generate(report_evidence_dir, SeqRouter([reply]))


def test_reasons_cn_blank_value_rejected(report_evidence_dir):
    reply = _reply(reasons={"F-2026-0004": "  "})
    with pytest.raises(NarrativeError, match="schema"):
        _generate(report_evidence_dir, SeqRouter([reply]))


def test_reasons_cn_missing_tolerated_empty_file(report_evidence_dir):
    """缺 reasons_cn（旧回复格式）容忍；落盘文件恒写为空 dict（防陈旧）。"""
    _generate(report_evidence_dir, SeqRouter([_reply()]))
    path = report_evidence_dir / "rejected_reasons_cn.json"
    assert path.is_file()
    assert json.loads(path.read_text(encoding="utf-8")) == {}


def test_reasons_cn_fact_guard_applies(report_evidence_dir):
    """reasons_cn 文本同样过事实守卫（幻觉 F-ID 拒）。"""
    reply = _reply(reasons={"F-2026-0004": "与 F-9999-0002 同款误报。"})
    with pytest.raises(NarrativeError, match="幻觉"):
        _generate(report_evidence_dir, SeqRouter([reply]))


# ---- ④ 落盘 + data 透传 + 模板渲染 ----

REASON_TEXT = "该版本匹配型 CVE 缺乏行为验证，按铁律排除。"


def test_reasons_cn_persist_audit_and_data_passthrough(report_evidence_dir, tmp_path):
    """reasons_cn 落盘 + 审计 kind=reason_cn + build_context 仅 Rejected 桶透传。"""
    audit = AuditLog(tmp_path / "audit.jsonl")
    _generate(
        report_evidence_dir,
        SeqRouter([_reply(reasons={"F-2026-0004": REASON_TEXT})]),
        audit,
    )
    path = report_evidence_dir / "rejected_reasons_cn.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "F-2026-0004": REASON_TEXT
    }
    events = [
        e
        for e in audit.read_all()
        if e["event"] == "narrative_generated" and e.get("kind") == "reason_cn"
    ]
    assert [e["finding_id"] for e in events] == ["F-2026-0004"]

    context = build_context(report_evidence_dir)
    rejected = context.rejected_findings[0]
    assert rejected.id == "F-2026-0004" and rejected.reason_cn == REASON_TEXT
    for row in (
        context.confirmed_findings
        + context.conditional_findings
        + context.hypothesis_findings
    ):
        assert row.reason_cn is None


def test_reason_cn_bad_file_tolerated(report_evidence_dir):
    """rejected_reasons_cn.json 坏 JSON → reason_cn 容忍 None（回退原文）。"""
    (report_evidence_dir / "rejected_reasons_cn.json").write_text(
        "不是 JSON", encoding="utf-8"
    )
    context = build_context(report_evidence_dir)
    assert context.rejected_findings[0].reason_cn is None


def _render_appendix_b(report_evidence_dir, tmp_path):
    template = tmp_path / "tpl.docx"
    make_default_template.main(["--out", str(template)])
    context = build_context(report_evidence_dir).as_template_context()
    out = render_docx(context, template, tmp_path / "out.docx")
    from docx import Document

    doc = Document(str(out))
    table = next(
        t
        for t in doc.tables
        if t.rows[0].cells[0].text == "ID"
        and t.rows[0].cells[1].text == "漏洞类型"
        and t.rows[0].cells[3].text == "排除原因"
    )
    return [[c.text for c in row.cells] for row in table.rows[1:]]


def test_reason_cn_render_and_fallback(report_evidence_dir, tmp_path):
    """附录 B：有 reason_cn 显示中文归因；无（旧数据）回退 rejection_reason。"""
    _generate(
        report_evidence_dir,
        SeqRouter([_reply(reasons={"F-2026-0004": REASON_TEXT})]),
    )
    rows = _render_appendix_b(report_evidence_dir, tmp_path)
    assert rows[0][0] == "F-2026-0004" and rows[0][3] == REASON_TEXT

    (report_evidence_dir / "rejected_reasons_cn.json").unlink()
    rows = _render_appendix_b(report_evidence_dir, tmp_path)
    assert "铁律禁止直接 Confirmed" in rows[0][3]


# ---- ⑤ 修复重试集成（M6a 语义自然生效）----

DISTORTED_OVERVIEW = "本次测试共确认 3 个漏洞。其中 F-2026-0002 已确认可利用。"
FIXED_OVERVIEW = "本次测试共确认 2 个漏洞。其中 F-2026-0002 经有效验证尚待终审。"


def test_factguard_repair_success(report_evidence_dir, tmp_path):
    """首轮状态失真 → 守卫拒 → 修复重试修正 → 落盘 + llm_repair_attempt success。"""
    audit = AuditLog(tmp_path / "audit.jsonl")
    _generate(
        report_evidence_dir,
        SeqRouter([_reply(overview=DISTORTED_OVERVIEW), _reply(overview=FIXED_OVERVIEW)]),
        audit,
    )
    attempts = [
        e for e in audit.read_all() if e["event"] == "llm_repair_attempt"
    ]
    assert len(attempts) == 1 and attempts[0]["caller"] == "narrative"
    assert attempts[0]["result"] == "success"
    sections = json.loads(
        (report_evidence_dir / "narrative_sections.json").read_text(encoding="utf-8")
    )
    assert sections["overview"] == FIXED_OVERVIEW


def test_factguard_double_failure_zero_write(report_evidence_dir, tmp_path):
    """两轮均失真 → NarrativeError 零写入 + result=failed。"""
    store = FindingStore(report_evidence_dir / "findings.jsonl")
    lines_before = len(store.path.read_text(encoding="utf-8").splitlines())
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(NarrativeError, match="事实守卫"):
        _generate(
            report_evidence_dir,
            SeqRouter(
                [
                    _reply(overview=DISTORTED_OVERVIEW),
                    _reply(overview="共确认 3 个漏洞。"),
                ]
            ),
            audit,
        )
    assert (
        len(store.path.read_text(encoding="utf-8").splitlines()) == lines_before
    )
    assert not (report_evidence_dir / "narrative_sections.json").exists()
    assert not (report_evidence_dir / "rejected_reasons_cn.json").exists()
    attempts = [
        e for e in audit.read_all() if e["event"] == "llm_repair_attempt"
    ]
    assert attempts[0]["result"] == "failed"


# ---- ⑥ prompt 加固 ----


def test_prompt_carries_state_roster_and_discipline(report_evidence_dir):
    """payload 含全量 id→state 清单 + rejected_reason_ids；系统提示含措辞纪律。"""
    router = SeqRouter([_reply()])
    _generate(report_evidence_dir, router)
    _, messages = router.calls[0]
    assert "措辞纪律" in messages[0]["content"]
    payload = json.loads(messages[1]["content"])
    roster = {r["id"]: r["state"] for r in payload["state_roster"]}
    assert roster == {
        "F-2026-0001": "confirmed",
        "F-2026-0005": "confirmed",
        "F-2026-0002": "reproduced",
        "F-2026-0003": "hypothesis",
        "F-2026-0004": "rejected",
    }
    assert payload["rejected_reason_ids"] == ["F-2026-0004"]
