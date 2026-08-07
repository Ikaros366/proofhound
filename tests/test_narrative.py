"""叙述生成测试（M4，§5.7）：T1 档 mock，不进真实 LLM。

覆盖验收点：
- 合法输出：narrative 落 findings.jsonl（Finding.narrative）+ 固定章节落
  narrative_sections.json + 审计 narrative_generated（含 tokens）+ 证据包
  finding.json 重刷；
- 无锚文字（未知键）/坏 JSON/空段落 → NarrativeError，全量拒收零落盘；
- BudgetExceededError 原样上抛；prompt 超 max_chars → ContextOverflowError；
- 红线 3：prompt 只有结构化摘要——原始证据内容、凭据值不进上下文。
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.context import ContextOverflowError, ContextPolicy
from proofhound.findings.evidence import assemble_evidence_pack
from proofhound.findings.finding import FindingStore, NarrativeParts
from proofhound.llm.router import Tier
from proofhound.llm.usage import BudgetExceededError, UsageRecord, UsageTracker
from proofhound.report.narrative import NarrativeError, NarrativeGenerator

RAW_SENTINEL = "RAW-SECRET-OUTPUT-7f3a9c"  # 只存在于证据原文的哨兵串
COOKIE_VALUE = "df6a4b9c0e1f2a3b4c5d6e7f890abcde"


class MockRouter:
    """罐头 T1 路由：记录调用，返回预设文本；带 tracker 时模拟计量。"""

    def __init__(self, reply: str | Exception, tracker: UsageTracker | None = None):
        self.reply = reply
        self.calls: list[tuple] = []
        self.configs = {Tier.T1: SimpleNamespace(model="t1-mock")}
        self.tracker = tracker

    def complete(self, tier, messages):
        self.calls.append((tier, messages))
        if isinstance(self.reply, Exception):
            raise self.reply
        if self.tracker is not None:
            self.tracker.record(
                UsageRecord(
                    tier="t1",
                    model="t1-mock",
                    prompt_tokens=10,
                    completion_tokens=6,
                    latency_ms=1.0,
                    estimated=False,
                )
            )
        return self.reply


VALID_REPLY = json.dumps(
    {
        "paragraphs": {
            "F-2026-0001": "该 SQL 注入可致数据泄漏。",
            "F-2026-0005": "该 RCE 可直接执行命令。",
            "overview": "本次测试共确认 2 个漏洞。",
            "remediation": "建议使用参数化查询。",
        }
    },
    ensure_ascii=False,
)


def _store(report_evidence_dir) -> FindingStore:
    return FindingStore(report_evidence_dir / "findings.jsonl")


def _generate(report_evidence_dir, router, audit=None):
    store = _store(report_evidence_dir)
    generator = NarrativeGenerator(router, audit)
    return generator.generate(
        store.load_all(), store=store, evidence_dir=report_evidence_dir
    )


def test_valid_paragraphs_persist_with_audit(report_evidence_dir):
    tracker = UsageTracker()
    audit = AuditLog(report_evidence_dir / "audit.jsonl")
    paragraphs = _generate(
        report_evidence_dir, MockRouter(VALID_REPLY, tracker), audit
    )
    assert paragraphs["F-2026-0001"] == "该 SQL 注入可致数据泄漏。"

    # narrative 落 findings.jsonl（回放可见）；事实字段不动
    store = _store(report_evidence_dir)
    finding = store.get("F-2026-0001")
    assert finding.narrative == "该 SQL 注入可致数据泄漏。"
    assert finding.vuln_type == "sqli" and finding.severity == "high"
    # hypothesis / rejected 无叙述
    assert store.get("F-2026-0003").narrative is None
    assert store.get("F-2026-0004").narrative is None

    # 固定章节落 narrative_sections.json
    sections = json.loads(
        (report_evidence_dir / "narrative_sections.json").read_text(
            encoding="utf-8"
        )
    )
    assert sections == {
        "overview": "本次测试共确认 2 个漏洞。",
        "remediation": "建议使用参数化查询。",
    }

    # 审计：每条 finding 一段 + 每个章节一段；tokens 来自路由计量差量
    events = [
        e for e in audit.read_all() if e["event"] == "narrative_generated"
    ]
    finding_events = [e for e in events if "finding_id" in e]
    section_events = [e for e in events if "section" in e]
    assert {e["finding_id"] for e in finding_events} == {
        "F-2026-0001",
        "F-2026-0005",
    }
    assert {e["section"] for e in section_events} == {"overview", "remediation"}
    assert all(e["model"] == "t1-mock" for e in events)
    assert all(e["tokens"] == 16 for e in events)  # 10 + 6

    # 证据包 finding.json 重刷（带入 narrative）
    pack_snapshot = json.loads(
        (
            report_evidence_dir / "findings" / "F-2026-0001" / "finding.json"
        ).read_text(encoding="utf-8")
    )
    assert pack_snapshot["narrative"] == "该 SQL 注入可致数据泄漏。"


def test_unknown_key_rejected_all_or_nothing(report_evidence_dir):
    """无锚文字（键不在允许集合）→ NarrativeError，零落盘。"""
    store_before = _store(report_evidence_dir)
    lines_before = len(
        store_before.path.read_text(encoding="utf-8").splitlines()
    )
    bad_reply = json.dumps(
        {"paragraphs": {"F-9999-9999": "无锚段落", "overview": "概述"}},
        ensure_ascii=False,
    )
    with pytest.raises(NarrativeError, match="无锚"):
        _generate(report_evidence_dir, MockRouter(bad_reply))
    assert (
        len(store_before.path.read_text(encoding="utf-8").splitlines())
        == lines_before
    )
    assert not (report_evidence_dir / "narrative_sections.json").exists()


def test_bad_json_and_empty_paragraph_rejected(report_evidence_dir):
    with pytest.raises(NarrativeError, match="非 JSON"):
        _generate(report_evidence_dir, MockRouter("这不是 JSON"))
    empty = json.dumps({"paragraphs": {"F-2026-0001": "  "}}, ensure_ascii=False)
    with pytest.raises(NarrativeError, match="schema"):
        _generate(report_evidence_dir, MockRouter(empty))


def test_budget_exceeded_propagates(report_evidence_dir):
    router = MockRouter(
        BudgetExceededError(tier="t1", used=100, limit=50, scope="run")
    )
    with pytest.raises(BudgetExceededError):
        _generate(report_evidence_dir, router)


def test_context_overflow_raises(report_evidence_dir):
    store = _store(report_evidence_dir)
    generator = NarrativeGenerator(
        MockRouter(VALID_REPLY), context_policy=ContextPolicy(max_chars=10)
    )
    with pytest.raises(ContextOverflowError):
        generator.generate(
            store.load_all(), store=store, evidence_dir=report_evidence_dir
        )
    # 超限在调用前检查：不应有 LLM 调用
    assert generator.router.calls == []


def test_prompt_has_no_raw_output(report_evidence_dir):
    """红线 3：prompt 只含结构化摘要——证据原文、凭据值不进上下文。"""
    log = report_evidence_dir / "run1.stdout.log"
    log.write_text(
        f"line1\n{RAW_SENTINEL}\nCookie: PHPSESSID={COOKIE_VALUE}\n",
        encoding="utf-8",
    )
    assemble_evidence_pack(  # 让哨兵进入证据包也不影响 prompt 边界
        _store(report_evidence_dir).get("F-2026-0001"),
        evidence_base=report_evidence_dir,
    )
    router = MockRouter(VALID_REPLY)
    _generate(report_evidence_dir, router)
    tier, messages = router.calls[0]
    assert tier is Tier.T1
    prompt_text = json.dumps(messages, ensure_ascii=False)
    assert RAW_SENTINEL not in prompt_text
    assert COOKIE_VALUE not in prompt_text
    #  sanity：结构化摘要在
    assert "F-2026-0001" in prompt_text and "sqli" in prompt_text


def test_prompt_payload_keys_and_stats(report_evidence_dir):
    """allowed_keys = confirmed/reproduced id ∪ 固定章节；rejected 只进统计。"""
    router = MockRouter(VALID_REPLY)
    _generate(report_evidence_dir, router)
    _, messages = router.calls[0]
    payload = json.loads(messages[1]["content"])
    assert set(payload["allowed_keys"]) == {
        "F-2026-0001",
        "F-2026-0002",  # reproduced（conditional）也生成叙述
        "F-2026-0005",
        "overview",
        "remediation",
    }
    assert payload["stats"]["rejected"] == 1
    assert payload["stats"]["rejected_reasons"][0]["id"] == "F-2026-0004"
    # rejected / hypothesis 不进叙述摘要
    narrated_ids = {f["id"] for f in payload["findings"]}
    assert "F-2026-0004" not in narrated_ids
    assert "F-2026-0003" not in narrated_ids


# ---- M4.5：三段叙述（narrative_parts） ----

PARTS_REPLY = json.dumps(
    {
        "paragraphs": {
            "F-2026-0001": {
                "description": "登录接口存在 SQL 注入。",
                "impact": "可致后台数据库内容泄漏。",
                "remediation": "改用参数化查询。",
            },
            "F-2026-0005": {
                "description": "接口可执行系统命令。",
                "impact": "可完全控制服务器。",
                "remediation": "收敛危险函数并加白名单。",
            },
            "overview": "本次测试共确认 2 个漏洞。",
            "remediation": "建议使用参数化查询。",
        }
    },
    ensure_ascii=False,
)


def test_valid_parts_persist_with_audit(report_evidence_dir):
    """三段对象：narrative_parts 落盘可回放、narrative 派生、审计同形。"""
    tracker = UsageTracker()
    audit = AuditLog(report_evidence_dir / "audit.jsonl")
    paragraphs = _generate(
        report_evidence_dir, MockRouter(PARTS_REPLY, tracker), audit
    )
    parts = paragraphs["F-2026-0001"]
    assert isinstance(parts, NarrativeParts)
    assert parts.description == "登录接口存在 SQL 注入。"

    store = _store(report_evidence_dir)
    finding = store.get("F-2026-0001")
    assert finding.narrative_parts is not None
    assert finding.narrative_parts.impact == "可致后台数据库内容泄漏。"
    # 单段 narrative 由三段确定性拼接派生（default_template 契约不变）
    assert finding.narrative == (
        "登录接口存在 SQL 注入。\n可致后台数据库内容泄漏。\n改用参数化查询。"
    )
    # 事实字段不动
    assert finding.vuln_type == "sqli" and finding.severity == "high"

    # 固定章节仍为字符串，落 narrative_sections.json
    sections = json.loads(
        (report_evidence_dir / "narrative_sections.json").read_text(
            encoding="utf-8"
        )
    )
    assert sections == {
        "overview": "本次测试共确认 2 个漏洞。",
        "remediation": "建议使用参数化查询。",
    }

    # 审计事件形状不变
    events = [
        e for e in audit.read_all() if e["event"] == "narrative_generated"
    ]
    assert {e["finding_id"] for e in events if "finding_id" in e} == {
        "F-2026-0001",
        "F-2026-0005",
    }
    assert {e["section"] for e in events if "section" in e} == {
        "overview",
        "remediation",
    }
    assert all(e["tokens"] == 16 for e in events)

    # 证据包 finding.json 重刷带出 narrative_parts
    pack_snapshot = json.loads(
        (
            report_evidence_dir / "findings" / "F-2026-0001" / "finding.json"
        ).read_text(encoding="utf-8")
    )
    assert pack_snapshot["narrative_parts"]["remediation"] == "改用参数化查询。"


def test_parts_invalid_rejected_all_or_nothing(report_evidence_dir):
    """三段对象非法（缺字段/字段空白/多余键）→ NarrativeError，零落盘。"""
    store_before = _store(report_evidence_dir)
    lines_before = len(
        store_before.path.read_text(encoding="utf-8").splitlines()
    )
    base = {"description": "描", "impact": "危", "remediation": "改"}
    bad_parts = [
        {k: v for k, v in base.items() if k != "impact"},  # 缺字段
        {**base, "impact": "  "},  # 字段空白
        {**base, "poc": "不该有"},  # 多余键（extra=forbid）
    ]
    for bad in bad_parts:
        reply = json.dumps(
            {"paragraphs": {"F-2026-0001": bad, "overview": "概述"}},
            ensure_ascii=False,
        )
        with pytest.raises(NarrativeError):
            _generate(report_evidence_dir, MockRouter(reply))
    assert (
        len(store_before.path.read_text(encoding="utf-8").splitlines())
        == lines_before
    )
    assert not (report_evidence_dir / "narrative_sections.json").exists()


def test_section_key_must_be_string(report_evidence_dir):
    """固定章节键给三段对象 → NarrativeError（章节段落必须是字符串）。"""
    reply = json.dumps(
        {
            "paragraphs": {
                "overview": {
                    "description": "描",
                    "impact": "危",
                    "remediation": "改",
                }
            }
        },
        ensure_ascii=False,
    )
    with pytest.raises(NarrativeError, match="章节"):
        _generate(report_evidence_dir, MockRouter(reply))
