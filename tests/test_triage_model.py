"""M9c① 模型 triage 在编排层的接线测试（含 scope 纪律与 fail-closed 归因）。

与 tests/test_llm_triage.py 的分工：那边测模块本身（schema/白名单/接地性/输入边界），
这边测**编排层接线**——两来源合并、scope 送审纪律、失败归因审计、默认关闭等价。
"""

from __future__ import annotations

import json

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings.finding import FindingStore
from proofhound.skills.registry import SkillRegistry

ALLOWED = "http://127.0.0.1:8000"


class TriageRouter:
    """替身路由：按 prompt 里出现的参数名回候选（记录调用次数）。"""

    def __init__(self, mapping=None):
        self.mapping = mapping or {"article_id": "sqli", "ref": "xss"}
        self.calls = 0

    def complete(self, messages):
        # legacy 单参客户端接口（ensure_router 包装后转发）
        self.calls += 1
        blob = messages[-1]["content"]
        found = [
            {
                "vuln_type": vuln,
                "param": name,
                "reason": "替身",
                "confidence": "medium",
            }
            for name, vuln in self.mapping.items()
            if name in blob
        ]
        return json.dumps({"hypotheses": found}, ensure_ascii=False)


class BrokenRouter:
    """总回非法输出（坏 JSON）——测 fail-closed 归因。"""

    def __init__(self):
        self.calls = 0

    def complete(self, messages):
        self.calls += 1
        return "这不是 JSON"


def _signal_row(asset, kind, evidence_ref, status=200, form_fields=None):
    row = {
        "asset": asset,
        "status_code": status,
        "title": None,
        "tech": [],
        "kind": kind,
        "source_tool": "katana",
        "skill": "recon-crawl",
        "evidence_ref": evidence_ref,
        "form_fields": form_fields or [],
    }
    return row


@pytest.fixture
def env(tmp_path, make_skill_dir):
    """evidence 目录 + 两条 param-endpoint Signal（一条表外参数）。"""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    raw = evidence_dir / "run1.stdout.log"
    raw.write_text('{"url":"x"}\n{"url":"y"}\n{"url":"z"}\n', encoding="utf-8")
    rows = [
        # 表外参数（规则表看不见）+ 表内参数（规则表看得见）
        _signal_row(f"{ALLOWED}/b/sqli?article_id=1", "param-endpoint", f"{raw}#L1"),
        _signal_row(f"{ALLOWED}/a/sqli?id=1", "param-endpoint", f"{raw}#L2"),
    ]
    with (evidence_dir / "run1.signals.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return evidence_dir


def test_model_path_finds_out_of_table_param(env, make_skill_dir):
    """核心价值：规则表看不见的 article_id 由模型补上，两来源合并落盘。"""
    router = TriageRouter()
    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=None,
        llm=router,
        audit=AuditLog(env / "audit.jsonl"),
        evidence_dir=env,
        triage_model=True,
    )
    findings = orch.run_triage_phase()
    params = sorted(f.param for f in findings)
    assert "article_id" in params, f"模型候选未产出（实得 {params}）"
    assert "id" in params, "规则候选应同时保留"
    assert router.calls == 1
    store = FindingStore(env / "findings.jsonl")
    assert len(store.load_all()) == len(findings)


def test_model_candidates_are_hypothesis_not_confirmed(env, make_skill_dir):
    """红线 2：模型候选只是 Hypothesis，绝不越过验证层。"""
    from proofhound.findings.finding import FindingState

    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=None,
        llm=TriageRouter(),
        audit=AuditLog(env / "audit.jsonl"),
        evidence_dir=env,
        triage_model=True,
    )
    for finding in orch.run_triage_phase():
        assert finding.state is FindingState.HYPOTHESIS


def test_invalid_model_output_records_audit_and_keeps_rules(env, make_skill_dir):
    """fail-closed 归因：模型输出非法 → 记 triage_model_invalid，规则结果照旧。"""
    audit = AuditLog(env / "audit.jsonl")
    router = BrokenRouter()
    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=None,
        llm=router,
        audit=audit,
        evidence_dir=env,
        triage_model=True,
    )
    findings = orch.run_triage_phase()
    events = [e["event"] for e in audit.read_all()]
    assert "triage_model_invalid" in events, f"缺归因审计（实得 {events}）"
    # 规则路径不受影响：表内 id 仍产出
    assert any(f.param == "id" for f in findings)


def test_model_disabled_by_default_makes_no_call(env, make_skill_dir):
    """缺省关闭：一条 LLM 调用都不发（旧测试 test_triage.py 的同一纪律）。"""
    router = TriageRouter()
    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=None,
        llm=router,
        audit=AuditLog(env / "audit.jsonl"),
        evidence_dir=env,
    )
    orch.run_triage_phase()
    assert router.calls == 0


def test_model_only_arm_disables_rules(env, make_skill_dir):
    """纯模型臂：triage_rules=False 时规则候选不再产出。"""
    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=None,
        llm=TriageRouter(mapping={"id": "sqli"}),
        audit=AuditLog(env / "audit.jsonl"),
        evidence_dir=env,
        triage_rules=False,
        triage_model=True,
    )
    findings = orch.run_triage_phase()
    assert findings, "纯模型臂应产出候选"
    assert all(f.param == "id" for f in findings), [f.param for f in findings]