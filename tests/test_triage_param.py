"""M3d triage 扩展测试：param-endpoint Signal → sqli Hypothesis。

覆盖验收点：启发式键名命中/未命中、dedup param 分量、越界丢弃
（triage_out_of_scope）、每 engagement 上限 20 条（triage_capped）、
runner 无 scope 的单测形态、零 LLM 调用。
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings.finding import FindingState, FindingStore
from proofhound.skills.registry import SkillRegistry

BASE = "http://127.0.0.1:8080"


class FakeLLM:
    def __init__(self):
        self.calls = 0

    def complete(self, messages):
        self.calls += 1
        raise AssertionError("triage 不得调用 LLM")


def _param_row(asset, evidence_ref):
    return {
        "asset": asset,
        "status_code": 200,
        "title": None,
        "tech": [],
        "kind": "param-endpoint",
        "source_tool": "katana",
        "skill": "recon-crawl",
        "evidence_ref": evidence_ref,
    }


@pytest.fixture
def env(tmp_path, make_skill_dir):
    """编排器（runner 挂 scope）+ 预置 crawl 证据文件的 evidence 目录。"""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    raw = evidence_dir / "crawl.stdout.log"
    raw.write_text(
        "\n".join(f"line{i}" for i in range(1, 80)) + "\n", encoding="utf-8"
    )
    audit = AuditLog(evidence_dir / "audit.jsonl")
    llm = FakeLLM()
    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=SimpleNamespace(scope=Scope(networks=["127.0.0.0/8"])),
        llm=llm,
        audit=audit,
        evidence_dir=evidence_dir,
    )
    return orch, audit, llm, evidence_dir, raw


def _write_signals(evidence_dir, rows):
    signals_path = evidence_dir / "crawl.signals.jsonl"
    with signals_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _summary(audit):
    return [e for e in audit.read_all() if e["event"] == "triage_completed"][0]


def test_hinted_param_creates_sqli_hypothesis(env):
    orch, audit, llm, evidence_dir, raw = env
    _write_signals(
        evidence_dir,
        [_param_row(f"{BASE}/vulnerabilities/sqli/?id=1&Submit=Submit", f"{raw}#L6")],
    )
    findings = orch.run_triage_phase()

    # id 命中 sqli 表；M8c 起 id 同中 idor 表 → 同产 sqli+idor（设计行为），
    # Submit 非启发式键不建；dedup 按 vuln_type 分量区分互不合并
    assert len(findings) == 2
    by_type = {f.vuln_type: f for f in findings}
    finding = by_type["sqli"]
    assert finding.state is FindingState.HYPOTHESIS
    assert finding.vuln_type == "sqli"
    assert finding.param == "id"
    assert finding.severity == "medium"
    assert finding.evidence_kinds == ["crawl-endpoint"]
    assert finding.asset == f"{BASE}/vulnerabilities/sqli/?id=1&Submit=Submit"
    assert finding.source_signal_refs == [f"{raw}#L6"]
    idor = by_type["idor"]  # M8c：同参数键同产的 idor 候选同构
    assert idor.state is FindingState.HYPOTHESIS
    assert idor.param == "id"
    assert idor.severity == "medium"
    assert idor.evidence_kinds == ["crawl-endpoint"]
    assert idor.asset == finding.asset
    assert idor.source_signal_refs == [f"{raw}#L6"]
    assert idor.dedup_key != finding.dedup_key
    summary = _summary(audit)
    assert summary["created"] == 2
    assert summary["created_by_type"] == {"sqli": 1, "idor": 1}
    assert summary["kept_signal"] == 0
    assert llm.calls == 0


def test_non_hint_key_stays_signal(env):
    orch, audit, _, evidence_dir, raw = env
    _write_signals(
        evidence_dir, [_param_row(f"{BASE}/x?Submit=ok&next=1", f"{raw}#L1")]
    )
    assert orch.run_triage_phase() == []
    assert not (evidence_dir / "findings.jsonl").exists()
    summary = _summary(audit)
    assert summary["created"] == 0
    assert summary["kept_signal"] == 1


def test_dedup_param_dimension(env):
    """同 URL 不同 param 不合并；同指纹（URL+param）合并证据。"""
    orch, audit, _, evidence_dir, raw = env
    _write_signals(
        evidence_dir,
        [
            _param_row(f"{BASE}/a?id=1&page=2", f"{raw}#L1"),
            _param_row(f"{BASE}/a?id=1&page=2", f"{raw}#L2"),
        ],
    )
    orch.run_triage_phase()

    store = FindingStore(evidence_dir / "findings.jsonl")
    findings = store.load_all()
    # M8c：id 同中 idor 表 → sqli:id、sqli:page、idor:id 三条（idor:id 与
    # sqli:id 同 param 不同 vuln_type，dedup 按 vuln_type 分量区分）
    assert len(findings) == 3
    by_key = {(f.vuln_type, f.param): f for f in findings}
    assert set(by_key) == {("sqli", "id"), ("sqli", "page"), ("idor", "id")}
    for finding in findings:
        assert finding.source_signal_refs == [f"{raw}#L1", f"{raw}#L2"]
    dedup_events = [e for e in audit.read_all() if e["event"] == "finding_deduplicated"]
    assert len(dedup_events) == 3
    summary = _summary(audit)
    assert summary["created"] == 3
    assert summary["merged"] == 3
    assert summary["merged_by_type"] == {"sqli": 2, "idor": 1}


def test_out_of_scope_dropped(env):
    """建 Hypothesis 前的 check_scope 层：越界 asset 丢弃并记审计。"""
    orch, audit, _, evidence_dir, raw = env
    _write_signals(
        evidence_dir, [_param_row("http://10.0.0.1:8080/x?id=1", f"{raw}#L1")]
    )
    assert orch.run_triage_phase() == []
    assert not (evidence_dir / "findings.jsonl").exists()
    oos = [e for e in audit.read_all() if e["event"] == "triage_out_of_scope"]
    assert len(oos) == 1
    assert oos[0]["asset"] == "http://10.0.0.1:8080/x?id=1"
    assert oos[0]["violations"]
    assert _summary(audit)["kept_signal"] == 1


def test_sqli_cap_20(env):
    """防确认洪泛：每 engagement 新建 sqli Hypothesis 上限 20，超出记
    triage_capped；重跑幂等（既有 20 条占满额度）。"""
    orch, audit, _, evidence_dir, raw = env
    _write_signals(
        evidence_dir,
        [_param_row(f"{BASE}/p{n}?id={n}", f"{raw}#L{n}") for n in range(1, 26)],
    )
    orch.run_triage_phase()

    store = FindingStore(evidence_dir / "findings.jsonl")
    # M8c：同批 id 键另产 idor 候选（独立上限 10，与 sqli 互不挤占）
    findings = store.load_all()
    assert sum(1 for f in findings if f.vuln_type == "sqli") == 20
    assert sum(1 for f in findings if f.vuln_type == "idor") == 10
    capped = [e for e in audit.read_all() if e["event"] == "triage_capped"]
    assert len(capped) == 2  # sqli 与 idor 各自独立记一条
    by_type = {e["vuln_type"]: e for e in capped}
    assert by_type["sqli"]["limit"] == 20
    assert by_type["sqli"]["dropped"] == 5
    assert by_type["idor"]["limit"] == 10
    assert by_type["idor"]["dropped"] == 15
    assert _summary(audit)["created"] == 30

    orch.run_triage_phase()  # 重跑：已建条幂等跳过；首轮被丢弃的候选
    # 确定性重判并再次丢弃（建侧幂等：findings 恒 30 条，不重复建）
    findings = store.load_all()
    assert sum(1 for f in findings if f.vuln_type == "sqli") == 20
    assert sum(1 for f in findings if f.vuln_type == "idor") == 10
    summaries = [e for e in audit.read_all() if e["event"] == "triage_completed"]
    assert summaries[1]["created"] == 0
    assert summaries[1]["merged"] == 0
    capped = [e for e in audit.read_all() if e["event"] == "triage_capped"]
    assert len(capped) == 4  # 首轮 + 重跑各按类型记一次，dropped 不变
    assert sum(1 for e in capped if e["vuln_type"] == "sqli") == 2
    assert sum(1 for e in capped if e["vuln_type"] == "idor") == 2
    assert all(e["dropped"] == 5 for e in capped if e["vuln_type"] == "sqli")
    assert all(e["dropped"] == 15 for e in capped if e["vuln_type"] == "idor")


def test_runner_without_scope_skips_check(tmp_path, make_skill_dir):
    """runner 未挂 scope（纯 triage 单测形态）：本层校验不触发，沙箱层仍是
    最终强校验——与 _session() 的 None 容忍范式一致。"""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    raw = evidence_dir / "crawl.stdout.log"
    raw.write_text("line1\n", encoding="utf-8")
    _write_signals(
        evidence_dir, [_param_row(f"{BASE}/x?id=1", f"{raw}#L1")]
    )
    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=None,
        llm=FakeLLM(),
        audit=AuditLog(evidence_dir / "audit.jsonl"),
        evidence_dir=evidence_dir,
    )
    findings = orch.run_triage_phase()
    # M8c：id 同中 idor 表 → 同产 sqli+idor
    assert len(findings) == 2
    assert {f.vuln_type for f in findings} == {"sqli", "idor"}
