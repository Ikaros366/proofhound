"""确定性 triage 阶段测试（M3a）：web-scan Signals → Finding，零 LLM 调用。

覆盖验收点：
- web-probe 存活 Signal 建 Finding 置 Hypothesis（含审计 finding_state）；
- 同 dedup_key 合并（追加 source_signal_refs，记 finding_deduplicated）；
- 不可映射 Signal（404 / version-cve kind）保持 Signal；
- triage 全程不调 LLM（FakeLLM 计数为 0）；
- 重复跑幂等；Rejected 不吸收新证据（新建下一条 Finding）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings.finding import FindingState, FindingStore
from proofhound.skills.registry import SkillRegistry

ASSET = "http://127.0.0.1:8000"


class FakeLLM:
    def __init__(self):
        self.calls = 0

    def complete(self, messages):
        self.calls += 1
        raise AssertionError("triage 不得调用 LLM")


def _signal_row(asset, status_code, evidence_ref, kind="web-probe"):
    return {
        "asset": asset,
        "status_code": status_code,
        "title": None,
        "tech": [],
        "kind": kind,
        "source_tool": "httpx",
        "skill": "web-scan",
        "evidence_ref": evidence_ref,
    }


@pytest.fixture
def env(tmp_path, make_skill_dir):
    """编排器 + 预置 signals/证据文件 的 evidence 目录。"""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    # 原始证据文件：3 行 httpx 输出，供 evidence_ref 锚点引用
    raw = evidence_dir / "run1.stdout.log"
    raw.write_text(
        '{"url":"%s","status_code":200}\n'
        '{"url":"%s","status_code":200,"title":"B"}\n'
        '{"url":"%s","status_code":404}\n' % (ASSET, ASSET, ASSET),
        encoding="utf-8",
    )
    rows = [
        _signal_row(ASSET, 200, f"{raw}#L1"),
        _signal_row(ASSET, 200, f"{raw}#L2"),  # 同资产同型：应合并
        _signal_row(ASSET, 404, f"{raw}#L3"),  # 不可映射：保持 Signal
    ]
    signals_path = evidence_dir / "run1.signals.jsonl"
    with signals_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    audit = AuditLog(evidence_dir / "audit.jsonl")
    llm = FakeLLM()
    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=None,  # triage 不执行工具
        llm=llm,
        audit=audit,
        evidence_dir=evidence_dir,
    )
    return orch, audit, llm, evidence_dir


def test_triage_maps_merges_and_keeps_signals(env):
    orch, audit, llm, evidence_dir = env
    orch.run_triage_phase()

    store = FindingStore(evidence_dir / "findings.jsonl")
    findings = store.load_all()
    assert len(findings) == 1  # 两条 200 合并为一条
    finding = findings[0]
    assert finding.state is FindingState.HYPOTHESIS
    assert finding.vuln_type == "web-exposure"
    assert finding.asset == ASSET
    assert finding.dedup_key.startswith("sha256:")
    assert finding.evidence_kinds == ["status-code"]
    assert len(finding.source_signal_refs) == 2  # 合并两条证据引用
    assert all(ref.endswith(("#L1", "#L2")) for ref in finding.source_signal_refs)

    # findings.jsonl 快照追加：建行 + 合并行
    lines = store.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    # 审计链
    events = audit.read_all()
    state_events = [e for e in events if e["event"] == "finding_state"]
    assert len(state_events) == 1
    assert state_events[0]["from"] == "signal"
    assert state_events[0]["to"] == "hypothesis"
    assert state_events[0]["actor"] == "triage"
    dedup_events = [e for e in events if e["event"] == "finding_deduplicated"]
    assert len(dedup_events) == 1
    assert dedup_events[0]["finding_id"] == finding.id
    summary = [e for e in events if e["event"] == "triage_completed"]
    assert summary[0]["signals"] == 3
    assert summary[0]["created"] == 1
    assert summary[0]["merged"] == 1
    assert summary[0]["kept_signal"] == 1  # 404 保持 Signal

    # 证据包就位：manifest 两项、含 sha256
    manifest = json.loads(
        (evidence_dir / "findings" / finding.id / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert len(manifest["items"]) == 2
    assert all(item["sha256"] for item in manifest["items"])

    assert llm.calls == 0  # 本刀零 LLM 调用


def test_triage_unmapped_signals_stay_signals(env, tmp_path):
    orch, audit, llm, evidence_dir = env
    # 覆盖为仅含不可映射 Signal 的输入
    raw = evidence_dir / "run1.stdout.log"
    signals_path = evidence_dir / "run1.signals.jsonl"
    rows = [
        _signal_row(ASSET, 404, f"{raw}#L3"),
        _signal_row(ASSET, 200, f"{raw}#L1", kind="version-cve"),
    ]
    with signals_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    result = orch.run_triage_phase()
    assert result == []
    assert not (evidence_dir / "findings.jsonl").exists()  # 无 Finding 落盘
    summary = [e for e in audit.read_all() if e["event"] == "triage_completed"]
    assert summary[0]["kept_signal"] == 2
    assert llm.calls == 0


def test_triage_rerun_is_idempotent(env):
    orch, audit, _, evidence_dir = env
    orch.run_triage_phase()
    orch.run_triage_phase()  # 重复跑：证据已归并，不再产生变更

    store = FindingStore(evidence_dir / "findings.jsonl")
    assert len(store.load_all()) == 1
    lines = store.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2  # 仍是首轮的建+并两行
    summaries = [e for e in audit.read_all() if e["event"] == "triage_completed"]
    assert summaries[1]["created"] == 0
    assert summaries[1]["merged"] == 0


def test_triage_rejected_finding_does_not_absorb(env):
    """同指纹但已 Rejected：不合并，新建下一条 Finding。"""
    orch, audit, _, evidence_dir = env
    findings = orch.run_triage_phase()
    store = FindingStore(evidence_dir / "findings.jsonl")
    first = findings[0]
    first.transition(FindingState.REJECTED, actor="verifier", reason="误报")
    store.append(first)

    orch.run_triage_phase()  # 同资产 Signal 仍在盘上
    all_findings = store.load_all()
    assert len(all_findings) == 2
    states = {f.id: f.state for f in all_findings}
    assert states[first.id] is FindingState.REJECTED
    new_id = next(i for i in states if i != first.id)
    assert states[new_id] is FindingState.HYPOTHESIS
