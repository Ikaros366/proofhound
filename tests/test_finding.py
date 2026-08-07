"""Finding 生命周期状态机与 FindingStore 单元测试（M3a，§5.4.1/§5.5）。

覆盖验收点：
- 合法链 signal→hypothesis→reproduced→confirmed 逐步迁移；
- 非法迁移表抛 InvalidTransitionError（含终态不可出）；
- 两条铁律（version-cve / 纯 status-code 证据）迁入 Confirmed 抛
  IronRuleViolationError（InvalidTransitionError 子类）；
- Confirmed 必须携带 verification.evidence_refs；
- 每次迁移记审计 finding_state{finding_id, from, to, actor, reason}；
- FindingStore：快照追加 last-wins 回放、next_id 序号、
  get_by_dedup_key 跳过 Rejected。
"""

from __future__ import annotations

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.findings.finding import (
    Finding,
    FindingState,
    FindingStore,
    InvalidTransitionError,
    IronRuleViolationError,
    Verification,
)

T0 = "2026-08-07T00:00:00.000+00:00"


def _make_finding(audit: AuditLog | None = None, **overrides) -> Finding:
    defaults = dict(
        id="F-2026-0001",
        vuln_type="sqli",
        asset="http://example.com/api/login",
        dedup_key="sha256:deadbeef",
        evidence_kinds=["status-code", "behavioral-diff"],
        created_at=T0,
        updated_at=T0,
        audit=audit,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _verification() -> Verification:
    return Verification(
        method="boolean-diff",
        evidence_refs=["evidence/F-2026-0001/response.txt#L1"],
        baseline_diff="真条件 1,203B / 假条件 217B",
        reproduction_steps=["curl 真条件请求", "curl 假条件请求"],
        verified_by="verify-sqli@1.0.0",
    )


def _to_reproduced(finding: Finding) -> Finding:
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="triage 通过")
    finding.transition(FindingState.REPRODUCED, actor="verify-sqli", reason="PoC 复现")
    return finding


def _to_confirmed(finding: Finding) -> Finding:
    _to_reproduced(finding)
    finding.verification = _verification()
    finding.transition(FindingState.CONFIRMED, actor="verify-sqli", reason="边界突破")
    return finding


# ---- 合法迁移 ----


def test_happy_path_signal_to_confirmed():
    finding = _make_finding()  # 无审计句柄：迁移照常可用（不记审计）
    assert finding.state is FindingState.SIGNAL

    _to_confirmed(finding)
    assert finding.state is FindingState.CONFIRMED
    assert finding.updated_at != T0  # 迁移推进 updated_at


def test_reject_from_any_non_terminal():
    for chain in ([], [FindingState.HYPOTHESIS], [FindingState.HYPOTHESIS, FindingState.REPRODUCED]):
        finding = _make_finding()
        for to in chain:
            finding.transition(to, actor="t", reason="r")
        finding.transition(FindingState.REJECTED, actor="verifier", reason="误报")
        assert finding.state is FindingState.REJECTED
        assert finding.rejection_reason == "误报"


# ---- 非法迁移 ----


@pytest.mark.parametrize(
    "chain,to",
    [
        ([], FindingState.REPRODUCED),
        ([], FindingState.CONFIRMED),
        ([FindingState.HYPOTHESIS], FindingState.CONFIRMED),
        ([FindingState.HYPOTHESIS], FindingState.SIGNAL),
        ([FindingState.HYPOTHESIS, FindingState.REPRODUCED], FindingState.SIGNAL),
        ([FindingState.HYPOTHESIS, FindingState.REPRODUCED], FindingState.HYPOTHESIS),
    ],
)
def test_illegal_transitions_raise(chain, to):
    finding = _make_finding()
    for step in chain:
        finding.transition(step, actor="t", reason="r")
    finding.verification = _verification()
    with pytest.raises(InvalidTransitionError):
        finding.transition(to, actor="t", reason="r")


def test_terminal_states_have_no_outgoing():
    confirmed = _to_confirmed(_make_finding())
    with pytest.raises(InvalidTransitionError):
        confirmed.transition(FindingState.REJECTED, actor="t", reason="r")

    rejected = _make_finding()
    rejected.transition(FindingState.REJECTED, actor="t", reason="误报")
    with pytest.raises(InvalidTransitionError):
        rejected.transition(FindingState.HYPOTHESIS, actor="t", reason="r")


# ---- 铁律（代码层硬编码） ----


def test_iron_rule_version_cve_never_confirmed():
    """版本匹配型 CVE：即使带行为证据与 verification，也永远禁止 Confirmed。"""
    finding = _to_reproduced(_make_finding(vuln_type="version-cve"))
    finding.verification = _verification()
    with pytest.raises(IronRuleViolationError):
        finding.transition(FindingState.CONFIRMED, actor="verify", reason="尝试晋级")
    assert finding.state is FindingState.REPRODUCED  # 拒绝后状态不变


def test_iron_rule_status_code_only_never_confirmed():
    """证据仅含 status-code：禁止 Confirmed。"""
    finding = _to_reproduced(_make_finding(evidence_kinds=["status-code"]))
    finding.verification = _verification()
    with pytest.raises(IronRuleViolationError):
        finding.transition(FindingState.CONFIRMED, actor="verify", reason="尝试晋级")


def test_iron_rule_empty_evidence_kinds_fail_closed():
    """无任何行为类证据标签（空列表）：fail-closed 禁止 Confirmed。"""
    finding = _to_reproduced(_make_finding(evidence_kinds=[]))
    finding.verification = _verification()
    with pytest.raises(IronRuleViolationError):
        finding.transition(FindingState.CONFIRMED, actor="verify", reason="尝试晋级")


def test_iron_rule_error_is_invalid_transition():
    """铁律拒绝同属非法迁移族，可被 InvalidTransitionError 捕获。"""
    finding = _to_reproduced(_make_finding(evidence_kinds=["status-code"]))
    finding.verification = _verification()
    with pytest.raises(InvalidTransitionError):
        finding.transition(FindingState.CONFIRMED, actor="verify", reason="r")


def test_confirm_requires_verification_evidence_refs():
    finding = _to_reproduced(_make_finding())
    assert finding.verification is None
    with pytest.raises(IronRuleViolationError):
        finding.transition(FindingState.CONFIRMED, actor="verify", reason="r")


def test_behavioral_evidence_allows_confirm():
    """补充行为类证据标签后铁律放行。"""
    finding = _to_reproduced(_make_finding(evidence_kinds=["status-code"]))
    finding.evidence_kinds.append("behavioral-diff")
    finding.verification = _verification()
    finding.transition(FindingState.CONFIRMED, actor="verify", reason="边界突破")
    assert finding.state is FindingState.CONFIRMED


# ---- 迁移审计 ----


def test_every_transition_records_audit(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    finding = _to_confirmed(_make_finding(audit=audit))

    events = [e for e in audit.read_all() if e["event"] == "finding_state"]
    assert len(events) == 3
    assert [(e["from"], e["to"]) for e in events] == [
        ("signal", "hypothesis"),
        ("hypothesis", "reproduced"),
        ("reproduced", "confirmed"),
    ]
    for event in events:
        assert event["finding_id"] == finding.id
        assert event["actor"]
        assert "reason" in event
    assert events[0]["actor"] == "triage"


def test_audit_handle_excluded_from_serialization():
    finding = _to_confirmed(_make_finding(audit=AuditLog("/dev/null")))
    payload = finding.model_dump()
    assert "audit" not in payload
    assert "audit" not in finding.model_dump_json()


# ---- FindingStore ----


def test_store_snapshot_append_and_last_wins(tmp_path):
    store = FindingStore(tmp_path / "findings.jsonl")
    finding = _make_finding()
    store.append(finding)
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="triage 通过")
    store.append(finding)

    lines = store.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2  # 快照追加，不覆盖
    loaded = store.load_all()
    assert len(loaded) == 1
    assert loaded[0].state is FindingState.HYPOTHESIS  # last-wins
    assert loaded[0].audit is None  # 运行期句柄不回填


def test_store_next_id_sequence(tmp_path):
    store = FindingStore(tmp_path / "findings.jsonl")
    first = store.next_id()
    assert first.startswith("F-")
    store.append(_make_finding(id=first))
    second = store.next_id()
    assert second != first
    assert int(second.rsplit("-", 1)[1]) == int(first.rsplit("-", 1)[1]) + 1


def test_store_get_by_dedup_key_skips_rejected(tmp_path):
    store = FindingStore(tmp_path / "findings.jsonl")
    rejected = _make_finding(id="F-2026-0001")
    rejected.transition(FindingState.REJECTED, actor="verifier", reason="误报")
    store.append(rejected)
    assert store.get_by_dedup_key("sha256:deadbeef") is None

    active = _make_finding(id="F-2026-0002")
    store.append(active)
    assert store.get_by_dedup_key("sha256:deadbeef").id == "F-2026-0002"
    assert store.get("F-2026-0001").state is FindingState.REJECTED
