"""自主模式引擎测试（M5a，§5.9.2）：闸门矩阵 + 模式切换规则 + 不可旁路声明。

不可旁路声明（与 proofhound/autonomy.py 模块 docstring 同源）：在任何模式
（含无人值守）下，scope 强制校验、token 预算硬闸、cookie 凭据脱敏、
append-only 审计追加永远生效——自主模式只影响"是否停下来问人"。本文件
以行为测试坐实该声明：闸门没有关闭硬闸的开关，未知风险等级在任何模式下
都 fail-closed；API 侧的无人值守预算/scope 硬闸见 test_api.py。
"""

from __future__ import annotations

import pytest

from proofhound.autonomy import (
    AutonomyGate,
    AutonomyMode,
    AutonomySwitchError,
    GateDecision,
    RISK_ORDER,
    gate_matrix,
)
from proofhound.compliance.audit import AuditLog


# ---- 闸门矩阵：三种模式 × 三种风险等级 ----

EXPECTED_MATRIX = {
    AutonomyMode.SUPERVISED: {
        "L0": GateDecision.AUTO,
        "L1": GateDecision.CONFIRM,
        "L2": GateDecision.CONFIRM,
    },
    AutonomyMode.SEMI_AUTO: {
        "L0": GateDecision.AUTO,
        "L1": GateDecision.AUTO,
        "L2": GateDecision.CONFIRM,
    },
    AutonomyMode.UNATTENDED: {
        "L0": GateDecision.AUTO,
        "L1": GateDecision.AUTO,
        "L2": GateDecision.AUTO,
    },
}


@pytest.mark.parametrize("mode", list(AutonomyMode))
@pytest.mark.parametrize("risk_level", ["L0", "L1", "L2"])
def test_gate_matrix(mode, risk_level):
    gate = AutonomyGate(mode)
    assert gate.decide(risk_level) is EXPECTED_MATRIX[mode][risk_level]


def test_gate_matrix_export_matches_behavior():
    exported = gate_matrix()
    for mode in AutonomyMode:
        for level in RISK_ORDER:
            assert exported[mode.value][level] == EXPECTED_MATRIX[mode][level].value


@pytest.mark.parametrize("mode", list(AutonomyMode))
def test_unknown_risk_level_forbidden_in_any_mode(mode):
    """未知/未分级风险等级一律 forbidden（fail-closed），无人值守也不例外。"""
    gate = AutonomyGate(mode)
    assert gate.decide("L9") is GateDecision.FORBIDDEN
    assert gate.decide("") is GateDecision.FORBIDDEN


def test_invalid_mode_name_rejected():
    with pytest.raises(ValueError):
        AutonomyGate("god-mode")
    with pytest.raises(ValueError):
        AutonomyMode("root")


# ---- 模式切换：收紧自由，放宽需显式确认 ----


def test_tightening_switch_anytime_without_operator(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    gate = AutonomyGate(AutonomyMode.UNATTENDED, audit)
    record = gate.switch_mode(AutonomyMode.SEMI_AUTO)
    assert record["changed"] is True
    assert gate.mode is AutonomyMode.SEMI_AUTO
    record = gate.switch_mode(AutonomyMode.SUPERVISED)
    assert record["changed"] is True
    assert gate.mode is AutonomyMode.SUPERVISED


def test_loosening_switch_requires_operator(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    gate = AutonomyGate(AutonomyMode.SUPERVISED, audit)
    with pytest.raises(AutonomySwitchError):
        gate.switch_mode(AutonomyMode.UNATTENDED)  # 无 operator
    with pytest.raises(AutonomySwitchError):
        gate.switch_mode(AutonomyMode.UNATTENDED, operator="  ")  # 空白 operator
    assert gate.mode is AutonomyMode.SUPERVISED  # 未切换


def test_loosening_switch_with_operator_writes_audit(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    gate = AutonomyGate(AutonomyMode.SUPERVISED, audit)
    record = gate.switch_mode(
        AutonomyMode.UNATTENDED, operator="ikaros", note="夜间批量已授权"
    )
    assert record == {
        "from": "supervised",
        "to": "unattended",
        "operator": "ikaros",
        "note": "夜间批量已授权",
        "changed": True,
    }
    events = [e for e in audit.read_all() if e["event"] == "autonomy_mode_changed"]
    assert len(events) == 1
    event = events[0]
    assert event["from"] == "supervised"
    assert event["to"] == "unattended"
    assert event["operator"] == "ikaros"
    assert "夜间批量" in event["note"]


def test_same_mode_switch_is_noop(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    gate = AutonomyGate(AutonomyMode.SEMI_AUTO, audit)
    record = gate.switch_mode(AutonomyMode.SEMI_AUTO)
    assert record["changed"] is False
    assert audit.read_all() == []  # 幂等：不记审计


def test_invalid_switch_target_rejected(tmp_path):
    gate = AutonomyGate(AutonomyMode.SEMI_AUTO, AuditLog(tmp_path / "a.jsonl"))
    with pytest.raises(ValueError):
        gate.switch_mode("unrestricted")


# ---- 不可旁路声明 ----


def test_non_bypassable_statement_in_module_docstring():
    """声明写进模块 docstring：scope/预算/脱敏/审计在任何模式下永远生效。"""
    import proofhound.autonomy as autonomy

    doc = autonomy.__doc__
    assert "不可旁路" in doc
    for keyword in ("scope", "预算", "脱敏", "审计"):
        assert keyword in doc


def test_gate_has_no_bypass_surface():
    """闸门只回答"是否停下来问人"：没有关闭 scope/预算/脱敏/审计的接口。"""
    gate = AutonomyGate(AutonomyMode.UNATTENDED)
    for attr in dir(gate):
        lowered = attr.lower()
        assert "bypass" not in lowered
        assert "disable" not in lowered
        assert "skip" not in lowered
