"""M9c③ 自治闸门 L2 细分（只读验证可自动 / 写操作留人工）测试。

覆盖验收点：
- 闸门矩阵两行：``mutating``（缺省）与 ``read_only``，**只在 semi_auto × L2 不同**；
  supervised 一律 confirm（细分不放宽最严格档）、unattended 本就全自动；
- ``decide`` 缺省 ``mutating=True`` → 与 M9c③ 之前逐字节等价（旧矩阵不受影响）；
- 未知风险等级在任一 ``mutating`` 取值下都 forbidden（fail-closed）；
- ``gate_matrix()`` 形态与旧版逐字节一致（API/控制台契约），
  ``gate_matrix_read_only()`` 仅在 semi_auto.L2 上给出 auto；
- skill manifest ``mutating`` 字段：缺省 True（fail-closed），可显式声明 false；
- 编排层：只声明只读的 verify-* 映射为 False，未声明的一律 True；
- runner 端到端：semi_auto 下只读验证不再进确认队列，写操作仍进。
"""

from __future__ import annotations

import pytest

from proofhound.autonomy import (
    AutonomyGate,
    AutonomyMode,
    GateDecision,
    gate_matrix,
    gate_matrix_read_only,
)

MUTATING = {
    AutonomyMode.SUPERVISED: {"L0": "auto", "L1": "confirm", "L2": "confirm"},
    AutonomyMode.SEMI_AUTO: {"L0": "auto", "L1": "auto", "L2": "confirm"},
    AutonomyMode.UNATTENDED: {"L0": "auto", "L1": "auto", "L2": "auto"},
}

READ_ONLY = {
    AutonomyMode.SUPERVISED: {"L0": "auto", "L1": "confirm", "L2": "confirm"},
    # 唯一差异格：semi_auto × L2
    AutonomyMode.SEMI_AUTO: {"L0": "auto", "L1": "auto", "L2": "auto"},
    AutonomyMode.UNATTENDED: {"L0": "auto", "L1": "auto", "L2": "auto"},
}


# ---------------- 闸门矩阵 ----------------


@pytest.mark.parametrize("mode", list(AutonomyMode))
@pytest.mark.parametrize("level", ["L0", "L1", "L2"])
def test_read_only_row(mode, level):
    gate = AutonomyGate(mode)
    assert gate.decide(level, mutating=False).value == READ_ONLY[mode][level]


@pytest.mark.parametrize("mode", list(AutonomyMode))
@pytest.mark.parametrize("level", ["L0", "L1", "L2"])
def test_mutating_row_unchanged(mode, level):
    gate = AutonomyGate(mode)
    assert gate.decide(level, mutating=True).value == MUTATING[mode][level]


@pytest.mark.parametrize("mode", list(AutonomyMode))
@pytest.mark.parametrize("level", ["L0", "L1", "L2"])
def test_default_is_mutating(mode, level):
    """缺省参数即写操作行——既有调用方零行为变化。"""
    gate = AutonomyGate(mode)
    assert gate.decide(level) is gate.decide(level, mutating=True)


def test_two_rows_differ_only_at_semi_auto_l2():
    """M9c③ 的全部改动面就是这一格，逐格核对防止误放宽其他档。"""
    diffs = [
        (mode, level)
        for mode in AutonomyMode
        for level in ["L0", "L1", "L2"]
        if MUTATING[mode][level] != READ_ONLY[mode][level]
    ]
    assert diffs == [(AutonomyMode.SEMI_AUTO, "L2")], diffs


def test_supervised_never_loosened_by_read_only():
    """细分级不放宽最严格档：supervised 下只读验证仍须人工确认。"""
    gate = AutonomyGate(AutonomyMode.SUPERVISED)
    assert gate.decide("L2", mutating=False) is GateDecision.CONFIRM


@pytest.mark.parametrize("mutating", [True, False])
def test_unknown_level_forbidden_in_both_rows(mutating):
    gate = AutonomyGate(AutonomyMode.UNATTENDED)
    assert gate.decide("L9", mutating=mutating) is GateDecision.FORBIDDEN
    assert gate.decide("", mutating=mutating) is GateDecision.FORBIDDEN


# ---------------- 导出契约 ----------------


def test_gate_matrix_shape_is_legacy():
    """API/控制台契约：gate_matrix() 仍返回扁平字符串（app.js 按字符串渲染）。"""
    exported = gate_matrix()
    for mode, row in exported.items():
        for level, decision in row.items():
            assert isinstance(decision, str), f"{mode}.{level} 不是字符串：{decision!r}"
    assert exported["semi_auto"]["L2"] == "confirm"  # 旧断言意图保留
    assert exported["supervised"]["L1"] == "confirm"


def test_read_only_export_differs_only_at_semi_auto_l2():
    base, ro = gate_matrix(), gate_matrix_read_only()
    diffs = [
        (mode, level)
        for mode in base
        for level in base[mode]
        if base[mode][level] != ro[mode][level]
    ]
    assert diffs == [("semi_auto", "L2")], diffs
    assert ro["semi_auto"]["L2"] == "auto"
    assert ro["supervised"]["L2"] == "confirm"


# ---------------- manifest 字段 ----------------


def _write_skill(root, name, *, mutating=None, risk_level="L2"):
    d = root / "skills" / name
    d.mkdir(parents=True, exist_ok=True)
    line = "" if mutating is None else f"mutating: {str(mutating).lower()}\n"
    d.joinpath("SKILL.md").write_text(
        f"---\n"
        f"name: {name}\n"
        f"description: 测试用 skill\n"
        f"version: 1.0.0\n"
        f"required_tools: []\n"
        f"risk_level: {risk_level}\n"
        f"inputs: [hypotheses]\n"
        f"outputs: [findings]\n"
        f"{line}"
        f"---\n\n正文\n",
        encoding="utf-8",
    )
    return root / "skills"


def test_manifest_mutating_defaults_to_true(tmp_path):
    """**fail-closed**：未声明 mutating 的 skill 一律按写操作对待。"""
    from proofhound.skills.registry import SkillRegistry

    root = _write_skill(tmp_path, "verify-undeclared")
    reg = SkillRegistry(root).discover()
    assert reg.get("verify-undeclared").manifest.mutating is True


def test_manifest_mutating_false_declared(tmp_path):
    from proofhound.skills.registry import SkillRegistry

    root = _write_skill(tmp_path, "verify-readonly", mutating=False)
    reg = SkillRegistry(root).discover()
    assert reg.get("verify-readonly").manifest.mutating is False


def test_builtin_verify_skills_declare_read_only():
    """内置 verify-* 必须显式声明只读——否则它们在 semi_auto 下无法自动执行。"""
    from pathlib import Path

    from proofhound.skills.registry import SkillRegistry

    repo_skills = Path(__file__).resolve().parent.parent / "skills"
    reg = SkillRegistry(repo_skills).discover()
    for name in ("verify-sqli", "verify-xss", "verify-idor"):
        skill = reg.get(name)
        assert skill is not None, f"{name} 未注册"
        assert skill.manifest.mutating is False, f"{name} 未声明只读"


def test_builtin_scan_skills_declare_mutating():
    """主动扫描/爬行会向目标发真实请求 → 必须声明为写操作（保守）。"""
    from pathlib import Path

    from proofhound.skills.registry import SkillRegistry

    repo_skills = Path(__file__).resolve().parent.parent / "skills"
    reg = SkillRegistry(repo_skills).discover()
    for name in ("web-scan", "recon-crawl"):
        assert reg.get(name).manifest.mutating is True, f"{name} 应声明 mutating: true"


# ---------------- 编排层映射 ----------------


def test_phases_expose_mutating_map(tmp_path):
    from proofhound.api.runner import OrchestratorPhases
    from proofhound.skills.registry import SkillRegistry

    root = tmp_path / "ws"
    root.mkdir()
    # OrchestratorPhases 默认槽位要求 web-scan / verify-sqli / recon-crawl 存在
    _write_skill(root, "web-scan", mutating=True, risk_level="L1")
    _write_skill(root, "verify-sqli", mutating=True)
    _write_skill(root, "recon-crawl", mutating=True, risk_level="L1")
    _write_skill(root, "verify-readonly", mutating=False)
    _write_skill(root, "verify-writer", mutating=True)
    _write_skill(root, "verify-undeclared", mutating=None)
    reg = SkillRegistry(root / "skills").discover()

    class FakeOrch:
        class audit:  # noqa: N801 - 测试替身
            @staticmethod
            def record(*a, **k):
                pass

    phases = OrchestratorPhases(FakeOrch(), reg)
    assert phases.mutating_by_skill["verify-readonly"] is False
    assert phases.mutating_by_skill["verify-writer"] is True
    assert phases.mutating_by_skill["verify-undeclared"] is True  # fail-closed


def test_skill_mutating_helper_is_fail_closed():
    """旧式 phases（无该属性）→ 一律 True，行为与 M9c③ 之前一致。"""
    from proofhound.api.runner import _skill_mutating

    class LegacyPhases:
        pass

    assert _skill_mutating(LegacyPhases(), "verify-sqli") is True

    class NewPhases:
        mutating_by_skill = {"verify-sqli": False}

    assert _skill_mutating(NewPhases(), "verify-sqli") is False
    assert _skill_mutating(NewPhases(), "unknown-skill") is True  # 查不到 = fail-closed