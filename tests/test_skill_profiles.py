"""M9d 内置 skill 风险画像：单一真相源一致性测试。

覆盖验收点：
- ``profiles.py`` 覆盖全部内置 skill（不多不少）；
- 每条 SKILL.md 的 frontmatter 与画像表**逐条一致**（risk_level 与 mutating）——
  文档可以读，但不能与代码矛盾；
- ``profile_for`` 未登记即抛（fail-closed，绝不返回默认值）；
- 画像表本身自洽：verify-* 只读、scan 类写操作；L2 与 mutating 的语义不矛盾；
- **诚实记录**：``OrchestratorPhases`` 的 ``scan_risk_level`` / ``verify_risk_level``
  已改由画像表提供，manifest 的 ``risk_level`` 在编排路径上**不再被读**——
  该断言防止它被误以为仍然生效。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from proofhound.skills.profiles import (
    SKILL_PROFILES,
    UnknownSkillProfileError,
    profile_for,
)

REPO_SKILLS = Path(__file__).resolve().parent.parent / "skills"


def _frontmatter(name: str) -> dict:
    """粗解析 SKILL.md frontmatter（避免依赖 yaml 细节，只看两者是否一致）。"""
    text = (REPO_SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines[0].strip() == "---", f"{name}: 缺 frontmatter"
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() in ("---", "..."):
            break
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def _builtin_names() -> list[str]:
    return sorted(p.parent.name for p in REPO_SKILLS.glob("*/SKILL.md"))


def test_profiles_cover_exactly_the_builtin_skills():
    """画像表与 skills/ 目录必须一一对应（漏登记或多登记都算失败）。"""
    assert sorted(SKILL_PROFILES) == _builtin_names()


@pytest.mark.parametrize("name", sorted(SKILL_PROFILES))
def test_frontmatter_risk_level_matches_profile(name):
    fm = _frontmatter(name)
    assert fm.get("risk_level") == SKILL_PROFILES[name].risk_level, (
        f"{name}: SKILL.md 的 risk_level={fm.get('risk_level')!r} 与画像表 "
        f"{SKILL_PROFILES[name].risk_level!r} 不一致——两处真相源漂移"
    )


@pytest.mark.parametrize("name", sorted(SKILL_PROFILES))
def test_frontmatter_mutating_matches_profile(name):
    fm = _frontmatter(name)
    declared = fm.get("mutating", "true").strip().lower()  # 缺省 true（fail-closed）
    expected = "true" if SKILL_PROFILES[name].mutating else "false"
    assert declared == expected, (
        f"{name}: SKILL.md 的 mutating={declared!r} 与画像表 {expected!r} 不一致"
    )


def test_unknown_skill_profile_fails_closed():
    with pytest.raises(UnknownSkillProfileError):
        profile_for("no-such-skill")
    with pytest.raises(KeyError):
        profile_for("")


def test_verify_skills_are_read_only_and_l2():
    """语义自洽：三个 verify-* 都是 L2 且只读（M9c③ 自动执行的依据）。"""
    for name in ("verify-sqli", "verify-xss", "verify-idor"):
        p = SKILL_PROFILES[name]
        assert p.risk_level == "L2", name
        assert p.mutating is False, name


def test_scan_skills_are_l1_and_mutating():
    """主动扫描/爬行会向目标发真实请求，保守声明为写操作。"""
    for name in ("web-scan", "recon-crawl"):
        p = SKILL_PROFILES[name]
        assert p.risk_level == "L1", name
        assert p.mutating is True, name


def test_every_profile_has_a_note():
    """每条画像必须写明判据——否则"为什么它可以自动执行"无从复核。"""
    for name, p in SKILL_PROFILES.items():
        assert p.note.strip(), f"{name} 缺判据说明"


def test_manifest_risk_level_is_inert_on_orchestration_path():
    """诚实记录（M9d）：编排路径的风险等级已由画像表提供，manifest 那份不再被读。

    这不是"manifest 被删了"，而是它的 ``risk_level`` 在闸门判定上**退化为文档**。
    本测试防止后来者误以为改 SKILL.md 的 risk_level 会改变闸门行为。
    """
    import inspect

    from proofhound.api import runner

    src = inspect.getsource(runner.OrchestratorPhases.__init__)
    # 允许作为 _builtin_risk_level 的回退实参出现，但不得直接作为判定值使用
    assert "_builtin_risk_level(" in src, "风险等级未走画像表"
    assert src.count("manifest.risk_level") == src.count("_builtin_risk_level("), (
        "存在未经画像表收敛的 manifest.risk_level 直接使用"
    )