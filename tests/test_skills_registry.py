"""Skill registry 测试（§5.1）。

覆盖验收硬指标：SKILL.md 缺必填字段必校验失败；内置 web-scan skill 走通
registry 加载全流程。
"""

from pathlib import Path

import pytest

from proofhound.skills import (
    SkillManifestError,
    SkillRegistry,
    parse_skill_md,
)

REPO_SKILLS_DIR = Path(__file__).parent.parent / "skills"

VALID_FRONTMATTER = """\
---
name: demo-skill
description: 演示用 skill
version: 1.0.0
required_tools: [httpx]
risk_level: L1
inputs: [targets]
outputs: [signals]
---

正文 SOP。
"""


def _write_skill(skills_dir: Path, name: str, content: str) -> Path:
    skill_dir = skills_dir / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")
    return skill_dir


class TestBuiltinWebScan:
    """内置 skill 全流程：扫描仓库 skills/ → 校验 → 注册 → 查询。"""

    def test_web_scan_loads(self):
        registry = SkillRegistry(REPO_SKILLS_DIR).discover()
        assert registry.errors == []
        skill = registry.get("web-scan")
        assert skill is not None
        assert skill.manifest.version == "1.0.0"
        assert skill.manifest.required_tools == ["httpx"]
        assert skill.manifest.risk_level == "L1"
        assert skill.enabled
        assert not skill.requires_confirmation  # L1 不需要逐次确认
        assert registry.find_by_tool("httpx") == [skill]

    def test_progressive_disclosure(self):
        registry = SkillRegistry(REPO_SKILLS_DIR).discover()
        summaries = registry.list()
        assert summaries[0]["name"] == "web-scan"
        assert "body" not in summaries[0]  # 列表视图不含正文
        body = registry.get("web-scan").read_body()
        assert "httpx" in body and "SOP" in body


class TestManifestValidation:
    def test_valid_manifest(self, tmp_path):
        _write_skill(tmp_path, "demo-skill", VALID_FRONTMATTER)
        manifest, body = parse_skill_md(tmp_path / "demo-skill" / "SKILL.md")
        assert manifest.name == "demo-skill"
        assert "正文 SOP" in body

    @pytest.mark.parametrize(
        "missing_field",
        [
            "name",
            "description",
            "version",
            "required_tools",
            "risk_level",
            "inputs",
            "outputs",
        ],
    )
    def test_missing_required_field_fails(self, tmp_path, missing_field):
        """验收硬指标：缺任一必填字段必校验失败。"""
        lines = [
            line
            for line in VALID_FRONTMATTER.splitlines(keepends=True)
            if not line.startswith(f"{missing_field}:")
        ]
        _write_skill(tmp_path, "demo-skill", "".join(lines))
        with pytest.raises(SkillManifestError):
            parse_skill_md(tmp_path / "demo-skill" / "SKILL.md")

    def test_invalid_risk_level_fails(self, tmp_path):
        content = VALID_FRONTMATTER.replace("risk_level: L1", "risk_level: L9")
        _write_skill(tmp_path, "demo-skill", content)
        with pytest.raises(SkillManifestError):
            parse_skill_md(tmp_path / "demo-skill" / "SKILL.md")

    def test_invalid_name_fails(self, tmp_path):
        content = VALID_FRONTMATTER.replace("name: demo-skill", "name: Demo_Skill")
        _write_skill(tmp_path, "demo-skill", content)
        with pytest.raises(SkillManifestError):
            parse_skill_md(tmp_path / "demo-skill" / "SKILL.md")

    def test_no_frontmatter_fails(self, tmp_path):
        _write_skill(tmp_path, "demo-skill", "# 没有 frontmatter\n")
        with pytest.raises(SkillManifestError):
            parse_skill_md(tmp_path / "demo-skill" / "SKILL.md")

    def test_broken_yaml_fails(self, tmp_path):
        _write_skill(tmp_path, "demo-skill", "---\nname: [unclosed\n---\n正文\n")
        with pytest.raises(SkillManifestError):
            parse_skill_md(tmp_path / "demo-skill" / "SKILL.md")


class TestRegistry:
    def test_broken_skill_recorded_not_fatal(self, tmp_path):
        _write_skill(tmp_path, "good-skill", VALID_FRONTMATTER.replace("demo-skill", "good-skill"))
        _write_skill(tmp_path, "bad-skill", "---\nname: bad-skill\n---\n")  # 缺字段
        registry = SkillRegistry(tmp_path).discover()
        assert [s["name"] for s in registry.list()] == ["good-skill"]
        assert len(registry.errors) == 1
        assert registry.errors[0].path.name == "bad-skill"

    def test_enable_disable(self, tmp_path):
        _write_skill(tmp_path, "demo-skill", VALID_FRONTMATTER)
        registry = SkillRegistry(tmp_path).discover()
        registry.disable("demo-skill")
        assert registry.enabled() == []
        registry.enable("demo-skill")
        assert [s.name for s in registry.enabled()] == ["demo-skill"]

    def test_unknown_skill_raises(self, tmp_path):
        registry = SkillRegistry(tmp_path).discover()
        assert registry.get("ghost") is None
        with pytest.raises(KeyError):
            registry.disable("ghost")

    def test_l2_requires_confirmation(self, tmp_path):
        _write_skill(
            tmp_path, "demo-skill", VALID_FRONTMATTER.replace("risk_level: L1", "risk_level: L2")
        )
        registry = SkillRegistry(tmp_path).discover()
        assert registry.get("demo-skill").requires_confirmation

    def test_missing_dir_is_empty(self, tmp_path):
        registry = SkillRegistry(tmp_path / "nonexistent").discover()
        assert registry.list() == []
        assert registry.errors == []

    def test_audit_events(self, tmp_path):
        from proofhound.compliance.audit import AuditLog

        _write_skill(tmp_path, "demo-skill", VALID_FRONTMATTER)
        _write_skill(tmp_path, "bad-skill", "---\nname: bad-skill\n---\n")
        audit = AuditLog(tmp_path / "audit.jsonl")
        registry = SkillRegistry(tmp_path, audit=audit).discover()
        registry.disable("demo-skill")
        events = [e["event"] for e in audit.read_all()]
        # 目录按字典序扫描：bad-skill 先于 demo-skill
        assert events == ["skill_rejected", "skill_registered", "skill_disabled"]
