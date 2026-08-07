"""Skill registry（§5.1）：扫描 skills 目录、校验注册、启用/禁用管理。

- 扫描 ``skills_dir/*/SKILL.md`` → 解析校验 → 过导入安全闸 → 注册；
- 单个 skill 解析失败不拖垮整体，记入 ``registry.errors``；
- 渐进式披露：``list()`` 只暴露 name + description（+ 元信息），正文 SOP
  经 ``skill.read_body()`` 懒加载，控制编排器上下文体积；
- 启用纪律：安全闸发现高危项的 skill 默认禁用，须 ``confirm()`` 显式确认
  后才可启用；``risk_level: L2`` 的 skill 恒 ``requires_confirmation=True``
  （每次执行需人工确认的标记，确认交互流程属编排器，M2 后续切片）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from proofhound.compliance.audit import AuditLog
from proofhound.skills.gate import RiskReport, scan_skill
from proofhound.skills.manifest import (
    SkillManifest,
    SkillManifestError,
    parse_skill_md,
)


@dataclass
class Skill:
    """一个已注册的 skill。"""

    manifest: SkillManifest
    path: Path  # skill 目录
    risk_report: RiskReport
    enabled: bool = True
    confirmed: bool = False  # 风险清单已经人工确认
    _body: str | None = field(default=None, repr=False)

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def requires_confirmation(self) -> bool:
        """L2（利用验证）skill 每次执行都需人工确认。"""
        return self.manifest.risk_level == "L2"

    def read_body(self) -> str:
        """懒加载 SKILL.md 正文 SOP（渐进式披露：命中时才读全文）。"""
        if self._body is None:
            _, self._body = parse_skill_md(self.path / "SKILL.md")
        return self._body

    def summary(self) -> dict:
        """注册表查询视图：只含元信息，不含正文。"""
        return {
            "name": self.manifest.name,
            "description": self.manifest.description,
            "version": self.manifest.version,
            "risk_level": self.manifest.risk_level,
            "required_tools": list(self.manifest.required_tools),
            "inputs": list(self.manifest.inputs),
            "outputs": list(self.manifest.outputs),
            "enabled": self.enabled,
            "requires_confirmation": self.requires_confirmation,
            "risk_findings": len(self.risk_report.findings),
        }


@dataclass
class RegistryError:
    """一个加载失败的 skill 目录。"""

    path: Path
    error: str


class SkillRegistry:
    """skill 目录扫描与注册表，供编排器查询。"""

    def __init__(self, skills_dir: str | Path, audit: AuditLog | None = None):
        self.skills_dir = Path(skills_dir)
        self.audit = audit
        self._skills: dict[str, Skill] = {}
        self.errors: list[RegistryError] = []

    def discover(self) -> "SkillRegistry":
        """扫描 skills 目录，注册全部合法 skill；返回自身（可链式调用）。"""
        self._skills.clear()
        self.errors.clear()
        if not self.skills_dir.is_dir():
            return self
        for child in sorted(self.skills_dir.iterdir()):
            skill_md = child / "SKILL.md"
            if not child.is_dir() or not skill_md.is_file():
                continue
            try:
                manifest, body = parse_skill_md(skill_md)
            except (SkillManifestError, OSError) as exc:
                self.errors.append(RegistryError(path=child, error=str(exc)))
                self._audit("skill_rejected", path=str(child), error=str(exc))
                continue
            report = scan_skill(child)
            # 安全闸命中高危项 → 默认禁用，待人工确认
            enabled = not report.has_high
            skill = Skill(
                manifest=manifest,
                path=child,
                risk_report=report,
                enabled=enabled,
                _body=body,
            )
            self._skills[manifest.name] = skill
            self._audit(
                "skill_registered",
                name=manifest.name,
                version=manifest.version,
                risk_level=manifest.risk_level,
                enabled=enabled,
                risk_findings=len(report.findings),
            )
        return self

    # ---- 查询（供编排器）----

    def list(self) -> list[dict]:
        """全部已注册 skill 的元信息（渐进式披露：不含正文）。"""
        return [skill.summary() for skill in self._skills.values()]

    def enabled(self) -> list[Skill]:
        return [s for s in self._skills.values() if s.enabled]

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def find_by_tool(self, tool: str) -> list[Skill]:
        """按依赖工具反查 skill。"""
        return [s for s in self._skills.values() if tool in s.manifest.required_tools]

    # ---- 启用/禁用 ----

    def enable(self, name: str) -> Skill:
        skill = self._require(name)
        if skill.risk_report.has_high and not skill.confirmed:
            raise PermissionError(
                f"skill {name} 存在高危风险项，须先 confirm() 显式确认"
            )
        skill.enabled = True
        self._audit("skill_enabled", name=name)
        return skill

    def disable(self, name: str) -> Skill:
        skill = self._require(name)
        skill.enabled = False
        self._audit("skill_disabled", name=name)
        return skill

    def confirm(self, name: str) -> Skill:
        """人工确认风险清单；确认后才可启用含高危项的 skill。"""
        skill = self._require(name)
        skill.confirmed = True
        self._audit(
            "skill_confirmed",
            name=name,
            risk_findings=len(skill.risk_report.findings),
        )
        return skill

    def _require(self, name: str) -> Skill:
        skill = self._skills.get(name)
        if skill is None:
            raise KeyError(f"未注册的 skill: {name}")
        return skill

    def _audit(self, event: str, **fields) -> None:
        if self.audit is not None:
            self.audit.record(event, **fields)
