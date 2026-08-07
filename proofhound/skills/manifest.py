"""Skill manifest schema（§5.1）：SKILL.md YAML frontmatter 的 Pydantic v2 强校验。

规范要点：
- 一个 skill 是一个目录，``SKILL.md`` = YAML frontmatter + 正文 SOP；
- frontmatter 七字段（name/description/version/required_tools/risk_level/
  inputs/outputs）**全部必填**——list 可为空，但键必须存在；
- 缺 frontmatter、YAML 损坏、字段缺失/非法均抛 :class:`SkillManifestError`。
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError


class SkillManifestError(ValueError):
    """SKILL.md 解析或校验失败。"""


class SkillManifest(BaseModel):
    """SKILL.md frontmatter 的 schema 化（§5.1）。"""

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    description: str = Field(min_length=1)
    version: str = Field(min_length=1)
    required_tools: list[str]
    risk_level: Literal["L0", "L1", "L2"]  # L0 被动 / L1 主动扫描 / L2 利用验证
    inputs: list[str]
    outputs: list[str]


def parse_skill_md(path: str | Path) -> tuple[SkillManifest, str]:
    """解析 SKILL.md，返回 (manifest, 正文)；不合规即抛 SkillManifestError。"""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    frontmatter, body = _split_frontmatter(text, path)
    try:
        data = yaml.safe_load(frontmatter)
    except yaml.YAMLError as exc:
        raise SkillManifestError(f"{path}: frontmatter YAML 解析失败: {exc}") from exc
    if not isinstance(data, dict):
        raise SkillManifestError(f"{path}: frontmatter 必须是 YAML 映射")
    try:
        return SkillManifest.model_validate(data), body
    except ValidationError as exc:
        raise SkillManifestError(f"{path}: manifest 校验失败: {exc}") from exc


def _split_frontmatter(text: str, path: Path) -> tuple[str, str]:
    """拆分 ``---`` 包围的 YAML frontmatter 与正文。"""
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        raise SkillManifestError(f"{path}: 缺少 YAML frontmatter（须以 --- 开头）")
    for i in range(1, len(lines)):
        if lines[i].strip() in ("---", "..."):
            return "".join(lines[1:i]), "".join(lines[i + 1:])
    raise SkillManifestError(f"{path}: frontmatter 未闭合（缺少结尾 ---）")
