"""规划输出 schema（§5.3，红线 1）：LLM 只产结构化 JSON 计划。

计划经 Pydantic v2 强校验：非法 JSON、未知动作、缺字段一律
:class:`PlanValidationError`。计划中只有 action/skill/tool/params/
预期产出，**不允许出现 shell 命令**——argv 由 tools/build.py 拼装。
"""

from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, model_validator


class PlanValidationError(ValueError):
    """计划解析或校验失败（JSON 非法 / schema 不符 / 语义越权）。"""


class PlanAction(BaseModel):
    """一个规划动作。``run_tool`` 必须给 tool+params；其余动作不得给。"""

    action: Literal["run_tool", "finish", "escalate"]
    skill: str = Field(min_length=1)
    tool: str | None = None
    params: dict = Field(default_factory=dict)
    expected_output: str = Field(min_length=1)  # 预期产出
    rationale: str | None = None

    @model_validator(mode="after")
    def _check_tool_params(self) -> "PlanAction":
        if self.action == "run_tool":
            if not self.tool:
                raise ValueError("run_tool 动作必须提供 tool")
            if not self.params:
                raise ValueError("run_tool 动作必须提供 params")
        else:
            if self.tool is not None or self.params:
                raise ValueError(f"{self.action} 动作不得携带 tool/params")
        return self


class Plan(BaseModel):
    """一轮规划输出：至少一个动作。"""

    actions: list[PlanAction] = Field(min_length=1)


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _extract_json(raw: str) -> str:
    """从 LLM 输出中提取 JSON 文本：优先 ``` 围栏，否则取首个 { 到末个 }。"""
    fence = _FENCE_RE.search(raw)
    if fence:
        return fence.group(1).strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end <= start:
        raise PlanValidationError("LLM 输出中未找到 JSON 对象")
    return raw[start : end + 1]


def parse_plan(raw: str) -> Plan:
    """把 LLM 原始输出解析为 :class:`Plan`；任何非法输入都抛 PlanValidationError。"""
    text = _extract_json(raw)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PlanValidationError(f"计划 JSON 解析失败: {exc}") from exc
    if not isinstance(data, dict):
        raise PlanValidationError("计划必须是 JSON 对象")
    try:
        return Plan.model_validate(data)
    except ValidationError as exc:
        raise PlanValidationError(f"计划 schema 校验失败: {exc}") from exc
