"""Signal 数据模型（§4.2）：解析器产出的结构化候选信号。

Signal 是**候选**，不是漏洞（红线 2）：发现类 skill 只能产出 Signal，
Confirmed 必须经 verify-* skill 产出（M3 验证层）。落盘形态为 JSONL；
``evidence_ref`` 必填——无证据不入库。
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Signal(BaseModel):
    """一条结构化候选信号（如 httpx 探活结果的一行）。"""

    asset: str = Field(min_length=1)  # URL 或 host
    status_code: int | None = None
    title: str | None = None
    tech: list[str] = Field(default_factory=list)
    kind: str = "web-probe"  # 信号类别，M3 去重指纹的组成部分
    source_tool: str = Field(min_length=1)
    skill: str = Field(min_length=1)  # 产出该信号的 skill 名
    evidence_ref: str = Field(min_length=1)  # 证据文件路径#L行号，必填
    note: str | None = None
    # M8a：仅 kind="form_page" 信号携带——页面内 POST 候选表单的字段名清单
    #（保序去重），供 triage 启发式键名匹配；其余 kind 恒为空。
    form_fields: list[str] = Field(default_factory=list)
