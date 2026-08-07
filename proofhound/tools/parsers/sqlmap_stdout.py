"""sqlmap stdout 解析器（manifest parser 标识：``sqlmap_stdout``，M3b）。

与其他解析器不同：sqlmap 是**验证类**工具，本解析器产出的是结构化
**验证结论**（:class:`SqlmapReport`），不是 Signal，因此不登记进
``PARSER_REGISTRY``（该注册表契约是 Signal 解析器，供 scan 阶段自动桥接）。

判定锚点（sqlmap 1.10.x stdout 格式，配版本快照测试防漂移）：
- 确认：出现 ``sqlmap identified the following injection point(s)`` 行，
  其后 ``---`` 块内为 ``Parameter: <name> (<kind>)`` 与若干
  ``Type/Title/Payload`` 三元组；
- 未确认：``do not appear to be injectable`` 或确认锚缺失；
- 解析容错：任何格式漂移只导致 confirmed=False / 空 techniques，
  不抛异常（fail-closed：解析不出就当没确认）。
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

_ANCHOR_RE = re.compile(r"sqlmap identified the following injection point\(s\)")
_PARAM_RE = re.compile(r"^Parameter:\s+(?P<name>\S+)\s+\((?P<kind>[^)]+)\)\s*$")
_REQUESTS_RE = re.compile(r"with a total of (?P<count>\d+) HTTP\(s\) requests")
_NOT_INJECTABLE_RE = re.compile(r"do not appear to be injectable")


class SqlmapTechnique(BaseModel):
    """一组注入技术证据（Type/Title/Payload 三元组）。"""

    type: str = Field(min_length=1)  # 如 boolean-based blind / time-based blind
    title: str = ""
    payload: str = ""


class SqlmapReport(BaseModel):
    """sqlmap 一次运行的结构化验证结论。"""

    confirmed: bool
    parameter: str | None = None  # 被确认的注入参数名
    param_kind: str | None = None  # GET / POST / ...
    techniques: list[SqlmapTechnique] = Field(default_factory=list)
    anchor_line: int | None = None  # "identified the following" 所在行号（1 起）
    requests_total: int | None = None
    note: str | None = None  # 未确认时的说明（如 all tested parameters ...）


def parse_sqlmap_stdout(text: str) -> SqlmapReport:
    """解析 sqlmap stdout，返回结构化验证结论（失败 fail-closed 为未确认）。

    行号统一按 ``\\n`` 切分（与 grep/编辑器一致）：sqlmap 进度输出含裸
    ``\\r``，若用 splitlines 会把 \\r 也当行界，导致 #L 锚点与编辑器行号
    对不上。
    """
    lines = text.split("\n")
    anchor_line: int | None = None
    requests_total: int | None = None
    for lineno, line in enumerate(lines, start=1):
        if anchor_line is None and _ANCHOR_RE.search(line):
            anchor_line = lineno
            match = _REQUESTS_RE.search(line)
            if match:
                requests_total = int(match.group("count"))
            break

    if anchor_line is None:
        note = None
        for line in lines:
            if _NOT_INJECTABLE_RE.search(line):
                note = line.strip()
                break
        return SqlmapReport(
            confirmed=False,
            note=note or "未找到注入确认锚点（identified the following ...）",
        )

    parameter: str | None = None
    param_kind: str | None = None
    techniques: list[SqlmapTechnique] = []
    current: dict[str, str] = {}

    def _flush() -> None:
        if current.get("type"):
            techniques.append(
                SqlmapTechnique(
                    type=current["type"],
                    title=current.get("title", ""),
                    payload=current.get("payload", ""),
                )
            )
        current.clear()

    for line in lines[anchor_line:]:  # 从锚点下一行开始
        stripped = line.strip()
        if parameter is None:
            match = _PARAM_RE.match(stripped)
            if match:
                parameter = match.group("name")
                param_kind = match.group("kind")
            continue
        if stripped.startswith("Type:"):
            _flush()
            current["type"] = stripped[len("Type:") :].strip()
        elif stripped.startswith("Title:"):
            current["title"] = stripped[len("Title:") :].strip()
        elif stripped.startswith("Payload:"):
            current["payload"] = stripped[len("Payload:") :].strip()
        elif stripped == "---":
            _flush()
            break  # 注入点块结束
    else:
        _flush()

    return SqlmapReport(
        confirmed=bool(parameter and techniques),
        parameter=parameter,
        param_kind=param_kind,
        techniques=techniques,
        anchor_line=anchor_line,
        requests_total=requests_total,
        note=None if (parameter and techniques) else "锚点后未解析出参数与技术清单",
    )
