"""dirsearch JSON 报告解析器（manifest parser 标识：``dirsearch_json``）。

M16-b。输入是沙箱 stdout —— wrapper 在 dirsearch 跑完后把容器内
``/tmp/ds_report.json``（rootfs 只读 + tmpfs 随容器销毁，不 cat 就没了）
整份 ``cat`` 出来，因此 stdout 形态是：

    [HH:MM:SS] 200 -    27B - http://host/admin      <- dirsearch 自己的结果行
    {"info": {...}, "results": [ {...}, ... ]}       <- wrapper cat 出来的报告

解析只认后面那段 **JSON 报告**（结果行的文本格式不稳定，不做正则解析）：

- **判据字段**（决定候选）：``results[].url`` / ``results[].status``；
- **不参与判据**的字段：``contentLength`` / ``contentType`` / ``elapsed`` /
  ``redirect`` —— 它们只落进 ``note``，供人工复核，**不进任何判定**。
  （M16-a 的教训：判据必须落在"决定候选的字段"上，不能落在整行文本上。）

产出的 Signal ``kind="web-probe"``：走 M3a 起就有的通道——
``orchestrator._triage_candidates`` 对 ``web-probe`` + 状态码 ∈
``_EXPOSED_STATUSES``（200/201/204/301/302/307/308/401/403）产 ``web-exposure``
候选。**零新增 Signal kind / 零 triage 改动**。

**刻意不做状态码过滤**：所有 ``results`` 条目都产 Signal（含 4xx/5xx 等
``_EXPOSED_STATUSES`` 之外的码）。理由：它们会作为 Signal 留在库里、不产候选，
是**可审计的事实**；在解析层丢掉反而看不见"dirsearch 发现了但判定不吃"的东西。

``evidence_ref`` 锚到 ``<evidence_path>#L<行号>``，行号取 **JSON 报告块的首行**
（整份报告一行内不可切分，故以块首为锚，指向"本批结果的出处"）。
坏行/无 JSON/结构不符一律计数跳过，**不猜、不造候选**。
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from proofhound.findings.signal import Signal

#: JSON 报告块的起始特征（dirsearch 的 JSON 输出是缩进的多行 JSON，
#: 顶层对象必定在行首以 ``{`` 开始；结果行则以 ``[HH:MM:SS]`` 或横幅文字开头）。
_JSON_START_PREFIX = "{"


def _find_json_block(text: str) -> tuple[dict | None, int]:
    """在 stdout 里定位 JSON 报告块，返回 ``(对象, 起始行号)``。

    从第一个以 ``{`` 开头的行起，把余下全部内容交给 ``json.JSONDecoder``
    （``raw_decode`` 会在对象结束后停下，故尾随内容不影响解析）。
    找不到或解析失败返回 ``(None, 0)``。
    """
    lines = text.splitlines()
    for idx, raw in enumerate(lines):
        if not raw.startswith(_JSON_START_PREFIX):
            continue
        candidate = "\n".join(lines[idx:])
        try:
            obj, _end = json.JSONDecoder().raw_decode(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj, idx + 1  # 1-based 行号
    return None, 0


def _note_for(entry: dict) -> str | None:
    """把**非判据**字段收进 note（供人工复核；不进任何判定）。

    字段名刻意与 dirsearch 原始输出一致，便于与落盘报告逐字对照。
    """
    parts: list[str] = []
    length = entry.get("contentLength")
    if isinstance(length, (int, float)):
        parts.append(f"contentLength={int(length)}")
    ctype = entry.get("contentType")
    if isinstance(ctype, str) and ctype:
        parts.append(f"contentType={ctype}")
    elapsed = entry.get("elapsed")
    if isinstance(elapsed, (int, float)):
        parts.append(f"elapsed={round(float(elapsed), 3)}")
    redirect = entry.get("redirect")
    if isinstance(redirect, str) and redirect:
        parts.append(f"redirect={redirect}")
    return " ".join(parts) if parts else None


def parse_dirsearch_json(
    text: str,
    *,
    evidence_path: str,
    skill: str,
    source_tool: str = "dirsearch",
) -> tuple[list[Signal], int]:
    """解析 wrapper cat 出来的 dirsearch JSON 报告，返回 ``(signals, skipped)``。

    ``skipped`` 计的是 ``results`` 里**结构不合格**的条目数（缺 ``url`` /
    ``url`` 非字符串或空 / JSON 块缺失）。缺 ``status`` 不算坏条目——状态码
    可以是 ``None``（Signal 本就允许），判定侧自然不命中。
    """
    report, start_line = _find_json_block(text)
    if report is None:
        return [], 1  # 整段没有可解析的 JSON 报告：计一处坏输入

    results = report.get("results")
    if not isinstance(results, list):
        return [], 1

    signals: list[Signal] = []
    seen: set[tuple[str, str]] = set()
    skipped = 0
    for entry in results:
        if not isinstance(entry, dict):
            skipped += 1
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not url.strip():
            skipped += 1
            continue
        url = url.strip()
        # fail-closed：只有 http(s) 绝对 URL 才收（相对/畸形 URL 不进发现链路）
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            skipped += 1
            continue
        status = entry.get("status")
        status_code = status if isinstance(status, int) and not isinstance(status, bool) else None
        key = ("web-probe", url)
        if key in seen:  # 同类同 URL 跨条目去重（首见锚点）
            continue
        seen.add(key)
        signals.append(
            Signal(
                asset=url,
                status_code=status_code,
                kind="web-probe",
                source_tool=source_tool,
                skill=skill,
                evidence_ref=f"{evidence_path}#L{start_line}",
                note=_note_for(entry),
            )
        )
    return signals, skipped
