"""httpx ``-json`` 输出解析器（manifest parser 标识：``httpx_json``）。

httpx 的 JSON 输出为 JSONL（每行一个对象）。逐行解析为 Signal；
坏行跳过并计数（解析容错，但计数进审计）；每行 Signal 的
``evidence_ref`` 指向原始输出文件的对应行号（``路径#L<行号>``）。
"""

from __future__ import annotations

import json

from proofhound.findings.signal import Signal


def parse_httpx_jsonl(
    text: str,
    *,
    evidence_path: str,
    skill: str,
    source_tool: str = "httpx",
) -> tuple[list[Signal], int]:
    """解析 httpx JSONL 输出，返回 ``(signals, skipped_lines)``。"""
    signals: list[Signal] = []
    skipped = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if not isinstance(data, dict):
            skipped += 1
            continue
        asset = data.get("url") or data.get("host")
        if not asset:
            skipped += 1
            continue
        status_code = data.get("status_code")
        signals.append(
            Signal(
                asset=asset,
                status_code=status_code if isinstance(status_code, int) else None,
                title=data.get("title"),
                tech=[str(t) for t in data.get("tech") or []],
                source_tool=source_tool,
                skill=skill,
                evidence_ref=f"{evidence_path}#L{lineno}",
            )
        )
    return signals, skipped
