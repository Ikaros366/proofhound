"""append-only 审计日志（§5.8）。

每条命令、每次 scope 判定、每次安装动作全部落盘，兼作报告证据链。
日志文件只以追加模式打开，本模块不提供任何修改/删除已有内容的能力。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    """JSONL 格式的 append-only 审计日志。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        """追加一条审计记录，返回写入的内容。"""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            **fields,
        }
        # 始终以追加模式打开，保证 append-only
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        return entry

    def read_all(self) -> list[dict[str, Any]]:
        """读取全部记录（只读，供测试与报告证据链使用）。"""
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
