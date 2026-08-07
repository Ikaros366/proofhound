"""去重指纹（M3a，§5.4.5）：sha256(规范化资产 + 漏洞类型 + 参数/路径)。

规范化规则：资产 strip → 全小写 → 去尾斜杠；漏洞类型 strip → 小写；
参数缺省与空串等价。三段以 NUL 连接防拼接歧义，输出带 ``sha256:`` 前缀。
同指纹合并到同一条 Finding，不同指纹新建。
"""

from __future__ import annotations

import hashlib


def normalize_asset(asset: str) -> str:
    """资产规范化：去首尾空白 → 全小写 → 去尾斜杠。"""
    return asset.strip().lower().rstrip("/")


def compute_dedup_key(asset: str, vuln_type: str, param: str | None = None) -> str:
    """计算去重指纹，返回 ``sha256:<hex>``。"""
    parts = [
        normalize_asset(asset),
        vuln_type.strip().lower(),
        (param or "").strip(),
    ]
    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
