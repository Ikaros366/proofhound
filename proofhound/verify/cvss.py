"""CVSS v3.1 base score 计算器（M6b）：纯 stdlib 自实现，零新依赖。

分工（红线：LLM 不产数字）：LLM（T2 Verifier）只基于证据产出 CVSS
**向量字符串**；分数与严重级由本模块按 FIRST 官方 v3.1 规范确定性计
算——同向量同分，可复现、可按向量重算复核。

- 向量解析 fail-closed：缺指标/非法值/未知指标/重复指标/错版本/多余
  temporal 指标（如 ``/E:F``）一律抛 :class:`CVSSVectorError`；指标
  顺序不强制（规范约定固定顺序，此处宽容乱序以抗模型重排，语义不变）；
- ``roundup`` 采用官方 3.1 算法（先 ×100000 取整再定进位，消除二进制
  浮点误差：4.02 → 4.1，7.5 → 7.5）；
- 严重级映射（规范定性分级）：0.0 none / 0.1–3.9 low / 4.0–6.9 medium
  / 7.0–8.9 high / 9.0–10.0 critical。

只实现 base score：Verifier 契约只收 8 个 base 指标向量。
"""

from __future__ import annotations

import math

VECTOR_PREFIX = "CVSS:3.1"

#: 8 个 base 指标（解析时要求各恰好一次）
BASE_METRICS: tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
#: PR 取值依赖 Scope（(值, S) → 数值）
_PR = {
    ("N", "U"): 0.85, ("N", "C"): 0.85,
    ("L", "U"): 0.62, ("L", "C"): 0.68,
    ("H", "U"): 0.27, ("H", "C"): 0.50,
}
_UI = {"N": 0.85, "R": 0.62}
_S = {"U", "C"}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

#: 指标 → 合法值集合（解析校验用）
_ALLOWED: dict[str, frozenset[str]] = {
    "AV": frozenset(_AV),
    "AC": frozenset(_AC),
    "PR": frozenset({"N", "L", "H"}),
    "UI": frozenset(_UI),
    "S": frozenset(_S),
    "C": frozenset(_CIA),
    "I": frozenset(_CIA),
    "A": frozenset(_CIA),
}

#: 严重级定性分档（(上限, 档位)，上开下闭；0.0 单列 none）
_SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (3.9, "low"),
    (6.9, "medium"),
    (8.9, "high"),
    (10.0, "critical"),
)


class CVSSVectorError(ValueError):
    """CVSS 向量非法（fail-closed：缺/重/未知指标、非法值、错版本）。"""


def parse_vector(vector: str) -> dict[str, str]:
    """严格解析 ``CVSS:3.1/AV:../AC:../...`` 为指标字典；非法抛
    :class:`CVSSVectorError`。指标顺序不强制，8 个 base 指标各恰好一次。"""
    if not isinstance(vector, str) or not vector.strip():
        raise CVSSVectorError(f"CVSS 向量为空或非字符串: {vector!r}")
    parts = vector.strip().split("/")
    if parts[0] != VECTOR_PREFIX:
        raise CVSSVectorError(
            f"CVSS 向量必须以 {VECTOR_PREFIX}/ 开头: {vector!r}"
        )
    metrics: dict[str, str] = {}
    for segment in parts[1:]:
        key, sep, value = segment.partition(":")
        if not sep or not key or not value:
            raise CVSSVectorError(f"CVSS 向量片段非法（须为 指标:值）: {segment!r}")
        if key not in _ALLOWED:
            raise CVSSVectorError(
                f"CVSS 向量含未知/非 base 指标 {key!r}（只收 "
                f"{'/'.join(BASE_METRICS)}）"
            )
        if key in metrics:
            raise CVSSVectorError(f"CVSS 向量指标重复: {key}")
        if value not in _ALLOWED[key]:
            raise CVSSVectorError(
                f"CVSS 指标 {key} 取值非法: {value!r}"
                f"（合法值 {sorted(_ALLOWED[key])}）"
            )
        metrics[key] = value
    missing = [key for key in BASE_METRICS if key not in metrics]
    if missing:
        raise CVSSVectorError(f"CVSS 向量缺指标: {missing}")
    return metrics


def roundup(value: float) -> float:
    """官方 v3.1 roundup：消除浮点误差的十分位向上进位。

    ``round(x×100000)`` 整万分位则原值，否则十分位进一（4.02→4.1，
    7.5→7.5）。``math.floor(i + 0.5)`` 对齐规范 JS 的 ``Math.round``
    （正数 half-up，而非 Python 银行家舍入）。
    """
    scaled = math.floor(value * 100000 + 0.5)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (math.floor(scaled / 10000) + 1) / 10


def base_score(vector: str) -> float:
    """按 FIRST v3.1 官方公式计算 base score；向量非法抛
    :class:`CVSSVectorError`。"""
    m = parse_vector(vector)
    isc = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if m["S"] == "U":
        impact = 6.42 * isc
    else:
        impact = 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15
    exploitability = (
        8.22 * _AV[m["AV"]] * _AC[m["AC"]] * _PR[(m["PR"], m["S"])] * _UI[m["UI"]]
    )
    if impact <= 0:
        return 0.0
    if m["S"] == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def severity_for_score(score: float) -> str:
    """分数 → 严重级：0.0 none / 0.1–3.9 low / 4.0–6.9 medium /
    7.0–8.9 high / 9.0–10.0 critical；越界输入抛 ValueError。"""
    if not 0.0 <= score <= 10.0:
        raise ValueError(f"CVSS 分数越界（须 ∈ [0, 10]）: {score!r}")
    if score == 0.0:
        return "none"
    for upper, band in _SEVERITY_BANDS:
        if score <= upper:
            return band
    raise AssertionError("unreachable")  # pragma: no cover
