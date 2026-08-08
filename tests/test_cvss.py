"""CVSS v3.1 计算器测试（M6b）：官方基准向量 + 解析拒绝矩阵 + 档位映射。

基准向量期望值取自 FIRST 官方 v3.1 规范与 Examples 文档公布值（逐条与
规范公式核算）；解析 fail-closed：缺/重/未知指标、非法值、错版本、多余
temporal 指标一律 CVSSVectorError；分数→严重级映射按规范定性分级。
"""

from __future__ import annotations

import pytest

from proofhound.verify.cvss import (
    CVSSVectorError,
    base_score,
    parse_vector,
    roundup,
    severity_for_score,
)

#: FIRST 官方 v3.1 规范/Examples 公布值基准（向量, 期望分数, 期望档位）
OFFICIAL_BENCHMARKS = [
    # 全 H / S:U —— 规范附录经典 9.8
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    # 全 H / S:C —— 封顶 10.0
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    # Heartbleed（CVE-2014-0160）官方 3.1 评分
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
    # 三低影响 / S:U
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3, "high"),
    # 仅可用性高影响 + AC:H
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9, "medium"),
    # 存储型 XSS 经典向量（S:C 且 1.08 不封顶路径）
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4, "medium"),
    # 零影响 → 0.0 none
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "none"),
]


@pytest.mark.parametrize("vector,want_score,want_severity", OFFICIAL_BENCHMARKS)
def test_official_benchmark_vectors(vector, want_score, want_severity):
    """官方规范基准向量：分数与严重级双双命中公布值。"""
    score = base_score(vector)
    assert score == want_score
    assert severity_for_score(score) == want_severity


def test_parse_returns_metrics_order_insensitive():
    """解析产出指标字典；乱序向量接受且同分（抗模型重排）。"""
    metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert metrics == {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    }
    shuffled = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"
    assert base_score(shuffled) == 9.8


REJECTED_VECTORS = [
    "",  # 空串
    None,  # 非字符串
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 缺 CVSS:3.1 前缀
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 错版本
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # 缺指标 A
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 非法值 AV:X
    "CVSS:3.1/XX:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 未知指标 XX
    "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 重复指标 AV
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F",  # 多余 temporal 指标
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",  # 尾斜杠空片段
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV",  # 缺冒号片段
]


@pytest.mark.parametrize("vector", REJECTED_VECTORS)
def test_parse_rejects_invalid_vectors(vector):
    """解析拒绝矩阵：一切非法形态 fail-closed。"""
    with pytest.raises(CVSSVectorError):
        parse_vector(vector)
    with pytest.raises(CVSSVectorError):
        base_score(vector)


SEVERITY_BOUNDARIES = [
    (0.0, "none"),
    (0.1, "low"),
    (3.9, "low"),
    (4.0, "medium"),
    (6.9, "medium"),
    (7.0, "high"),
    (8.9, "high"),
    (9.0, "critical"),
    (10.0, "critical"),
]


@pytest.mark.parametrize("score,want", SEVERITY_BOUNDARIES)
def test_severity_mapping_boundaries(score, want):
    """规范定性分级边界：3.9/4.0、6.9/7.0、8.9/9.0 逐点命中。"""
    assert severity_for_score(score) == want


@pytest.mark.parametrize("bad", [-0.1, 10.1])
def test_severity_out_of_range_rejected(bad):
    with pytest.raises(ValueError):
        severity_for_score(bad)


def test_roundup_official_algorithm():
    """官方 roundup：整十分位不进位，x.y0000z 进位（消除浮点误差）。"""
    assert roundup(7.5) == 7.5  # 整十分位原样
    assert roundup(4.02) == 4.1  # 规范示例：4.02 必须进位为 4.1
    assert roundup(0.0) == 0.0
    assert roundup(10.0) == 10.0
