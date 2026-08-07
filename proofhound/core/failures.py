"""失败信号分类与失败预算（§5.3"失败预算与阻塞升级"）。

- 规则表 :data:`RULES`：按序匹配执行输出采样，区分凭证错误 / 验证码 /
  限流 / 账号锁定 / 网络异常，兜底 unknown；扩展 = 往 RULES 追加规则；
- :class:`FailureBudget`：每个子任务按类别计数，同类失败默认上限 2 次，
  命中即耗尽（编排器据此置 blocked 并升级），从机制上消灭无限重试；
- 验证码、账号锁定属人机区分机制（硬阻塞）：命中一次即耗尽预算，
  不作为自动攻克目标。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class FailureCategory(str, Enum):
    AUTH = "auth"  # 凭证错误
    CAPTCHA = "captcha"  # 验证码 / 人机校验（硬阻塞）
    RATELIMIT = "ratelimit"  # 限流
    LOCKOUT = "lockout"  # 账号锁定（硬阻塞）
    NETWORK = "network"  # 网络异常
    UNKNOWN = "unknown"


#: 命中即硬阻塞的类别（不消耗重试预算，一次即停）
HARD_BLOCK_CATEGORIES: frozenset[FailureCategory] = frozenset(
    {FailureCategory.CAPTCHA, FailureCategory.LOCKOUT}
)


@dataclass(frozen=True)
class FailureRule:
    category: FailureCategory
    patterns: tuple[re.Pattern, ...]

    def matches(self, text: str) -> bool:
        return any(p.search(text) for p in self.patterns)


def _patterns(*exprs: str) -> tuple[re.Pattern, ...]:
    return tuple(re.compile(e, re.IGNORECASE) for e in exprs)


#: 规则表：按序命中即返回；硬阻塞类别排在前面
RULES: list[FailureRule] = [
    FailureRule(
        FailureCategory.CAPTCHA,
        _patterns(r"captcha", r"recaptcha", r"人机验证", r"人机校验"),
    ),
    FailureRule(
        FailureCategory.LOCKOUT,
        _patterns(
            r"account\s+(is\s+)?locked",
            r"locked\s+out",
            r"too\s+many\s+(failed\s+)?(login\s+)?attempts",
            r"账[号户]锁定",
        ),
    ),
    FailureRule(
        FailureCategory.RATELIMIT,
        _patterns(r"\b429\b", r"rate[\s-]?limit", r"too\s+many\s+requests", r"限流"),
    ),
    FailureRule(
        FailureCategory.AUTH,
        _patterns(
            r"\b401\b",
            r"authentication\s+failed",
            r"invalid\s+credentials?",
            r"login\s+required",
            r"unauthorized",
        ),
    ),
    FailureRule(
        FailureCategory.NETWORK,
        _patterns(
            r"connection\s+(refused|reset)",
            r"timed?\s*out",
            r"no\s+route\s+to\s+host",
            r"name\s+resolution",
            r"network\s+unreachable",
        ),
    ),
]


def classify(output: str) -> FailureCategory:
    """对执行输出采样分类失败信号；无命中返回 ``unknown``。"""
    for rule in RULES:
        if rule.matches(output):
            return rule.category
    return FailureCategory.UNKNOWN


class FailureBudget:
    """子任务失败预算：同类失败计满 ``limit_per_category`` 次即耗尽。"""

    def __init__(
        self,
        limit_per_category: int = 2,
        hard_block: frozenset[FailureCategory] = HARD_BLOCK_CATEGORIES,
    ):
        if limit_per_category < 1:
            raise ValueError("limit_per_category 必须 >= 1")
        self.limit_per_category = limit_per_category
        self.hard_block = hard_block

    def record(self, node, category: FailureCategory) -> bool:
        """给 ``node`` 记一次该类别失败，返回 True 表示预算耗尽（应置 blocked）。"""
        count = node.failure_counts.get(category.value, 0) + 1
        node.failure_counts[category.value] = count
        if category in self.hard_block:
            return True
        return count >= self.limit_per_category
