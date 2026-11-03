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
    TOOL_MISSING = "tool_missing"  # 工具缺失 / 不可执行（exit 126/127）
    TOOL_BROKEN = "tool_broken"  # 工具自身报错（含"exit 0 但打印致命错误"）
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
    # ---- M31-e：工具缺失 / 工具自身报错 -------------------------------------
    # 严格说这两类是"工具没跑起来"而不是"目标在拒绝我们"，与上面五类不同层。
    # 早先它们一律落到 unknown，于是 task_blocked 的理由文案把锅甩给规划器
    # （"你无权自行给出 rate_rps/concurrency/max_requests"），与真实原因无关。
    FailureRule(
        FailureCategory.TOOL_MISSING,
        _patterns(
            r"command not found",
            r"executable file not found",
            r"no such file or directory: '[^']*\.(?:py|exe)'",
        ),
    ),
    FailureRule(
        FailureCategory.TOOL_BROKEN,
        _patterns(
            r"traceback \(most recent call last\)",
            r"modulenotfounderror",
            r"importerror:",
            r"cannot establish the proxy connection",
            r"error with the (?:system )?proxy",
            r"invalid proxy url",
        ),
    ),
]


#: 退出码即类别（M31-e）：126/127 是 shell 对"工具不在 / 不可执行"的固定
#: 回答，比任何文案都权威，故优先于文本规则。
EXIT_CODE_CATEGORIES: dict[int, FailureCategory] = {
    126: FailureCategory.TOOL_MISSING,
    127: FailureCategory.TOOL_MISSING,
}


def classify(
    output: str, *, exit_code: int | None = None, assume_failed: bool = False
) -> FailureCategory:
    """对执行输出采样分类失败信号；无命中返回 ``unknown``。

    - ``exit_code`` 为 126/127 ⇒ 直接 ``tool_missing``（最权威的判据）；
    - 否则按 :data:`RULES` 顺次匹配（文案能给出更具体的原因）；
    - 文案无命中时：调用方**已知这次执行失败**（``assume_failed``，或退出码非 0）
      不再回落到 ``unknown``，而是 ``tool_broken``——"工具跑挂了"比"不知道为什么"
      更可信，也避免把工具自身的错误说成规划缺陷（M31-e）。
    """
    if exit_code in EXIT_CODE_CATEGORIES:
        return EXIT_CODE_CATEGORIES[exit_code]
    for rule in RULES:
        if rule.matches(output):
            return rule.category
    if assume_failed or (exit_code is not None and exit_code != 0):
        return FailureCategory.TOOL_BROKEN
    return FailureCategory.UNKNOWN


# ---- 假成功签名（M31-e）----------------------------------------------------
#: "退出码 0 却打印了致命错误"的工具签名。
#:
#: 实测（eng-20261102T093506Z-aac47e3a）：dirsearch 打印
#: ``Cannot establish the proxy connection`` 后**仍以 0 退出**，编排器据此记
#: ``signals_recorded count=0`` + ``phases: web-dirsearch=done`` +
#: ``degraded=False``——一次 26 秒"跑完"、实际一个目录爆破请求都没发出的假成功。
#: 退出码不可信的工具在这里登记，命中即按失败处理（走失败预算，不记成功）。
#:
#: 只登记"命中即代表整轮没跑起来"的**精确**签名：单条路径的偶发失败在正常扫描里
#: 也会出现（例如 ``Cannot connect to:`` 的一次重试），不能当致命错误处理。
FALSE_SUCCESS_SIGNATURES: dict[str, tuple[re.Pattern, ...]] = {
    "dirsearch": _patterns(
        r"cannot establish the proxy connection",
        r"error with the (?:system )?proxy",
        r"invalid proxy url",
        r"ssl certificate verification failed",
    ),
}

#: 与工具无关的假成功签名：进程还在，但工具自己崩了。
_GENERIC_FALSE_SUCCESS: tuple[re.Pattern, ...] = _patterns(
    r"traceback \(most recent call last\)",
    r"modulenotfounderror",
)


def false_success_signature(tool: str, output: str) -> str | None:
    """命中"退出码 0 但整轮失败"的签名时返回命中片段，否则 ``None``。"""
    patterns = (*FALSE_SUCCESS_SIGNATURES.get(tool, ()), *_GENERIC_FALSE_SUCCESS)
    for pattern in patterns:
        match = pattern.search(output)
        if match:
            return match.group(0)[:120]
    return None


#: 每类失败的重试上限缺省值。M29 起提成常量：无人值守档按能力系数放大它
#: （见 ``orchestrator.UNATTENDED_CAP_SCALE``），不再在两处各写一个 2。
DEFAULT_LIMIT_PER_CATEGORY = 2


class FailureBudget:
    """子任务失败预算：同类失败计满 ``limit_per_category`` 次即耗尽。"""

    def __init__(
        self,
        limit_per_category: int = DEFAULT_LIMIT_PER_CATEGORY,
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
