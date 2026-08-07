"""LLM 用量计量与 token 预算硬闸（M2c，§5.3 预算控制 / §5.6 成本可观测）。

- 每次 LLM 调用记一条 :class:`UsageRecord`（tier/model/tokens/耗时）；
  响应无 usage 字段时按字符数估算（:func:`estimate_tokens`）并标记
  ``estimated=True``——字符/4 是经验近似值，仅作兜底，以服务商 usage 为准；
- :class:`TokenBudget`：Run 级预算硬闸（总量 + 可选分档上限），由路由器
  （llm/router.py）在每次调用前检查，超限抛 :class:`BudgetExceededError`；
  预算与 scope 同为任何自治模式不可绕过的硬闸（§5.8），不设关闭开关；
- 已知近似：check-then-call 对并行子任务不做互斥，最多超出一个在途调用的
  token 量（编排器 run_dag 为线程池）；精确到 token 的并发互斥暂不追求。
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from proofhound.llm.client import LLMError, load_dotenv

ENV_MAX_TOKENS_PER_RUN = "PROOFHOUND_MAX_TOKENS_PER_RUN"
#: 分档上限：PROOFHOUND_MAX_TOKENS_PER_RUN_T0 / _T1 / _T2
ENV_MAX_TOKENS_PER_TIER = "PROOFHOUND_MAX_TOKENS_PER_RUN_{tier}"


def estimate_tokens(text: str) -> int:
    """按字符数估算 token（4 字符 ≈ 1 token 的经验近似），仅作无 usage 时的兜底。"""
    return (len(text) + 3) // 4


class BudgetExceededError(RuntimeError):
    """LLM 预算超限（硬闸）：调用前检查命中即抛，不发 HTTP、不计用量。

    刻意不继承 :class:`~proofhound.llm.client.LLMError`，避免被编排器
    "规划失败 → failed"路径吞掉；编排器须单独捕获并置节点 blocked。
    """

    def __init__(self, *, tier: str, used: int, limit: int, scope: str):
        self.tier = tier
        self.used = used
        self.limit = limit
        self.scope = scope  # "run" = 总量上限；否则为分档值（如 "t1"）
        super().__init__(
            f"LLM 预算超限（{scope}）：档位 {tier} 已用 {used} tokens，上限 {limit}"
        )


@dataclass(frozen=True)
class UsageRecord:
    """一次 LLM 调用的用量记录。"""

    tier: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    estimated: bool  # True = tokens 为字符估算（响应无 usage 字段）
    ts: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    )

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class UsageTracker:
    """Run 级用量聚合：线程安全（编排器 run_dag 为线程池并行）。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._records: list[UsageRecord] = []

    def record(self, usage: UsageRecord) -> None:
        with self._lock:
            self._records.append(usage)

    @property
    def records(self) -> list[UsageRecord]:
        with self._lock:
            return list(self._records)

    def total_tokens(self, tier: str | None = None) -> int:
        """已消耗 token 总量；给 ``tier`` 时只合计该档位。"""
        with self._lock:
            return sum(
                r.total_tokens
                for r in self._records
                if tier is None or r.tier == tier
            )


class TokenBudget:
    """Run 级 token 预算硬闸：总量上限 + 可选分档上限。

    上限为 0 表示"任何调用都拒绝"（首次调用前即被闸）；``None``/未配置
    表示不设上限。调用前检查：已用量 ``>=`` 上限即拒绝。
    """

    def __init__(
        self,
        max_total: int | None = None,
        max_per_tier: dict[str, int] | None = None,
    ):
        for name, value in [("max_total", max_total), *(max_per_tier or {}).items()]:
            if value is not None and value < 0:
                raise ValueError(f"预算上限必须 >= 0: {name}={value}")
        self.max_total = max_total
        self.max_per_tier = dict(max_per_tier or {})

    def check(self, tracker: UsageTracker, tier: str) -> None:
        """调用前检查；超限抛 :class:`BudgetExceededError`。"""
        if self.max_total is not None:
            used = tracker.total_tokens()
            if used >= self.max_total:
                raise BudgetExceededError(
                    tier=tier, used=used, limit=self.max_total, scope="run"
                )
        tier_limit = self.max_per_tier.get(tier)
        if tier_limit is not None:
            used = tracker.total_tokens(tier)
            if used >= tier_limit:
                raise BudgetExceededError(
                    tier=tier, used=used, limit=tier_limit, scope=tier
                )

    @classmethod
    def from_env(cls, env_file: str | Path = ".env") -> "TokenBudget | None":
        """从环境变量/.env 读预算；全部未设置返回 ``None``（不设上限）。

        - ``PROOFHOUND_MAX_TOKENS_PER_RUN``：Run 级总量上限；
        - ``PROOFHOUND_MAX_TOKENS_PER_RUN_T0/T1/T2``：分档上限（可选）。
        值非法（非整数或负数）抛 :class:`LLMError` 并指明变量名。
        """
        dotenv = load_dotenv(env_file)

        def _get(name: str) -> str | None:
            return os.environ.get(name) or dotenv.get(name)

        def _parse(name: str) -> int | None:
            raw = _get(name)
            if raw is None or raw == "":
                return None
            try:
                value = int(raw)
            except ValueError:
                raise LLMError(f"预算配置 {name} 必须为非负整数: {raw!r}") from None
            if value < 0:
                raise LLMError(f"预算配置 {name} 必须为非负整数: {raw!r}")
            return value

        max_total = _parse(ENV_MAX_TOKENS_PER_RUN)
        per_tier = {}
        for tier in ("t0", "t1", "t2"):
            value = _parse(ENV_MAX_TOKENS_PER_TIER.format(tier=tier.upper()))
            if value is not None:
                per_tier[tier] = value
        if max_total is None and not per_tier:
            return None
        return cls(max_total=max_total, max_per_tier=per_tier)
