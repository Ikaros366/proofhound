"""上下文治理（M2c，§5.6）：确定性压缩 + prompt 大小硬上限。

- 红线 3 不变：工具原始输出 100% 落盘 evidence/，进 LLM 上下文的只有
  结构化摘要；本模块只在摘要层面治理，不读证据文件；
- :func:`compress_state`：planner 状态中的 Signal 摘要超过
  ``max_signals`` 条时按 ``kind`` 聚合——每类保留最新 ``keep_latest`` 条，
  并附 ``signals_summary``（total + by_kind 计数）；attempts、
  failure_counts 等其他键原样保留。**纯代码、确定性**，不调 LLM；
- prompt 大小硬上限（``max_chars``，字符数）：超限先压缩，压缩后仍超限
  抛 :class:`ContextOverflowError`——**禁止静默截断丢信息**。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from proofhound.llm.client import LLMError, load_dotenv

ENV_MAX_SIGNALS = "PROOFHOUND_CONTEXT_MAX_SIGNALS"
ENV_KEEP_LATEST = "PROOFHOUND_CONTEXT_KEEP_LATEST"
ENV_MAX_CHARS = "PROOFHOUND_CONTEXT_MAX_CHARS"


class ContextOverflowError(RuntimeError):
    """prompt 超过硬上限且压缩后仍超限：任务应置 failed，禁止静默截断。"""

    def __init__(self, *, chars: int, limit: int):
        self.chars = chars
        self.limit = limit
        super().__init__(f"LLM 上下文超限：{chars} 字符 > 硬上限 {limit}（压缩后仍超）")


@dataclass(frozen=True)
class ContextPolicy:
    """上下文治理策略：Signal 摘要条数与 prompt 字符硬上限。"""

    max_signals: int = 20  # Signal 摘要超过该条数即触发聚合压缩
    keep_latest: int = 5  # 压缩时每类保留的最新条数
    max_chars: int = 32000  # prompt 字符硬上限

    def __post_init__(self):
        for name in ("max_signals", "keep_latest", "max_chars"):
            if getattr(self, name) < 1:
                raise ValueError(f"ContextPolicy.{name} 必须 >= 1")

    @classmethod
    def from_env(cls, env_file: str | Path = ".env") -> "ContextPolicy":
        """从环境变量/.env 读阈值（缺省用默认值）；非法值抛 :class:`LLMError`。"""
        dotenv = load_dotenv(env_file)

        def _parse(name: str, default: int) -> int:
            raw = os.environ.get(name) or dotenv.get(name)
            if raw is None or raw == "":
                return default
            try:
                value = int(raw)
            except ValueError:
                raise LLMError(f"上下文配置 {name} 必须为正整数: {raw!r}") from None
            if value < 1:
                raise LLMError(f"上下文配置 {name} 必须为正整数: {raw!r}")
            return value

        return cls(
            max_signals=_parse(ENV_MAX_SIGNALS, cls.max_signals),
            keep_latest=_parse(ENV_KEEP_LATEST, cls.keep_latest),
            max_chars=_parse(ENV_MAX_CHARS, cls.max_chars),
        )


def compress_state(
    state: dict, policy: ContextPolicy
) -> tuple[dict, dict | None]:
    """压缩 planner 状态中的 Signal 摘要；返回 (新状态, 压缩信息|None)。

    未超 ``max_signals`` 时原样返回（信息为 None）。压缩时按 ``kind``
    （缺省 ``"unknown"``）聚合，每类保留最新 ``keep_latest`` 条（保持原
    相对顺序），并写入 ``signals_summary = {total, by_kind, kept}``。
    同输入必得同输出（确定性）；不修改传入的 state。
    """
    signals = state.get("signals") or []
    if len(signals) <= policy.max_signals:
        return state, None

    # 每类保留最新 K 条：先按类取尾部下标，再按原顺序输出
    latest_index_by_kind: dict[str, list[int]] = {}
    counts: dict[str, int] = {}
    for index, signal in enumerate(signals):
        kind = str(signal.get("kind") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
        latest_index_by_kind.setdefault(kind, []).append(index)
    keep_indexes: set[int] = set()
    for indexes in latest_index_by_kind.values():
        keep_indexes.update(indexes[-policy.keep_latest :])
    kept = [s for i, s in enumerate(signals) if i in keep_indexes]

    new_state = dict(state)
    new_state["signals"] = kept
    new_state["signals_summary"] = {
        "total": len(signals),
        "by_kind": counts,
        "kept": len(kept),
    }
    info = {"total": len(signals), "kept": len(kept), "by_kind": counts}
    return new_state, info


def messages_chars(messages: list[dict]) -> int:
    """prompt 大小估算：各消息 content 字符数求和。"""
    return sum(len(str(m.get("content", ""))) for m in messages)
