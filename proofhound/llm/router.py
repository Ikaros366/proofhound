"""模型路由（M2c，§5.3 模型路由 / §5.6 路由表）：按任务档位选模型。

- 三档 T0（解析/分类/去重/润色）、T1（triage/摘要/假设生成/规划）、
  T2（漏洞推理/Verifier 终审）；每档独立配置 base_url/api_key/model
  （可选 temperature/max_tokens），经环境变量或 .env 提供：
  ``PROOFHOUND_T0_*`` / ``PROOFHOUND_T1_*`` / ``PROOFHOUND_T2_*``；
- 本模块只做选路与计量：HTTP 调用复用 :class:`~proofhound.llm.client.LLMClient`；
- 每次调用记录 tier/model/tokens/耗时（llm/usage.py），并追加审计
  ``llm_call``；配置预算（:class:`~proofhound.llm.usage.TokenBudget`）时
  每次调用前检查，超限抛 :class:`~proofhound.llm.usage.BudgetExceededError`；
- 红线 4 启动校验：T2 与 T1 配置了相同模型时打警告（Verifier 与发现端
  必须用不同模型，M3 验证层将使用 T2）。
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from proofhound.compliance.audit import AuditLog
from proofhound.llm.client import LLMClient, LLMConfig, LLMError, load_dotenv
from proofhound.llm.usage import (
    BudgetExceededError,
    TokenBudget,
    UsageRecord,
    UsageTracker,
    estimate_tokens,
)


class Tier(str, Enum):
    """模型档位（§5.6 路由表）。"""

    T0 = "t0"  # 廉价/本地：解析兜底、分类、去重、润色
    T1 = "t1"  # 中档：triage、摘要、假设生成、规划
    T2 = "t2"  # 前沿：漏洞推理、利用链规划、Verifier 终审


#: 每档的必需环境变量名（PROOFHOUND_T0_BASE_URL 形式）
def _env_names(tier: Tier) -> tuple[str, str, str]:
    prefix = f"PROOFHOUND_{tier.name}_"
    return prefix + "BASE_URL", prefix + "API_KEY", prefix + "MODEL"


@dataclass
class TierConfig:
    """单档模型接入配置。"""

    base_url: str  # OpenAI 兼容端点
    api_key: str
    model: str
    temperature: float | None = None
    max_tokens: int | None = None
    timeout: float = 60.0

    def to_llm_config(self) -> LLMConfig:
        return LLMConfig(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            timeout=self.timeout,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

    @classmethod
    def from_env(cls, tier: Tier, env_file: str | Path = ".env") -> "TierConfig":
        """从环境变量构建某档配置；``.env`` 作缺省值，已有环境变量优先。
        缺必需变量时抛 :class:`LLMError` 并列出确切变量名。"""
        dotenv = load_dotenv(env_file)

        def _get(name: str) -> str | None:
            return os.environ.get(name) or dotenv.get(name)

        base_name, key_name, model_name = _env_names(tier)
        missing = [n for n in (base_name, key_name, model_name) if not _get(n)]
        if missing:
            raise LLMError(
                f"模型档位 {tier.value} 缺少配置: {', '.join(missing)}（环境变量或 .env 提供）"
            )
        prefix = f"PROOFHOUND_{tier.name}_"
        temperature = _get(prefix + "TEMPERATURE")
        max_tokens = _get(prefix + "MAX_TOKENS")
        try:
            return cls(
                base_url=_get(base_name).rstrip("/"),
                api_key=_get(key_name),
                model=_get(model_name),
                temperature=float(temperature) if temperature else None,
                max_tokens=int(max_tokens) if max_tokens else None,
            )
        except ValueError:
            raise LLMError(
                f"模型档位 {tier.value} 的 TEMPERATURE/MAX_TOKENS 必须为数值"
            ) from None


class ModelRouter:
    """三档模型路由器：选路 + 用量计量 + 预算硬闸，不重复实现 HTTP。"""

    def __init__(
        self,
        configs: dict[Tier, TierConfig],
        *,
        audit: AuditLog | None = None,
        tracker: UsageTracker | None = None,
        budget: TokenBudget | None = None,
    ):
        self.configs = dict(configs)
        self.audit = audit
        self.tracker = tracker if tracker is not None else UsageTracker()
        self.budget = budget
        self._clients = {
            tier: LLMClient(cfg.to_llm_config()) for tier, cfg in self.configs.items()
        }
        t1, t2 = self.configs.get(Tier.T1), self.configs.get(Tier.T2)
        if t1 is not None and t2 is not None and t1.model == t2.model:
            warnings.warn(
                f"T2 与 T1 配置了相同模型（{t1.model}）：红线 4 要求 Verifier "
                "与发现端使用不同模型（M3 验证层将使用 T2 档）",
                stacklevel=2,
            )

    @classmethod
    def from_env(
        cls,
        env_file: str | Path = ".env",
        **kwargs,
    ) -> "ModelRouter":
        """从环境变量/.env 构建路由器。

        某档三个必需变量全缺 → 该档不配置（调用该档时才报错）；
        部分配置 → 立即抛 :class:`LLMError`（清晰报出缺失变量名）。
        """
        dotenv = load_dotenv(env_file)

        def _any_set(names: tuple[str, ...]) -> list[str]:
            return [n for n in names if os.environ.get(n) or dotenv.get(n)]

        configs: dict[Tier, TierConfig] = {}
        for tier in Tier:
            names = _env_names(tier)
            present = _any_set(names)
            if not present:
                continue  # 未配置该档
            configs[tier] = TierConfig.from_env(tier, env_file)  # 部分缺失在此报错
        return cls(configs, **kwargs)

    def complete(self, tier: Tier | str, messages: list[dict]) -> str:
        """经指定档位发起一次对话补全，返回 assistant 文本。

        失败：档位未配置 → :class:`LLMError`；预算超限 →
        :class:`BudgetExceededError`（不发 HTTP、不计用量）；HTTP/格式异常 →
        :class:`LLMError`。
        """
        tier = Tier(tier)
        config = self.configs.get(tier)
        if config is None:
            names = ", ".join(_env_names(tier))
            raise LLMError(f"模型档位 {tier.value} 未配置（需 {names}）")
        if self.budget is not None:
            self.budget.check(self.tracker, tier.value)  # 硬闸：调用前检查

        result = self._clients[tier].complete_with_usage(messages)
        usage = result.usage or {}
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        estimated = not (
            isinstance(prompt_tokens, int) and isinstance(completion_tokens, int)
        )
        if estimated:
            prompt_tokens = sum(
                estimate_tokens(str(m.get("content", ""))) for m in messages
            )
            completion_tokens = estimate_tokens(result.content)

        record = UsageRecord(
            tier=tier.value,
            model=config.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=result.latency_ms,
            estimated=estimated,
        )
        self.tracker.record(record)
        if self.audit is not None:
            self.audit.record(
                "llm_call",
                tier=record.tier,
                model=record.model,
                prompt_tokens=record.prompt_tokens,
                completion_tokens=record.completion_tokens,
                latency_ms=round(record.latency_ms, 1),
                estimated=record.estimated,
            )
        return result.content


class _LegacyClientAdapter:
    """向后兼容 shim：把 M2b 单模型客户端（``complete(messages)``，含测试
    mock）包装成路由器接口。忽略档位、不计量、不检查预算——新代码应直接
    注入 :class:`ModelRouter`。"""

    def __init__(self, client):
        self._client = client

    def complete(self, tier: Tier | str, messages: list[dict]) -> str:
        return self._client.complete(messages)


def ensure_router(obj):
    """:class:`ModelRouter` 原样返回；旧式单模型客户端包成适配器。"""
    if isinstance(obj, ModelRouter):
        return obj
    return _LegacyClientAdapter(obj)


__all__ = [
    "BudgetExceededError",
    "ModelRouter",
    "Tier",
    "TierConfig",
    "ensure_router",
]
