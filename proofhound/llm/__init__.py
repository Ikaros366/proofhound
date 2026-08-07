"""llm 模块：OpenAI 兼容协议客户端（M2b）+ 模型路由/用量/预算（M2c）。

- client.py：单端点最小封装（urllib 零依赖）；
- router.py：T0/T1/T2 三档选路（§5.6 路由表），HTTP 复用 client；
- usage.py：用量计量（llm_call 审计）与 Run 级 token 预算硬闸；
  上下文治理在 core/context.py（确定性压缩 + prompt 字符硬上限）。
"""

from proofhound.llm.client import (
    CompletionResult,
    LLMClient,
    LLMConfig,
    LLMError,
    load_dotenv,
)
from proofhound.llm.router import (
    ModelRouter,
    Tier,
    TierConfig,
    ensure_router,
)
from proofhound.llm.usage import (
    BudgetExceededError,
    TokenBudget,
    UsageRecord,
    UsageTracker,
    estimate_tokens,
)

__all__ = [
    "BudgetExceededError",
    "CompletionResult",
    "LLMClient",
    "LLMConfig",
    "LLMError",
    "ModelRouter",
    "Tier",
    "TierConfig",
    "TokenBudget",
    "UsageRecord",
    "UsageTracker",
    "ensure_router",
    "estimate_tokens",
    "load_dotenv",
]
