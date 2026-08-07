"""L3 编排器（§5.3）：任务树/DAG、规划器、失败预算（M2b）+ 上下文治理（M2c）。

模型路由与 token 预算硬闸在 llm/（router.py / usage.py）；本包含编排器
核心与上下文治理（context.py：确定性压缩 + prompt 字符硬上限）。
"""

from proofhound.core.context import (
    ContextOverflowError,
    ContextPolicy,
    compress_state,
    messages_chars,
)
from proofhound.core.failures import (
    FailureBudget,
    FailureCategory,
    FailureRule,
    classify,
)
from proofhound.core.orchestrator import Orchestrator
from proofhound.core.plan import (
    Plan,
    PlanAction,
    PlanValidationError,
    parse_plan,
)
from proofhound.core.planner import Planner
from proofhound.core.tasks import (
    InvalidTransitionError,
    TaskNode,
    TaskStatus,
    aggregate_phase,
    run_dag,
)

__all__ = [
    "ContextOverflowError",
    "ContextPolicy",
    "FailureBudget",
    "FailureCategory",
    "FailureRule",
    "InvalidTransitionError",
    "Orchestrator",
    "Plan",
    "PlanAction",
    "PlanValidationError",
    "Planner",
    "TaskNode",
    "TaskStatus",
    "aggregate_phase",
    "classify",
    "compress_state",
    "messages_chars",
    "parse_plan",
    "run_dag",
]
