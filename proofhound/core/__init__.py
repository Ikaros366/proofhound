"""L3 编排器（§5.3）：任务树/DAG、规划器、失败预算（M2b）。

模型路由、预算帽、上下文治理属 M2c；本包当前仅含编排器核心。
"""

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
    "parse_plan",
    "run_dag",
]
