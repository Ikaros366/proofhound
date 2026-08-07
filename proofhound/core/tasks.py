"""任务模型（§5.3）：树/DAG 混合 + 节点状态机。

- 阶段间串行（recon → scan → verify → report），阶段内独立子任务经
  :func:`run_dag` 并行（ThreadPoolExecutor）；M2b 仅落地 scan 阶段；
- 节点状态机：pending → running → done/failed/blocked；failed → pending
  仅供显式重排队使用；done/blocked 为终态；非法迁移抛
  :class:`InvalidTransitionError`；
- 每次状态迁移记审计 ``task_state``（append-only，兼作证据链）。
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from proofhound.compliance.audit import AuditLog


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    BLOCKED = "blocked"


class InvalidTransitionError(RuntimeError):
    """非法状态迁移。"""


_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.PENDING: frozenset({TaskStatus.RUNNING}),
    TaskStatus.RUNNING: frozenset({TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.BLOCKED}),
    TaskStatus.FAILED: frozenset({TaskStatus.PENDING}),
    TaskStatus.DONE: frozenset(),
    TaskStatus.BLOCKED: frozenset(),
}

TERMINAL_STATES: frozenset[TaskStatus] = frozenset(
    {TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.BLOCKED}
)


@dataclass
class TaskNode:
    """任务树节点：phase（阶段）或 subtask（子任务）。"""

    name: str
    kind: str = "subtask"  # phase / subtask
    audit: AuditLog | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: TaskStatus = TaskStatus.PENDING
    children: list["TaskNode"] = field(default_factory=list)
    failure_counts: dict[str, int] = field(default_factory=dict)  # 按失败类别计数
    attempts: int = 0
    meta: dict = field(default_factory=dict)

    def transition(self, to: TaskStatus, *, reason: str = "") -> None:
        """状态迁移；非法迁移抛 :class:`InvalidTransitionError`，迁移记审计。"""
        if to not in _TRANSITIONS[self.status]:
            raise InvalidTransitionError(
                f"节点 {self.name}({self.id}) 非法迁移: {self.status.value} -> {to.value}"
            )
        old = self.status
        self.status = to
        if self.audit is not None:
            self.audit.record(
                "task_state",
                node_id=self.id,
                name=self.name,
                kind=self.kind,
                **{"from": old.value, "to": to.value, "reason": reason},
            )


def run_dag(
    nodes: list[TaskNode],
    fn: Callable[[TaskNode], None],
    *,
    max_workers: int = 4,
) -> None:
    """并行执行同阶段子任务。``fn`` 自身负责节点状态迁移；``fn`` 未捕获的
    异常在此兜底：节点置 failed（不拖垮同阶段其他子任务）。"""
    if not nodes:
        return
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fn, node): node for node in nodes}
        for future in as_completed(futures):
            node = futures[future]
            exc = future.exception()
            if exc is not None and node.status not in TERMINAL_STATES:
                if node.status == TaskStatus.PENDING:
                    node.transition(TaskStatus.RUNNING, reason="异常兜底补记启动")
                node.transition(
                    TaskStatus.FAILED, reason=f"未捕获异常: {type(exc).__name__}: {exc}"
                )


def aggregate_phase(phase: TaskNode) -> TaskStatus:
    """由子任务状态聚合阶段终态：任一 failed → failed；否则任一 blocked →
    blocked；全部 done → done。阶段尚有子任务未终态时抛 ValueError。"""
    if not phase.children:
        raise ValueError(f"阶段 {phase.name} 无子任务")
    statuses = {child.status for child in phase.children}
    if not statuses <= TERMINAL_STATES:
        raise ValueError(f"阶段 {phase.name} 尚有子任务未到终态: {statuses}")
    if TaskStatus.FAILED in statuses:
        return TaskStatus.FAILED
    if TaskStatus.BLOCKED in statuses:
        return TaskStatus.BLOCKED
    return TaskStatus.DONE
