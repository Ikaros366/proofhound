"""任务模型单元测试（M2b）：状态机、并行 DAG、阶段聚合、审计。"""

import time

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.tasks import (
    InvalidTransitionError,
    TaskNode,
    TaskStatus,
    aggregate_phase,
    run_dag,
)


def test_happy_path_transitions(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    node = TaskNode(name="t", audit=audit)
    node.transition(TaskStatus.RUNNING)
    node.transition(TaskStatus.DONE)
    assert node.status == TaskStatus.DONE

    events = audit.read_all()
    assert [e["to"] for e in events] == ["running", "done"]
    assert events[0]["from"] == "pending"
    assert events[0]["kind"] == "subtask"


@pytest.mark.parametrize(
    "frm,to",
    [
        (TaskStatus.PENDING, TaskStatus.DONE),
        (TaskStatus.PENDING, TaskStatus.FAILED),
        (TaskStatus.PENDING, TaskStatus.BLOCKED),
        (TaskStatus.DONE, TaskStatus.RUNNING),
        (TaskStatus.BLOCKED, TaskStatus.RUNNING),
        (TaskStatus.RUNNING, TaskStatus.PENDING),
    ],
)
def test_invalid_transitions(frm, to):
    node = TaskNode(name="t")
    node.status = frm
    with pytest.raises(InvalidTransitionError):
        node.transition(to)


def test_failed_can_requeue():
    node = TaskNode(name="t")
    node.transition(TaskStatus.RUNNING)
    node.transition(TaskStatus.FAILED)
    node.transition(TaskStatus.PENDING)
    node.transition(TaskStatus.RUNNING)
    assert node.status == TaskStatus.RUNNING


def test_run_dag_parallel_all_done(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    nodes = [TaskNode(name=f"t{i}", audit=audit) for i in range(3)]
    started = []

    def fn(node):
        node.transition(TaskStatus.RUNNING)
        started.append(time.monotonic())
        time.sleep(0.05)
        node.transition(TaskStatus.DONE)

    t0 = time.monotonic()
    run_dag(nodes, fn, max_workers=3)
    elapsed = time.monotonic() - t0
    assert all(n.status == TaskStatus.DONE for n in nodes)
    assert elapsed < 0.14  # 并行：总耗时应远小于 3×50ms 串行


def test_run_dag_exception_marks_failed(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    good = TaskNode(name="good", audit=audit)
    bad = TaskNode(name="bad", audit=audit)

    def fn(node):
        if node.name == "bad":
            raise RuntimeError("boom")  # 未迁移就抛异常，run_dag 兜底
        node.transition(TaskStatus.RUNNING)
        node.transition(TaskStatus.DONE)

    run_dag([good, bad], fn)
    assert good.status == TaskStatus.DONE
    assert bad.status == TaskStatus.FAILED
    events = [e for e in audit.read_all() if e.get("node_id") == bad.id]
    assert events[-1]["to"] == "failed"
    assert "boom" in events[-1]["reason"]


def test_aggregate_phase():
    phase = TaskNode(name="p", kind="phase")
    with pytest.raises(ValueError):
        aggregate_phase(phase)  # 无子任务

    a, b = TaskNode(name="a"), TaskNode(name="b")
    phase.children = [a, b]
    with pytest.raises(ValueError):
        aggregate_phase(phase)  # 未到终态

    a.status = TaskStatus.DONE
    b.status = TaskStatus.DONE
    assert aggregate_phase(phase) == TaskStatus.DONE

    b.status = TaskStatus.BLOCKED
    assert aggregate_phase(phase) == TaskStatus.BLOCKED

    b.status = TaskStatus.FAILED
    assert aggregate_phase(phase) == TaskStatus.FAILED  # failed 优先于 blocked
