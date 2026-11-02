"""M31：scan 链路按 manifest 传镜像 + 越界信号在记录处丢弃。

两条都来自同一个真实任务（eng-20261102T085135Z-885d7d33）暴露的问题：

1. `_exec_run_tool` 从不传 `image`，一律用 runner 缺省镜像（alpine:3.20）——
   httpx/katana 是静态 Go 二进制看不出问题，dirsearch 是 Python 工具，
   alpine 里没有 python3 ⇒ `exit 127`，连挂两次后被失败预算判 blocked；
2. 越界信号只在 triage 建候选前才 check_scope，katana `-jc` 从 JS 文本里提出的
   跨源绝对 URL（实测 `redux.js.org` 的报错文档链接）仍会落进 signals.jsonl。
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import RequestBudget, Scope
from proofhound.core.orchestrator import Orchestrator
from proofhound.core.plan import PlanAction
from proofhound.core.tasks import TaskNode, TaskStatus
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.sandbox import RunResult

REPO = Path(__file__).resolve().parent.parent
TARGET = "http://127.0.0.1:8000"


class FakeRunner:
    """记录每次调用的 argv 与 image；stdout 内容由 handler 决定。"""

    egress_proxy_url = None

    def __init__(self, evidence_dir, scope, handler=None):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.scope = scope
        self.handler = handler or (lambda tool, args: "")
        self.calls: list[dict] = []

    def run(self, tool, args, timeout=300, image=None):
        self.calls.append({"tool": tool, "args": list(args), "image": image})
        uid = uuid.uuid4().hex[:12]
        stdout_path = self.evidence_dir / f"{uid}.stdout.log"
        stderr_path = self.evidence_dir / f"{uid}.stderr.log"
        stdout_path.write_text(self.handler(tool, args), encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        return RunResult(
            rejected=False,
            command=[tool, *args],
            exit_code=0,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )


@pytest.fixture
def registry(make_skill_dir):
    return SkillRegistry(make_skill_dir()).discover()


def _orch(tmp_path, registry, *, scope=None, handler=None, tool_images=None):
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    runner = FakeRunner(tmp_path / "evidence", scope, handler)
    orch = Orchestrator(
        registry,
        runner,
        SimpleNamespace(complete=lambda messages: "{}"),
        audit,
        evidence_dir=tmp_path / "evidence",
    )
    if tool_images is not None:
        orch.tool_images = tool_images
    return orch, runner


def _action(tool: str) -> PlanAction:
    return PlanAction(
        action="run_tool",
        skill="web-scan",
        tool=tool,
        params={"target": TARGET},
        expected_output="signals",
    )


def _running_node() -> TaskNode:
    node = TaskNode(name="scan:test", meta={"target": TARGET})
    node.transition(TaskStatus.RUNNING, reason="子任务启动")
    return node


# =====================================================================
# 一、镜像
# =====================================================================


def test_scan_tool_passes_manifest_image(registry, tmp_path):
    """有 manifest 镜像的工具必须把 image 传给 runner（dirsearch 的存活前提）。"""
    orch, runner = _orch(
        tmp_path,
        registry,
        scope=Scope(networks=["127.0.0.0/8"]),
        tool_images={"httpx": "python:3.12-alpine"},
    )

    assert orch._exec_run_tool(_running_node(), _action("httpx"), SimpleNamespace(name="web-scan")) == "ok"
    assert runner.calls[0]["image"] == "python:3.12-alpine"


def test_scan_tool_without_manifest_image_passes_none(registry, tmp_path):
    """没有镜像覆盖的工具（httpx/katana 的缺省情形）传 None，行为不变。"""
    orch, runner = _orch(
        tmp_path, registry, scope=Scope(networks=["127.0.0.0/8"]), tool_images={}
    )

    assert orch._exec_run_tool(_running_node(), _action("httpx"), SimpleNamespace(name="web-scan")) == "ok"
    assert runner.calls[0]["image"] is None


def test_default_tool_images_has_python_image_for_dirsearch():
    """守护：dirsearch 的 manifest 必须仍声明 python 镜像（否则这条链会再挂）。"""
    from proofhound.core.orchestrator import _default_tool_images

    assert _default_tool_images().get("dirsearch", "").startswith("python:")


# =====================================================================
# 二、越界信号
# =====================================================================

KATANA_JSONL = (
    '{"request":{"method":"GET","endpoint":"http://127.0.0.1:8000/a?id=1"}}\n'
    '{"request":{"method":"GET",'
    '"endpoint":"https://redux.js.org/Errors?code=${e}"}}\n'
)


def _record(orch, node, tool="katana", text=KATANA_JSONL):
    log = orch.evidence_dir / f"{uuid.uuid4().hex[:8]}.stdout.log"
    log.write_text(text, encoding="utf-8")
    result = SimpleNamespace(stdout_path=log, exit_code=0)
    orch._record_signals(node, _action(tool), SimpleNamespace(name="recon-crawl"), result)
    out = orch.evidence_dir / f"{log.stem}.signals.jsonl"
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
    return rows


def test_out_of_scope_signal_is_dropped_before_writing(registry, tmp_path):
    orch, _ = _orch(
        tmp_path, registry, scope=Scope(networks=["127.0.0.0/8"])
    )
    node = _running_node()

    rows = _record(orch, node)

    assert [r["asset"] for r in rows] == ["http://127.0.0.1:8000/a?id=1"]
    events = orch.audit.read_all()
    recorded = [e for e in events if e["event"] == "signals_recorded"][0]
    assert recorded["count"] == 1
    assert recorded["dropped_out_of_scope"] == 1
    dropped = [e for e in events if e["event"] == "signal_out_of_scope"]
    assert dropped and dropped[0]["count"] == 1
    assert "redux.js.org" in dropped[0]["assets"][0]


def test_without_scope_all_signals_are_kept(registry, tmp_path):
    """runner 未挂 scope（单测/CLI 直连）时不做过滤，行为与 M31 之前一致。"""
    orch, _ = _orch(tmp_path, registry, scope=None)
    node = _running_node()

    rows = _record(orch, node)

    assert len(rows) == 2
    events = orch.audit.read_all()
    assert not [e for e in events if e["event"] == "signal_out_of_scope"]
