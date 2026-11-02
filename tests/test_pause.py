"""M27-UI：engagement 的**协作式暂停/继续**（阶段边界生效，不冻结在途阶段）。

## 为什么要"协作式"

执行线程按阶段串行推进（scan → triage → verify），每个阶段内部是编排器的一次
整体调用（沙箱内可能跑几分钟）。要"立即冻结线程"只能强行中断，那会让沙箱子进程、
确认队列与状态机同时停在半截——**比不能暂停更糟**。故暂停是**请求 + 检查点**：
``POST /pause`` 只登记请求，执行线程在下一个阶段边界（scan 的每个 skill 之后、
triage 之后、verify 的每个 skill 之后）转入 ``paused`` 并阻塞，``POST /resume``
放行并回到暂停前的阶段态。

## 本文件钉住

- 请求受理与生效是**两个时刻**（``pause_requested`` vs ``state=paused``）；
- ``paused_from`` 如实给出暂停前所处阶段（UI 的进度条据此停在正确一格）；
- 继续后**不重跑**已完成的阶段（暂停点之后的阶段才继续）；最终 done；
- 状态机边界：未运行 / 终态 / 待确认都拒绝暂停，非 paused 拒绝继续（409）；
- 审计四条：``engagement_pause_requested`` / ``engagement_state``（paused 与恢复）/
  ``engagement_resumed``。
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app

REPO_ROOT = Path(__file__).resolve().parent.parent


class PhaseGate:
    """测试用闸门：让 triage 停在半路，好让我们在"运行中"发暂停请求。"""

    def __init__(self) -> None:
        self.triage_entered = threading.Event()
        self.triage_release = threading.Event()
        self.verify_entered = threading.Event()


class BlockingPhases:
    """与 OrchestratorPhases 同接口的假阶段执行器（无 Docker/LLM）。"""

    scan_skill = "web-scan"
    scan_risk_level = "L1"
    verify_skill = "verify-sqli"
    verify_risk_level = "L2"

    def __init__(self, runtime, gate: PhaseGate):
        self.dir = runtime.engagement.dir
        self.target = runtime.engagement.target
        self.audit = runtime.audit
        self.gate = gate
        self.scanned: list[str] = []

    def scan(self, targets: list[str]) -> None:
        self.scanned.extend(targets)

    def triage(self) -> list:
        self.gate.triage_entered.set()
        assert self.gate.triage_release.wait(5.0), "测试闸门没有被放行"
        return []

    def verify_covered_vuln_types(self) -> frozenset[str]:
        return frozenset()

    def verify(self) -> list:
        self.gate.verify_entered.set()
        return []


@pytest.fixture()
def workspace(tmp_path):
    (tmp_path / "scope.yaml").write_text(
        "networks: [127.0.0.0/8]\n", encoding="utf-8"
    )
    return tmp_path


def _client(workspace):
    gate = PhaseGate()

    def factory(runtime):
        return BlockingPhases(runtime, gate)

    app = create_app(workspace, phases_factory=factory, confirm_timeout=5.0)
    return TestClient(app), gate


def _create(client) -> str:
    resp = client.post(
        "/api/engagements",
        json={
            "target": "http://127.0.0.1:8080",
            "scope_paths": ["scope.yaml"],
            "autonomy_mode": "unattended",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _wait_state(client, eng_id: str, states: set[str], timeout: float = 8.0) -> dict:
    deadline = time.monotonic() + timeout
    last = {}
    while time.monotonic() < deadline:
        last = client.get(f"/api/engagements/{eng_id}").json()
        if last["state"] in states:
            return last
        time.sleep(0.02)
    raise AssertionError(f"等待状态 {states} 超时，最后状态: {last}")


def _events(client, eng_id: str) -> list[dict]:
    payload = client.get(f"/api/engagements/{eng_id}/audit?tail=500").json()
    return payload["events"]


def test_pause_requests_then_takes_effect_at_phase_boundary(workspace):
    client, gate = _client(workspace)
    with client:
        eng_id = _create(client)
        assert client.post(f"/api/engagements/{eng_id}/run").status_code == 202
        assert gate.triage_entered.wait(5.0)

        # 运行中：状态仍是 triaging，受理暂停 ≠ 立即暂停
        resp = client.post(f"/api/engagements/{eng_id}/pause")
        assert resp.status_code == 202, resp.text
        detail = client.get(f"/api/engagements/{eng_id}").json()
        assert detail["state"] == "triaging"
        assert detail["pause_requested"] is True
        assert detail["running"] is True

        # 到达检查点（triage 返回）后转入 paused，且 paused_from 如实记录
        gate.triage_release.set()
        paused = _wait_state(client, eng_id, {"paused"})
        assert paused["paused_from"] == "triaging"
        assert paused["pause_requested"] is False
        assert paused["running"] is True  # 线程仍活着，只是阻塞在检查点

        # 继续：回到 triaging 再进入 verify，最终 done（不重跑已完成的阶段）
        assert client.post(f"/api/engagements/{eng_id}/resume").status_code == 202
        done = _wait_state(client, eng_id, {"done"})
        assert done["state"] == "done"

        events = _events(client, eng_id)
        names = [event["event"] for event in events]
        assert "engagement_pause_requested" in names
        assert "engagement_resumed" in names
        paused_events = [
            event
            for event in events
            if event["event"] == "engagement_state" and event.get("to") == "paused"
        ]
        assert len(paused_events) == 1
        assert paused_events[0]["from"] == "triaging"
        resumed_events = [
            event
            for event in events
            if event["event"] == "engagement_state"
            and event.get("from") == "paused"
            and event.get("to") == "triaging"
        ]
        assert len(resumed_events) == 1


def test_pause_is_rejected_when_not_running(workspace):
    client, _gate = _client(workspace)
    with client:
        eng_id = _create(client)
        resp = client.post(f"/api/engagements/{eng_id}/pause")
        assert resp.status_code == 409
        assert resp.json()["detail"]["error"] == "invalid_state"


def test_resume_is_rejected_when_not_paused(workspace):
    client, _gate = _client(workspace)
    with client:
        eng_id = _create(client)
        resp = client.post(f"/api/engagements/{eng_id}/resume")
        assert resp.status_code == 409
        assert "仅 paused 可继续" in resp.json()["detail"]["message"]


def test_pause_is_rejected_after_done(workspace):
    client, gate = _client(workspace)
    with client:
        eng_id = _create(client)
        gate.triage_release.set()  # triage 立即放行
        assert client.post(f"/api/engagements/{eng_id}/run").status_code == 202
        _wait_state(client, eng_id, {"done"})
        resp = client.post(f"/api/engagements/{eng_id}/pause")
        assert resp.status_code == 409
        assert resp.json()["detail"]["error"] == "invalid_state"


def test_double_pause_is_rejected_while_paused(workspace):
    client, gate = _client(workspace)
    with client:
        eng_id = _create(client)
        assert client.post(f"/api/engagements/{eng_id}/run").status_code == 202
        assert gate.triage_entered.wait(5.0)
        assert client.post(f"/api/engagements/{eng_id}/pause").status_code == 202
        gate.triage_release.set()
        _wait_state(client, eng_id, {"paused"})
        second = client.post(f"/api/engagements/{eng_id}/pause")
        assert second.status_code == 409
        client.post(f"/api/engagements/{eng_id}/resume")
        _wait_state(client, eng_id, {"done"})


def test_paused_state_survives_metadata_write(workspace):
    """暂停态写进 api.json（重启后由 _load_all 回退 created，这是既有粗粒度恢复）。"""
    client, gate = _client(workspace)
    with client:
        eng_id = _create(client)
        client.post(f"/api/engagements/{eng_id}/run")
        assert gate.triage_entered.wait(5.0)
        client.post(f"/api/engagements/{eng_id}/pause")
        gate.triage_release.set()
        _wait_state(client, eng_id, {"paused"})
        meta = (workspace / "engagements" / eng_id / "api.json").read_text(
            encoding="utf-8"
        )
        assert '"state": "paused"' in meta
        client.post(f"/api/engagements/{eng_id}/resume")
        _wait_state(client, eng_id, {"done"})
