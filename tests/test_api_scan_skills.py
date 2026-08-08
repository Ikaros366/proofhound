"""M3d runner 多 scan skill 接线测试：逐 skill 过闸 + 旧接口回退。

覆盖验收点：scan_skills 多 skill（web-scan + recon-crawl）在 semi_auto 下
直通零确认；supervised 下逐 skill 进确认队列（批准/拒绝粒度正确）；
无 scan_skills 属性的旧式 phases 走回退路径（行为与 M5a 一致）。
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app

REPO_ROOT = Path(__file__).resolve().parent.parent


class FakePhasesMulti:
    """暴露 scan_skills 的假阶段执行器（M3d 多 skill 接口）。"""

    scan_skills = [("web-scan", "L1"), ("recon-crawl", "L1")]
    verify_skill = "verify-sqli"
    verify_risk_level = "L2"

    def __init__(self, runtime):
        self.dir = runtime.engagement.dir
        self.scans: list[tuple[str, list[str]]] = []

    def scan_with_skill(self, skill_name: str, targets: list[str]) -> None:
        self.scans.append((skill_name, list(targets)))

    def triage(self) -> list:
        return []

    def verify_covered_vuln_types(self) -> frozenset[str]:
        return frozenset({"sqli"})

    def verify(self) -> list:
        return []


class FakePhasesLegacy:
    """无 scan_skills 的旧式假阶段执行器（M5a 单 skill 接口）。"""

    scan_skill = "web-scan"
    scan_risk_level = "L1"
    verify_skill = "verify-sqli"
    verify_risk_level = "L2"

    def __init__(self, runtime):
        self.dir = runtime.engagement.dir
        self.scanned: list[str] = []

    def scan(self, targets: list[str]) -> None:
        self.scanned.extend(targets)

    def triage(self) -> list:
        return []

    def verify_covered_vuln_types(self) -> frozenset[str]:
        return frozenset({"sqli"})

    def verify(self) -> list:
        return []


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "scope.yaml").write_text("networks: [127.0.0.0/8]\n", encoding="utf-8")
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    shutil.copyfile(
        REPO_ROOT / "templates" / "default_template.docx",
        templates_dir / "default_template.docx",
    )
    return tmp_path


def _make_client(workspace, phases_cls):
    instances = []

    def _factory(runtime):
        phases = phases_cls(runtime)
        instances.append(phases)
        return phases

    app = create_app(workspace, phases_factory=_factory, confirm_timeout=30.0)
    return app, instances


def _create(client, **overrides) -> str:
    body = {"target": "http://127.0.0.1:8080", "scope_paths": ["scope.yaml"]}
    body.update(overrides)
    resp = client.post("/api/engagements", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _wait_state(client, eng_id, states, timeout=15.0):
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state in states:
            return state
        time.sleep(0.05)
    raise AssertionError(f"等待状态 {states} 超时，当前: {state}")


def _wait_pending(client, eng_id, action, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        confs = client.get(f"/api/engagements/{eng_id}/confirmations").json()[
            "confirmations"
        ]
        for conf in confs:
            if conf["action"] == action:
                return conf
        time.sleep(0.05)
    raise AssertionError(f"等待 {action} 待确认动作超时")


def test_semi_auto_both_skills_auto(workspace):
    """semi_auto：两个 L1 scan skill 均直通，零确认，逐 skill 执行。"""
    app, instances = _make_client(workspace, FakePhasesMulti)
    with TestClient(app) as client:
        eng_id = _create(client, autonomy_mode="semi_auto")
        assert client.post(f"/api/engagements/{eng_id}/run").status_code == 202
        assert _wait_state(client, eng_id, {"done"}) == "done"
        phases = instances[0]
        assert [name for name, _ in phases.scans] == ["web-scan", "recon-crawl"]
        assert all(targets == ["http://127.0.0.1:8080"] for _, targets in phases.scans)
        confs = client.get(f"/api/engagements/{eng_id}/confirmations").json()[
            "confirmations"
        ]
        assert confs == []


def test_supervised_per_skill_confirmation(workspace):
    """supervised：L1 逐 skill 进确认队列；批准 web-scan、拒绝 recon-crawl，
    只有批准的执行，被拒记 phase_skipped（确认/审计粒度到 skill）。"""
    app, instances = _make_client(workspace, FakePhasesMulti)
    with TestClient(app) as client:
        eng_id = _create(client, autonomy_mode="supervised")
        assert client.post(f"/api/engagements/{eng_id}/run").status_code == 202

        conf = _wait_pending(client, eng_id, "web-scan")
        assert conf["risk_level"] == "L1"
        assert conf["target"] == "http://127.0.0.1:8080"
        assert client.post(
            f"/api/confirmations/{conf['cid']}/approve", json={"operator": "tester"}
        ).status_code == 200

        conf2 = _wait_pending(client, eng_id, "recon-crawl")
        assert client.post(
            f"/api/confirmations/{conf2['cid']}/reject", json={"operator": "tester"}
        ).status_code == 200

        assert _wait_state(client, eng_id, {"done"}) == "done"
        phases = instances[0]
        assert [name for name, _ in phases.scans] == ["web-scan"]  # 仅批准的执行
        audit_lines = (workspace / "engagements" / eng_id / "audit.jsonl").read_text(
            encoding="utf-8"
        )
        skipped = [
            json.loads(line)
            for line in audit_lines.splitlines()
            if '"phase_skipped"' in line
        ]
        assert any(e["phase"] == "scan:recon-crawl" for e in skipped)


def test_legacy_phases_fallback(workspace):
    """无 scan_skills 属性的旧式 phases：回退单 skill 接口，行为不变。"""
    app, instances = _make_client(workspace, FakePhasesLegacy)
    with TestClient(app) as client:
        eng_id = _create(client, autonomy_mode="semi_auto")
        assert client.post(f"/api/engagements/{eng_id}/run").status_code == 202
        assert _wait_state(client, eng_id, {"done"}) == "done"
        phases = instances[0]
        assert phases.scanned == ["http://127.0.0.1:8080"]
