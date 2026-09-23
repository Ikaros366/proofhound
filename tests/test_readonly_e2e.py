"""M9c③ 端到端接线测试：semi_auto 下只读验证不再进确认队列。

test_gate_sublevels.py 覆盖闸门决策与 manifest 声明；本文件覆盖**真实 runner
代码路径**——``EngagementRunner._verify`` 是否真的按 skill 的 mutating 声明
细分裁定、是否真的不再入队、以及审计是否留痕。
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.findings.evidence import assemble_evidence_pack
from proofhound.findings.finding import (
    Finding,
    FindingState,
    FindingStore,
    Verification,
)
from proofhound.skills.registry import SkillRegistry

REPO_ROOT = Path(__file__).resolve().parent.parent


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _write_skill(root: Path, name: str, *, mutating: bool, risk_level="L2") -> None:
    d = root / "skills" / name
    d.mkdir(parents=True, exist_ok=True)
    d.joinpath("SKILL.md").write_text(
        f"---\n"
        f"name: {name}\n"
        f"description: 测试用 skill\n"
        f"version: 1.0.0\n"
        f"required_tools: []\n"
        f"risk_level: {risk_level}\n"
        f"inputs: [hypotheses]\n"
        f"outputs: [findings]\n"
        f"mutating: {str(mutating).lower()}\n"
        f"---\n\n正文\n",
        encoding="utf-8",
    )


class _ReadOnlyVerifyPhases:
    """真实 OrchestratorPhases 的等价替身：verify-* 声明为**只读**。"""

    scan_skill = "web-scan"
    scan_risk_level = "L1"
    verify_skill = "verify-sqli"
    verify_risk_level = "L2"
    scan_skills = [("web-scan", "L1")]
    verify_skills = [("verify-sqli", "L2")]
    # M9c③ 关键：声明只读
    mutating_by_skill = {"web-scan": True, "verify-sqli": False}

    def __init__(self, runtime):
        self.dir = runtime.engagement.dir
        self.target = runtime.engagement.target
        self.audit = runtime.audit

    def scan(self, targets):
        pass

    def scan_with_skill(self, skill_name, targets):
        pass

    def triage(self):
        store = FindingStore(self.dir / "findings.jsonl")
        key = "sha256:e2e-readonly"
        if store.get_by_dedup_key(key) is not None:
            return []
        finding = Finding(
            id=store.next_id(),
            state=FindingState.SIGNAL,
            vuln_type="sqli",
            severity="high",
            asset=f"{self.target}/v?article_id=1",
            param="article_id",
            confidence="low",
            evidence_kinds=["crawl-endpoint"],
            dedup_key=key,
            created_at=_utc_now(),
            updated_at=_utc_now(),
            audit=self.audit,
        )
        finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="测试")
        store.append(finding)
        return [finding]

    def verify_covered_vuln_types(self, skill_name=None):
        return frozenset({"sqli"})

    def verify(self):
        return self._do()

    def verify_with_skill(self, skill_name):
        return self._do()

    def _do(self):
        store = FindingStore(self.dir / "findings.jsonl")
        log = self.dir / "verify.stdout.log"
        log.write_text("sqlmap confirmed\n", encoding="utf-8")
        out = []
        for finding in store.load_all():
            if finding.state is not FindingState.HYPOTHESIS:
                continue
            finding.audit = self.audit
            finding.verification = Verification(
                method="sqlmap-confirmed",
                evidence_refs=[f"{log}#L1"],
                reproduction_steps=["步骤"],
                verified_by="verify-sqli@test",
                verified_at=_utc_now(),
            )
            if "behavioral" not in finding.evidence_kinds:
                finding.evidence_kinds.append("behavioral")
            finding.transition(
                FindingState.REPRODUCED, actor="verify-sqli", reason="行为复现"
            )
            finding.transition(
                FindingState.CONFIRMED, actor="verifier", reason="终审确认"
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.dir)
            out.append(finding)
        return out


@pytest.fixture
def ws(tmp_path):
    (tmp_path / "scope.yaml").write_text("networks: [127.0.0.0/8]\n", encoding="utf-8")
    (tmp_path / "templates").mkdir()
    shutil.copyfile(
        REPO_ROOT / "templates" / "default_template.docx",
        tmp_path / "templates" / "default_template.docx",
    )
    _write_skill(tmp_path, "verify-sqli", mutating=False)
    _write_skill(tmp_path, "web-scan", mutating=True, risk_level="L1")
    return tmp_path


def _wait_state(client, eng_id, states, timeout=20.0):
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state in states:
            return state
        time.sleep(0.05)
    raise AssertionError(f"等待 {states} 超时，当前 {state}")


def test_read_only_verify_skips_confirmation_queue(ws):
    """semi_auto 下声明只读的 verify-* 直接自动执行，不进确认队列。"""
    app = create_app(ws, phases_factory=_ReadOnlyVerifyPhases, confirm_timeout=5.0)
    with TestClient(app) as client:
        eng_id = client.post(
            "/api/engagements",
            json={
                "target": "http://127.0.0.1:8080",
                "scope_paths": ["scope.yaml"],
                "autonomy_mode": "semi_auto",
            },
        ).json()["id"]
        client.post(f"/api/engagements/{eng_id}/run")
        state = _wait_state(client, eng_id, {"done", "failed"})
        assert state == "done", f"engagement 未完成：{state}"

        eng_dir = ws / "engagements" / eng_id
        # 1) 全程零确认（只读验证没问人）
        pending = client.get(f"/api/engagements/{eng_id}/confirmations").json()
        assert pending["confirmations"] == [], pending
        assert not (eng_dir / "confirmations.jsonl").exists()
        # 2) 审计如实记下「为什么这次没人被问」
        events = [
            json.loads(line)["event"]
            for line in (eng_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert "action_read_only_auto" in events, events
        # 3) 确认链路没有被绕过：Finding 仍走完行为验证 → Confirmed
        findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
        assert findings[0]["state"] == "confirmed"
        assert "behavioral" in findings[0]["evidence_kinds"]


def test_writer_skill_still_queues_confirmation(ws):
    """同一模式下，声明为写操作的 verify-* 仍进确认队列（细分级不放宽写操作）。"""
    class _WriterPhases(_ReadOnlyVerifyPhases):
        mutating_by_skill = {"web-scan": True, "verify-sqli": True}

    app = create_app(ws, phases_factory=_WriterPhases, confirm_timeout=5.0)
    with TestClient(app) as client:
        eng_id = client.post(
            "/api/engagements",
            json={
                "target": "http://127.0.0.1:8080",
                "scope_paths": ["scope.yaml"],
                "autonomy_mode": "semi_auto",
            },
        ).json()["id"]
        client.post(f"/api/engagements/{eng_id}/run")
        # 出现待确认动作（L2 写操作）
        deadline = time.monotonic() + 15.0
        confs = []
        while time.monotonic() < deadline:
            confs = client.get(f"/api/engagements/{eng_id}/confirmations").json()[
                "confirmations"
            ]
            if confs:
                break
            time.sleep(0.05)
        assert confs, "写操作未进确认队列"
        assert confs[0]["action"] == "verify-sqli"
        eng_dir = ws / "engagements" / eng_id
        events = [
            json.loads(line)["event"]
            for line in (eng_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert "action_read_only_auto" not in events