"""API 层测试（M5a，§5.9.1）：FastAPI TestClient + fake 阶段执行器。

不碰 Docker、不调真模型：``FakePhases`` 实现与 ``OrchestratorPhases`` 相同的
阶段接口（scan/triage/verify_covered_vuln_types/verify），verify 走合法状态机
迁移（Hypothesis→Reproduced→Confirmed，铁律要件齐全），闸门/确认队列/审计/
报告全链路为真实代码。
"""

from __future__ import annotations

import json
import shutil
import stat
import time
from datetime import datetime, timezone
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

REPO_ROOT = Path(__file__).resolve().parent.parent
COOKIE_VALUE = "abc123def456789"  # 测试凭据：任何响应体都不得出现该值


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class FakePhases:
    """与 OrchestratorPhases 同接口的假阶段执行器（无 Docker/LLM）。"""

    scan_skill = "web-scan"
    scan_risk_level = "L1"
    verify_skill = "verify-sqli"
    verify_risk_level = "L2"

    def __init__(self, runtime):
        self.dir = runtime.engagement.dir
        self.target = runtime.engagement.target
        self.audit = runtime.audit
        self.scanned: list[str] = []

    def scan(self, targets: list[str]) -> None:
        self.scanned.extend(targets)

    def triage(self) -> list:
        store = FindingStore(self.dir / "findings.jsonl")
        dedup_key = "sha256:fake-sqli"
        existing = store.get_by_dedup_key(dedup_key)
        if existing is not None:
            return [existing]  # 幂等：与真实 triage 同指纹归并语义一致
        finding = Finding(
            id=store.next_id(),
            state=FindingState.SIGNAL,
            vuln_type="sqli",
            severity="high",
            asset=f"{self.target}/vulnerabilities/sqli/?id=1&Submit=Submit",
            param="id",
            confidence="low",
            evidence_kinds=["status-code"],
            dedup_key=dedup_key,
            created_at=_utc_now(),
            updated_at=_utc_now(),
            audit=self.audit,
        )
        finding.transition(
            FindingState.HYPOTHESIS, actor="triage", reason="fake triage 规则映射"
        )
        store.append(finding)
        return [finding]

    def verify_covered_vuln_types(self) -> frozenset[str]:
        return frozenset({"sqli"})

    def verify(self) -> list:
        """对剩余 Hypothesis 走合法迁移链确认（铁律要件：behavioral + 证据引用）。"""
        store = FindingStore(self.dir / "findings.jsonl")
        log = self.dir / "fake-sqlmap.stdout.log"
        log.write_text(
            "sqlmap identified the following injection point(s)\n", encoding="utf-8"
        )
        processed = []
        for finding in store.load_all():
            if finding.state is not FindingState.HYPOTHESIS:
                continue
            finding.audit = self.audit
            finding.verification = Verification(
                method="sqlmap-confirmed",
                evidence_refs=[f"{log}#L1"],
                reproduction_steps=["fake 复现步骤"],
                verified_by="verify-sqli@fake",
                verified_at=_utc_now(),
            )
            if "behavioral" not in finding.evidence_kinds:
                finding.evidence_kinds.append("behavioral")
            finding.transition(
                FindingState.REPRODUCED, actor="verify-sqli", reason="fake 行为复现"
            )
            finding.transition(
                FindingState.CONFIRMED, actor="verifier", reason="fake 终审确认"
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.dir)
            processed.append(finding)
        return processed


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "scope.yaml").write_text(
        "networks: [127.0.0.0/8]\n", encoding="utf-8"
    )
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    shutil.copyfile(
        REPO_ROOT / "templates" / "default_template.docx",
        templates_dir / "default_template.docx",
    )
    return tmp_path


@pytest.fixture
def fake_factory():
    instances = []

    def _factory(runtime):
        phases = FakePhases(runtime)
        instances.append(phases)
        return phases

    _factory.instances = instances
    return _factory


@pytest.fixture
def client(workspace, fake_factory):
    app = create_app(workspace, phases_factory=fake_factory, confirm_timeout=30.0)
    with TestClient(app) as test_client:
        yield test_client


# ---- 工具函数 ----


def _create(client, **overrides) -> str:
    body = {"target": "http://127.0.0.1:8080", "scope_paths": ["scope.yaml"]}
    body.update(overrides)
    resp = client.post("/api/engagements", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _wait_state(client, eng_id: str, states: set[str], timeout: float = 15.0) -> str:
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state in states:
            return state
        time.sleep(0.05)
    raise AssertionError(f"等待状态 {states} 超时，当前状态: {state}")


def _wait_confirmation(client, eng_id: str, timeout: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        confs = client.get(f"/api/engagements/{eng_id}/confirmations").json()[
            "confirmations"
        ]
        if confs:
            return confs[0]
        time.sleep(0.05)
    raise AssertionError("等待待确认动作超时")


def _eng_dir(workspace: Path, eng_id: str) -> Path:
    return workspace / "engagements" / eng_id


# ---- 全生命周期 ----


def test_full_lifecycle_semi_auto(client, workspace):
    eng_id = _create(client)
    resp = client.post(f"/api/engagements/{eng_id}/run")
    assert resp.status_code == 202, resp.text

    # verify 遇 L2 阻塞 → 确认队列出现
    conf = _wait_confirmation(client, eng_id)
    assert conf["action"] == "verify-sqli"
    assert conf["risk_level"] == "L2"
    assert conf["finding_id"] is not None
    assert _wait_state(client, eng_id, {"confirming"}) == "confirming"

    resp = client.post(
        f"/api/confirmations/{conf['cid']}/approve",
        json={"operator": "tester", "note": "授权验证"},
    )
    assert resp.status_code == 200, resp.text
    assert _wait_state(client, eng_id, {"done"}) == "done"

    # findings：1 条 confirmed
    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    assert len(findings) == 1
    assert findings[0]["state"] == "confirmed"
    fid = findings[0]["id"]

    # 证据包端点：等价 findings show（内容 + sha256 + 行号锚点）
    evidence = client.get(f"/api/engagements/{eng_id}/findings/{fid}/evidence").json()
    assert evidence["finding"]["id"] == fid
    assert evidence["assembled"] is True
    assert any(
        item.get("sha256") and item.get("anchor_line_text") for item in evidence["items"]
    )

    # 报告：构建 + 下载字节与磁盘一致
    resp = client.post(f"/api/engagements/{eng_id}/report", json={})
    assert resp.status_code == 200, resp.text
    assert resp.json()["summary"]["confirmed"] == 1
    resp = client.get(f"/api/engagements/{eng_id}/report")
    assert resp.status_code == 200
    disk_bytes = (_eng_dir(workspace, eng_id) / "report.docx").read_bytes()
    assert resp.content == disk_bytes

    # 审计：approve 事件落盘，operator 落款
    audit = client.get(f"/api/engagements/{eng_id}/audit").json()
    approved = [e for e in audit["events"] if e["event"] == "action_approved"]
    assert len(approved) == 1
    assert approved[0]["operator"] == "tester"
    assert approved[0]["cid"] == conf["cid"]


# ---- 三种模式闸门矩阵 ----


def test_supervised_mode_blocks_l1_and_l2(client):
    eng_id = _create(client, autonomy_mode="supervised")
    client.post(f"/api/engagements/{eng_id}/run")

    # 监督模式：L1 扫描动作也阻塞
    scan_conf = _wait_confirmation(client, eng_id)
    assert scan_conf["action"] == "web-scan"
    assert scan_conf["risk_level"] == "L1"
    client.post(
        f"/api/confirmations/{scan_conf['cid']}/approve",
        json={"operator": "tester"},
    )
    # L2 验证动作同样阻塞
    verify_conf = _wait_confirmation(client, eng_id)
    assert verify_conf["action"] == "verify-sqli"
    assert verify_conf["risk_level"] == "L2"
    client.post(
        f"/api/confirmations/{verify_conf['cid']}/approve",
        json={"operator": "tester"},
    )
    assert _wait_state(client, eng_id, {"done"}) == "done"


def test_semi_auto_passes_l1_blocks_l2(client, workspace):
    eng_id = _create(client, autonomy_mode="semi_auto")
    client.post(f"/api/engagements/{eng_id}/run")
    conf = _wait_confirmation(client, eng_id)
    assert conf["action"] == "verify-sqli"  # L1 直通，首个阻塞即 L2
    client.post(
        f"/api/confirmations/{conf['cid']}/approve", json={"operator": "tester"}
    )
    assert _wait_state(client, eng_id, {"done"}) == "done"
    # 确认队列全程只有 L2 动作（L1 从未入队）
    path = _eng_dir(workspace, eng_id) / "confirmations.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert {r["action"] for r in records} == {"verify-sqli"}


def test_unattended_mode_all_auto(client, workspace):
    eng_id = _create(client, autonomy_mode="unattended")
    client.post(f"/api/engagements/{eng_id}/run")
    assert _wait_state(client, eng_id, {"done"}) == "done"
    # 全程无确认阻塞
    confs = client.get(f"/api/engagements/{eng_id}/confirmations").json()[
        "confirmations"
    ]
    assert confs == []
    assert not (_eng_dir(workspace, eng_id) / "confirmations.jsonl").exists()
    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    assert findings[0]["state"] == "confirmed"


# ---- reject 路径 ----


def test_reject_path_finding_rejected_and_in_report(client):
    eng_id = _create(client)
    client.post(f"/api/engagements/{eng_id}/run")
    conf = _wait_confirmation(client, eng_id)
    resp = client.post(
        f"/api/confirmations/{conf['cid']}/reject",
        json={"operator": "tester", "note": "该资产不予验证"},
    )
    assert resp.status_code == 200
    assert _wait_state(client, eng_id, {"done"}) == "done"

    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    assert len(findings) == 1
    assert findings[0]["state"] == "rejected"
    assert "operator_rejected" in findings[0]["rejection_reason"]

    # 报告 rejected 桶可见（误报附录数据源）
    resp = client.post(f"/api/engagements/{eng_id}/report", json={})
    assert resp.status_code == 200
    assert resp.json()["summary"]["rejected"] == 1
    assert resp.json()["summary"]["confirmed"] == 0


def test_confirmation_timeout_auto_rejects(workspace, fake_factory):
    """确认队列阻塞等待带超时（可配置）：超时默认拒绝并写审计。"""
    app = create_app(workspace, phases_factory=fake_factory, confirm_timeout=0.3)
    with TestClient(app) as client:
        eng_id = _create(client)
        client.post(f"/api/engagements/{eng_id}/run")
        conf = _wait_confirmation(client, eng_id)
        # 不做任何裁定：等待超时自动拒绝，engagement 继续推进到 done
        assert _wait_state(client, eng_id, {"done"}) == "done"
        # 确认记录持久化为 rejected（operator=system），不再 pending
        assert (
            client.get(f"/api/engagements/{eng_id}/confirmations").json()[
                "confirmations"
            ]
            == []
        )
        store_path = _eng_dir(workspace, eng_id) / "confirmations.jsonl"
        records = [
            json.loads(line)
            for line in store_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert records[-1]["cid"] == conf["cid"]
        assert records[-1]["status"] == "rejected"
        assert records[-1]["operator"] == "system"
        assert "确认超时" in records[-1]["note"]
        # 审计 action_rejected operator=system
        events = client.get(f"/api/engagements/{eng_id}/audit").json()["events"]
        assert any(
            e["event"] == "action_rejected"
            and e["cid"] == conf["cid"]
            and e["operator"] == "system"
            for e in events
        )
        # 对应 Finding 终态 rejected，归因为 system 超时
        findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
        assert findings[0]["state"] == "rejected"
        assert "operator_rejected" in findings[0]["rejection_reason"]
        assert "确认超时" in findings[0]["rejection_reason"]


# ---- 模式切换 ----


def test_autonomy_switch_audit_and_validation(client, workspace):
    eng_id = _create(client)
    # 收紧：半自动 → 监督，无需 operator
    resp = client.post(
        f"/api/engagements/{eng_id}/autonomy", json={"mode": "supervised"}
    )
    assert resp.status_code == 200
    assert resp.json()["mode"] == "supervised"
    # 放宽无 operator：拒绝
    resp = client.post(
        f"/api/engagements/{eng_id}/autonomy", json={"mode": "unattended"}
    )
    assert resp.status_code == 409
    # 放宽带 operator：允许 + 审计落盘
    resp = client.post(
        f"/api/engagements/{eng_id}/autonomy",
        json={"mode": "unattended", "operator": "ikaros", "note": "夜间批量已授权"},
    )
    assert resp.status_code == 200
    assert resp.json()["mode"] == "unattended"
    events = [
        e
        for e in (_eng_dir(workspace, eng_id) / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if e.strip()
    ]
    switched = [
        json.loads(e) for e in events if json.loads(e)["event"] == "autonomy_mode_changed"
    ]
    assert len(switched) == 2  # 收紧 + 放宽各一条
    assert switched[-1]["from"] == "supervised"
    assert switched[-1]["to"] == "unattended"
    assert switched[-1]["operator"] == "ikaros"
    # 非法模式名：422
    resp = client.post(f"/api/engagements/{eng_id}/autonomy", json={"mode": "god"})
    assert resp.status_code == 422


# ---- scope / 预算硬闸 ----


def test_scope_violation_on_create_zero_side_effects(client, workspace):
    resp = client.post(
        "/api/engagements",
        json={"target": "http://169.254.10.10:80", "scope_paths": ["scope.yaml"]},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "scope_violation"
    # 零目录零审计外副作用
    engagements_dir = workspace / "engagements"
    assert not engagements_dir.exists() or list(engagements_dir.iterdir()) == []
    assert list(workspace.rglob("audit.jsonl")) == []


def test_run_rechecks_scope_after_file_change(client, workspace):
    eng_id = _create(client)
    # 创建后改 scope 文件（合法运维操作）→ run 时目标越界
    (workspace / "scope.yaml").write_text("networks: [10.0.0.0/8]\n", encoding="utf-8")
    resp = client.post(f"/api/engagements/{eng_id}/run")
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "scope_violation"
    events = client.get(f"/api/engagements/{eng_id}/audit").json()["events"]
    rechecks = [e for e in events if e["event"] == "scope_recheck"]
    assert len(rechecks) == 1
    assert rechecks[0]["allowed"] is False


def test_budget_zero_run_402_even_unattended(client):
    """预算硬闸在无人值守模式下同样不可绕过（不可旁路声明的 API 侧坐实）。"""
    eng_id = _create(client, autonomy_mode="unattended", budget=0)
    resp = client.post(f"/api/engagements/{eng_id}/run")
    assert resp.status_code == 402
    assert resp.json()["detail"]["error"] == "budget_exceeded"
    # engagement 未被启动
    assert client.get(f"/api/engagements/{eng_id}").json()["state"] == "created"


def test_unattended_scope_still_enforced(client):
    """无人值守模式下 scope 校验依旧硬闸（不可旁路声明）。"""
    resp = client.post(
        "/api/engagements",
        json={
            "target": "http://192.0.2.1:80",
            "scope_paths": ["scope.yaml"],
            "autonomy_mode": "unattended",
        },
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "scope_violation"


# ---- cookie 脱敏 ----


def test_cookie_never_in_any_response(client, workspace):
    eng_id = _create(client, cookie=f"PHPSESSID={COOKIE_VALUE}; security=low")
    detail = client.get(f"/api/engagements/{eng_id}")
    assert detail.json()["with_session"] is True
    assert COOKIE_VALUE not in detail.text
    listing = client.get("/api/engagements")
    assert COOKIE_VALUE not in listing.text
    # session.json 0600 且不含在 detail 字段中
    session_path = _eng_dir(workspace, eng_id) / "session.json"
    assert stat.S_IMODE(session_path.stat().st_mode) == 0o600
    # 跑完全程后审计端点同样无凭据原文
    _run_unattended_to_done(client, eng_id)
    audit = client.get(f"/api/engagements/{eng_id}/audit")
    assert COOKIE_VALUE not in audit.text
    findings = client.get(f"/api/engagements/{eng_id}/findings")
    assert COOKIE_VALUE not in findings.text


def _run_unattended_to_done(client, eng_id: str) -> None:
    client.post(f"/api/engagements/{eng_id}/autonomy", json={"mode": "supervised"})
    client.post(
        f"/api/engagements/{eng_id}/autonomy",
        json={"mode": "unattended", "operator": "tester"},
    )
    client.post(f"/api/engagements/{eng_id}/run")
    assert _wait_state(client, eng_id, {"done"}) == "done"


def test_malformed_cookie_rejected_422(client):
    resp = client.post(
        "/api/engagements",
        json={
            "target": "http://127.0.0.1:8080",
            "scope_paths": ["scope.yaml"],
            "cookie": "not-a-cookie",
        },
    )
    assert resp.status_code == 422


# ---- M8c：第二身份会话（reference/victim） ----

REF_COOKIE_VALUE = "a1b2c3d4e5f60718"


def test_reference_cookie_stored_and_never_in_response(client, workspace):
    """reference_cookie：写 session.json reference 结构（0600），永不进任何响应体。"""
    eng_id = _create(
        client,
        cookie=f"PHPSESSID={COOKIE_VALUE}",
        reference_cookie=f"phsess={REF_COOKIE_VALUE}",
    )
    detail = client.get(f"/api/engagements/{eng_id}")
    assert detail.json()["with_session"] is True
    assert detail.json()["with_reference_session"] is True
    assert REF_COOKIE_VALUE not in detail.text
    listing = client.get("/api/engagements")
    assert REF_COOKIE_VALUE not in listing.text
    # session.json：reference 嵌套结构 + 0600
    session_path = _eng_dir(workspace, eng_id) / "session.json"
    assert stat.S_IMODE(session_path.stat().st_mode) == 0o600
    data = json.loads(session_path.read_text(encoding="utf-8"))
    assert data["cookies"] == {"PHPSESSID": COOKIE_VALUE}
    assert data["reference"] == {"cookies": {"phsess": REF_COOKIE_VALUE}}
    # 跑完全程：审计只记布尔标记，无凭据原文
    _run_unattended_to_done(client, eng_id)
    audit = client.get(f"/api/engagements/{eng_id}/audit")
    assert REF_COOKIE_VALUE not in audit.text
    assert COOKIE_VALUE not in audit.text
    assert "with_reference_session" in audit.text


def test_without_reference_cookie_behaves_as_before(client, workspace):
    """不传 reference_cookie = 单会话（现有行为不变，session.json 无 reference 键）。"""
    eng_id = _create(client, cookie=f"PHPSESSID={COOKIE_VALUE}")
    detail = client.get(f"/api/engagements/{eng_id}")
    assert detail.json()["with_session"] is True
    assert detail.json()["with_reference_session"] is False
    data = json.loads(
        (_eng_dir(workspace, eng_id) / "session.json").read_text(encoding="utf-8")
    )
    assert "reference" not in data


def test_malformed_reference_cookie_rejected_422(client, workspace):
    """畸形 reference_cookie 同样 422 且零副作用（不建任何目录）。"""
    resp = client.post(
        "/api/engagements",
        json={
            "target": "http://127.0.0.1:8080",
            "scope_paths": ["scope.yaml"],
            "reference_cookie": "not-a-cookie",
        },
    )
    assert resp.status_code == 422
    engagements_dir = workspace / "engagements"
    assert not engagements_dir.exists() or not list(engagements_dir.iterdir())


def test_load_session_builds_nested_reference(tmp_path):
    """_load_session：reference 键构造嵌套 SessionConfig；旧格式兼容 None。"""
    from types import SimpleNamespace

    from proofhound.api.runner import EngagementManager

    (tmp_path / "session.json").write_text(
        json.dumps(
            {
                "cookies": {"PHPSESSID": "x" * 16},
                "reference": {"cookies": {"phsess": "y" * 16}},
            }
        ),
        encoding="utf-8",
    )
    session = EngagementManager._load_session(SimpleNamespace(dir=tmp_path))
    assert session.cookies == {"PHPSESSID": "x" * 16}
    assert session.reference is not None
    assert session.reference.cookies == {"phsess": "y" * 16}
    # 两会话秘密值均被脱敏清单覆盖
    assert "y" * 16 in session.secret_values()
    # 旧格式（无 reference 键）回放兼容
    (tmp_path / "session.json").write_text(
        json.dumps({"cookies": {"a": "b"}}), encoding="utf-8"
    )
    session = EngagementManager._load_session(SimpleNamespace(dir=tmp_path))
    assert session.reference is None


def test_extras_written_to_engagement_json(client, workspace):
    """报告 extras（M4.5 透传）：创建时写入 engagement.json，审计记键名。"""
    eng_id = _create(
        client,
        extras={
            "company_name": "某某单位",
            "system_name": "自定义企业演示系统",
            "report_date": "2026年8月",
        },
    )
    meta = json.loads(
        (_eng_dir(workspace, eng_id) / "engagement.json").read_text(encoding="utf-8")
    )
    assert meta["company_name"] == "某某单位"
    assert meta["system_name"] == "自定义企业演示系统"
    assert meta["report_date"] == "2026年8月"
    assert meta["target"] == "http://127.0.0.1:8080"  # 系统键不受影响
    assert meta["started_at"]  # 系统生成键仍在
    created = [
        e
        for e in (
            json.loads(line)
            for line in (_eng_dir(workspace, eng_id) / "audit.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        )
        if e["event"] == "engagement_created"
    ]
    assert created[0]["extras"] == ["company_name", "report_date", "system_name"]


def test_extras_reserved_keys_rejected_422(client, workspace):
    """extras 占用系统保留键 → 422（与 cookie 畸形同纪律：不创建任何资源）。"""
    before = set((_eng_dir(workspace, "").parent).glob("eng-*"))
    resp = client.post(
        "/api/engagements",
        json={
            "target": "http://127.0.0.1:8080",
            "scope_paths": ["scope.yaml"],
            "extras": {"started_at": "2026-01-01"},
        },
    )
    assert resp.status_code == 422
    after = set((_eng_dir(workspace, "").parent).glob("eng-*"))
    assert after == before  # 零副作用


def test_extras_blank_key_rejected_422(client):
    resp = client.post(
        "/api/engagements",
        json={
            "target": "http://127.0.0.1:8080",
            "scope_paths": ["scope.yaml"],
            "extras": {"  ": "x"},
        },
    )
    assert resp.status_code == 422


# ---- 确认队列重启恢复 ----


def test_confirmations_survive_app_restart(workspace, fake_factory):
    app1 = create_app(workspace, phases_factory=fake_factory, confirm_timeout=60.0)
    with TestClient(app1) as client1:
        eng_id = _create(client1)
        client1.post(f"/api/engagements/{eng_id}/run")
        conf = _wait_confirmation(client1, eng_id)
        cid = conf["cid"]

        # 重建 app 实例（模拟重启）：待确认队列仍在
        app2 = create_app(workspace, phases_factory=fake_factory, confirm_timeout=60.0)
        with TestClient(app2) as client2:
            confs = client2.get(f"/api/engagements/{eng_id}/confirmations").json()[
                "confirmations"
            ]
            assert [c["cid"] for c in confs] == [cid]
            # 新实例批准（裁定随 confirmations.jsonl 持久化）
            resp = client2.post(
                f"/api/confirmations/{cid}/approve", json={"operator": "tester"}
            )
            assert resp.status_code == 200
            # 重跑推进：闸门复用既有批准（action_resumed），不再阻塞直至完成
            resp = client2.post(f"/api/engagements/{eng_id}/run")
            assert resp.status_code == 202
            assert _wait_state(client2, eng_id, {"done"}, timeout=10.0) == "done"
            findings = client2.get(f"/api/engagements/{eng_id}/findings").json()[
                "findings"
            ]
            assert len(findings) == 1
            assert findings[0]["state"] == "confirmed"
            events = client2.get(f"/api/engagements/{eng_id}/audit").json()["events"]
            assert any(e["event"] == "action_resumed" for e in events)

        # 收尾：唤醒 app1 遗留的等待线程（生产语义下它已随进程死亡）
        app1.state.manager.confirmation_event(cid).set()


# ---- 状态机与杂项 ----


def test_invalid_state_transitions(client):
    eng_id = _create(client)
    # 未 done 不可构建报告
    resp = client.post(f"/api/engagements/{eng_id}/report", json={})
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "invalid_state"
    # 重复启动
    client.post(f"/api/engagements/{eng_id}/run")
    resp = client.post(f"/api/engagements/{eng_id}/run")
    assert resp.status_code == 409
    # 收尾：批准后 done；done 后不可再 run
    conf = _wait_confirmation(client, eng_id)
    client.post(f"/api/confirmations/{conf['cid']}/approve", json={"operator": "t"})
    assert _wait_state(client, eng_id, {"done"}) == "done"
    resp = client.post(f"/api/engagements/{eng_id}/run")
    assert resp.status_code == 409


def test_not_found_and_audit_tail(client):
    assert client.get("/api/engagements/eng-nonexistent").status_code == 404
    eng_id = _create(client, autonomy_mode="unattended")
    client.post(f"/api/engagements/{eng_id}/run")
    assert _wait_state(client, eng_id, {"done"}) == "done"
    full = client.get(f"/api/engagements/{eng_id}/audit").json()
    assert full["total"] > 2
    tail = client.get(f"/api/engagements/{eng_id}/audit?tail=2").json()
    assert len(tail["events"]) == 2
    assert tail["total"] == full["total"]
    assert tail["events"] == full["events"][-2:]
    # 未生成报告时下载 404
    assert client.get(f"/api/engagements/{eng_id}/report").status_code == 404


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.json()["autonomy_gate"]["supervised"]["L1"] == "confirm"
