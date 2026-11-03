"""M5b Web 控制台测试：静态资源 + 证据文件只读端点 + 模板清单 + 绑定告警。

不碰 Docker、不调真模型：fake 阶段执行器沿用 test_api.py 同款模式
（拷贝而非复用，旧测试文件一行不动）。
"""

from __future__ import annotations

import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.api.__main__ import loopback_warning
from proofhound.api.server import EVIDENCE_FILE_MAX_BYTES
from proofhound.findings.evidence import assemble_evidence_pack
from proofhound.findings.finding import (
    Finding,
    FindingState,
    FindingStore,
    Verification,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = REPO_ROOT / "proofhound" / "api" / "static"
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

    def scan(self, targets: list[str]) -> None:
        pass

    def triage(self) -> list:
        store = FindingStore(self.dir / "findings.jsonl")
        dedup_key = "sha256:fake-sqli"
        existing = store.get_by_dedup_key(dedup_key)
        if existing is not None:
            return [existing]
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
    # 混入非模板文件：清单端点必须只回 *.docx
    (templates_dir / "notes.txt").write_text("not a template", encoding="utf-8")
    (templates_dir / "x.docx:Zone.Identifier").write_text("zone", encoding="utf-8")
    return tmp_path


@pytest.fixture
def fake_factory():
    def _factory(runtime):
        return FakePhases(runtime)

    return _factory


@pytest.fixture
def client(workspace, fake_factory):
    app = create_app(workspace, phases_factory=fake_factory, confirm_timeout=30.0)
    with TestClient(app) as test_client:
        yield test_client


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


def _run_to_done_with_confirmed(client, **create_overrides) -> tuple[str, str]:
    """unattended 跑完全程，返回 (engagement_id, confirmed_finding_id)。"""
    eng_id = _create(client, autonomy_mode="unattended", **create_overrides)
    client.post(f"/api/engagements/{eng_id}/run")
    assert _wait_state(client, eng_id, {"done"}) == "done"
    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    confirmed = [f for f in findings if f["state"] == "confirmed"]
    assert confirmed, findings
    return eng_id, confirmed[0]["id"]


# ---- 静态资源 ----


def test_console_index_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "/static/app.js" in resp.text
    assert "/static/app.css" in resp.text


def test_static_assets_served(client):
    for name, ct_hint in (
        ("app.css", "text/css"),
        ("app.js", "javascript"),
        ("api.js", "javascript"),
    ):
        resp = client.get(f"/static/{name}")
        assert resp.status_code == 200, name
        assert ct_hint in resp.headers["content-type"], name


def test_static_assets_zero_external_refs():
    """零依赖纪律守卫：静态目录任何文件不得含 http(s) 外链（完全离线可用）。"""
    assert STATIC_DIR.is_dir()
    for path in STATIC_DIR.iterdir():
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert "http://" not in text, path.name
            assert "https://" not in text, path.name


def test_static_js_no_innerhtml():
    """XSS 纪律守卫：前端渲染只走 textContent，不出现 innerHTML。"""
    for path in STATIC_DIR.glob("*.js"):
        assert "innerHTML" not in path.read_text(encoding="utf-8"), path.name


def test_unknown_paths_not_shadowed_by_console(client):
    """控制台挂载不得吞掉未知路径：未知 API 仍 404 JSON，未知页面 404。"""
    resp = client.get("/api/definitely-not-a-route")
    assert resp.status_code == 404
    assert resp.json()["detail"]  # Starlette 默认 404 JSON
    assert client.get("/no-such-page").status_code == 404


# ---- 证据文件只读端点 ----


def test_evidence_file_content_matches_disk(client, workspace):
    eng_id, fid = _run_to_done_with_confirmed(client)
    evidence = client.get(f"/api/engagements/{eng_id}/findings/{fid}/evidence").json()
    item = next(i for i in evidence["items"] if i.get("file"))
    resp = client.get(
        f"/api/engagements/{eng_id}/findings/{fid}/evidence/{item['file']}"
    )
    assert resp.status_code == 200
    disk_text = (
        workspace / "engagements" / eng_id / "findings" / fid / item["file"]
    ).read_text(encoding="utf-8")
    assert resp.text == disk_text


def test_evidence_file_not_in_manifest_404(client):
    eng_id, fid = _run_to_done_with_confirmed(client)
    # manifest 存在但文件未列入白名单（如 finding.json / api.json）
    assert (
        client.get(f"/api/engagements/{eng_id}/findings/{fid}/evidence/finding.json")
        .status_code
        == 404
    )
    assert (
        client.get(f"/api/engagements/{eng_id}/findings/{fid}/evidence/manifest.json")
        .status_code
        == 404
    )


def test_evidence_file_traversal_rejected(client):
    eng_id, fid = _run_to_done_with_confirmed(client)
    base = f"/api/engagements/{eng_id}/findings/{fid}/evidence"
    assert client.get(f"{base}/..%2F..%2Fapi.json").status_code == 404
    assert client.get(f"{base}/..").status_code == 404


def test_evidence_file_unknown_finding_404(client):
    eng_id, _fid = _run_to_done_with_confirmed(client)
    resp = client.get(f"/api/engagements/{eng_id}/findings/F-0000-9999/evidence/x.log")
    assert resp.status_code == 404


def test_evidence_file_never_contains_cookie(client):
    eng_id, fid = _run_to_done_with_confirmed(
        client, cookie=f"PHPSESSID={COOKIE_VALUE}; security=low"
    )
    evidence = client.get(f"/api/engagements/{eng_id}/findings/{fid}/evidence").json()
    for item in evidence["items"]:
        if item.get("file"):
            resp = client.get(
                f"/api/engagements/{eng_id}/findings/{fid}/evidence/{item['file']}"
            )
            assert COOKIE_VALUE not in resp.text


# ---- 模板清单端点 ----


def test_templates_listing(client):
    resp = client.get("/api/templates")
    assert resp.status_code == 200
    names = resp.json()["templates"]
    assert "default_template.docx" in names
    assert all(n.endswith(".docx") for n in names)
    assert not any("Zone.Identifier" in n for n in names)


# ---- 健康端点新增键 ----


def test_health_includes_version_and_confirm_timeout(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    # 0.6.1 披露：版本号 0.6.0 -> 0.6.1（M31 全轮：dirsearch 扫描链路 + 控制台计时）。
    # 0.6.0 披露：版本号 0.5.0 -> 0.6.0（M27~M30 + 协议改 AGPL-3.0 发布）。
    # 0.5.0 披露：版本号 0.4.0 -> 0.5.0（M19/M20 发布）。
    # 0.4.0 披露：版本号 0.3.0 -> 0.4.0（M18 发布）。
    # 0.3.0 披露：版本号 0.2.0 -> 0.3.0。断言**意图不变**——仍锁死
    # /api/health 回报的版本号，只是把新版本号纳入锁定。
    assert data["version"] == "0.6.1"
    assert data["confirm_timeout"] == 30.0
    assert data["autonomy_gate"]["semi_auto"]["L2"] == "confirm"


# ---- 非回环绑定告警 ----


def test_loopback_warning_helper(capsys):
    assert loopback_warning("127.0.0.1") is None
    assert loopback_warning("localhost") is None
    assert loopback_warning("::1") is None
    warning = loopback_warning("0.0.0.0")
    assert warning is not None
    assert "0.0.0.0" in warning
    assert "公网" in warning
    # main() 路径的 stderr 打印由 demo 的 Step 1 实证；此处验 helper 纯函数
    capsys.readouterr()


def test_evidence_file_size_cap_constant():
    """截断上限常量存在且为 2 MiB（实际截断路径由 demo 大文件场景覆盖）。"""
    assert EVIDENCE_FILE_MAX_BYTES == 2 * 1024 * 1024


def test_evidence_file_bare_cr_anchor_consistent(client, workspace):
    """裸 \\r/混合行尾（sqlmap 进度符场景）：文件端点行尾归一化后，
    按 \\n 分行的锚点行与 evidence 端点 anchor_line_text 严格一致。"""
    eng_id = _create(client)
    eng_dir = workspace / "engagements" / eng_id
    src = eng_dir / "mixed.log"
    src.write_bytes(b"alpha\rbeta\r\ngamma\ndelta\n")
    store = FindingStore(eng_dir / "findings.jsonl")
    finding = Finding(
        id=store.next_id(),
        state=FindingState.HYPOTHESIS,
        vuln_type="sqli",
        severity="high",
        asset="http://127.0.0.1:8080/x?id=1",
        param="id",
        evidence_kinds=["status-code", "behavioral"],
        dedup_key="sha256:crlf-test",
        verification=Verification(
            method="sqlmap-confirmed",
            evidence_refs=[f"{src}#L3"],
            reproduction_steps=["step"],
            verified_by="verify-sqli@test",
            verified_at=_utc_now(),
        ),
        created_at=_utc_now(),
        updated_at=_utc_now(),
    )
    finding.transition(FindingState.REPRODUCED, actor="verify-sqli", reason="t")
    store.append(finding)
    assemble_evidence_pack(finding, evidence_base=eng_dir)

    evidence = client.get(
        f"/api/engagements/{eng_id}/findings/{finding.id}/evidence"
    ).json()
    item = next(i for i in evidence["items"] if i.get("file"))
    # read_text 归一化后行序列 alpha/beta/gamma/delta → L3 == gamma
    assert item["line_anchor"] == 3
    assert item["anchor_line_text"] == "gamma"
    resp = client.get(
        f"/api/engagements/{eng_id}/findings/{finding.id}/evidence/{item['file']}"
    )
    assert resp.status_code == 200
    assert "\r" not in resp.text
    assert resp.text.split("\n")[2] == "gamma"


# ---- M31-g：「已耗时」在终态后必须停住 ----


def test_detail_exposes_finished_at_once_terminal(client):
    """终态后详情必须给出 ``finished_at``（控制台据此停表）。

    旧实现详情里只有 ``created_at``，前端只能恒用 ``Date.now()`` 当终点 ⇒ 任务
    done 之后「已耗时」还在一直涨，一个早已跑完的任务看起来永远在跑。
    """
    eng_id, _ = _run_to_done_with_confirmed(client)

    first = client.get(f"/api/engagements/{eng_id}").json()
    assert first["state"] == "done"
    assert first["finished_at"], first
    # 终态时间是**事实**，不是"现在"：再轮询一次必须一模一样（否则前端还会涨）
    time.sleep(0.05)
    second = client.get(f"/api/engagements/{eng_id}").json()
    assert second["finished_at"] == first["finished_at"]
    assert second["finished_at"] >= second["created_at"]


def test_detail_finished_at_is_none_before_terminal(client):
    """未到终态必须是 None —— 前端据此继续走实时时钟，而不是一上来就停表。"""
    eng_id = _create(client)
    detail = client.get(f"/api/engagements/{eng_id}").json()
    assert detail["state"] == "created"
    assert detail["finished_at"] is None


def test_legacy_engagement_finished_at_backfilled_from_engagement_json(
    workspace, fake_factory
):
    """升级前跑完的任务也要停表：api.json 没有 finished_at 时回落读 engagement.json。

    M31-g 之前 ``finished_at`` 只写进 ``engagement.json``。若只认 api.json，用户手里
    那些早已 done 的任务在控制台上还会继续涨——等于"升级了但没修好"。
    """
    app = create_app(workspace, phases_factory=fake_factory, confirm_timeout=30.0)
    with TestClient(app) as first_client:
        eng_id, _ = _run_to_done_with_confirmed(first_client)

    eng_dir = workspace / "engagements" / eng_id
    api_json = eng_dir / "api.json"
    meta = json.loads(api_json.read_text(encoding="utf-8"))
    assert meta.pop("finished_at", None)  # 前提：本轮确实写过（旧数据没有这一键）
    api_json.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")

    from_report = json.loads(
        (eng_dir / "engagement.json").read_text(encoding="utf-8")
    )["finished_at"]

    # 重开一个 app = 服务重启后 manager._load_all 从 api.json 重建记录
    restarted = create_app(workspace, phases_factory=fake_factory, confirm_timeout=30.0)
    with TestClient(restarted) as second_client:
        detail = second_client.get(f"/api/engagements/{eng_id}").json()

    assert detail["state"] == "done"
    assert detail["finished_at"] == from_report


def test_static_js_elapsed_clock_stops_on_terminal():
    """前端调用形态守卫：``fmtElapsed`` 必须收到 ``detail.finished_at`` 当终点。

    只钉住调用形态（与 ``test_static_js_no_innerhtml`` 同一纪律）。反面形态是
    ``fmtElapsed(detail.created_at)`` —— 那一版恒用 ``Date.now()``。
    """
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert js.count("fmtElapsed(detail.created_at, detail.finished_at)") == 2
    assert "function fmtElapsed(iso, endIso)" in js
    # 终点取 endIso 有值时的那个时刻，而不是无条件 now()
    assert "endIso ? new Date(endIso).getTime() : Date.now()" in js


# ---- 审计流：默认只轮询最近 N 条，但必须能看全量 ----


def test_audit_endpoint_tail_is_window_not_cap(client):
    """`tail` 只裁剪**返回窗口**，`total` 始终是全量计数。

    后端从来没有条数上限：不带 ``tail`` 就返回全部。控制台默认只轮询最近
    ``AUDIT_TAIL`` 条（省流量），「查看全部」则用不带 tail 的请求取全量——
    这条契约就是那个入口能成立的前提。
    """
    eng_id, _ = _run_to_done_with_confirmed(client)

    full = client.get(f"/api/engagements/{eng_id}/audit").json()
    assert full["total"] > 0
    assert len(full["events"]) == full["total"]  # 不带 tail = 全量

    tailed = client.get(
        f"/api/engagements/{eng_id}/audit", params={"tail": 5}
    ).json()
    assert tailed["total"] == full["total"]  # 总数不因窗口而缩水
    assert len(tailed["events"]) == 5
    assert tailed["events"] == full["events"][-5:]  # 是"最后 5 条"


def test_audit_endpoint_rejects_non_positive_tail(client):
    eng_id, _ = _run_to_done_with_confirmed(client)
    assert client.get(
        f"/api/engagements/{eng_id}/audit", params={"tail": 0}
    ).status_code == 422


def test_static_js_audit_panel_has_full_history_entry():
    """前端必须同时具备两种审计请求：轮询用 tail，按需用全量。

    只钉调用形态（同 ``test_static_js_no_innerhtml`` 的纪律）。若只剩
    ``audit?tail=...``，用户就被永久锁在"最近 N 条"里。
    """
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert "audit?tail=${AUDIT_TAIL}" in js   # 轮询：只拉最近 N 条
    assert "/audit`)" in js                   # 按需：不带 tail 的全量
    assert "auditShowAll" in js               # 两种模式的开关
