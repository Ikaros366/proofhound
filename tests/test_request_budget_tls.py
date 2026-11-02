"""M28：请求量授权贯通全链路 + 进程内探针的 TLS 策略。

两条都源自"功能齐备但生产路径永不触发"这一类缺陷：

1. ``load_scope`` 合并且只带 domains/networks/ports，scope 文件里写的
   ``request_budget`` 被静默丢掉 ⇒ ``web-dirsearch`` 的 opt-in 判据
   （``scope.request_budget is not None``）在生产链路上永远为假。
2. 进程内探针（``verify/raw_http.py``）缺省校验证书、且原先没有放宽通道，
   自签靶一律 blocked；而沙箱内 CLI 工具对同一靶照常返回 200（实测）。

不碰 Docker、不调真模型。
"""

from __future__ import annotations

import shutil
import ssl
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings.dedup import compute_dedup_key
from proofhound.findings.finding import Finding, FindingState, FindingStore
from proofhound.skills.registry import SkillRegistry
from proofhound.verify.raw_http import RawResponse, _tls_context

REPO = Path(__file__).resolve().parent.parent
ASSET = "http://127.0.0.1:8080"


# =====================================================================
# 一、request_budget：合并时不能被丢掉
# =====================================================================


@pytest.fixture
def manager(tmp_path):
    """只有 scope 加载能力的最小 manager（不建 engagement）。"""
    from proofhound.api.runner import EngagementManager

    return EngagementManager(tmp_path)


def _write_scope(tmp_path, name: str, body: str) -> str:
    (tmp_path / name).write_text(body, encoding="utf-8")
    return name


def test_scope_file_request_budget_survives_merge(manager, tmp_path):
    """回归：scope 文件声明了请求量授权，合并后必须还在（否则 dirsearch 永不触发）。"""
    name = _write_scope(
        tmp_path,
        "with_budget.yaml",
        "networks: [127.0.0.0/8]\n"
        "request_budget:\n"
        "  rate_rps: 20\n"
        "  concurrency: 3\n"
        "  max_requests: 800\n",
    )

    scope = manager.load_scope([name])

    assert scope.request_budget is not None
    assert scope.request_budget.rate_rps == 20
    assert scope.request_budget.concurrency == 3
    assert scope.request_budget.max_requests == 800
    assert scope.request_budget_source() == "explicit"


def test_budget_composition_takes_strictest(manager, tmp_path):
    """多来源取最严：多写一份授权不等于多要配额。"""
    name = _write_scope(
        tmp_path,
        "budget.yaml",
        "networks: [127.0.0.0/8]\n"
        "request_budget:\n"
        "  rate_rps: 100\n"
        "  concurrency: 5\n"
        "  max_requests: 1000\n",
    )

    scope = manager.load_scope(
        [name],
        request_budget={
            "rate_rps": 50,
            "concurrency": 10,
            "max_requests": 5000,
            "window_minutes": 10,
        },
    )

    budget = scope.request_budget
    assert (budget.rate_rps, budget.concurrency, budget.max_requests) == (50, 5, 1000)
    assert budget.window_minutes == 10  # 只在一侧声明时照用


def test_no_budget_stays_none(manager, tmp_path):
    """都没声明 → 保持 None（= 不爆破），不能被缺省值悄悄补上。"""
    name = _write_scope(tmp_path, "plain.yaml", "networks: [127.0.0.0/8]\n")
    assert manager.load_scope([name]).request_budget is None


# =====================================================================
# 二、API → 运行期 scope
# =====================================================================


class CapturingPhases:
    """旧式单 skill 假阶段执行器：只记录 runtime.scope，不产生任何候选。"""

    scan_skill = "web-scan"
    scan_risk_level = "L1"
    verify_skill = "verify-sqli"
    verify_risk_level = "L2"

    captured: list = []

    def __init__(self, runtime):
        self.rt = runtime
        CapturingPhases.captured.append(runtime)

    def scan(self, targets):
        return None

    def triage(self):
        return []

    def verify_covered_vuln_types(self):
        return frozenset()

    def verify(self):
        return []


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "scope.yaml").write_text(
        "networks: [127.0.0.0/8]\n", encoding="utf-8"
    )
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    shutil.copyfile(
        REPO / "templates" / "default_template.docx",
        templates_dir / "default_template.docx",
    )
    return tmp_path


@pytest.fixture
def app_and_client_factory(workspace):
    def _make():
        factory = lambda runtime: CapturingPhases(runtime)  # noqa: E731
        app = create_app(workspace, phases_factory=factory, confirm_timeout=30.0)
        return app

    return _make


def _create_and_run(client, **overrides) -> str:
    body = {"target": ASSET, "scope_paths": ["scope.yaml"]}
    body.update(overrides)
    resp = client.post("/api/engagements", json=body)
    assert resp.status_code == 201, resp.text
    eng_id = resp.json()["id"]
    assert client.post(f"/api/engagements/{eng_id}/run").status_code == 202
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state in {"done", "failed"}:
            return eng_id
        time.sleep(0.05)
    raise AssertionError("等待终态超时")


def test_created_request_budget_reaches_run_scope(app_and_client_factory):
    CapturingPhases.captured.clear()
    with TestClient(app_and_client_factory()) as client:
        _create_and_run(
            client,
            request_budget={
                "rate_rps": 30,
                "concurrency": 4,
                "max_requests": 600,
                "window_minutes": 5,
            },
        )

    scope = CapturingPhases.captured[-1].scope
    assert scope.request_budget is not None
    assert (scope.request_budget.rate_rps, scope.request_budget.concurrency) == (30, 4)
    assert scope.request_budget.max_requests == 600


def test_without_budget_run_scope_has_none(app_and_client_factory):
    CapturingPhases.captured.clear()
    with TestClient(app_and_client_factory()) as client:
        _create_and_run(client)
    assert CapturingPhases.captured[-1].scope.request_budget is None


# =====================================================================
# 三、TLS：缺省严格，显式才放宽
# =====================================================================


def test_tls_defaults_to_strict(app_and_client_factory):
    CapturingPhases.captured.clear()
    with TestClient(app_and_client_factory()) as client:
        eng_id = _create_and_run(client)
        events = client.get(f"/api/engagements/{eng_id}/audit").json()["events"]

    assert CapturingPhases.captured[-1].scope.tls_verify == "strict"
    assert not [e for e in events if e["event"] == "tls_verify_disabled"]


def test_tls_insecure_is_explicit_and_audited(app_and_client_factory):
    CapturingPhases.captured.clear()
    with TestClient(app_and_client_factory()) as client:
        eng_id = _create_and_run(client, tls_verify="insecure")
        detail = client.get(f"/api/engagements/{eng_id}").json()
        events = client.get(f"/api/engagements/{eng_id}/audit").json()["events"]

    assert detail["state"] == "done"
    assert CapturingPhases.captured[-1].scope.tls_verify == "insecure"
    disabled = [e for e in events if e["event"] == "tls_verify_disabled"]
    assert len(disabled) == 1
    assert "自签" in disabled[0]["reason"]


def test_explicit_strict_in_scope_file_beats_api_insecure(workspace):
    """scope 文件显式写 strict 时，API 的 insecure 不得把它放宽。"""
    (workspace / "strict.yaml").write_text(
        "networks: [127.0.0.0/8]\ntls_verify: strict\n", encoding="utf-8"
    )
    CapturingPhases.captured.clear()
    factory = lambda runtime: CapturingPhases(runtime)  # noqa: E731
    app = create_app(workspace, phases_factory=factory, confirm_timeout=30.0)
    with TestClient(app) as client:
        body = {
            "target": ASSET,
            "scope_paths": ["strict.yaml"],
            "tls_verify": "insecure",
        }
        resp = client.post("/api/engagements", json=body)
        assert resp.status_code == 201, resp.text
        eng_id = resp.json()["id"]
        client.post(f"/api/engagements/{eng_id}/run")
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if client.get(f"/api/engagements/{eng_id}").json()["state"] == "done":
                break
            time.sleep(0.05)

    assert CapturingPhases.captured[-1].scope.tls_verify == "strict"


def test_invalid_values_rejected(workspace):
    factory = lambda runtime: CapturingPhases(runtime)  # noqa: E731
    app = create_app(workspace, phases_factory=factory, confirm_timeout=30.0)
    with TestClient(app) as client:
        bad_budget = client.post(
            "/api/engagements",
            json={
                "target": ASSET,
                "scope_paths": ["scope.yaml"],
                "request_budget": {"rate_rps": 0},
            },
        )
        assert bad_budget.status_code == 422
        bad_tls = client.post(
            "/api/engagements",
            json={"target": ASSET, "scope_paths": ["scope.yaml"], "tls_verify": "off"},
        )
        assert bad_tls.status_code == 422
        unknown = client.post(
            "/api/engagements",
            json={
                "target": ASSET,
                "scope_paths": ["scope.yaml"],
                "request_budget": {"rate_rps": 10, "bogus": 1},
            },
        )
        assert unknown.status_code == 422


# =====================================================================
# 四、探针真的按策略传参
# =====================================================================


class _Runner:
    egress_proxy_url = None

    def __init__(self, scope: Scope) -> None:
        self.scope = scope


class RecordingSender:
    """记录调用 kwargs 的 sender（探针只关心"传没传 verify_tls"）。"""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, host, port, payload, *, tls, timeout, **kwargs):
        self.calls.append(kwargs)
        return RawResponse(status=400, body=b"<html><body>generic</body></html>")


def _error_disclosure_env(tmp_path, scope: Scope, sender):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    audit = AuditLog(evidence_dir / "audit.jsonl")
    registry = SkillRegistry(REPO / "skills").discover()
    orch = Orchestrator(
        registry,
        _Runner(scope),
        SimpleNamespace(),  # 本用例走不到 Verifier
        audit,
        evidence_dir=evidence_dir,
        raw_http_send=sender,
    )
    store = FindingStore(evidence_dir / "findings.jsonl")
    return orch, store, registry


def _seed_error_disclosure_finding(store: FindingStore) -> Finding:
    finding = Finding(
        id=store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type="error-disclosure",
        severity="low",
        asset=ASSET,
        param=None,
        confidence="low",
        evidence_kinds=["status-code"],
        dedup_key=compute_dedup_key(ASSET, "error-disclosure", None),
        source_signal_refs=[],
        created_at="2026-11-02T00:00:00.000+00:00",
        updated_at="2026-11-02T00:00:00.000+00:00",
    )
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="测试种子")
    store.append(finding)
    return finding


def test_probe_keeps_strict_tls_by_default(tmp_path):
    sender = RecordingSender()
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080])
    orch, store, registry = _error_disclosure_env(tmp_path, scope, sender)
    finding = _seed_error_disclosure_finding(store)

    orch._verify_error_disclosure(finding, registry.get("verify-error-disclosure"), store)

    assert sender.calls
    # 缺省不给 sender 传 verify_tls（既有注入式 sender 的签名保持兼容）
    assert all("verify_tls" not in call for call in sender.calls)


def test_probe_passes_verify_tls_false_when_scope_says_insecure(tmp_path):
    sender = RecordingSender()
    scope = Scope(
        networks=["127.0.0.0/8"], ports=[8080], tls_verify="insecure"
    )
    orch, store, registry = _error_disclosure_env(tmp_path, scope, sender)
    finding = _seed_error_disclosure_finding(store)

    orch._verify_error_disclosure(finding, registry.get("verify-error-disclosure"), store)

    assert sender.calls
    assert all(call.get("verify_tls") is False for call in sender.calls)


def test_tls_context_modes():
    assert _tls_context(True).verify_mode is ssl.CERT_REQUIRED
    lax = _tls_context(False)
    assert lax.verify_mode is ssl.CERT_NONE
    assert lax.check_hostname is False
