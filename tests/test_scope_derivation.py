"""M9a：从目标派生 scope 的集成测试（API 全链路，无 Docker / 无 LLM）。

单元测试（``tests/test_derive.py``）只证明"派生函数算得对"。本文件证明
**接入之后整条链路仍然安全**——这是 M9a 真正的风险所在：降摩擦最怕顺手
放宽了防线。因此每个"便利性"断言都配一个"边界未被放宽"的断言。

关键回归点（M9a 实现过程中真实踩到的坑）：
``_persist()`` 原先硬编码 key 白名单，会把 ``derived_scope`` 抹掉——那样每次
状态迁移写回后 ``start()`` 就重校验到一个空 scope，授权范围静默消失。
``test_derived_scope_survives_manager_restart`` 锁死这一点。
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app

REPO_ROOT = Path(__file__).resolve().parent.parent


class NoopPhases:
    """最小假阶段执行器：本文件不跑扫描，只验证创建/启动的 scope 语义。"""

    scan_skill = "web-scan"
    scan_risk_level = "L1"
    verify_skill = "verify-sqli"
    verify_risk_level = "L2"

    def __init__(self, runtime):
        self.dir = runtime.engagement.dir
        self.target = runtime.engagement.target
        self.audit = runtime.audit

    def scan(self, targets):
        pass

    def triage(self):
        return []

    def verify_covered_vuln_types(self):
        return set()

    def verify(self, finding):  # pragma: no cover - 本文件不触发
        return finding


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "templates").mkdir()
    shutil.copyfile(
        REPO_ROOT / "templates" / "default_template.docx",
        tmp_path / "templates" / "default_template.docx",
    )
    return tmp_path


def _factory(runtime):
    return NoopPhases(runtime)


@pytest.fixture
def app(workspace):
    return create_app(workspace, phases_factory=_factory, confirm_timeout=5.0)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


def _audit_events(workspace: Path, eng_id: str) -> list[dict]:
    path = workspace / "engagements" / eng_id / "audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _api_meta(workspace: Path, eng_id: str) -> dict:
    return json.loads(
        (workspace / "engagements" / eng_id / "api.json").read_text(encoding="utf-8")
    )


# ------------------------------------------------- 1. 零摩擦路径真的可用


def test_target_only_creates_without_scope_file(client, workspace):
    """只给目标 + 授权确认即可创建——M9a 的存在意义。"""
    resp = client.post(
        "/api/engagements",
        json={
            "target": "http://127.0.0.1:8080",
            "acknowledge_authorization": True,
        },
    )
    assert resp.status_code == 201, resp.text
    eng_id = resp.json()["id"]

    meta = _api_meta(workspace, eng_id)
    assert meta["scope_paths"] == []
    assert meta["derived_scope"]["scope_derived"] is True
    assert meta["derived_scope"]["networks"] == ["127.0.0.1/32"]
    assert meta["derived_scope"]["ports"] == [8080]


def test_derivation_is_audited_with_full_scope(client, workspace):
    resp = client.post(
        "/api/engagements",
        json={"target": "https://target.example.com", "acknowledge_authorization": True},
    )
    eng_id = resp.json()["id"]
    events = {e["event"]: e for e in _audit_events(workspace, eng_id)}

    assert "scope_derived" in events
    derived = events["scope_derived"]
    assert derived["derived_from_target"] == "https://target.example.com"
    assert derived["domains"] == ["target.example.com"]

    # 派生与授权是两件事，必须分别留痕
    assert "authorization_acknowledged" in events
    ack = events["authorization_acknowledged"]
    assert ack["derived"] is True
    assert ack["target"] == "https://target.example.com"


def test_engagement_can_be_started_and_target_rechecks_against_derived_scope(client, workspace):
    resp = client.post(
        "/api/engagements",
        json={"target": "http://127.0.0.1:8080", "acknowledge_authorization": True},
    )
    eng_id = resp.json()["id"]
    run = client.post(f"/api/engagements/{eng_id}/run")
    assert run.status_code in (200, 202), run.text

    events = _audit_events(workspace, eng_id)
    recheck = [e for e in events if e["event"] == "scope_recheck"]
    assert recheck, "启动时必须重新过 check_scope"
    assert recheck[0]["allowed"] is True


# ------------------------------------------- 2. 授权确认不可绕过（合规红线）


def test_derived_scope_requires_explicit_acknowledgement(client, workspace):
    resp = client.post("/api/engagements", json={"target": "http://127.0.0.1:8080"})
    assert resp.status_code == 403
    assert "授权" in resp.text
    # 零副作用：不得建目录
    assert not (workspace / "engagements").exists() or not list(
        (workspace / "engagements").iterdir()
    )


def test_explicit_scope_file_does_not_require_acknowledgement(client, workspace):
    """向后兼容：显式给了 scope 文件的老调用方不受影响。"""
    (workspace / "scopes").mkdir(exist_ok=True)
    (workspace / "scopes" / "s.yaml").write_text("networks: [127.0.0.0/8]\n", encoding="utf-8")
    resp = client.post(
        "/api/engagements",
        json={"target": "http://127.0.0.1:8080", "scope_paths": ["scopes/s.yaml"]},
    )
    assert resp.status_code == 201, resp.text
    assert _api_meta(workspace, resp.json()["id"]).get("derived_scope") is None


# --------------------------------------- 3. 派生之后防线依然有效（最重要）


def test_scope_created_for_one_target_rejects_a_different_target(app, workspace):
    """给目标 A 建 engagement 后，用 A 的 scope 去校验 B 必须被拒。

    这是"派生只收窄、不放宽"最直接的行为证明：派生范围与目标严格对应。
    """
    from proofhound.api.runner import ScopeViolationError

    eng_id = None
    with TestClient(app) as c:
        eng_id = c.post(
            "/api/engagements",
            json={"target": "https://target.example.com", "acknowledge_authorization": True},
        ).json()["id"]

    manager = app.state.manager
    eng = manager.get(eng_id)
    scope = manager.load_scope(
        eng.scope_paths, derived_scope=eng.derived_scope, target=eng.target
    )
    # 自己的目标放行
    manager.check_target(scope, "https://target.example.com/")
    # 别人的目标一律拒绝
    for outside in ("https://evil.example.com/", "http://127.0.0.1:8080/"):
        with pytest.raises(ScopeViolationError):
            manager.check_target(scope, outside)


def test_derived_scope_does_not_authorize_a_sibling_host(client, workspace, app):
    """跨目标验证：A 派生出的 scope 不得放行 B。"""
    from proofhound.compliance.scope import Scope, check_scope

    resp = client.post(
        "/api/engagements",
        json={"target": "https://target.example.com", "acknowledge_authorization": True},
    )
    eng_id = resp.json()["id"]
    manager = app.state.manager
    eng = manager.get(eng_id)

    scope = manager.load_scope(
        eng.scope_paths, derived_scope=eng.derived_scope, target=eng.target
    )
    assert isinstance(scope, Scope)
    assert check_scope(scope, ["https://target.example.com/x"]).allowed
    for outside in [
        "https://evil.example.com/",
        "https://target.example.com.evil.example.com/",
        "http://127.0.0.1:8080/",
    ]:
        assert not check_scope(scope, [outside]).allowed, f"{outside} 不该被放行"


@pytest.mark.parametrize(
    "target",
    ["https://*", "https://com", "https://*.example.com", "not a url at all"],
)
def test_unparsable_or_overbroad_target_is_refused(client, workspace, target):
    resp = client.post(
        "/api/engagements", json={"target": target, "acknowledge_authorization": True}
    )
    assert resp.status_code == 403, f"{target} 应被拒绝，实际 {resp.status_code}"
    eng_dir = workspace / "engagements"
    assert not eng_dir.exists() or not list(eng_dir.iterdir())


# ------------------------------------------- 4. 持久化（真实踩到的回归点）


def test_derived_scope_survives_manager_restart(workspace):
    """``_persist()`` 曾把 derived_scope 抹掉——本测试锁死该回归。"""
    app1 = create_app(workspace, phases_factory=_factory, confirm_timeout=5.0)
    with TestClient(app1) as c1:
        eng_id = c1.post(
            "/api/engagements",
            json={"target": "http://127.0.0.1:8080", "acknowledge_authorization": True},
        ).json()["id"]

    # 重新建 manager（模拟进程重启，从 engagements/ 目录回放）
    app2 = create_app(workspace, phases_factory=_factory, confirm_timeout=5.0)
    with TestClient(app2) as c2:
        eng = app2.state.manager.get(eng_id)
        assert eng.derived_scope is not None, "派生范围重启后必须仍在"
        assert eng.derived_scope["networks"] == ["127.0.0.1/32"]
        # 重启后仍能启动（scope 重校验用的是恢复出来的派生范围）
        assert c2.post(f"/api/engagements/{eng_id}/run").status_code in (200, 202)


def test_derived_scope_survives_state_transition_persist(client, workspace):
    """任意一次状态迁移都会 _persist()；派生范围必须活过每一次写回。"""
    eng_id = client.post(
        "/api/engagements",
        json={"target": "http://127.0.0.1:8080", "acknowledge_authorization": True},
    ).json()["id"]
    # 切换自治模式会触发 _persist()
    client.post(f"/api/engagements/{eng_id}/mode", json={"autonomy_mode": "supervised"})
    meta = _api_meta(workspace, eng_id)
    assert meta.get("derived_scope"), "状态迁移后 derived_scope 不得丢失"


# ------------------------------------------- 5. 派生 + 显式 scope 并集语义


def test_explicit_scope_file_takes_precedence_over_derivation(client, workspace, app):
    """给了 scope_paths 就不派生（derived_scope 为 None），显式文件是唯一起作用的授权。

    这是刻意的：操作员显式写下的范围是权威来源，系统不去猜。派生只是
    "没写 scope 文件时"的便利路径。
    """
    (workspace / "scopes").mkdir(exist_ok=True)
    (workspace / "scopes" / "extra.yaml").write_text(
        "domains: [target.example.com, cdn.example.net]\n", encoding="utf-8"
    )
    resp = client.post(
        "/api/engagements",
        json={
            "target": "https://target.example.com",
            "scope_paths": ["scopes/extra.yaml"],
            "acknowledge_authorization": True,
        },
    )
    assert resp.status_code == 201, resp.text
    eng_id = resp.json()["id"]

    manager = app.state.manager
    eng = manager.get(eng_id)
    assert eng.derived_scope is None
    scope = manager.load_scope(eng.scope_paths, derived_scope=eng.derived_scope, target=eng.target)
    assert set(scope.domains) == {"target.example.com", "cdn.example.net"}


def test_derived_and_file_scope_union_when_both_present(workspace, app):
    """并集语义：显式文件叠加在派生范围之上（load_scope 的真实契约）。

    直接对 load_scope 断言，避免经 API 时被"有 scope_paths 就不派生"的
    创建期规则遮住——那条规则与 load_scope 的并集语义是两件事。
    """
    (workspace / "scopes").mkdir(exist_ok=True)
    (workspace / "scopes" / "extra.yaml").write_text(
        "domains: [cdn.example.net]\nports: [8443]\n", encoding="utf-8"
    )
    manager = app.state.manager
    scope = manager.load_scope(
        ["scopes/extra.yaml"],
        derived_scope={
            "domains": ["target.example.com"],
            "networks": [],
            "ports": [],
        },
    )
    assert set(scope.domains) == {"target.example.com", "cdn.example.net"}
    assert scope.ports == [8443]


def test_no_scope_and_no_derivable_target_is_refused(workspace, app):
    """空 scope + 不可派生目标 → 必须拒绝，绝不能"没范围就放行"。"""
    from proofhound.api.runner import ScopeViolationError

    manager = app.state.manager
    with pytest.raises(ScopeViolationError):
        manager.load_scope([])
