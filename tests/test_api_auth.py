"""API 认证测试（M14，§5.9.1）：HTTP Basic 单账户，deny-by-default。

无 docker / browser 标记。注意 `tests/conftest.py` 的 autouse fixture 会替**旧**测试
客户端注入默认凭据头（那是"替测试把凭据带上"，**不是**绕过校验）；本文件正是要测认证
本身，故一律显式 `api_auth=False`，需要凭据时自己带头。
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.api.__main__ import loopback_warning, main
from proofhound.api.auth import (
    DEFAULT_API_PASSWORD,
    DEFAULT_API_USER,
    PASSWORD_KEY,
    REALM,
    USER_KEY,
    ApiAuth,
    is_loopback,
    resolve_auth,
    startup_blocker,
)


def basic(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "skills").mkdir()
    return tmp_path


@pytest.fixture(autouse=True)
def _no_ambient_credentials(monkeypatch):
    """本文件测的是凭据解析与校验，故清掉 conftest 注入的环境变量，保持可判定。"""
    monkeypatch.delenv(USER_KEY, raising=False)
    monkeypatch.delenv(PASSWORD_KEY, raising=False)


def make_client(workspace: Path, headers=None, **kwargs) -> TestClient:
    return TestClient(
        create_app(workspace, **kwargs), headers=headers, api_auth=False
    )


# ---- deny-by-default ----


def test_health_requires_credentials(workspace):
    with make_client(workspace) as client:
        resp = client.get("/api/health")

    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == f'Basic realm="{REALM}"'
    assert resp.json()["detail"]["error"] == "unauthorized"


def test_console_and_static_also_require_credentials(workspace):
    """不只是 /api：控制台首页与静态资源同样在认证之内（否则前端可被匿名读取）。"""
    with make_client(workspace) as client:
        assert client.get("/").status_code == 401
        assert client.get("/static/app.js").status_code == 401
        assert client.get("/static/app.css").status_code == 401


def test_default_credentials_allow_console_and_api(workspace):
    with make_client(
        workspace, headers=basic(DEFAULT_API_USER, DEFAULT_API_PASSWORD)
    ) as client:
        health = client.get("/api/health")
        index = client.get("/")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert index.status_code == 200
    assert "text/html" in index.headers["content-type"]


@pytest.mark.parametrize(
    "headers",
    [
        basic(DEFAULT_API_USER, "wrong-password"),
        basic("nobody", DEFAULT_API_PASSWORD),
        basic(DEFAULT_API_USER, DEFAULT_API_PASSWORD + "x"),
        {"Authorization": "Bearer some-token"},
        {"Authorization": "Basic"},
        {"Authorization": "Basic !!!not-base64!!!"},
        {"Authorization": "basic " + base64.b64encode(b"no-colon").decode()},
    ],
)
def test_rejected_credentials(workspace, headers):
    with make_client(workspace, headers=headers) as client:
        assert client.get("/api/health").status_code == 401


def test_unauthenticated_body_does_not_echo_submitted_credentials(workspace):
    with make_client(workspace, headers=basic("attacker", "s3cr3t-attempt")) as client:
        body = client.get("/api/health").text

    assert "s3cr3t-attempt" not in body
    assert "attacker" not in body


# ---- 凭据解析优先级 ----


def test_default_auth_object_is_flagged(workspace):
    auth = resolve_auth(workspace)

    assert (auth.username, auth.password, auth.source) == (
        DEFAULT_API_USER,
        DEFAULT_API_PASSWORD,
        "default",
    )
    assert auth.is_default is True


def test_env_overrides_default(workspace, monkeypatch):
    monkeypatch.setenv(USER_KEY, "envuser")
    monkeypatch.setenv(PASSWORD_KEY, "envpass")

    auth = resolve_auth(workspace)

    assert (auth.username, auth.password, auth.source) == ("envuser", "envpass", "env")
    assert auth.is_default is False


def test_dotenv_file_is_read(workspace):
    (workspace / ".env").write_text(
        f"{USER_KEY}=dotenvuser\n{PASSWORD_KEY}='dotenvpass'\n", encoding="utf-8"
    )

    auth = resolve_auth(workspace)

    assert (auth.username, auth.password, auth.source) == (
        "dotenvuser",
        "dotenvpass",
        "dotenv",
    )


def test_env_wins_over_dotenv(workspace, monkeypatch):
    (workspace / ".env").write_text(
        f"{USER_KEY}=dotenvuser\n{PASSWORD_KEY}=dotenvpass\n", encoding="utf-8"
    )
    monkeypatch.setenv(PASSWORD_KEY, "envpass")  # 只覆盖口令，用户仍来自 .env

    auth = resolve_auth(workspace)

    assert (auth.username, auth.password, auth.source) == (
        "dotenvuser",
        "envpass",
        "mixed",
    )


def test_explicit_auth_object_replaces_resolution(workspace):
    auth = ApiAuth("alice", "pw-alice", "explicit")
    with make_client(workspace, auth=auth) as client:
        allowed = client.get("/api/health", headers=basic("alice", "pw-alice"))
        denied = client.get(
            "/api/health", headers=basic(DEFAULT_API_USER, DEFAULT_API_PASSWORD)
        )

    assert allowed.status_code == 200
    assert denied.status_code == 401


def test_dotenv_credentials_reach_the_app(workspace):
    (workspace / ".env").write_text(
        f"{USER_KEY}=dotenvuser\n{PASSWORD_KEY}=dotenvpass\n", encoding="utf-8"
    )
    with make_client(workspace) as client:
        denied = client.get(
            "/api/health", headers=basic(DEFAULT_API_USER, DEFAULT_API_PASSWORD)
        )
        allowed = client.get("/api/health", headers=basic("dotenvuser", "dotenvpass"))

    assert denied.status_code == 401
    assert allowed.status_code == 200


# ---- 启动护栏（默认口令 + 非回环 = 拒绝启动）----


def test_is_loopback_helper():
    assert is_loopback("127.0.0.1")
    assert is_loopback("::1")
    assert is_loopback("localhost")
    assert not is_loopback("0.0.0.0")
    assert not is_loopback("192.168.1.10")
    assert not is_loopback("example.internal")  # 主机名按非回环（fail-closed）


def test_startup_blocker_matrix():
    assert startup_blocker("127.0.0.1", ApiAuth()) is None
    assert startup_blocker("::1", ApiAuth()) is None
    assert startup_blocker("localhost", ApiAuth()) is None

    custom = ApiAuth("me", "own-password", "env")
    assert startup_blocker("0.0.0.0", custom) is None  # 换了口令即可对外
    assert startup_blocker("192.168.1.10", custom) is None

    reason = startup_blocker("0.0.0.0", ApiAuth())
    assert reason is not None
    assert "拒绝启动" in reason
    assert "0.0.0.0" in reason
    assert DEFAULT_API_PASSWORD not in reason  # 提示不复述口令原文
    assert USER_KEY in reason and PASSWORD_KEY in reason  # 给出出路


def test_main_refuses_to_start_with_default_credentials_on_non_loopback(
    workspace, capsys
):
    rc = main(["--workspace", str(workspace), "--host", "0.0.0.0", "--port", "0"])

    assert rc == 2
    err = capsys.readouterr().err
    assert "拒绝启动" in err
    assert DEFAULT_API_PASSWORD not in err


# ---- health 载荷与控制台顶栏（防止 UI 谎报「无认证」）----


def test_health_reports_auth_status(workspace):
    with make_client(
        workspace, headers=basic(DEFAULT_API_USER, DEFAULT_API_PASSWORD)
    ) as client:
        auth_block = client.get("/api/health").json()["auth"]

    assert auth_block == {"enabled": True, "user": DEFAULT_API_USER,
                          "default_credentials": True}


def test_health_marks_custom_credentials_as_non_default(workspace):
    (workspace / ".env").write_text(
        f"{USER_KEY}=dotenvuser\n{PASSWORD_KEY}=dotenvpass\n", encoding="utf-8"
    )
    with make_client(workspace, headers=basic("dotenvuser", "dotenvpass")) as client:
        auth_block = client.get("/api/health").json()["auth"]

    assert auth_block["user"] == "dotenvuser"
    assert auth_block["default_credentials"] is False


def test_console_page_no_longer_claims_no_auth(workspace):
    """M14 之前顶栏写的是「本机实例 · 无认证」——加了认证后那句话就是假的。"""
    with make_client(
        workspace, headers=basic(DEFAULT_API_USER, DEFAULT_API_PASSWORD)
    ) as client:
        html = client.get("/").text

    assert "无认证" not in html
    assert 'id="auth-note"' in html


def test_loopback_warning_kept_for_custom_credentials(workspace, monkeypatch):
    """非回环 + 自定义口令：告警仍然打（Basic 无 TLS），且文案不再谎称"无认证"。"""
    monkeypatch.setenv(USER_KEY, "envuser")
    monkeypatch.setenv(PASSWORD_KEY, "envpass")

    assert loopback_warning("127.0.0.1") is None
    warning = loopback_warning("0.0.0.0")

    assert warning is not None
    assert "0.0.0.0" in warning
    assert "Basic" in warning
    assert "无认证" not in warning
