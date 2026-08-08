"""Scope 文件管理面测试（M6a，§5.9.2）：scopes/ 约定目录内的 CRUD。

覆盖验收点：
- CRUD 往返 + scopes/ 不存在自动创建；
- 校验矩阵（坏 YAML/非法 CIDR/非法端口/session 键/未知键）→ 422 零写入；
- 文件名白名单 + 目录外拒绝（resolve 后必须在 scopes/ 内）；
- scope_created/scope_updated（新旧 sha256）/scope_deleted 进 management.jsonl；
- 管理面产物即刻可被创建任务使用（scope_paths 契约不变）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app

VALID_SCOPE = "networks: [127.0.0.0/8]\nports: [8080]\n"


@pytest.fixture
def workspace(tmp_path):
    # 目录外（workspace 根）的遗留 scope：不经 API 管理
    (tmp_path / "scope.yaml").write_text("networks: [10.0.0.0/8]\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def client(workspace):
    with TestClient(create_app(workspace)) as test_client:
        yield test_client


def _events(workspace: Path) -> list[dict]:
    path = workspace / "management.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


# ---- CRUD 往返 ----


def test_create_get_list_roundtrip(client, workspace):
    assert (workspace / "scopes").is_dir()  # 约定目录自动创建
    resp = client.post(
        "/api/scopes", json={"name": "demo.yaml", "content": VALID_SCOPE}
    )
    assert resp.status_code == 201, resp.text
    sha = resp.json()["sha256"]

    got = client.get("/api/scopes/demo.yaml")
    assert got.status_code == 200
    assert got.json()["content"] == VALID_SCOPE
    assert got.json()["sha256"] == sha

    listing = client.get("/api/scopes").json()["scopes"]
    entry = {s["name"]: s for s in listing}["demo.yaml"]
    assert entry["valid"] is True
    assert entry["networks"] == ["127.0.0.0/8"]
    assert entry["ports"] == [8080]
    assert entry["sha256"] == sha

    events = _events(workspace)
    assert [e["event"] for e in events] == ["scope_created"]
    assert events[0]["sha256"] == sha


def test_create_duplicate_409(client):
    body = {"name": "demo.yaml", "content": VALID_SCOPE}
    assert client.post("/api/scopes", json=body).status_code == 201
    assert client.post("/api/scopes", json=body).status_code == 409


def test_update_scope(client, workspace):
    client.post("/api/scopes", json={"name": "demo.yaml", "content": VALID_SCOPE})
    new_content = "networks: [127.0.0.0/8, 10.0.0.0/8]\nports: [8080, 8443]\n"
    resp = client.put("/api/scopes/demo.yaml", json={"content": new_content})
    assert resp.status_code == 200, resp.text
    assert client.get("/api/scopes/demo.yaml").json()["content"] == new_content

    events = _events(workspace)
    assert [e["event"] for e in events] == ["scope_created", "scope_updated"]
    assert events[1]["old_sha256"] == events[0]["sha256"]
    assert events[1]["new_sha256"] == resp.json()["sha256"]


def test_update_invalid_keeps_original(client, workspace):
    client.post("/api/scopes", json={"name": "demo.yaml", "content": VALID_SCOPE})
    resp = client.put(
        "/api/scopes/demo.yaml", json={"content": "ports: [0]"}
    )
    assert resp.status_code == 422
    path = workspace / "scopes" / "demo.yaml"
    assert path.read_text(encoding="utf-8") == VALID_SCOPE  # 零写入
    assert not (workspace / "scopes" / "demo.yaml.tmp").exists()


def test_update_missing_404(client):
    assert (
        client.put("/api/scopes/no.yaml", json={"content": VALID_SCOPE}).status_code
        == 404
    )


def test_delete_scope(client, workspace):
    client.post("/api/scopes", json={"name": "demo.yaml", "content": VALID_SCOPE})
    resp = client.delete("/api/scopes/demo.yaml")
    assert resp.status_code == 200
    assert client.get("/api/scopes/demo.yaml").status_code == 404
    assert client.delete("/api/scopes/demo.yaml").status_code == 404
    events = _events(workspace)
    assert [e["event"] for e in events] == ["scope_created", "scope_deleted"]
    assert len(events[1]["sha256"]) == 64


# ---- 校验矩阵 ----


@pytest.mark.parametrize(
    "label,content",
    [
        ("坏YAML", "ports: [8080\n"),
        ("非法CIDR", "networks: [999.1.1.1/8]\n"),
        ("CIDR非字符串", "networks: [12345]\n"),
        ("端口0", "ports: [0]\n"),
        ("端口超上限", "ports: [70000]\n"),
        ("端口非整数", "ports: [abc]\n"),
        ("端口布尔", "ports: [true]\n"),
        ("session键", "session: {cookies: {PHPSESSID: abc123}}\n"),
        ("未知键", "network: [10.0.0.0/8]\n"),  # typo：授权书不静默吞
        ("非映射", "- 只是一个列表\n"),
    ],
)
def test_scope_validation_matrix(client, workspace, label, content):
    resp = client.post("/api/scopes", json={"name": "bad.yaml", "content": content})
    assert resp.status_code == 422, (label, resp.text)
    assert resp.json()["detail"]["error"] == "validation_failed"
    assert not (workspace / "scopes" / "bad.yaml").exists(), label  # 零写入
    assert _events(workspace) == [], label  # 拒绝不进审计


def test_list_marks_broken_file_on_disk(client, workspace):
    client.post("/api/scopes", json={"name": "ok.yaml", "content": VALID_SCOPE})
    # 盘上手工写坏文件：列表不拖垮，标 valid=false
    (workspace / "scopes" / "broken.yaml").write_text("ports: [0]\n", encoding="utf-8")
    scopes = {s["name"]: s for s in client.get("/api/scopes").json()["scopes"]}
    assert scopes["ok.yaml"]["valid"] is True
    assert scopes["broken.yaml"]["valid"] is False
    assert "error" in scopes["broken.yaml"]


# ---- 文件名白名单与目录外拒绝 ----


@pytest.mark.parametrize("name", ["evil", "evil.txt", "../evil.yaml", "a/b.yaml"])
def test_scope_name_whitelist(client, name):
    resp = client.post("/api/scopes", json={"name": name, "content": VALID_SCOPE})
    assert resp.status_code == 422


def test_scope_outside_dir_not_managed(client):
    # workspace 根的 scope.yaml 真实存在，但目录外文件不经 API 读写
    assert client.get("/api/scopes/scope.yaml").status_code == 404
    assert (
        client.put("/api/scopes/scope.yaml", json={"content": VALID_SCOPE}).status_code
        == 404
    )
    assert client.delete("/api/scopes/scope.yaml").status_code == 404


def test_scope_traversal_rejected(client):
    resp = client.get("/api/scopes/..%2F..%2Fscope.yaml")
    assert resp.status_code in (404, 422)


# ---- 管理面产物即刻可用（契约不变） ----


def test_engagement_create_with_managed_scope(client):
    client.post("/api/scopes", json={"name": "demo.yaml", "content": VALID_SCOPE})
    resp = client.post(
        "/api/engagements",
        json={"target": "http://127.0.0.1:8080", "scope_paths": ["scopes/demo.yaml"]},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["scope_paths"] == ["scopes/demo.yaml"]
