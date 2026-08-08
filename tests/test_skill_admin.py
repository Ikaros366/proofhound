"""Skill 管理面测试（M6a，§5.9.2）：上传/编辑/删除 + copy-on-edit + 热重载。

覆盖验收点：
- zip 上传校验矩阵（缺字段/非法 risk_level/未知工具/路径穿越/双顶层目录/
  无 SKILL.md/超 1 MiB/目录名≠manifest name）→ 422 且 skills/ 零残留；
- 上传/编辑/删除全量进 management.jsonl（skill_updated 含新旧 sha256）；
- copy-on-edit（符号链接 workspace）：PUT 内置 skill 不触碰仓库文件，
  workspace 落实体副本；DELETE 内置 409；
- registry 热重载：上传后同进程重新 discover 立即可见，无需重启。
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.skills.registry import SkillRegistry

SKILL_MD = """\
---
name: {name}
description: 测试 skill
version: 1.0.0
required_tools: [{tools}]
risk_level: L1
inputs: [targets]
outputs: [signals]
---

SOP 正文。
"""


def _zip(files: dict[str, str], stored: bool = False) -> bytes:
    buf = io.BytesIO()
    compression = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _valid_zip(name: str = "demo-probe", tools: str = "httpx") -> bytes:
    return _zip(
        {
            f"{name}/SKILL.md": SKILL_MD.format(name=name, tools=tools),
            f"{name}/notes.md": "辅助说明文件\n",
        }
    )


@pytest.fixture
def workspace(tmp_path):
    """真目录 workspace：一个用户 skill + tools.d/httpx 已装标记。"""
    skill_dir = tmp_path / "skills" / "demo-skill"
    skill_dir.mkdir(parents=True)
    skill_dir.joinpath("SKILL.md").write_text(
        SKILL_MD.format(name="demo-skill", tools="httpx"), encoding="utf-8"
    )
    (tmp_path / "tools.d" / "httpx").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def symlink_workspace(tmp_path):
    """符号链接 workspace（仿演示）：skills -> 仓库式目录，含内置 web-scan。"""
    repo_skills = tmp_path / "repo" / "skills"
    (repo_skills / "web-scan").mkdir(parents=True)
    (repo_skills / "web-scan" / "SKILL.md").write_text(
        SKILL_MD.format(name="web-scan", tools="httpx"), encoding="utf-8"
    )
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "skills").symlink_to(repo_skills)
    return ws, repo_skills


@pytest.fixture
def client(workspace):
    with TestClient(create_app(workspace)) as test_client:
        yield test_client


def _management_events(workspace: Path) -> list[dict]:
    path = workspace / "management.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


# ---- 列表 ----


def test_list_skills_builtin_and_tool_marks(client, workspace):
    # 盘上手工放一个引用未知工具的 skill（API 层拦不住手工落盘）
    rogue = workspace / "skills" / "rogue-skill"
    rogue.mkdir()
    rogue.joinpath("SKILL.md").write_text(
        SKILL_MD.format(name="rogue-skill", tools="nuclei"), encoding="utf-8"
    )
    resp = client.get("/api/skills")
    assert resp.status_code == 200
    skills = {s["name"]: s for s in resp.json()["skills"]}
    demo = skills["demo-skill"]
    assert demo["builtin"] is False
    assert demo["missing_tools"] == []  # tools.d/httpx 已装
    assert demo["unknown_tools"] == []
    assert len(demo["sha256"]) == 64
    assert demo["risk_level"] == "L1"
    assert skills["rogue-skill"]["unknown_tools"] == ["nuclei"]
    assert skills["rogue-skill"]["missing_tools"] == ["nuclei"]


def test_list_marks_missing_tool(symlink_workspace):
    ws, _ = symlink_workspace
    with TestClient(create_app(ws)) as client:
        skills = {s["name"]: s for s in client.get("/api/skills").json()["skills"]}
    assert skills["web-scan"]["builtin"] is True  # 符号链接逃出 workspace
    assert skills["web-scan"]["missing_tools"] == ["httpx"]  # 无 tools.d


# ---- 上传 ----


def test_upload_valid_zip_and_hot_reload(client, workspace):
    resp = client.post("/api/skills", content=_valid_zip())
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["name"] == "demo-probe"
    assert (workspace / "skills" / "demo-probe" / "notes.md").is_file()

    skills = {s["name"]: s for s in client.get("/api/skills").json()["skills"]}
    assert "demo-probe" in skills
    assert skills["demo-probe"]["sha256"] == body["sha256"]

    # 热重载：同进程新建 registry 立即可见（无需重启）
    registry = SkillRegistry(workspace / "skills").discover()
    assert registry.get("demo-probe") is not None

    events = _management_events(workspace)
    assert [e["event"] for e in events] == ["skill_imported"]
    assert events[0]["name"] == "demo-probe"
    assert events[0]["sha256"] == body["sha256"]


def test_upload_duplicate_409(client):
    assert client.post("/api/skills", content=_valid_zip()).status_code == 201
    resp = client.post("/api/skills", content=_valid_zip())
    assert resp.status_code == 409


@pytest.mark.parametrize(
    "label,body",
    [
        ("缺字段", _zip({"demo-x/SKILL.md": SKILL_MD.format(
            name="demo-x", tools="httpx").replace("version: 1.0.0\n", "")})),
        ("非法risk_level", _zip({"demo-x/SKILL.md": SKILL_MD.format(
            name="demo-x", tools="httpx").replace("risk_level: L1", "risk_level: L9")})),
        ("未知工具", _valid_zip(name="demo-x", tools="nuclei")),
        ("路径穿越", _zip({"demo-x/SKILL.md": SKILL_MD.format(name="demo-x", tools="httpx"),
                           "demo-x/../evil.txt": "x"})),
        ("双顶层目录", _zip({"a/SKILL.md": SKILL_MD.format(name="a", tools="httpx"),
                             "b/SKILL.md": SKILL_MD.format(name="b", tools="httpx")})),
        ("无SKILL.md", _zip({"demo-x/readme.txt": "x"})),
        ("超1MiB", _zip({"demo-x/SKILL.md": SKILL_MD.format(name="demo-x", tools="httpx"),
                          "demo-x/big.bin": "A" * (1024 * 1024 + 1)}, stored=True)),
        ("目录名不符", _zip({"foo/SKILL.md": SKILL_MD.format(name="bar", tools="httpx")})),
    ],
)
def test_upload_validation_matrix(client, workspace, label, body):
    before = sorted(p.name for p in (workspace / "skills").iterdir())
    resp = client.post("/api/skills", content=body)
    assert resp.status_code == 422, (label, resp.text)
    assert resp.json()["detail"]["error"] == "validation_failed"
    # all-or-nothing：零残留（含 .tmp-* 临时目录）
    after = sorted(p.name for p in (workspace / "skills").iterdir())
    assert after == before, label


def test_upload_bad_zip(client):
    resp = client.post("/api/skills", content=b"not a zip at all")
    assert resp.status_code == 422


# ---- 编辑 ----


def test_update_user_skill(client, workspace):
    skill_md = workspace / "skills" / "demo-skill" / "SKILL.md"
    old_sha = hashlib.sha256(skill_md.read_bytes()).hexdigest()
    new_content = SKILL_MD.format(name="demo-skill", tools="httpx").replace(
        "测试 skill", "改后的描述"
    )
    resp = client.put("/api/skills/demo-skill", json={"content": new_content})
    assert resp.status_code == 200, resp.text
    assert resp.json()["copied_from_builtin"] is False
    assert client.get("/api/skills/demo-skill").json()["content"] == new_content

    events = _management_events(workspace)
    assert [e["event"] for e in events] == ["skill_updated"]
    assert events[0]["old_sha256"] == old_sha
    assert events[0]["new_sha256"] == hashlib.sha256(
        new_content.encode("utf-8")
    ).hexdigest()


def test_update_invalid_keeps_original(client, workspace):
    skill_md = workspace / "skills" / "demo-skill" / "SKILL.md"
    original = skill_md.read_bytes()
    resp = client.put("/api/skills/demo-skill", json={"content": "没有 frontmatter"})
    assert resp.status_code == 422
    assert skill_md.read_bytes() == original  # 零写入
    assert _management_events(workspace) == []


def test_update_unknown_404(client):
    resp = client.put("/api/skills/no-such", json={"content": "x"})
    assert resp.status_code == 404


# ---- copy-on-edit / 内置只读 ----


def test_builtin_copy_on_edit(symlink_workspace):
    ws, repo_skills = symlink_workspace
    repo_md = repo_skills / "web-scan" / "SKILL.md"
    repo_sha_before = hashlib.sha256(repo_md.read_bytes()).hexdigest()
    new_content = SKILL_MD.format(name="web-scan", tools="httpx").replace(
        "测试 skill", "workspace 定制版"
    )
    with TestClient(create_app(ws)) as client:
        resp = client.put("/api/skills/web-scan", json={"content": new_content})
        assert resp.status_code == 200, resp.text
        assert resp.json()["copied_from_builtin"] is True
        assert client.get("/api/skills/web-scan").json()["content"] == new_content

        # 仓库文件零触碰；workspace 落实体副本（不再是符号链接）
        assert hashlib.sha256(repo_md.read_bytes()).hexdigest() == repo_sha_before
        assert not (ws / "skills").is_symlink()
        copy = ws / "skills" / "web-scan"
        assert copy.is_dir() and not copy.is_symlink()
        assert (copy / "SKILL.md").read_text(encoding="utf-8") == new_content

        # 副本转为 workspace 实体（builtin=false），可删除
        skills = {s["name"]: s for s in client.get("/api/skills").json()["skills"]}
        assert skills["web-scan"]["builtin"] is False


def test_builtin_delete_409(symlink_workspace):
    ws, repo_skills = symlink_workspace
    with TestClient(create_app(ws)) as client:
        resp = client.delete("/api/skills/web-scan")
        assert resp.status_code == 409
    assert (repo_skills / "web-scan" / "SKILL.md").is_file()  # 仓库零触碰
    assert (ws / "skills").is_symlink()  # 只读路径不做本地化


# ---- 删除 ----


def test_delete_user_skill(client, workspace):
    resp = client.delete("/api/skills/demo-skill")
    assert resp.status_code == 200
    assert not (workspace / "skills" / "demo-skill").exists()
    assert client.get("/api/skills/demo-skill").status_code == 404
    events = _management_events(workspace)
    assert [e["event"] for e in events] == ["skill_deleted"]
    assert events[0]["name"] == "demo-skill"
    assert len(events[0]["sha256"]) == 64
