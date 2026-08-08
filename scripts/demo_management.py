#!/usr/bin/env python3
"""M6a 管理面验收 demo（不进 pytest）：Skill 管理 + Scope 管理 + 管理审计。

链路（TestClient 起真实 API；无需 DVWA/Docker/LLM——管理面只读写配置
与文本，零命令构造）：

1. 上传一个合法新 skill（内存构造最小 demo-probe zip）→ 列表出现；
2. 编辑保存（PUT）→ 200；再做一次非法保存（未知工具）→ 422 原样打印
   校验错误，原文逐字节不变；
3. 内置 skill 只读：DELETE web-scan → 409；PUT web-scan → copy-on-edit，
   断言仓库 skills/web-scan/SKILL.md 的 sha256 不变（绝不顺符号链接写仓库）；
4. 新建 scope（demo.yaml）→ GET /api/scopes 断言下拉数据源含该名；
5. 用该 scope 创建 engagement（scope_paths=["scopes/demo.yaml"]，契约不变）→ 201；
6. 删除 demo skill 与 demo scope → 200；
7. 原文打印 management.jsonl 全部事件（管理审计通道）。

用法：
    .venv/bin/python scripts/demo_management.py

产物落 evidence/demo_management/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行

from fastapi.testclient import TestClient

from proofhound.api import create_app

DEMO_SKILL_MD = """\
---
name: demo-probe
description: M6a 演示 skill（最小合法）
version: 1.0.0
required_tools: [httpx]
risk_level: L1
inputs: [targets]
outputs: [signals]
---

演示 SOP：探活并产出 signals。
"""

SCOPE_YAML = "networks: [127.0.0.0/8]\nports: [8080]\n"


class DemoError(RuntimeError):
    pass


def _check(cond: bool, msg: str) -> None:
    if not cond:
        raise DemoError(msg)


def _demo_skill_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo-probe/SKILL.md", DEMO_SKILL_MD)
        zf.writestr("demo-probe/notes.md", "演示辅助文件\n")
    return buf.getvalue()


def _make_workspace(root: Path) -> Path:
    """演示工作区：skills 符号链接指向仓库（仿 demo_console 真实形态）。"""
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "skills").symlink_to(REPO_ROOT / "skills")
    return workspace


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    demo_dir = REPO_ROOT / "evidence" / "demo_management" / stamp
    demo_dir.mkdir(parents=True, exist_ok=True)
    workspace = _make_workspace(demo_dir)
    print(f"[*] 演示工作区: {workspace}（skills -> 仓库符号链接）")

    client = TestClient(create_app(workspace))

    # ---- Step 1：上传合法新 skill ----
    print("\n" + "=" * 72 + "\nStep 1：上传新 skill（demo-probe zip）\n" + "=" * 72)
    resp = client.post("/api/skills", content=_demo_skill_zip())
    _check(resp.status_code == 201, f"上传失败: {resp.status_code} {resp.text}")
    imported = resp.json()
    print(f"[+] 上传成功: {imported['name']} sha256={imported['sha256'][:16]}…")
    skills = {s["name"]: s for s in client.get("/api/skills").json()["skills"]}
    _check("demo-probe" in skills, "列表未出现新 skill")
    _check(skills["demo-probe"]["builtin"] is False, "新 skill 应为用户来源")
    _check(skills["web-scan"]["builtin"] is True, "web-scan 应为内置（符号链接逃出）")
    print(f"[+] 列表已出现（共 {len(skills)} 个）；来源标记：demo-probe=用户 web-scan=内置 ✓")

    # ---- Step 2：编辑保存 + 一次非法保存被拒 ----
    print("\n" + "=" * 72 + "\nStep 2：编辑 skill（合法保存 + 非法保存被拒）\n" + "=" * 72)
    edited = DEMO_SKILL_MD.replace("M6a 演示 skill（最小合法）", "M6a 演示 skill（已编辑）")
    resp = client.put("/api/skills/demo-probe", json={"content": edited})
    _check(resp.status_code == 200, f"编辑失败: {resp.text}")
    print(f"[+] 编辑保存成功: sha256={resp.json()['sha256'][:16]}…")
    bad = edited.replace("required_tools: [httpx]", "required_tools: [nuclei-x]")
    resp = client.put("/api/skills/demo-probe", json={"content": bad})
    _check(resp.status_code == 422, f"非法保存应 422: {resp.status_code}")
    print(f"[+] 非法保存被拒（422）: {resp.json()['detail']['message'].splitlines()[0]}…")
    current = client.get("/api/skills/demo-probe").json()["content"]
    _check(current == edited, "非法保存后原文被改动（all-or-nothing 破坏）")
    print("[+] 原文逐字节不变（all-or-nothing）✓")

    # ---- Step 3：内置只读 + copy-on-edit ----
    print("\n" + "=" * 72 + "\nStep 3：内置 skill 只读 / copy-on-edit\n" + "=" * 72)
    repo_md = REPO_ROOT / "skills" / "web-scan" / "SKILL.md"
    repo_sha_before = hashlib.sha256(repo_md.read_bytes()).hexdigest()
    resp = client.delete("/api/skills/web-scan")
    _check(resp.status_code == 409, f"内置删除应 409: {resp.status_code}")
    print(f"[+] DELETE 内置 web-scan 被拒（409）: {resp.json()['detail']['message']}")
    builtin_edit = repo_md.read_text(encoding="utf-8").replace(
        "version: 1.0.0", "version: 1.0.1", 1
    )
    resp = client.put("/api/skills/web-scan", json={"content": builtin_edit})
    _check(resp.status_code == 200, f"copy-on-edit 失败: {resp.text}")
    _check(resp.json()["copied_from_builtin"] is True, "应标记 copied_from_builtin")
    repo_sha_after = hashlib.sha256(repo_md.read_bytes()).hexdigest()
    _check(repo_sha_before == repo_sha_after, "仓库文件被顺符号链接写入！")
    _check(not (workspace / "skills").is_symlink(), "skills/ 应已本地化为真目录")
    print(f"[+] copy-on-edit 成功：workspace 副本 sha256={resp.json()['sha256'][:16]}…")
    print(f"[+] 仓库 skills/web-scan/SKILL.md sha256 不变（{repo_sha_before[:16]}…）✓")

    # ---- Step 4：新建 scope + 下拉数据源断言 ----
    print("\n" + "=" * 72 + "\nStep 4：新建 scope（下拉数据源断言）\n" + "=" * 72)
    resp = client.post("/api/scopes", json={"name": "demo.yaml", "content": SCOPE_YAML})
    _check(resp.status_code == 201, f"新建 scope 失败: {resp.text}")
    print(f"[+] scope 创建成功: demo.yaml sha256={resp.json()['sha256'][:16]}…")
    scopes = {s["name"]: s for s in client.get("/api/scopes").json()["scopes"]}
    _check("demo.yaml" in scopes, "下拉数据源（GET /api/scopes）未含新 scope")
    _check(scopes["demo.yaml"]["networks"] == ["127.0.0.0/8"], "networks 不符")
    print("[+] GET /api/scopes 含 demo.yaml（控制台创建表单下拉数据源）✓")

    # ---- Step 5：用该 scope 创建 engagement ----
    print("\n" + "=" * 72 + "\nStep 5：用管理面 scope 创建 engagement\n" + "=" * 72)
    resp = client.post(
        "/api/engagements",
        json={"target": "http://127.0.0.1:8080", "scope_paths": ["scopes/demo.yaml"]},
    )
    _check(resp.status_code == 201, f"创建 engagement 失败: {resp.text}")
    print(f"[+] engagement 创建成功: {resp.json()['id']}（契约不变：scopes/demo.yaml）✓")

    # ---- Step 6：删除 demo skill 与 scope ----
    print("\n" + "=" * 72 + "\nStep 6：删除 demo skill 与 scope\n" + "=" * 72)
    resp = client.delete("/api/skills/demo-probe")
    _check(resp.status_code == 200, f"删除 skill 失败: {resp.text}")
    print("[+] demo-probe 已删除")
    resp = client.delete("/api/scopes/demo.yaml")
    _check(resp.status_code == 200, f"删除 scope 失败: {resp.text}")
    print("[+] demo.yaml 已删除")

    # ---- Step 7：management.jsonl 原文打印 ----
    print("\n" + "=" * 72 + "\nStep 7：management.jsonl 全事件原文\n" + "=" * 72)
    log_path = workspace / "management.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        print(line)
    events = [json.loads(l) for l in lines]
    kinds = [e["event"] for e in events]
    _check(
        kinds
        == [
            "skill_imported",
            "skill_updated",
            "skill_updated",
            "scope_created",
            "skill_deleted",
            "scope_deleted",
        ],
        f"management.jsonl 事件序列不符: {kinds}",
    )
    print("\n[+] 管理审计通道事件序列完整（含新旧 sha256）✓")

    print("\n" + "=" * 72)
    print("M6a 管理面验收通过")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
