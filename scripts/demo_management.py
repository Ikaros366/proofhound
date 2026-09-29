#!/usr/bin/env python3
"""M6a 管理面验收 demo（不进 pytest）：Scope 管理 + 管理审计。

> **M9d 变更**：本 demo 原先还覆盖 Skill 管理（zip 上传 / 编辑 / 内置只读 /
> copy-on-edit）。M9d 撤下用户自写 skill 后，那套端点已整体移除，demo 相应
> 收窄为 **Scope 管理面**，并**新增一条断言证明 skill 端点确已消失**——
> 这比删除测试更有价值：它把「移除」这件事也钉住了。

链路（TestClient 起真实 API；无需 DVWA/Docker/LLM——管理面只读写配置
与文本，零命令构造）：

1. 断言 `/api/skills` 全族端点已移除（404）；
2. 新建 scope（demo.yaml）→ GET /api/scopes 断言下拉数据源含该名；
3. 读取 scope 全文 + sha256；编辑保存（PUT）→ 200 且 sha 变化；
4. 一次非法保存（含 session 凭据键）→ 422 原样打印，原文逐字节不变；
5. 用该 scope 创建 engagement（scope_paths=["scopes/demo.yaml"]，契约不变）→ 201；
6. 删除 demo scope → 200；
7. 原文打印 management.jsonl 全部事件（管理审计通道）。

用法：
    .venv/bin/python scripts/demo_management.py

产物落 evidence/demo_management/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行

from fastapi.testclient import TestClient

from proofhound.api import create_app

SCOPE_YAML = "networks: [127.0.0.0/8]\nports: [8080]\n"
SCOPE_EDITED = "networks: [127.0.0.0/8]\nports: [8080, 8443]\n"
#: 含凭据键的非法 scope（session 只走创建任务 cookie 入口，不进管理面）
SCOPE_WITH_CREDENTIALS = (
    "networks: [127.0.0.0/8]\nsession:\n  cookies:\n    PHPSESSID: leaked\n"
)


class DemoError(RuntimeError):
    pass


def _check(cond: bool, msg: str) -> None:
    if not cond:
        raise DemoError(msg)


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

    app = create_app(workspace)
    # M14：API 认证缺省开启——脚本作为客户端如实带凭据（不绕过校验）
    client = TestClient(app, headers=app.state.auth.basic_header())

    # ---- Step 1：skill 端点已移除（M9d）----
    print("\n" + "=" * 72 + "\nStep 1：断言 skill 管理端点已移除（M9d）\n" + "=" * 72)
    probes = [
        ("GET", "/api/skills", None),
        ("GET", "/api/skills/web-scan", None),
        ("POST", "/api/skills", b"not-a-zip"),
        ("PUT", "/api/skills/web-scan", {"content": "x"}),
        ("DELETE", "/api/skills/web-scan", None),
    ]
    for method, path, body in probes:
        resp = client.request(method, path, json=body) if isinstance(body, dict) else (
            client.request(method, path, content=body) if body else client.request(method, path)
        )
        _check(
            resp.status_code == 404,
            f"{method} {path} 应已移除（404），实得 {resp.status_code}",
        )
        print(f"[+] {method:6s} {path:28s} → 404（端点已移除）✓")

    # ---- Step 2：新建 scope + 下拉数据源断言 ----
    print("\n" + "=" * 72 + "\nStep 2：新建 scope（下拉数据源断言）\n" + "=" * 72)
    resp = client.post("/api/scopes", json={"name": "demo.yaml", "content": SCOPE_YAML})
    _check(resp.status_code == 201, f"新建 scope 失败: {resp.text}")
    print(f"[+] scope 创建成功: demo.yaml sha256={resp.json()['sha256'][:16]}…")
    scopes = {s["name"]: s for s in client.get("/api/scopes").json()["scopes"]}
    _check("demo.yaml" in scopes, "下拉数据源（GET /api/scopes）未含新 scope")
    _check(scopes["demo.yaml"]["networks"] == ["127.0.0.0/8"], "networks 不符")
    print("[+] GET /api/scopes 含 demo.yaml（控制台创建表单下拉数据源）✓")

    # ---- Step 3：读取全文 + 编辑保存 ----
    print("\n" + "=" * 72 + "\nStep 3：读取与编辑 scope\n" + "=" * 72)
    detail = client.get("/api/scopes/demo.yaml").json()
    _check(detail["content"] == SCOPE_YAML, "读取全文不符")
    before_sha = detail["sha256"]
    print(f"[+] 读取成功，原文一致（sha256 {before_sha[:16]}…）✓")
    resp = client.put("/api/scopes/demo.yaml", json={"content": SCOPE_EDITED})
    _check(resp.status_code == 200, f"编辑失败: {resp.text}")
    _check(resp.json()["sha256"] != before_sha, "编辑后 sha256 未变化")
    print(f"[+] 编辑保存成功: old={before_sha[:16]}… new={resp.json()['sha256'][:16]}…")

    # ---- Step 4：非法保存被拒（含凭据键）+ 原文不变 ----
    print("\n" + "=" * 72 + "\nStep 4：非法 scope 被拒（凭据键）\n" + "=" * 72)
    resp = client.put(
        "/api/scopes/demo.yaml", json={"content": SCOPE_WITH_CREDENTIALS}
    )
    _check(resp.status_code == 422, f"含凭据键应 422: {resp.status_code}")
    print(f"[+] 非法保存被拒（422）: {resp.json()['detail']['message'].splitlines()[0]}…")
    current = client.get("/api/scopes/demo.yaml").json()["content"]
    _check(current == SCOPE_EDITED, "非法保存后原文被改动（all-or-nothing 破坏）")
    print("[+] 原文逐字节不变（all-or-nothing）✓")

    # ---- Step 5：用该 scope 创建 engagement ----
    print("\n" + "=" * 72 + "\nStep 5：用管理面 scope 创建 engagement\n" + "=" * 72)
    resp = client.post(
        "/api/engagements",
        json={"target": "http://127.0.0.1:8080", "scope_paths": ["scopes/demo.yaml"]},
    )
    _check(resp.status_code == 201, f"创建 engagement 失败: {resp.text}")
    print(f"[+] engagement 创建成功: {resp.json()['id']}（契约不变：scopes/demo.yaml）✓")

    # ---- Step 6：删除 demo scope ----
    print("\n" + "=" * 72 + "\nStep 6：删除 demo scope\n" + "=" * 72)
    resp = client.delete("/api/scopes/demo.yaml")
    _check(resp.status_code == 200, f"删除 scope 失败: {resp.text}")
    print("[+] demo.yaml 已删除 ✓")

    # ---- Step 7：management.jsonl 原文打印 ----
    print("\n" + "=" * 72 + "\nStep 7：management.jsonl 全事件原文\n" + "=" * 72)
    log_path = workspace / "management.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        print(line)
    kinds = [json.loads(l)["event"] for l in lines]
    _check(
        kinds == ["scope_created", "scope_updated", "scope_deleted"],
        f"management.jsonl 事件序列不符: {kinds}",
    )
    print("\n[+] 管理审计通道事件序列完整（含新旧 sha256）✓")

    print("\n" + "=" * 72)
    print("M6a 管理面（Scope）验收通过；skill 端点确已移除（M9d）")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())