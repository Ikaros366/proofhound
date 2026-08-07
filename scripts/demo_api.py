#!/usr/bin/env python3
"""M5a 真实链路验收 demo（不进 pytest）：Web API + 自主模式闸门。

链路（TestClient 起真实 API + 真实编排栈，不 mock 任何闸门）：

- Part A（semi_auto 全流程）：DVWA 就绪 → 创建 engagement（web-scan, L1）
  → POST /run → L1 自动直通 → triage → verify 阶段无 L2 覆盖项（web-exposure
  不被 verify-sqli 覆盖）→ 全程零确认自动完成 → API 构建报告 → 下载字节
  与磁盘一致。注：本仓库一切工具执行强制走 Docker 沙箱（红线），故
  "不经过 docker" 不适用于本实现——本步不需要的是 sqlmap 镜像与 T2 模型，
  且不会触发任何 L2 确认。
- Part B（L2 阻塞→API 批准→Confirmed）：带 cookie 创建 engagement → 种子
  sqli Hypothesis → POST /run → semi_auto 下 L2 verify 阻塞进确认队列 →
  API 批准（operator 落款）→ sqlmap 行为确认 + 证据门 + Verifier T2 终审 →
  Confirmed → 报告 + approve 审计事件原文打印 + 凭据脱敏自检。
  本步需要 Docker + T2 模型配置，可用 --skip-l2 单独跳过。

用法：
    .venv/bin/python scripts/demo_api.py                       # A + B
    .venv/bin/python scripts/demo_api.py --skip-l2             # 仅 Part A
    .venv/bin/python scripts/demo_api.py --dvwa-url http://127.0.0.1:8080

.env 需要：Part A 需 PROOFHOUND_T1_*（规划）；Part B 另需 PROOFHOUND_T2_*
（Verifier 终审）。产物落 evidence/demo_api/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用 seed_finding / demo_verify_dvwa

from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.llm.client import LLMError
from proofhound.llm.router import ModelRouter, Tier

import seed_finding
from demo_verify_dvwa import DvwaError, ensure_dvwa

DVWA_IMAGE_NOTE = "vulnerables/web-dvwa:latest"


class DemoError(RuntimeError):
    pass


def _wait_state(client: TestClient, eng_id: str, states: set[str], timeout: float) -> str:
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state in states:
            return state
        time.sleep(2)
    raise DemoError(f"等待状态 {states} 超时（当前 {state}）")


def _wait_confirmation(client: TestClient, eng_id: str, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        confs = client.get(f"/api/engagements/{eng_id}/confirmations").json()[
            "confirmations"
        ]
        if confs:
            return confs[0]
        time.sleep(2)
    raise DemoError("等待待确认动作超时")


def _make_workspace(root: Path, port: int) -> Path:
    """演示工作区：scope.yaml + 符号链接复用仓库 templates/skills/tools.d。"""
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "scope.yaml").write_text(
        f"networks: [127.0.0.0/8]\nports: [{port}]\n", encoding="utf-8"
    )
    for name in ("templates", "skills", "tools.d"):
        link = workspace / name
        if not link.exists():
            link.symlink_to(REPO_ROOT / name)
    return workspace


def _check(resp, expected: int, what: str) -> dict:
    if resp.status_code != expected:
        raise DemoError(f"{what} 失败: HTTP {resp.status_code} {resp.text[:300]}")
    return resp.json()


def part_a(client: TestClient, stamp: str) -> str:
    print("\n" + "=" * 72)
    print("Part A：semi_auto 全流程（web-scan L1 直通，无 L2 确认，自动出报告）")
    print("=" * 72)
    eng_id = _check(
        client.post(
            "/api/engagements",
            json={
                "target": PART_A_TARGET,
                "scope_paths": ["scope.yaml"],
                "autonomy_mode": "semi_auto",
            },
        ),
        201,
        "创建 engagement",
    )["id"]
    print(f"[*] engagement 已创建: {eng_id}（semi_auto）")
    _check(client.post(f"/api/engagements/{eng_id}/run"), 202, "启动")
    print("[*] 已启动（异步）；等待自动跑完（scan → triage → verify）...")
    state = _wait_state(client, eng_id, {"done", "failed"}, timeout=600)
    if state != "done":
        raise DemoError(f"Part A engagement 终态为 {state}（预期 done）")

    confs = client.get(f"/api/engagements/{eng_id}/confirmations").json()[
        "confirmations"
    ]
    assert confs == [], f"semi_auto 下不应出现待确认动作: {confs}"
    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    states = {}
    for f in findings:
        states[f["state"]] = states.get(f["state"], 0) + 1
    print(f"[*] 全程零确认自动完成；findings 分桶: {states}")

    resp = _check(
        client.post(f"/api/engagements/{eng_id}/report", json={}), 200, "报告构建"
    )
    print(f"[*] 报告已构建: {resp['report']} summary={resp['summary']}")
    download = client.get(f"/api/engagements/{eng_id}/report")
    assert download.status_code == 200
    disk = (
        DEMO_DIR / "workspace" / "engagements" / eng_id / "report.docx"
    ).read_bytes()
    assert download.content == disk, "下载字节与磁盘不一致"
    print(f"[*] 报告下载字节与磁盘一致（{len(disk)} 字节）")
    return eng_id


def part_b(client: TestClient, dvwa, stamp: str) -> str:
    print("\n" + "=" * 72)
    print("Part B：L2 verify 阻塞 → API 批准 → Confirmed（需 Docker + T2）")
    print("=" * 72)
    cookies = dvwa.session_cookies()
    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
    created = _check(
        client.post(
            "/api/engagements",
            json={
                "target": PART_A_TARGET,
                "scope_paths": ["scope.yaml"],
                "cookie": cookie_header,
                "autonomy_mode": "semi_auto",
            },
        ),
        201,
        "创建 engagement（带会话）",
    )
    eng_id = created["id"]
    assert created["with_session"] is True
    assert cookies.get("PHPSESSID", "∅") not in json.dumps(created)
    print(f"[*] engagement 已创建: {eng_id}（with_session=true，响应无 cookie 回显 ✓）")

    # 种子 sqli Hypothesis（LLM triage 未做，M3b 替代入口）
    eng_dir = DEMO_DIR / "workspace" / "engagements" / eng_id
    sqli_url = f"{PART_A_TARGET}/vulnerabilities/sqli/?id=1&Submit=Submit"
    seed_finding.main(
        [
            "--dir", str(eng_dir),
            "--asset", sqli_url,
            "--vuln-type", "sqli",
            "--param", "id",
            "--title", "DVWA sqli id 参数 SQL 注入（API L2 闸门演示）",
        ]
    )

    _check(client.post(f"/api/engagements/{eng_id}/run"), 202, "启动")
    print("[*] 已启动；等待 L2 verify 动作阻塞进确认队列 ...")
    conf = _wait_confirmation(client, eng_id, timeout=600)
    assert conf["action"] == "verify-sqli" and conf["risk_level"] == "L2", conf
    print(f"[*] L2 阻塞如期出现: cid={conf['cid']} action={conf['action']} "
          f"finding={conf['finding_id']}")
    print(f"    summary: {conf['summary']}")
    state = client.get(f"/api/engagements/{eng_id}").json()["state"]
    assert state == "confirming", state

    _check(
        client.post(
            f"/api/confirmations/{conf['cid']}/approve",
            json={"operator": "demo-operator", "note": "演示授权：批准 sqlmap 行为验证"},
        ),
        200,
        "批准确认",
    )
    print("[*] 已批准；等待 sqlmap 行为确认 + 证据门 + Verifier T2 终审"
          "（实跑约需数分钟）...")
    state = _wait_state(client, eng_id, {"done", "failed"}, timeout=1200)
    if state != "done":
        raise DemoError(f"Part B engagement 终态为 {state}（预期 done）")

    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    confirmed = [f for f in findings if f["state"] == "confirmed"]
    if not confirmed:
        raise DemoError("Part B 无 Confirmed Finding")
    sqli = next(f for f in confirmed if f["vuln_type"] == "sqli")
    print(f"[*] Confirmed: {sqli['id']} method={sqli['verification']['method']}")
    print(f"    verifier={sqli['verifier']['model']} verdict={sqli['verifier']['verdict']}")
    print(f"    reason={sqli['verifier']['reason']}")

    # approve 审计事件原文（完成报告素材）
    audit_lines = (eng_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    approved = [
        line for line in audit_lines
        if '"action_approved"' in line and conf["cid"] in line
    ]
    assert approved, "审计链缺少 action_approved 事件"
    print(f"[*] approve 审计事件原文:\n    {approved[0]}")

    # 凭据脱敏自检：除 session.json（0600 凭据存储）外任何文件无 cookie 原文
    leaks = []
    cookie_value = cookies.get("PHPSESSID", "")
    for path in eng_dir.rglob("*"):
        if path.is_file() and path.name != "session.json":
            if cookie_value and cookie_value.encode() in path.read_bytes():
                leaks.append(str(path))
    assert not leaks, f"Cookie 原文泄漏: {leaks}"
    print("[*] 凭据脱敏自检通过：审计/findings/证据/确认队列均无 PHPSESSID 原文")

    resp = _check(
        client.post(f"/api/engagements/{eng_id}/report", json={}), 200, "报告构建"
    )
    print(f"[*] 报告已构建: summary={resp['summary']}")
    return eng_id


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M5a API + 自主模式验收")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument("--dvwa-url", default="http://127.0.0.1:8080")
    parser.add_argument("--skip-l2", action="store_true", help="跳过 Part B（需 Docker + T2 的 L2 演示）")
    args = parser.parse_args()

    global PART_A_TARGET, DEMO_DIR
    PART_A_TARGET = args.dvwa_url.rstrip("/")
    port = urllib.parse.urlparse(PART_A_TARGET).port or 80
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    DEMO_DIR = REPO_ROOT / "evidence" / "demo_api" / stamp
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    # 环境预检：LLM 档位 + Docker + DVWA
    try:
        router = ModelRouter.from_env(args.env_file)
    except LLMError as exc:
        print(f"[配置错误] {exc}", file=sys.stderr)
        return 2
    if Tier.T1 not in router.configs:
        print("[配置错误] Part A 需要 T1 档（规划）：PROOFHOUND_T1_*", file=sys.stderr)
        return 2
    if not args.skip_l2 and Tier.T2 not in router.configs:
        print("[配置错误] Part B 需要 T2 档（Verifier）：PROOFHOUND_T2_*"
              "（或用 --skip-l2 跳过）", file=sys.stderr)
        return 2
    try:
        import docker

        docker_client = docker.from_env()
        docker_client.ping()
    except Exception as exc:
        print(f"[环境错误] Docker 不可用（沙箱执行是红线，无法跳过）: {exc}",
              file=sys.stderr)
        return 2
    try:
        dvwa, dvwa_container = ensure_dvwa(docker_client, PART_A_TARGET, port)
    except DvwaError as exc:
        print(f"[环境错误] {exc}", file=sys.stderr)
        return 2

    workspace = _make_workspace(DEMO_DIR, port)
    app = create_app(workspace, env_file=args.env_file, confirm_timeout=900.0)
    print(f"[*] API 应用已创建（TestClient，真实编排栈不 mock）：workspace={workspace}")

    try:
        with TestClient(app) as client:
            health = client.get("/api/health").json()
            print(f"[*] 健康检查: {health['status']}；闸门矩阵: "
                  f"{json.dumps(health['autonomy_gate'], ensure_ascii=False)}")
            eng_a = part_a(client, stamp)
            eng_b = None
            if not args.skip_l2:
                eng_b = part_b(client, dvwa, stamp)
            else:
                print("\n[*] --skip-l2：跳过 Part B（L2 阻塞→批准→Confirmed 演示）")
    finally:
        if dvwa_container is not None:
            print(f"\n[*] 清理 DVWA 容器 {dvwa_container.short_id}（--rm 自动删除）")
            dvwa_container.stop()

    print("\n" + "=" * 72)
    print(f"[验收通过] Part A engagement: {eng_a}")
    if eng_b:
        print(f"[验收通过] Part B engagement: {eng_b}（L2 阻塞→批准→Confirmed）")
    print(f"产物目录: {DEMO_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
