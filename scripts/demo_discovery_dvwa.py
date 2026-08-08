#!/usr/bin/env python3
"""M3d 实靶验收 demo（不进 pytest）：发现自动化全链路（零种子）。

链路（TestClient 起真实 API + 真实编排栈，不 mock 任何闸门）：

DVWA 就绪 → 带 cookie 创建 semi_auto engagement → POST /run →
web-scan + recon-crawl（L1 直通；katana 沙箱爬行，-cos 防会话自毁）→
triage 自动产出 sqli Hypothesis（asset 含 /vulnerabilities/sqli/、param=id，
**零种子脚本**）→ verify 阶段 L2 逐条阻塞进确认队列 →
批准 sqli/id 那条、拒绝其余 → sqlmap 行为确认 + 证据门 + Verifier T2
终审 → Confirmed；被拒条目落 rejected 桶（operator_rejected 归因）。

断言：审计含 command_executed tool=katana；Confirmed 证据包含 katana
stdout 出处链；批准/拒绝两路径审计事件原文打印；全程凭据脱敏自检。

用法：
    .venv/bin/python scripts/demo_discovery_dvwa.py                      # 全链路（需 T1+T2+Docker）
    .venv/bin/python scripts/demo_discovery_dvwa.py --skip-l2            # 只验到 sqli Hypothesis 自动产出
    .venv/bin/python scripts/demo_discovery_dvwa.py --dvwa-url http://127.0.0.1:8080

.env 需要：PROOFHOUND_T1_*（web-scan/recon-crawl 规划）；全链路另需
PROOFHOUND_T2_*（Verifier 终审）。产物落 evidence/demo_discovery/<时间戳>/
（gitignored）。
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
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用 demo_verify_dvwa

from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.llm.client import LLMError
from proofhound.llm.router import ModelRouter, Tier

from demo_verify_dvwa import DvwaError, ensure_dvwa

TARGET_ASSET_MARK = "/vulnerabilities/sqli/?id="  # 要批准的那条 Hypothesis
DEMO_DIR: Path
TARGET: str


class DemoError(RuntimeError):
    pass


def _check(resp, expected: int, what: str) -> dict:
    if resp.status_code != expected:
        raise DemoError(f"{what} 失败: HTTP {resp.status_code} {resp.text[:300]}")
    return resp.json()


def _wait_state(client: TestClient, eng_id: str, states: set[str], timeout: float) -> str:
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state in states:
            return state
        time.sleep(2)
    raise DemoError(f"等待状态 {states} 超时（当前 {state}）")


def _wait_pending(client: TestClient, eng_id: str, timeout: float) -> dict | None:
    """等一个 pending 确认；engagement 到终态则返回 None。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state in ("done", "failed"):
            return None
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


def _audit_events(eng_dir: Path, event: str) -> list[dict]:
    lines = (eng_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if f'"{event}"' in line]


def run_demo(client: TestClient, dvwa, eng_id: str, skip_l2: bool) -> None:
    eng_dir = DEMO_DIR / "workspace" / "engagements" / eng_id

    print("[*] 已启动（异步）；scan/triage 自动推进，等待首个 L2 确认或终态 ...")
    approved_cid = None
    decisions = {"approved": 0, "rejected": 0}
    while True:
        conf = _wait_pending(client, eng_id, timeout=900)
        if conf is None:
            break
        if skip_l2:
            print(f"[*] --skip-l2：待确认出现即证明 L2 闸门消费自动产出的 "
                  f"Hypothesis（{conf['action']} {conf['finding_id']}），拒绝收尾")
            _check(
                client.post(
                    f"/api/confirmations/{conf['cid']}/reject",
                    json={"operator": "demo-operator", "note": "skip-l2 演示收尾"},
                ),
                200,
                "拒绝确认",
            )
            decisions["rejected"] += 1
            continue
        if TARGET_ASSET_MARK in conf["summary"] and approved_cid is None:
            _check(
                client.post(
                    f"/api/confirmations/{conf['cid']}/approve",
                    json={"operator": "demo-operator",
                          "note": "演示授权：批准 sqli id 参数行为验证"},
                ),
                200,
                "批准确认",
            )
            approved_cid = conf["cid"]
            decisions["approved"] += 1
            print(f"[*] 批准目标条目: cid={conf['cid']} finding={conf['finding_id']}")
            print(f"    summary: {conf['summary']}")
            print("    （sqlmap 实跑 + Verifier 终审约需数分钟）...")
        else:
            _check(
                client.post(
                    f"/api/confirmations/{conf['cid']}/reject",
                    json={"operator": "demo-operator",
                          "note": "演示：非目标条目，拒绝以展示两路径"},
                ),
                200,
                "拒绝确认",
            )
            decisions["rejected"] += 1
            print(f"[*] 拒绝: cid={conf['cid']} finding={conf['finding_id']} "
                  f"（{conf['summary'][:80]}）")

    state = _wait_state(client, eng_id, {"done", "failed"}, timeout=1200)
    if state != "done":
        raise DemoError(f"engagement 终态为 {state}（预期 done）")
    print(f"[*] engagement 终态 done（批准 {decisions['approved']} / "
          f"拒绝 {decisions['rejected']}）")

    # ---- 断言 1：审计含 command_executed tool=katana（爬行真实发生） ----
    katana_runs = [
        e for e in _audit_events(eng_dir, "command_executed") if e.get("tool") == "katana"
    ]
    assert katana_runs, "审计链缺少 command_executed tool=katana"
    katana_stdout = Path(katana_runs[0]["stdout_path"])
    print(f"[*] 断言通过：审计含 katana 执行记录（exit={katana_runs[0]['exit_code']}，"
          f"stdout={katana_stdout.name}）")

    # ---- 断言 2：sqli Hypothesis 自动产出（零种子） ----
    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    sqli_hypo = [
        f for f in findings
        if f["vuln_type"] == "sqli" and TARGET_ASSET_MARK in f["asset"]
    ]
    assert sqli_hypo, "未自动产出目标 sqli Finding"
    target_finding = sqli_hypo[0]
    assert target_finding["param"] == "id", target_finding
    assert "crawl-endpoint" in target_finding["evidence_kinds"], target_finding
    print(f"[*] 断言通过：sqli Finding 自动产出（{target_finding['id']} "
          f"param=id evidence_kinds={target_finding['evidence_kinds']}，零种子）")
    buckets: dict[str, int] = {}
    for f in findings:
        buckets[f["state"]] = buckets.get(f["state"], 0) + 1
    print(f"[*] findings 分桶: {buckets}")

    if skip_l2:
        print("[*] --skip-l2：Hypothesis 自动产出与 L2 闸门消费已验证，跳过 sqlmap/Verifier")
        return

    # ---- 断言 3：批准路径 → Confirmed（sqlmap + 证据门 + Verifier） ----
    confirmed = [f for f in findings if f["state"] == "confirmed"]
    assert confirmed, "无 Confirmed Finding"
    sqli = next(f for f in confirmed if TARGET_ASSET_MARK in f["asset"])
    print(f"[*] Confirmed: {sqli['id']} method={sqli['verification']['method']}")
    print(f"    verifier={sqli['verifier']['model']} verdict={sqli['verifier']['verdict']}")
    print(f"    reason={sqli['verifier']['reason']}")

    # ---- 断言 4：Confirmed 证据包含 katana stdout 出处链 ----
    evidence = client.get(
        f"/api/engagements/{eng_id}/findings/{sqli['id']}/evidence"
    ).json()
    pack_refs = [item.get("source_ref") or "" for item in evidence["items"]]
    pack_files = [item.get("file") for item in evidence["items"]]
    assert any(katana_stdout.name in ref for ref in pack_refs), (
        f"证据包缺 katana stdout 出处（{katana_stdout.name} ∉ {pack_refs}）"
    )
    print(f"[*] 断言通过：证据包含 katana stdout 出处链（{katana_stdout.name} → "
          f"包内 {[f for f, r in zip(pack_files, pack_refs) if katana_stdout.name in r]}）"
          f"+ baseline + sqlmap 输出，共 {len(pack_files)} 项")

    # ---- 批准/拒绝两路径审计事件原文 ----
    approved = [
        e for e in _audit_events(eng_dir, "action_approved") if e.get("cid") == approved_cid
    ]
    rejected = _audit_events(eng_dir, "action_rejected")
    assert approved, "审计链缺少目标条目的 action_approved"
    assert rejected, "审计链缺少 action_rejected"
    print(f"[*] 批准审计事件原文:\n    {json.dumps(approved[0], ensure_ascii=False)}")
    print(f"[*] 拒绝审计事件原文（首条）:\n    {json.dumps(rejected[0], ensure_ascii=False)}")

    # ---- 凭据脱敏自检 ----
    cookie_value = dvwa.session_cookies().get("PHPSESSID", "")
    leaks = []
    for path in eng_dir.rglob("*"):
        if path.is_file() and path.name != "session.json":
            if cookie_value and cookie_value.encode() in path.read_bytes():
                leaks.append(str(path))
    assert not leaks, f"Cookie 原文泄漏: {leaks}"
    print("[*] 凭据脱敏自检通过：审计/findings/证据/确认队列均无 PHPSESSID 原文")


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M3d 发现自动化实靶验收")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument("--dvwa-url", default="http://127.0.0.1:8080")
    parser.add_argument("--skip-l2", action="store_true",
                        help="只验证到 sqli Hypothesis 自动产出（跳过 sqlmap/Verifier）")
    args = parser.parse_args()

    global TARGET, DEMO_DIR
    TARGET = args.dvwa_url.rstrip("/")
    port = urllib.parse.urlparse(TARGET).port or 80
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    DEMO_DIR = REPO_ROOT / "evidence" / "demo_discovery" / stamp
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    # 环境预检：LLM 档位 + Docker + DVWA
    try:
        router = ModelRouter.from_env(args.env_file)
    except LLMError as exc:
        print(f"[配置错误] {exc}", file=sys.stderr)
        return 2
    if Tier.T1 not in router.configs:
        print("[配置错误] 需要 T1 档（web-scan/recon-crawl 规划）：PROOFHOUND_T1_*",
              file=sys.stderr)
        return 2
    if not args.skip_l2 and Tier.T2 not in router.configs:
        print("[配置错误] 全链路需要 T2 档（Verifier）：PROOFHOUND_T2_*"
              "（或用 --skip-l2 只验到 Hypothesis 产出）", file=sys.stderr)
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
        dvwa, dvwa_container = ensure_dvwa(docker_client, TARGET, port)
    except DvwaError as exc:
        print(f"[环境错误] {exc}", file=sys.stderr)
        return 2

    workspace = _make_workspace(DEMO_DIR, port)
    app = create_app(workspace, env_file=args.env_file, confirm_timeout=900.0)
    print(f"[*] API 应用已创建（TestClient，真实编排栈不 mock）：workspace={workspace}")

    try:
        with TestClient(app) as client:
            cookies = dvwa.session_cookies()
            cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
            created = _check(
                client.post(
                    "/api/engagements",
                    json={
                        "target": TARGET,
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
            print(f"[*] engagement 已创建: {eng_id}（semi_auto，带 cookie，零种子）")
            _check(client.post(f"/api/engagements/{eng_id}/run"), 202, "启动")
            run_demo(client, dvwa, eng_id, args.skip_l2)
    finally:
        if dvwa_container is not None:
            print(f"\n[*] 清理 DVWA 容器 {dvwa_container.short_id}（--rm 自动删除）")
            dvwa_container.stop()

    print("\n" + "=" * 72)
    print(f"[验收通过] M3d 发现自动化全链路（产物目录: {DEMO_DIR}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
