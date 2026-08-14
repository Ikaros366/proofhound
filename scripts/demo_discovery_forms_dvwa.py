#!/usr/bin/env python3
"""M8a 实靶验收 demo（不进 pytest）：POST 表单发现自动化（sqlmap --forms）。

链路（TestClient 起真实 API + 真实编排栈，不 mock 任何闸门，复用
demo_discovery 骨架）：

DVWA 就绪（low 自检通过）→ cookie 翻转 **security=medium**（medium 下
sqli/sqli_blind 页渲染 ``<form method="POST"><select name="id">``，
已从镜像源文件坐实）→ 带 cookie 创建 semi_auto engagement → POST /run →
web-scan + recon-crawl → katana 爬行 → 解析器产 form_page 信号 →
triage 自动产出 forms 模式 sqli Hypothesis（asset=裸页面 URL、param=id、
evidence_kinds 含 crawl-form，**零种子**）→ L2 确认队列批准该条、拒绝
其余 → sqlmap **--forms** 行为确认 + 证据门 + Verifier T2 终审。

断言全部在**机制层**（不断言具体漏洞结论）：
1. 审计含 ``command_executed tool=katana``（爬行真实发生）；
2. forms 模式 sqli Finding 自动产出（asset 裸页面、param=id、crawl-form）；
3. ``triage_completed`` 审计 ``created_by_source.form_page >= 1``；
4. 批准后审计含 ``command_executed tool=sqlmap`` 且 command 含 ``--forms``、
   不含 ``--data``；其 stdout 证据文件落盘非空（--forms 模式原始输出）；
5. 审计链含 ``verify_completed``（discovery→triage→verify 完整）；
6. 若实跑 Confirmed 则打印 verifier 结论（不断言）；
7. 全程凭据脱敏自检（PHPSESSID 原文只在 session.json）。

用法：
    .venv/bin/python scripts/demo_discovery_forms_dvwa.py              # 全链路（需 T1+T2+Docker）
    .venv/bin/python scripts/demo_discovery_forms_dvwa.py --skip-l2    # 只验到 forms Hypothesis 产出
    .venv/bin/python scripts/demo_discovery_forms_dvwa.py --dvwa-url http://127.0.0.1:8080

.env 需要：PROOFHOUND_T1_*（web-scan/recon-crawl 规划）；全链路另需
PROOFHOUND_T2_*（Verifier 终审）。产物落 evidence/demo_discovery_forms/<时间戳>/
（gitignored）。
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用 demo_verify/demo_discovery

from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.llm.client import LLMError
from proofhound.llm.router import ModelRouter, Tier

from demo_discovery_dvwa import (  # 复用 M3d demo 助手（同形态实靶验收）
    DemoError,
    _audit_events,
    _check,
    _make_workspace,
    _wait_pending,
    _wait_state,
)
from demo_verify_dvwa import DvwaError, _make_cookie, ensure_dvwa

DEMO_DIR: Path
TARGET: str


def _forms_asset() -> str:
    """要批准的那条 forms 模式 Hypothesis 的 asset（POST 表单页裸 URL）。"""
    return f"{TARGET}/vulnerabilities/sqli/"


def run_demo(client: TestClient, dvwa, eng_id: str, skip_l2: bool) -> None:
    eng_dir = DEMO_DIR / "workspace" / "engagements" / eng_id
    target_asset = _forms_asset()
    approve_mark = f"（sqli {target_asset}）"  # 裸页面 URL + 右括号精确区分 GET 候选

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
        if approve_mark in conf["summary"] and approved_cid is None:
            _check(
                client.post(
                    f"/api/confirmations/{conf['cid']}/approve",
                    json={"operator": "demo-operator",
                          "note": "演示授权：批准 POST 表单页 sqlmap --forms 行为验证"},
                ),
                200,
                "批准确认",
            )
            approved_cid = conf["cid"]
            decisions["approved"] += 1
            print(f"[*] 批准 forms 目标条目: cid={conf['cid']} "
                  f"finding={conf['finding_id']}")
            print(f"    summary: {conf['summary']}")
            print("    （sqlmap --forms 实跑 + Verifier 终审约需数分钟）...")
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
    print(f"[*] 断言通过：审计含 katana 执行记录（exit={katana_runs[0]['exit_code']}）")

    # ---- 断言 2：forms 模式 sqli Finding 自动产出（零种子） ----
    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    forms_sqli = [
        f for f in findings
        if f["vuln_type"] == "sqli" and f["asset"] == target_asset
    ]
    assert forms_sqli, f"未自动产出 forms 模式 sqli Finding（asset={target_asset}）"
    target_finding = forms_sqli[0]
    assert target_finding["param"] == "id", target_finding
    assert "crawl-form" in target_finding["evidence_kinds"], target_finding
    print(f"[*] 断言通过：forms sqli Finding 自动产出（{target_finding['id']} "
          f"asset=裸页面 param=id evidence_kinds={target_finding['evidence_kinds']}，"
          f"零种子）")
    buckets: dict[str, int] = {}
    for f in findings:
        buckets[f["state"]] = buckets.get(f["state"], 0) + 1
    print(f"[*] findings 分桶: {buckets}")

    # ---- 断言 3：triage 摘要区分 get_param / form_page 两类候选 ----
    triage = _audit_events(eng_dir, "triage_completed")
    assert triage, "审计链缺少 triage_completed"
    by_source = triage[0].get("created_by_source") or {}
    assert by_source.get("form_page", 0) >= 1, (
        f"triage_completed.created_by_source 缺 form_page: {by_source}"
    )
    print(f"[*] 断言通过：triage_completed.created_by_source = {by_source}"
          f"（get_param/form_page 分类计数）")

    if skip_l2:
        print("[*] --skip-l2：forms Hypothesis 自动产出与 L2 闸门消费已验证，"
              "跳过 sqlmap/Verifier")
        return

    # ---- 断言 4：--forms 模式 sqlmap 原始输出落盘 + 审计 command 含 --forms ----
    sqlmap_runs = [
        e for e in _audit_events(eng_dir, "command_executed") if e.get("tool") == "sqlmap"
    ]
    forms_runs = [e for e in sqlmap_runs if "--forms" in (e.get("command") or "")]
    assert forms_runs, "审计链缺少 --forms 模式的 sqlmap 执行记录"
    run = forms_runs[0]
    assert "--data" not in run["command"], run["command"]
    stdout_path = Path(run["stdout_path"])
    assert stdout_path.is_file() and stdout_path.stat().st_size > 0, (
        f"--forms 模式 sqlmap stdout 未落盘: {stdout_path}"
    )
    print(f"[*] 断言通过：sqlmap --forms 实跑（exit={run['exit_code']}，"
          f"stdout={stdout_path.name} {stdout_path.stat().st_size}B）")
    print(f"    command（脱敏）: {run['command']}")

    # ---- 断言 5：discovery→triage→verify 审计链完整 ----
    assert _audit_events(eng_dir, "verify_completed"), "审计链缺少 verify_completed"
    print("[*] 断言通过：审计链 discovery→triage→verify 完整"
          "（command_executed katana → triage_completed → action_approved "
          "→ command_executed sqlmap --forms → verify_completed）")

    # ---- 机制层之外：实跑结论只打印不断言 ----
    final = next(f for f in findings if f["id"] == target_finding["id"])
    print(f"[*] 目标 Finding 终态（不断言）: state={final['state']}")
    if final["state"] == "confirmed":
        print(f"    verifier={final['verifier']['model']} "
              f"verdict={final['verifier']['verdict']}")
        print(f"    cvss={final.get('cvss_score')}（{final.get('cvss_vector')}）")

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
    parser = argparse.ArgumentParser(
        description="ProofHound M8a POST 表单发现自动化实靶验收（security=medium）"
    )
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument("--dvwa-url", default="http://127.0.0.1:8080")
    parser.add_argument("--skip-l2", action="store_true",
                        help="只验证到 forms sqli Hypothesis 自动产出（跳过 sqlmap/Verifier）")
    args = parser.parse_args()

    global TARGET, DEMO_DIR
    TARGET = args.dvwa_url.rstrip("/")
    port = urllib.parse.urlparse(TARGET).port or 80
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    DEMO_DIR = REPO_ROOT / "evidence" / "demo_discovery_forms" / stamp
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

    # M8a：medium 下 sqli/sqli_blind 页渲染 POST 表单（select name="id"）；
    # 安全级别存于客户端 cookie，直接翻转（与 security.php 表单等效）
    dvwa.jar.set_cookie(_make_cookie("security", "medium", dvwa.host))
    print("[*] 会话安全级已翻转：security=low → medium（POST 表单形态）")

    workspace = _make_workspace(DEMO_DIR, port)
    app = create_app(workspace, env_file=args.env_file, confirm_timeout=900.0)
    print(f"[*] API 应用已创建（TestClient，真实编排栈不 mock）：workspace={workspace}")

    try:
        with TestClient(app) as client:
            cookies = dvwa.session_cookies()
            assert cookies.get("security") == "medium", cookies
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
            print(f"[*] engagement 已创建: {eng_id}（semi_auto，security=medium，零种子）")
            _check(client.post(f"/api/engagements/{eng_id}/run"), 202, "启动")
            run_demo(client, dvwa, eng_id, args.skip_l2)
    finally:
        if dvwa_container is not None:
            print(f"\n[*] 清理 DVWA 容器 {dvwa_container.short_id}（--rm 自动删除）")
            dvwa_container.stop()

    print("\n" + "=" * 72)
    print(f"[验收通过] M8a POST 表单发现自动化全链路（产物目录: {DEMO_DIR}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
