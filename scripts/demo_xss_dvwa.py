#!/usr/bin/env python3
"""M8b 实靶验收 demo（不进 pytest）：verify-xss 无头浏览器行为确认。

链路（TestClient 起真实 API + 真实编排栈，不 mock 任何闸门，复用
demo_discovery 骨架）：

DVWA 就绪（security=low，xss_r 页 GET 表单 ?name= 直接执行 <script>）→
带 cookie 创建 semi_auto engagement → POST /run → web-scan + recon-crawl →
katana 爬行 → 解析器分支 B 合成 ``/vulnerabilities/xss_r/?name=1`` →
triage 自动产出 xss Hypothesis（**零种子**；name 两表皆中，sqli 候选同产）
→ L2 确认队列批准 verify-xss 该条、拒绝其余 → 无头 Chromium 逐 payload
probe → canary 执行事件命中 → 证据门（browser-confirmed）→ Verifier T2
终审（CVSS 向量 LLM 出、分数代码算）→ Confirmed（四段式证据结构）。

断言全部在**机制层**（不断言具体 CVSS 分数）：
1. 审计含 ``command_executed tool=katana``（爬行真实发生）；
2. xss Finding 自动产出（asset 含 /vulnerabilities/xss_r/、param=name）；
3. ``triage_completed`` 审计 ``created_by_type.xss >= 1``；
4. 批准后审计含 ``xss_probe_attempt`` 且存在 ``canary=true`` 条目；
   canary 事件 JSON 与 DOM 快照落盘非空；
5. 审计链完整：katana → triage_completed → action_approved →
   xss_probe_attempt → verify_completed；
6. 目标 Finding 终态 Confirmed、method=browser-confirmed、四段式字段齐全；
7. payload 集为代码常量（canary JSON 中 payload ∈ PAYLOAD_TEMPLATES 渲染
   结果，无任何 LLM 介入）；
8. 全程凭据脱敏自检（PHPSESSID 原文只在 session.json，含浏览器证据）。

用法：
    .venv/bin/python scripts/demo_xss_dvwa.py              # 全链路（需 T1+T2+Docker+Chromium）
    .venv/bin/python scripts/demo_xss_dvwa.py --skip-l2    # 只验到 xss Hypothesis 产出
    .venv/bin/python scripts/demo_xss_dvwa.py --dvwa-url http://127.0.0.1:8080

.env 需要：PROOFHOUND_T1_*（web-scan/recon-crawl 规划）；全链路另需
PROOFHOUND_T2_*（Verifier 终审）；Chromium 二进制经
``playwright install chromium`` 安装。产物落 evidence/demo_xss/<时间戳>/
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
from proofhound.verify.browser import PAYLOAD_TEMPLATES

from demo_discovery_dvwa import (  # 复用 M3d demo 助手（同形态实靶验收）
    DemoError,
    _audit_events,
    _check,
    _make_workspace,
    _wait_pending,
    _wait_state,
)
from demo_verify_dvwa import DvwaError, ensure_dvwa

DEMO_DIR: Path
TARGET: str

XSS_PAGE_MARK = "/vulnerabilities/xss_r/"  # 要批准的那条 xss Hypothesis 所在页


def _check_browser_available() -> str | None:
    """playwright + Chromium 预检；不可用返回错误说明，可用返回 None。"""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "playwright 未安装（pip install playwright==1.62.0）"
    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True)
        version = browser.version
        browser.close()
        pw.stop()
    except Exception as exc:
        return f"Chromium 不可用（playwright install chromium）: {exc}"
    print(f"[*] 浏览器预检通过：Chromium {version}")
    return None


def run_demo(client: TestClient, dvwa, eng_id: str, skip_l2: bool) -> None:
    eng_dir = DEMO_DIR / "workspace" / "engagements" / eng_id

    def _is_target_xss(conf: dict) -> bool:
        return (
            conf["action"] == "verify-xss" and XSS_PAGE_MARK in conf["summary"]
        )

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
        if _is_target_xss(conf) and approved_cid is None:
            _check(
                client.post(
                    f"/api/confirmations/{conf['cid']}/approve",
                    json={"operator": "demo-operator",
                          "note": "演示授权：批准 xss_r 页浏览器 canary 行为验证"},
                ),
                200,
                "批准确认",
            )
            approved_cid = conf["cid"]
            decisions["approved"] += 1
            print(f"[*] 批准 xss 目标条目: cid={conf['cid']} "
                  f"finding={conf['finding_id']}")
            print(f"    summary: {conf['summary']}")
            print("    （Chromium 逐 payload probe + Verifier 终审约需数分钟）...")
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

    # ---- 断言 2：xss Finding 自动产出（零种子） ----
    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    xss_hits = [
        f for f in findings
        if f["vuln_type"] == "xss" and XSS_PAGE_MARK in f["asset"]
    ]
    assert xss_hits, f"未自动产出 xss Finding（asset 含 {XSS_PAGE_MARK}）"
    target_finding = xss_hits[0]
    assert target_finding["param"] == "name", target_finding
    print(f"[*] 断言通过：xss Finding 自动产出（{target_finding['id']} "
          f"asset 含 xss_r、param=name，零种子）")
    buckets: dict[str, int] = {}
    for f in findings:
        buckets[f["state"]] = buckets.get(f["state"], 0) + 1
    print(f"[*] findings 分桶: {buckets}")

    # ---- 断言 3：triage 摘要含 xss 分桶 ----
    triage = _audit_events(eng_dir, "triage_completed")
    assert triage, "审计链缺少 triage_completed"
    by_type = triage[0].get("created_by_type") or {}
    assert by_type.get("xss", 0) >= 1, (
        f"triage_completed.created_by_type 缺 xss: {by_type}"
    )
    print(f"[*] 断言通过：triage_completed.created_by_type = {by_type}")

    if skip_l2:
        print("[*] --skip-l2：xss Hypothesis 自动产出与 L2 闸门消费已验证，"
              "跳过浏览器验证/Verifier")
        return

    # ---- 断言 4：canary 执行事件 + 证据落盘 ----
    attempts = _audit_events(eng_dir, "xss_probe_attempt")
    assert attempts, "审计链缺少 xss_probe_attempt"
    canary_attempts = [e for e in attempts if e.get("canary")]
    assert canary_attempts, "全部 probe 均未命中 canary（DVWA low xss_r 应执行）"
    hit = canary_attempts[0]
    print(f"[*] 断言通过：xss_probe_attempt {len(attempts)} 次，"
          f"命中 canary（seq={hit['seq']} token={hit['token']} "
          f"events={hit['event_types']}）")
    canary_files = sorted(eng_dir.glob("xss_*_canary.json"))
    dom_files = sorted(eng_dir.glob("xss_*_dom.html"))
    assert canary_files and all(p.stat().st_size > 0 for p in canary_files)
    assert dom_files and all(p.stat().st_size > 0 for p in dom_files)
    print(f"[*] 断言通过：canary 事件 JSON ×{len(canary_files)}、"
          f"DOM 快照 ×{len(dom_files)} 落盘非空")

    # ---- 审计链：M9c③ 起 semi_auto 下只读 L2 验证自动执行，不进确认队列 ----
    # 人工闸细分只对「写操作」保留确认（唯一差异格 = semi_auto × L2 只读），
    # 故这里断言的不再是 action_approved，而是闸门如实记下的自动放行。
    assert not _audit_events(eng_dir, "action_approved"), (
        "semi_auto 下只读验证不应出现人工批准"
    )
    auto_events = [
        e for e in _audit_events(eng_dir, "action_read_only_auto")
        if e.get("action") == "verify-xss"
    ]
    assert auto_events, "审计链缺少 action_read_only_auto(verify-xss)"
    assert all(e.get("mode") == "semi_auto" for e in auto_events), auto_events
    assert _audit_events(eng_dir, "verify_completed"), "审计链缺少 verify_completed"
    print("[*] 断言通过：审计链 katana → triage_completed → "
          f"action_read_only_auto ×{len(auto_events)} → xss_probe_attempt → "
          "verify_completed 完整")

    # ---- 断言 6：Confirmed + 四段式（不断言 CVSS 分数，只打印） ----
    final = next(f for f in findings if f["id"] == target_finding["id"])
    assert final["state"] == "confirmed", (
        f"目标 Finding 终态 {final['state']}（DVWA low xss_r 应 Confirmed）"
    )
    verification = final["verification"]
    assert verification["method"] == "browser-confirmed"
    assert verification["claim"] and verification["expected"] and verification["actual"]
    print(f"[*] 断言通过：终态 Confirmed、method=browser-confirmed、四段式齐全")
    print(f"    claim:   {verification['claim']}")
    print(f"    actual:  {verification['actual']}")
    print(f"    verifier={final['verifier']['model']} "
          f"verdict={final['verifier']['verdict']}")
    print(f"    cvss={final.get('cvss_score')}（{final.get('cvss_vector')}，"
          "分数为代码算分，不断言）")

    # ---- 断言 7：payload 集为代码常量（无 LLM 介入） ----
    for path in canary_files:
        doc = json.loads(path.read_text(encoding="utf-8"))
        rendered = {t.replace("{token}", doc["token"]) for t in PAYLOAD_TEMPLATES}
        assert doc["payload"] in rendered, (
            f"{path.name} 的 payload 不在代码常量模板集内: {doc['payload']!r}"
        )
    print("[*] 断言通过：全部 payload 来自代码常量模板集（LLM 零介入）")

    # ---- 凭据脱敏自检 ----
    cookie_value = dvwa.session_cookies().get("PHPSESSID", "")
    leaks = []
    for path in eng_dir.rglob("*"):
        if path.is_file() and path.name != "session.json":
            if cookie_value and cookie_value.encode() in path.read_bytes():
                leaks.append(str(path))
    assert not leaks, f"Cookie 原文泄漏: {leaks}"
    print("[*] 凭据脱敏自检通过：审计/findings/证据（含浏览器证据）/确认队列"
          "均无 PHPSESSID 原文")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ProofHound M8b verify-xss 无头浏览器行为确认实靶验收（security=low）"
    )
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument("--dvwa-url", default="http://127.0.0.1:8080")
    parser.add_argument("--skip-l2", action="store_true",
                        help="只验证到 xss Hypothesis 自动产出（跳过浏览器验证/Verifier）")
    args = parser.parse_args()

    global TARGET, DEMO_DIR
    TARGET = args.dvwa_url.rstrip("/")
    port = urllib.parse.urlparse(TARGET).port or 80
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    DEMO_DIR = REPO_ROOT / "evidence" / "demo_xss" / stamp
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    # 环境预检：LLM 档位 + Docker + DVWA + Chromium
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
    if not args.skip_l2:
        browser_error = _check_browser_available()
        if browser_error is not None:
            print(f"[环境错误] {browser_error}", file=sys.stderr)
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
        with TestClient(app, headers=app.state.auth.basic_header()) as client:
            cookies = dvwa.session_cookies()
            assert cookies.get("security") == "low", cookies
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
            print(f"[*] engagement 已创建: {eng_id}（semi_auto，security=low，零种子）")
            _check(client.post(f"/api/engagements/{eng_id}/run"), 202, "启动")
            run_demo(client, dvwa, eng_id, args.skip_l2)
    finally:
        if dvwa_container is not None:
            print(f"\n[*] 清理 DVWA 容器 {dvwa_container.short_id}（--rm 自动删除）")
            dvwa_container.stop()

    print("\n" + "=" * 72)
    print(f"[验收通过] M8b verify-xss 浏览器行为确认全链路（产物目录: {DEMO_DIR}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
