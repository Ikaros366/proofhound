#!/usr/bin/env python3
"""M6b 实靶验收 demo（不进 pytest）：CVSS 评分真实化全链路。

链路（TestClient 起真实 API + 真实编排栈，不 mock 任何闸门，复用
demo_discovery 骨架）：

DVWA 就绪 → 带 cookie 创建 semi_auto engagement → POST /run →
web-scan + recon-crawl → triage 自动产出 sqli Hypothesis（零种子）→
L2 确认队列批准 sqli/id、拒绝其余 → sqlmap 行为确认 + 证据门 +
Verifier T2 终审（**产出 CVSS 向量**）→ Confirmed。

M6b 断言（红线：LLM 只产向量，分数 100% 代码计算）：
- Confirmed Finding 携带合法 cvss_vector（``base_score`` 解析通过）、
  ``cvss_score == base_score(vector)``、``severity == severity_for_score``
  ——机制级断言：severity 是算分映射结果、由代码覆盖 triage 种子值，
  **不预设档位**（按证据定指标是 SOP 本身的要求，实靶从严得 medium
  即正确行为）；
- 审计 ``verifier_verdict`` 事件携带 cvss_vector；
- 默认模板构建报告（narrative=false），读回文本含
  ``CVSS：{score}（{vector}）`` 行；
- 全程凭据脱敏自检（沿用 demo_discovery 检查）。

用法：
    .venv/bin/python scripts/demo_cvss_dvwa.py                      # 全链路（需 T1+T2+Docker）
    .venv/bin/python scripts/demo_cvss_dvwa.py --dvwa-url http://127.0.0.1:8080

.env 需要：PROOFHOUND_T1_*（规划）+ PROOFHOUND_T2_*（Verifier 终审）。
产物落 evidence/demo_cvss/<时间戳>/（gitignored）。
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
from proofhound.verify.cvss import base_score, severity_for_score

from demo_discovery_dvwa import (  # 复用 M3d demo 助手（同形态实靶验收）
    TARGET_ASSET_MARK,
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


def run_demo(client: TestClient, dvwa, eng_id: str) -> None:
    eng_dir = DEMO_DIR / "workspace" / "engagements" / eng_id

    print("[*] 已启动（异步）；scan/triage 自动推进，等待 L2 确认或终态 ...")
    decisions = {"approved": 0, "rejected": 0}
    while True:
        conf = _wait_pending(client, eng_id, timeout=900)
        if conf is None:
            break
        if TARGET_ASSET_MARK in conf["summary"]:
            _check(
                client.post(
                    f"/api/confirmations/{conf['cid']}/approve",
                    json={"operator": "demo-operator",
                          "note": "演示授权：批准 sqli id 参数行为验证"},
                ),
                200,
                "批准确认",
            )
            decisions["approved"] += 1
            print(f"[*] 批准目标条目: cid={conf['cid']} finding={conf['finding_id']}")
            print("    （sqlmap 实跑 + Verifier 终审约需数分钟）...")
        else:
            _check(
                client.post(
                    f"/api/confirmations/{conf['cid']}/reject",
                    json={"operator": "demo-operator",
                          "note": "演示：非目标条目，拒绝"},
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

    # ---- 断言 1：Confirmed Finding 的 CVSS 三字段（向量合法 + 分数代码算） ----
    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    confirmed = [f for f in findings if f["state"] == "confirmed"]
    assert confirmed, "无 Confirmed Finding"
    sqli = next(f for f in confirmed if TARGET_ASSET_MARK in f["asset"])
    vector = sqli.get("cvss_vector")
    assert vector, f"Confirmed Finding 缺 cvss_vector: {sqli['id']}"
    computed = base_score(vector)  # 向量非法会在此抛 CVSSVectorError
    assert sqli["cvss_score"] == computed, (
        f"分数非代码算分结果: 落盘 {sqli['cvss_score']} != 重算 {computed}"
    )
    assert sqli["severity"] == severity_for_score(computed), (
        f"severity 与算分不一致: {sqli['severity']} != {severity_for_score(computed)}"
    )
    # 不预设档位：按证据定指标（SOP），severity 是算分映射结果而非种子值
    print(f"[*] 断言通过：Confirmed {sqli['id']} 的 CVSS 字段——")
    print(f"    cvss_vector = {sqli['cvss_vector']}")
    print(f"    cvss_score  = {sqli['cvss_score']}（代码按官方公式计算）")
    print(f"    severity    = {sqli['severity']}（triage 种子值已被覆盖）")
    rationale = (sqli.get("verifier") or {}).get("cvss_rationale")
    if rationale:
        print(f"    rationale   = {rationale}")

    # ---- 断言 2：审计 verifier_verdict 携带向量 ----
    verdicts = [
        e for e in _audit_events(eng_dir, "verifier_verdict")
        if e.get("verdict") == "confirm"
    ]
    assert verdicts and verdicts[0].get("cvss_vector") == vector, (
        "verifier_verdict 审计事件缺 cvss_vector"
    )
    print(f"[*] 断言通过：verifier_verdict 审计含向量，事件原文:\n"
          f"    {json.dumps(verdicts[0], ensure_ascii=False)}")

    # ---- 断言 3：报告读回含 CVSS 行 ----
    built = _check(
        client.post(
            f"/api/engagements/{eng_id}/report",
            json={"template": "default_template.docx", "narrative": False},
        ),
        200,
        "构建报告",
    )
    print(f"[*] 报告已构建: {built['report']} summary={built['summary']}")
    from docx import Document

    paras = [p.text for p in Document(str(eng_dir / "report.docx")).paragraphs]
    cvss_lines = [p for p in paras if p.startswith("CVSS：")]
    expected = f"CVSS：{computed}（{vector}）"
    assert expected in cvss_lines, f"报告缺 CVSS 行 {expected!r}（实际 {cvss_lines}）"
    print(f"[*] 断言通过：报告含 CVSS 行，原文: {cvss_lines[0]}")

    # ---- 凭据脱敏自检 ----
    cookie_value = dvwa.session_cookies().get("PHPSESSID", "")
    leaks = []
    for path in eng_dir.rglob("*"):
        if path.is_file() and path.name != "session.json":
            if cookie_value and cookie_value.encode() in path.read_bytes():
                leaks.append(str(path))
    assert not leaks, f"Cookie 原文泄漏: {leaks}"
    print("[*] 凭据脱敏自检通过：审计/findings/证据/报告均无 PHPSESSID 原文")


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M6b CVSS 评分实靶验收")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument("--dvwa-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()

    global TARGET, DEMO_DIR
    TARGET = args.dvwa_url.rstrip("/")
    port = urllib.parse.urlparse(TARGET).port or 80
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    DEMO_DIR = REPO_ROOT / "evidence" / "demo_cvss" / stamp
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    # 环境预检：T1（规划）+ T2（Verifier）+ Docker + DVWA
    try:
        router = ModelRouter.from_env(args.env_file)
    except LLMError as exc:
        print(f"[配置错误] {exc}", file=sys.stderr)
        return 2
    for tier, purpose in ((Tier.T1, "web-scan/recon-crawl 规划"), (Tier.T2, "Verifier 终审")):
        if tier not in router.configs:
            print(f"[配置错误] 需要 {tier.name} 档（{purpose}）：PROOFHOUND_{tier.name}_*",
                  file=sys.stderr)
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
            run_demo(client, dvwa, eng_id)
    finally:
        if dvwa_container is not None:
            print(f"\n[*] 清理 DVWA 容器 {dvwa_container.short_id}（--rm 自动删除）")
            dvwa_container.stop()

    print("\n" + "=" * 72)
    print(f"[验收通过] M6b CVSS 评分真实化全链路（产物目录: {DEMO_DIR}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
