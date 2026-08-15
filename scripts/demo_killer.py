#!/usr/bin/env python3
"""M8d Killer Demo（不进 pytest）：三漏洞一键全证据链演示（v0.2.0 发布 artifact）。

单 engagement 覆盖双目标：DVWA（sqli + xss_r，security=low）+ IDOR fixture
（/invoice?id=1001 无授权判断=漏洞 / ?id=1002 有授权判断=对照）。fixture
复用 demo_idor_fixture 的 handler 类（from 导入 + 子类化，不复制粘贴）：
首页门户化，除发票链接外追加 DVWA 深链——katana 从 fixture 单种子沿链接
跨端口覆盖双站点（``-fs rdn`` 对 IP 型种子的 rdn 即 IP 本身，端口不参与）。

双站会话 = 合并 Cookie 头（零代码改动方案）：主会话 cookie =
``PHPSESSID=<dvwa>; security=low; phsess=<A_TOKEN>``，reference_cookie =
``phsess=<B_TOKEN>``。各消费者按名取所需 cookie：sqlmap ``--cookie`` 全发
DVWA（DVWA 忽略 ``phsess``）、浏览器 ``add_cookies`` 按 origin 绑定（cookie
不按端口隔离，127.0.0.1 两站天然共存）、idor fetch 发 fixture（fixture 按名
取 ``phsess``）、katana 带合并头爬双站；两站均为 127.0.0.1 且在 scope 内，
脱敏走 ``secret_values()`` 一个口子（三份凭据裸值均 ≥8 字符纳入脱敏）。

链路（TestClient 起真实 API + 真实编排栈，不 mock 任何闸门）：

门户 fixture 就绪 → 合并 cookie 创建 semi_auto engagement → POST /run →
katana 沙箱爬行双目标 → triage 自动产出三类候选（sqli / xss / idor，同产
候选是设计行为）→ L2 确认队列按白名单批准 4 条（sqli 页 1 + xss_r 1 +
idor 1001/1002 各 1）、拒绝其余 → sqlmap 行为确认 / Chromium canary
确认 / 双会话属性验证 → 三 skill 各 Confirmed → 1002 对照 REJECTED →
构建报告（默认模板，默认 T1 叙述）。

断言全部在**机制层**（不断言 CVSS 分数）：
1. Confirmed ≥ 3 且 sqli/xss/idor 各至少一条；
2. 每条 Confirmed 四段式（claim/method/expected/actual）齐全、method ∈
   {sqlmap-confirmed, browser-confirmed, dual-session-confirmed} 且与
   vuln_type 匹配；
3. 对照组 /invoice?id=1002 REJECTED（B=200/A=403 不误报）；
4. 审计链含三类 probe/command 事件（sqlmap command_executed +
   xss_probe_attempt 命中 canary + idor_probe_attempt 成对）；
5. 报告 docx 生成成功，解压 word/document.xml 含 "browser-confirmed" 与
   "dual-session-confirmed" 字样（四段式进了报告）；
6. 全目录脱敏自检（DVWA PHPSESSID 与 fixture 双 token 原文只在
   session.json，0600）；
7. 终态 done，审计无 llm_budget_exceeded。

用法：
    .venv/bin/python scripts/demo_killer.py                  # 全链路（需 T1+T2+Docker+Chromium）
    .venv/bin/python scripts/demo_killer.py --skip-l2        # 只验到三类 Hypothesis 自动产出
    .venv/bin/python scripts/demo_killer.py --no-narrative   # 报告跳过 T1 叙述（快速复跑）
    .venv/bin/python scripts/demo_killer.py --dvwa-url http://127.0.0.1:8080

.env 需要：PROOFHOUND_T1_*（web-scan/recon-crawl 规划 + 叙述）；全链路另需
PROOFHOUND_T2_*（Verifier 终审）；Chromium 二进制经 ``playwright install
chromium`` 安装。产物落 evidence/demo_killer/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.parse
import zipfile
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用 demo 家族骨架

from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.compliance.session import secret_marker
from proofhound.llm.client import LLMError
from proofhound.llm.router import ModelRouter, Tier

from demo_discovery_dvwa import (  # 复用 M3d demo 助手（同形态实靶验收）
    DemoError,
    _audit_events,
    _check,
    _wait_pending,
    _wait_state,
)
from demo_idor_fixture import A_TOKEN, B_TOKEN, _FixtureHandler
from demo_verify_dvwa import DvwaError, ensure_dvwa
from demo_xss_dvwa import _check_browser_available

DEMO_DIR: Path

DVWA_SQLI_MARK = "/vulnerabilities/sqli/?id="  # 批准的 sqli Hypothesis 所在页
DVWA_XSS_MARK = "/vulnerabilities/xss_r/"  # 批准的 xss Hypothesis 所在页
IDOR_MARKS = ("id=1001", "id=1002")  # 批准的 idor Hypothesis（漏洞 + 对照）
EXPECTED_METHOD = {
    "sqli": "sqlmap-confirmed",
    "xss": "browser-confirmed",
    "idor": "dual-session-confirmed",
}


# ---- 门户化 fixture（子类化复用，不动 demo_idor_fixture） ----


class _PortalHandler(_FixtureHandler):
    """门户化 fixture：``/`` 除发票链接外追加 DVWA 深链（katana 单种子覆盖双站）。"""

    dvwa_base: str = ""  # 启动前由 main() 注入（类属性，handler 实例共享）

    def do_GET(self):  # noqa: N802（BaseHTTPRequestHandler 约定）
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/" and self.dvwa_base:
            self._respond(
                200,
                "<html><body><h1>发票系统</h1><nav>"
                '<a href="/invoice?id=1001">发票 1001</a>'
                '<a href="/invoice?id=1002">发票 1002</a>'
                "</nav><hr><nav>"
                f'<a href="{self.dvwa_base}/vulnerabilities/sqli/">DVWA SQLi</a>'
                f'<a href="{self.dvwa_base}/vulnerabilities/xss_r/">DVWA XSS</a>'
                "</nav></body></html>",
            )
            return
        super().do_GET()


def _start_portal_fixture() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PortalHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _make_dual_workspace(root: Path, ports: list[int]) -> Path:
    """演示工作区：scope.yaml（双端口）+ 符号链接复用仓库 templates/skills/tools.d。"""
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    port_list = ", ".join(str(p) for p in ports)
    (workspace / "scope.yaml").write_text(
        f"networks: [127.0.0.0/8]\nports: [{port_list}]\n", encoding="utf-8"
    )
    for name in ("templates", "skills", "tools.d"):
        link = workspace / name
        if not link.exists():
            link.symlink_to(REPO_ROOT / name)
    return workspace


# ---- 纯函数（单测覆盖） ----


def _decide(
    action: str,
    summary: str,
    approved_marks: frozenset[str],
    skip_l2: bool = False,
) -> tuple[str, str, str | None]:
    """L2 确认裁定（纯函数）：返回 (decision, note, mark)。

    白名单：sqli 页 sqli ×1、xss_r 页 xss ×1、idor 1001/1002 各 ×1；同一
    标记只批首条（防同页多候选重复触发验证），其余一律拒绝（同产候选与
    非目标候选是预期的拒绝路径演示）。mark 为命中的批准标记（reject 时 None）。
    """
    if skip_l2:
        return "reject", "skip-l2 演示收尾", None
    rules = (
        ("verify-sqli", DVWA_SQLI_MARK, "演示授权：批准 sqli 页 id 参数 sqlmap 行为验证"),
        ("verify-xss", DVWA_XSS_MARK, "演示授权：批准 xss_r 页浏览器 canary 行为验证"),
        ("verify-idor", IDOR_MARKS[0], "演示授权：批准发票 1001 双会话属性验证（漏洞）"),
        ("verify-idor", IDOR_MARKS[1], "演示授权：批准发票 1002 双会话属性验证（对照）"),
    )
    for expected_action, mark, note in rules:
        if action == expected_action and mark in summary:
            if mark in approved_marks:
                return "reject", f"演示：{mark} 已批准过一条，重复候选拒绝", None
            return "approve", note, mark
    return "reject", "演示：非目标条目，拒绝以展示两路径", None


def _check_confirmed_matrix(findings: list[dict]) -> list[str]:
    """Confirmed 矩阵校验（需求①②）：返回违规清单（空 = 通过）。"""
    violations: list[str] = []
    confirmed = [f for f in findings if f.get("state") == "confirmed"]
    if len(confirmed) < 3:
        violations.append(f"Confirmed 数量 {len(confirmed)} < 3")
    by_type: dict[str, list[dict]] = {}
    for f in confirmed:
        by_type.setdefault(f.get("vuln_type") or "", []).append(f)
    for vuln_type in EXPECTED_METHOD:
        if not by_type.get(vuln_type):
            violations.append(f"Confirmed 缺 vuln_type={vuln_type}")
    known_methods = set(EXPECTED_METHOD.values())
    for f in confirmed:
        vuln_type = f.get("vuln_type") or ""
        verification = f.get("verification") or {}
        method = verification.get("method") or ""
        if method not in known_methods:
            violations.append(f"{f.get('id')} method={method!r} 不在白名单")
        elif EXPECTED_METHOD.get(vuln_type) != method:
            violations.append(
                f"{f.get('id')} vuln_type={vuln_type} 与 method={method} 不匹配"
            )
        for key in ("claim", "expected", "actual"):
            if not verification.get(key):
                violations.append(f"{f.get('id')} 四段式缺 {key}")
    return violations


def _render_summary_table(
    findings: list[dict], evidence_files: dict[str, list[str]]
) -> str:
    """三漏洞证据链摘要表（终端打印，纯函数）。"""
    order = {vuln_type: i for i, vuln_type in enumerate(EXPECTED_METHOD)}
    confirmed = [f for f in findings if f.get("state") == "confirmed"]
    confirmed.sort(key=lambda f: order.get(f.get("vuln_type") or "", 99))
    lines = [
        "",
        "=" * 78,
        "三漏洞证据链摘要（Confirmed）",
        "=" * 78,
    ]
    for f in confirmed:
        verification = f.get("verification") or {}
        verifier = f.get("verifier") or {}
        lines.append(
            f"[{f.get('vuln_type')}] {f.get('id')}  "
            f"CVSS {f.get('cvss_score')}（severity={f.get('severity')}）"
        )
        lines.append(f"  asset:  {f.get('asset')}")
        lines.append(
            f"  method: {verification.get('method')}  "
            f"verifier: {verifier.get('model')} verdict={verifier.get('verdict')}"
        )
        files = evidence_files.get(f.get("id") or "", [])
        lines.append(f"  证据 {len(files)} 项:")
        lines.extend(f"    - {name}" for name in files)
    return "\n".join(lines)


def _check_report_xml(
    docx_path: Path,
    needles: tuple[str, ...] = ("browser-confirmed", "dual-session-confirmed"),
) -> list[str]:
    """报告 docx 解压校验（需求⑤）：word/document.xml 中缺失的 needle 清单。"""
    if not docx_path.is_file():
        return list(needles)
    with zipfile.ZipFile(docx_path) as zf:
        xml = zf.read("word/document.xml").decode("utf-8", errors="replace")
    return [needle for needle in needles if needle not in xml]


def _find_secret_leaks(
    root: Path, secrets: list[str], exempt: str = "session.json"
) -> list[str]:
    """脱敏自检（需求⑥）：secret 原文出现在豁免文件之外的路径清单。"""
    leaks: list[str] = []
    for path in root.rglob("*"):
        if path.is_file() and path.name != exempt:
            content = path.read_bytes()
            for secret in secrets:
                if secret and secret.encode() in content:
                    leaks.append(f"{path}（含 {secret_marker(secret)}）")
    return leaks


# ---- 全链路 ----


def run_demo(
    client: TestClient,
    eng_id: str,
    skip_l2: bool,
    narrative: bool,
    secrets: list[str],
) -> None:
    eng_dir = DEMO_DIR / "workspace" / "engagements" / eng_id
    started = time.monotonic()

    print("[*] 已启动（异步）；scan/triage 自动推进，等待首个 L2 确认或终态 ...")
    approved_marks: set[str] = set()
    decisions = {"approved": 0, "rejected": 0}
    last_state = ""
    while True:
        conf = _wait_pending(client, eng_id, timeout=900)
        if conf is None:
            break
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state != last_state:
            print(f"[*] 阶段推进: {state}（elapsed {time.monotonic() - started:.0f}s）")
            last_state = state
        decision, note, mark = _decide(
            conf["action"], conf["summary"], frozenset(approved_marks), skip_l2
        )
        _check(
            client.post(
                f"/api/confirmations/{conf['cid']}/{decision}",
                json={"operator": "demo-operator", "note": note},
            ),
            200,
            f"{decision} 确认",
        )
        if decision == "approve":
            approved_marks.add(mark)
            decisions["approved"] += 1
            print(f"[*] 批准 {conf['action']}: cid={conf['cid']} "
                  f"finding={conf['finding_id']}")
            print(f"    summary: {conf['summary']}")
            if conf["action"] == "verify-sqli":
                print("    （sqlmap 实跑 + Verifier 终审约需数分钟）...")
        else:
            decisions["rejected"] += 1
            print(f"[*] 拒绝: {conf['action']} finding={conf['finding_id']} "
                  f"（{conf['summary'][:80]}）")

    state = _wait_state(client, eng_id, {"done", "failed"}, timeout=1200)
    if state != "done":
        raise DemoError(f"engagement 终态为 {state}（预期 done）")
    elapsed = time.monotonic() - started
    print(f"[*] engagement 终态 done（批准 {decisions['approved']} / "
          f"拒绝 {decisions['rejected']}，scan→verify 耗时 {elapsed:.0f}s）")

    # ---- 断言 1：katana 爬行真实发生（双目标单种子） ----
    katana_runs = [
        e for e in _audit_events(eng_dir, "command_executed") if e.get("tool") == "katana"
    ]
    assert katana_runs, "审计链缺少 command_executed tool=katana"
    print(f"[*] 断言通过：审计含 katana 执行记录（exit={katana_runs[0]['exit_code']}）")

    # ---- 断言 2：三类候选自动产出（零种子，triage 分桶覆盖三类） ----
    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    produced = {
        "sqli": [f for f in findings
                 if f["vuln_type"] == "sqli" and DVWA_SQLI_MARK in f["asset"]],
        "xss": [f for f in findings
                if f["vuln_type"] == "xss" and DVWA_XSS_MARK in f["asset"]],
        "idor-1001": [f for f in findings
                      if f["vuln_type"] == "idor" and IDOR_MARKS[0] in f["asset"]],
        "idor-1002": [f for f in findings
                      if f["vuln_type"] == "idor" and IDOR_MARKS[1] in f["asset"]],
    }
    missing = [name for name, hits in produced.items() if not hits]
    assert not missing, f"未自动产出目标候选: {missing}"
    triage = _audit_events(eng_dir, "triage_completed")
    assert triage, "审计链缺少 triage_completed"
    by_type = triage[0].get("created_by_type") or {}
    for vuln_type in EXPECTED_METHOD:
        assert by_type.get(vuln_type, 0) >= 1, (
            f"triage_completed.created_by_type 缺 {vuln_type}: {by_type}"
        )
    buckets: dict[str, int] = {}
    for f in findings:
        buckets[f["state"]] = buckets.get(f["state"], 0) + 1
    print(f"[*] 断言通过：三类候选自动产出（triage created_by_type={by_type}，"
          f"findings 分桶={buckets}，零种子）")

    if skip_l2:
        print("[*] --skip-l2：三类 Hypothesis 自动产出与 L2 闸门消费已验证，"
              "跳过行为验证/Verifier/报告")
        return

    # ---- 断言 3：白名单 4 条全批准（sqli×1 + xss×1 + idor×2） ----
    assert approved_marks == {DVWA_SQLI_MARK, DVWA_XSS_MARK, *IDOR_MARKS}, (
        f"批准标记不齐: {approved_marks}"
    )
    print(f"[*] 断言通过：白名单 4 条全批准（{sorted(approved_marks)}）")

    # ---- 断言 4：三类 probe/command 事件（需求④） ----
    sqlmap_runs = [
        e for e in _audit_events(eng_dir, "command_executed") if e.get("tool") == "sqlmap"
    ]
    assert sqlmap_runs, "审计链缺少 command_executed tool=sqlmap"
    xss_attempts = _audit_events(eng_dir, "xss_probe_attempt")
    canary_hits = [e for e in xss_attempts if e.get("canary")]
    assert canary_hits, "xss_probe_attempt 无 canary 命中"
    idor_attempts = _audit_events(eng_dir, "idor_probe_attempt")
    by_finding: dict[str, list[dict]] = {}
    for event in idor_attempts:
        by_finding.setdefault(event["finding_id"], []).append(event)
    assert idor_attempts, "审计链缺少 idor_probe_attempt"
    print(f"[*] 断言通过：三类 probe/command 事件齐全（sqlmap ×{len(sqlmap_runs)}、"
          f"xss_probe ×{len(xss_attempts)} 命中 canary ×{len(canary_hits)}、"
          f"idor_probe ×{len(idor_attempts)}）")

    # ---- 断言 5：Confirmed 矩阵（需求①②） ----
    violations = _check_confirmed_matrix(findings)
    assert not violations, f"Confirmed 矩阵违规: {violations}"
    confirmed = [f for f in findings if f["state"] == "confirmed"]
    for f in confirmed:
        verification = f["verification"]
        print(f"[*] Confirmed: {f['id']} vuln_type={f['vuln_type']} "
              f"method={verification['method']} 四段式齐全")
        print(f"    verifier={f['verifier']['model']} verdict={f['verifier']['verdict']}")
        print(f"    cvss={f.get('cvss_score')}（{f.get('cvss_vector')}，代码算分不断言）")

    # ---- 断言 6：对照组 1002 REJECTED（需求③） ----
    control = produced["idor-1002"][0]
    assert control["state"] == "rejected", f"1002 对照组未 REJECTED: {control['state']}"
    c_pair = by_finding[control["id"]]
    assert [e["role"] for e in c_pair] == ["reference", "attacker"]
    assert c_pair[0]["status"] == 200 and c_pair[1]["status"] == 403
    print(f"[*] 断言通过：对照组 1002 REJECTED（B=200 / A=403，判定不成立不误报）")

    # ---- 断言 7：三 skill verify_completed + Verifier 带向量 + 预算无异常（需求⑦） ----
    for skill in ("verify-sqli", "verify-xss", "verify-idor"):
        completed = [
            e for e in _audit_events(eng_dir, "verify_completed") if e.get("skill") == skill
        ]
        assert completed and completed[0]["confirmed"] >= 1, f"缺 {skill} 的确认产出"
    verdicts = _audit_events(eng_dir, "verifier_verdict")
    with_vector = [e for e in verdicts if e.get("cvss_vector")]
    assert len(with_vector) >= 3, f"verifier_verdict 带向量不足 3 条: {len(with_vector)}"
    assert not _audit_events(eng_dir, "llm_budget_exceeded"), "审计含 llm_budget_exceeded"
    print(f"[*] 断言通过：三 skill verify_completed 各 confirmed≥1、"
          f"verifier_verdict 带向量 ×{len(with_vector)}、无预算异常")

    # ---- 断言 8：报告构建 + XML 含确认方法字样（需求⑤） ----
    built = _check(
        client.post(
            f"/api/engagements/{eng_id}/report",
            json={"template": "default_template.docx", "narrative": narrative},
        ),
        200,
        "构建报告",
    )
    report_path = eng_dir / built["report"]
    missing_needles = _check_report_xml(report_path)
    assert not missing_needles, f"报告 XML 缺确认方法字样: {missing_needles}"
    print(f"[*] 断言通过：报告构建成功（narrative={narrative}，"
          f"summary={built['summary']}），XML 含 browser-confirmed / "
          "dual-session-confirmed（四段式进报告）")

    # ---- 断言 9：脱敏自检（需求⑥） ----
    leaks = _find_secret_leaks(eng_dir, secrets)
    assert not leaks, f"凭据原文泄漏: {leaks}"
    session_path = eng_dir / "session.json"
    assert (session_path.stat().st_mode & 0o777) == 0o600
    session_data = json.loads(session_path.read_text(encoding="utf-8"))
    assert session_data["reference"]["cookies"]["phsess"] == B_TOKEN
    print("[*] 脱敏自检通过：审计/findings/证据/确认队列均无 PHPSESSID 与 "
          "fixture 双 token 原文（session.json 0600 且 reference 结构正确）")

    # ---- 证据链摘要表 + 报告路径 ----
    evidence_files: dict[str, list[str]] = {}
    for f in confirmed:
        evidence = client.get(
            f"/api/engagements/{eng_id}/findings/{f['id']}/evidence"
        ).json()
        evidence_files[f["id"]] = [item.get("file") for item in evidence["items"]]
    print(_render_summary_table(findings, evidence_files))
    print(f"\n[*] 报告: {report_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ProofHound M8d Killer Demo：三漏洞一键全证据链演示"
    )
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument("--dvwa-url", default="http://127.0.0.1:8080")
    parser.add_argument("--skip-l2", action="store_true",
                        help="只验证到三类 Hypothesis 自动产出（跳过行为验证/Verifier/报告）")
    parser.add_argument("--no-narrative", action="store_true",
                        help="报告跳过 T1 叙述生成（叙述失败时快速复跑）")
    args = parser.parse_args()

    global DEMO_DIR
    target = args.dvwa_url.rstrip("/")
    dvwa_port = urllib.parse.urlparse(target).port or 80
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    DEMO_DIR = REPO_ROOT / "evidence" / "demo_killer" / stamp
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    # 环境预检：LLM 档位 + Docker + Chromium + DVWA
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
        dvwa, dvwa_container = ensure_dvwa(docker_client, target, dvwa_port)
    except DvwaError as exc:
        print(f"[环境错误] {exc}", file=sys.stderr)
        return 2

    _PortalHandler.dvwa_base = target
    server, fixture_url = _start_portal_fixture()
    fixture_port = int(urllib.parse.urlparse(fixture_url).port)
    print(f"[*] 门户 fixture 已启动: {fixture_url}（发票 1001/1002 + DVWA 深链门户）")
    workspace = _make_dual_workspace(DEMO_DIR, [dvwa_port, fixture_port])
    app = create_app(workspace, env_file=args.env_file, confirm_timeout=900.0)
    print(f"[*] API 应用已创建（TestClient，真实编排栈不 mock）：workspace={workspace}")

    try:
        with TestClient(app) as client:
            cookies = dvwa.session_cookies()
            assert cookies.get("security") == "low", cookies
            cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
            cookie_header += f"; phsess={A_TOKEN}"  # 合并 Cookie 头（双站按名取用）
            created = _check(
                client.post(
                    "/api/engagements",
                    json={
                        "target": fixture_url,
                        "scope_paths": ["scope.yaml"],
                        "cookie": cookie_header,
                        "reference_cookie": f"phsess={B_TOKEN}",
                        "autonomy_mode": "semi_auto",
                    },
                ),
                201,
                "创建 engagement（双目标合并会话）",
            )
            eng_id = created["id"]
            assert created["with_session"] is True
            assert created["with_reference_session"] is True
            secrets = [cookies.get("PHPSESSID", ""), A_TOKEN, B_TOKEN]
            assert all(s not in json.dumps(created) for s in secrets if s)
            print(f"[*] engagement 已创建: {eng_id}（semi_auto，target=fixture 门户，"
                  "cookie=DVWA+fixtureA 合并头，reference=fixtureB，零种子）")
            _check(client.post(f"/api/engagements/{eng_id}/run"), 202, "启动")
            run_demo(client, eng_id, args.skip_l2, not args.no_narrative, secrets)
    finally:
        server.shutdown()
        print("\n[*] fixture 应用已停止")
        if dvwa_container is not None:
            print(f"[*] 清理 DVWA 容器 {dvwa_container.short_id}（--rm 自动删除）")
            dvwa_container.stop()

    print("\n" + "=" * 78)
    print(f"[验收通过] M8d Killer Demo 三漏洞全证据链（产物目录: {DEMO_DIR}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
