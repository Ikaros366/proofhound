#!/usr/bin/env python3
"""M8c 实弹验收 demo（不进 pytest）：verify-idor 双会话属性验证全链路（零种子）。

不用 DVWA（无 IDOR 页面）：stdlib http.server 起 fixture 应用——

- 两个用户身份（cookie phsess=<token>，token ≥16 字符使裸值也纳入脱敏）；
- 发票对象 /invoice?id=1001 属 b，**无授权判断**（a 访问同样 200 同内容）；
- 对照组 /invoice?id=1002 属 b，**有授权判断**（a 访问 403）；
- 首页列出两张发票链接（katana 带 a 会话爬行可发现）；无有效 cookie → 302 登录页。

链路（TestClient 起真实 API + 真实编排栈，不 mock 任何闸门）：

fixture 就绪 → 带双会话（cookie=a / reference_cookie=b）创建 semi_auto
engagement → POST /run → katana 沙箱爬行 → triage 自动产出 idor 候选
（param=id 命中 _IDOR_PARAM_HINTS；同产 sqli 候选是设计行为）→ L2 确认
队列：批准全部 verify-idor 条目、拒绝 verify-sqli 条目 → 双会话验证：
1001 属性违反成立 → 证据门 → Verifier T2 终审 → Confirmed；1002 判定不
成立 → REJECTED（对照组证明不误报）。

断言（机制层，不断言漏洞结论之外的内容）：审计链完整（katana 执行 +
idor_probe_attempt 成对（M11b 起三条：reference/attacker/未认证对照）+
action_read_only_auto + verifier_verdict +
verify_completed）、判定 JSON 落盘含相似度数值、method=
dual-session-confirmed、四段式齐全、双会话凭据全目录无原文（除
session.json，0600）。

用法：
    .venv/bin/python scripts/demo_idor_fixture.py              # 全链路（需 T1+T2+Docker）
    .venv/bin/python scripts/demo_idor_fixture.py --skip-l2    # 只验到 idor Hypothesis 自动产出

.env 需要：PROOFHOUND_T1_*（web-scan/recon-crawl 规划）；全链路另需
PROOFHOUND_T2_*（Verifier 终审）。不需要 Chromium。产物落
evidence/demo_idor/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用 demo_discovery_dvwa 骨架

from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.llm.client import LLMError
from proofhound.llm.router import ModelRouter, Tier

from demo_discovery_dvwa import (
    DemoError,
    _audit_events,
    _check,
    _make_workspace,
    _wait_pending,
    _wait_state,
)

A_TOKEN = "a1b2c3d4e5f60718"  # 身份 A（主会话，低权限/攻击者视角）
B_TOKEN = "8071f6e5d4c3b2a1"  # 身份 B（reference/victim，发票属主）
TOKENS = {"phsess": {A_TOKEN: "a", B_TOKEN: "b"}}
DEMO_DIR: Path


# ---- fixture 应用（stdlib http.server，双身份 + 有/无授权判断两对象） ----


def _invoice_body(inv_id: str, identity: str) -> str:
    """发票页（属主 b；嵌入当前会话 token 以演练证据脱敏路径）。"""
    token = {"a": A_TOKEN, "b": B_TOKEN}[identity]
    items = "".join(f"<li>明细行 {i}：服务费 ¥1,000.00</li>" for i in range(1, 9))
    return (
        f"<html><head><title>发票 #{inv_id}</title></head><body>"
        # M11b：用真实归属字段名 ``所有者``（``属主`` 属泛化叙述词，刻意不收）
        f"<h1>发票 #{inv_id}</h1><p>金额 ¥8,000.00（所有者：b）</p>"
        f"<ul>{items}</ul>"
        f"<footer>当前登录会话 phsess={token}（fixture 回显以演练脱敏）</footer>"
        f"</body></html>"
    )


class _FixtureHandler(BaseHTTPRequestHandler):
    """fixture：/ 列发票链接；/invoice?id=1001 无授权判断（漏洞）；

    /invoice?id=1002 有授权判断（对照组，a→403）；无有效 cookie → 302 登录页。
    """

    def _identity(self) -> str | None:
        cookie = self.headers.get("Cookie") or ""
        for segment in cookie.split(";"):
            name, _, value = segment.strip().partition("=")
            if name == "phsess":
                return TOKENS["phsess"].get(value)
        return None

    def _respond(self, status: int, body: str, extra: dict | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802（BaseHTTPRequestHandler 约定）
        identity = self._identity()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if identity is None and path != "/login":
            self._respond(302, "", extra={"Location": "/login"})
            return
        if path == "/":
            self._respond(
                200,
                "<html><body><h1>发票系统</h1><nav>"
                '<a href="/invoice?id=1001">发票 1001</a>'
                '<a href="/invoice?id=1002">发票 1002</a>'
                "</nav></body></html>",
            )
            return
        if path == "/login":
            self._respond(200, "<html><body>请登录</body></html>")
            return
        if path == "/invoice":
            inv_id = (query.get("id") or [""])[0]
            if inv_id == "1001":
                self._respond(200, _invoice_body("1001", identity))  # 漏洞：无授权判断
                return
            if inv_id == "1002":
                if identity != "b":  # 对照组：有授权判断
                    self._respond(403, "<html><body>Forbidden</body></html>")
                    return
                self._respond(200, _invoice_body("1002", identity))
                return
        self._respond(404, "not found")

    def log_message(self, *args):
        pass


def _start_fixture() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    return server, f"http://127.0.0.1:{port}"


# ---- 全链路 ----


def run_demo(client: TestClient, eng_id: str, skip_l2: bool) -> None:
    eng_dir = DEMO_DIR / "workspace" / "engagements" / eng_id

    print("[*] 已启动（异步）；scan/triage 自动推进，等待首个 L2 确认或终态 ...")
    approved: list[str] = []
    rejected = 0
    while True:
        conf = _wait_pending(client, eng_id, timeout=900)
        if conf is None:
            break
        if not skip_l2 and conf["action"] == "verify-idor":
            _check(
                client.post(
                    f"/api/confirmations/{conf['cid']}/approve",
                    json={"operator": "demo-operator",
                          "note": "演示授权：批准 IDOR 双会话属性验证"},
                ),
                200,
                "批准确认",
            )
            approved.append(conf["cid"])
            print(f"[*] 批准 verify-idor: cid={conf['cid']} finding={conf['finding_id']}")
            print(f"    summary: {conf['summary']}")
        else:
            note = ("skip-l2 演示收尾" if skip_l2 else "演示：非 verify-idor 条目，拒绝")
            _check(
                client.post(
                    f"/api/confirmations/{conf['cid']}/reject",
                    json={"operator": "demo-operator", "note": note},
                ),
                200,
                "拒绝确认",
            )
            rejected += 1
            print(f"[*] 拒绝: {conf['action']} finding={conf['finding_id']} "
                  f"（{conf['summary'][:80]}）")

    state = _wait_state(client, eng_id, {"done", "failed"}, timeout=1200)
    if state != "done":
        raise DemoError(f"engagement 终态为 {state}（预期 done）")
    print(f"[*] engagement 终态 done（批准 {len(approved)} / 拒绝 {rejected}）")

    # ---- 断言 1：审计含 command_executed tool=katana（爬行真实发生） ----
    katana_runs = [
        e for e in _audit_events(eng_dir, "command_executed") if e.get("tool") == "katana"
    ]
    assert katana_runs, "审计链缺少 command_executed tool=katana"
    print(f"[*] 断言通过：审计含 katana 执行记录（exit={katana_runs[0]['exit_code']}）")

    # ---- 断言 2：idor Hypothesis 自动产出（零种子，param=id 命中） ----
    findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    idor_findings = {f["asset"]: f for f in findings if f["vuln_type"] == "idor"}
    target = next((f for a, f in idor_findings.items() if "id=1001" in a), None)
    assert target is not None, f"未自动产出 /invoice?id=1001 的 idor Finding（{list(idor_findings)}）"
    assert target["param"] == "id" and "crawl-endpoint" in target["evidence_kinds"]
    print(f"[*] 断言通过：idor Finding 自动产出（{target['id']} param=id，零种子）")
    control = next((f for a, f in idor_findings.items() if "id=1002" in a), None)

    if skip_l2:
        print("[*] --skip-l2：idor Hypothesis 自动产出与 L2 闸门消费已验证，跳过后续")
        return

    # ---- 断言 3：idor_probe_attempt 成对（reference/attacker，按次计数） ----
    attempts = _audit_events(eng_dir, "idor_probe_attempt")
    assert attempts, "审计链缺少 idor_probe_attempt"
    by_finding: dict[str, list[dict]] = {}
    for event in attempts:
        by_finding.setdefault(event["finding_id"], []).append(event)
    pair = by_finding[target["id"]]
    # M11b：除 reference/attacker 外，新增**未认证对照**请求（角色固定第三位）
    assert [e["role"] for e in pair] == [
        "reference",
        "attacker",
        "unauthenticated_control",
    ], pair
    print(f"[*] 断言通过：idor_probe_attempt 三条按次（{target['id']}："
          f"reference={pair[0]['status']} attacker={pair[1]['status']} "
          f"control={pair[2]['status']}）")

    # ---- 断言 3b（M11b 新增）：确定性对照 + 归属结论 ----
    control_doc = json.loads(
        (eng_dir / f"idor_{target['id']}_control.json").read_text(encoding="utf-8")
    )
    ctrl = control_doc["unauthenticated_control"]
    own = control_doc["object_ownership"]
    assert ctrl["verdict"] == "protected", ctrl
    assert own["verdict"] == "matched", own
    assert own["line_anchor"] is not None, own
    assert control_doc["baseline_body_sha256"] != control_doc["control_body_sha256"]
    print(f"[*] 断言通过：未认证对照={ctrl['verdict']}（control 状态 "
          f"{ctrl['control_status']}）· 对象归属={own['verdict']}"
          f"（字段 {own['field']}，行 {own['line_anchor']}）")

    # ---- 断言 4：1001 → Confirmed（method + 四段式 + 判定 JSON 数值） ----
    assert target["state"] == "confirmed", f"1001 未 Confirmed: {target['state']}"
    verification = target["verification"]
    assert verification["method"] == "dual-session-confirmed", verification
    assert "behavioral" in target["evidence_kinds"]
    for key in ("claim", "expected", "actual"):
        assert verification.get(key), f"四段式缺 {key}"
    print(f"[*] Confirmed: {target['id']} method={verification['method']}")
    print(f"    verifier={target['verifier']['model']} verdict={target['verifier']['verdict']}")
    print(f"    cvss={target.get('cvss_vector')} score={target.get('cvss_score')}")
    j_paths = sorted(eng_dir.glob(f"idor_{target['id']}_judgment.json"))
    assert j_paths, "判定 JSON 未落盘"
    judgment = json.loads(j_paths[0].read_text(encoding="utf-8"))
    assert judgment["violation"] is True
    assert judgment["b_status"] == 200 and judgment["a_status"] == 200
    assert judgment["similarity"] >= judgment["thresholds"]["similarity"]
    print(f"[*] 断言通过：判定 JSON 落盘（similarity={judgment['similarity']:.3f} "
          f"≥ {judgment['thresholds']['similarity']}，violation=true）")

    # ---- 断言 5：对照组 1002 → REJECTED（证明不误报；未被爬则记录说明） ----
    if control is None:
        print("[*] 对照组说明：/invoice?id=1002 未被爬出（a 访问 403），接受缺省路径")
    else:
        assert control["state"] == "rejected", f"1002 对照组未 REJECTED: {control['state']}"
        c_attempts = by_finding.get(control["id"], [])
        # M11b：三条按次审计（第三位是未认证对照）
        assert [e["role"] for e in c_attempts][:2] == ["reference", "attacker"]
        assert len(c_attempts) == 3 and c_attempts[2]["role"] == "unauthenticated_control"
        assert c_attempts[0]["status"] == 200 and c_attempts[1]["status"] == 403
        print(f"[*] 断言通过：对照组 1002 REJECTED（B=200 / A=403，判定不成立不误报）")

    # ---- 审计链：M9c③ 起 semi_auto 下只读 L2 验证自动执行，不进确认队列 ----
    # 人工闸细分只对「写操作」保留确认（唯一差异格 = semi_auto × L2 只读），
    # 故这里断言的不再是 action_approved，而是闸门如实记下的自动放行。
    assert not _audit_events(eng_dir, "action_approved"), (
        "semi_auto 下只读验证不应出现人工批准"
    )
    auto_events = [
        e for e in _audit_events(eng_dir, "action_read_only_auto")
        if e.get("action") == "verify-idor"
    ]
    assert auto_events, "审计链缺少 action_read_only_auto(verify-idor)"
    assert all(e.get("mode") == "semi_auto" for e in auto_events), auto_events
    verdicts = _audit_events(eng_dir, "verifier_verdict")
    assert verdicts and verdicts[0].get("cvss_vector"), "verifier_verdict 缺 CVSS 向量"
    completed = [e for e in _audit_events(eng_dir, "verify_completed")
                 if e.get("skill") == "verify-idor"]
    assert completed and completed[0]["confirmed"] >= 1
    print("[*] 只读自动执行审计事件原文（首条）:\n    "
          f"{json.dumps(auto_events[0], ensure_ascii=False)}")
    print(f"[*] 断言通过：审计链完整（action_read_only_auto ×{len(auto_events)} + "
          f"verifier_verdict 带向量 + verify_completed confirmed={completed[0]['confirmed']}）")

    # ---- 断言 7：双会话凭据全目录无原文（除 session.json）+ 0600 ----
    leaks = []
    for path in eng_dir.rglob("*"):
        if path.is_file() and path.name != "session.json":
            content = path.read_bytes()
            for token in (A_TOKEN, B_TOKEN):
                if token.encode() in content:
                    leaks.append(f"{path}（含 {'A' if token == A_TOKEN else 'B'} token）")
    assert not leaks, f"会话凭据原文泄漏: {leaks}"
    session_path = eng_dir / "session.json"
    assert (session_path.stat().st_mode & 0o777) == 0o600
    session_data = json.loads(session_path.read_text(encoding="utf-8"))
    assert session_data["reference"]["cookies"]["phsess"] == B_TOKEN
    print("[*] 双会话脱敏自检通过：审计/findings/证据/确认队列均无 A/B token 原文"
          "（session.json 0600 且 reference 结构正确）")


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M8c verify-idor fixture 实弹验收")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument("--skip-l2", action="store_true",
                        help="只验证到 idor Hypothesis 自动产出（跳过双会话验证/Verifier）")
    args = parser.parse_args()

    global DEMO_DIR
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    DEMO_DIR = REPO_ROOT / "evidence" / "demo_idor" / stamp
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    # 环境预检：LLM 档位 + Docker（katana 沙箱）
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

        docker.from_env().ping()
    except Exception as exc:
        print(f"[环境错误] Docker 不可用（沙箱执行是红线，无法跳过）: {exc}",
              file=sys.stderr)
        return 2

    server, target = _start_fixture()
    port = int(urllib.parse.urlparse(target).port)
    print(f"[*] fixture 应用已启动: {target}（身份 A/B 双会话，1001 漏洞 / 1002 对照）")
    workspace = _make_workspace(DEMO_DIR, port)
    app = create_app(workspace, env_file=args.env_file, confirm_timeout=900.0)
    print(f"[*] API 应用已创建（TestClient，真实编排栈不 mock）：workspace={workspace}")

    try:
        with TestClient(app) as client:
            created = _check(
                client.post(
                    "/api/engagements",
                    json={
                        "target": target,
                        "scope_paths": ["scope.yaml"],
                        "cookie": f"phsess={A_TOKEN}",
                        "reference_cookie": f"phsess={B_TOKEN}",
                        # M11b：对象页展示的属主标识是 ``b``（与会话凭据不同源），
                        # 故显式声明归属比对期望值
                        "reference_identity": "b",
                        "autonomy_mode": "semi_auto",
                    },
                ),
                201,
                "创建 engagement（双会话）",
            )
            eng_id = created["id"]
            assert created["with_session"] is True
            assert created["with_reference_session"] is True
            assert A_TOKEN not in json.dumps(created) and B_TOKEN not in json.dumps(created)
            print(f"[*] engagement 已创建: {eng_id}（semi_auto，cookie=A reference=B，零种子）")
            _check(client.post(f"/api/engagements/{eng_id}/run"), 202, "启动")
            run_demo(client, eng_id, args.skip_l2)
    finally:
        server.shutdown()
        print("\n[*] fixture 应用已停止")

    print("\n" + "=" * 72)
    print(f"[验收通过] M8c verify-idor 双会话属性验证全链路（产物目录: {DEMO_DIR}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
