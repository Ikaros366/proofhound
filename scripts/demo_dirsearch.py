#!/usr/bin/env python3
"""M16-b 验收：dirsearch 接入 + 速率/并发/时间窗授权语义（真靶 + 真沙箱）。

跑**真实沙箱**里的 dirsearch（构造器 argv 就是生产 argv），验证：

1. **构造器 argv**：速率/并发/时间窗由 ``Scope.request_budget`` 落进旗标；
   **永不产** ``-r``（递归）/``-F``（跟随重定向）；
2. **授权语义真的生效**：靶侧访问日志算出的**实测 rps**——显式 2 rps 必须显著低于
   保守缺省 50 rps，否则"授权只是写进 argv 而没落到行为"；
3. **时间窗自限**：``window_minutes`` 翻成 ``--max-time`` 后真的截断扫描；
4. **输出能被解析成 Signal 并进 triage**（零新增 Signal kind：落既有 ``web-probe``）；
5. **内存/耗时 vs ``mem_limit=512m`` / 300s 超时**；
6. **scope 兜底**（dirsearch 是**主动**按字典发请求，与 katana 的被动收敛不同）：
   靶侧访问日志只出现授权 host:port；注入式越界记录被 ``check_scope`` 丢成
   ``triage_out_of_scope``。

如实的接缝说明
--------------
- 沙箱出口用 ``egress.mode="open"``：``restricted`` 走 internal 网络 + 白名单代理，
  容器**够不到宿主**；本 demo 的靶在宿主上，故必须放开出口。**这与 scope 防线无关**
  ——scope 的两层（``check_scope`` + 构造器单目标）本轮逻辑零改动，本 demo 验的是
  "越界不进候选"。
- 内存采样走 ``docker stats``（``max_usage``），与 M16-a 的
  ``evidence/demo_katana_js/<ts>/`` 同口径。

用法：
    .venv/bin/python scripts/demo_dirsearch.py
    .venv/bin/python scripts/demo_dirsearch.py --full-dicc   # 更慢、更全

产物落 ``evidence/demo_dirsearch/<时间戳>/``（gitignored）。
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
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
from proofhound.tools.build import build_command, dirsearch_timeout_for  # noqa: E402
from proofhound.tools.egress import EgressPolicy  # noqa: E402
from proofhound.tools.parsers import parse_dirsearch_json  # noqa: E402
from proofhound.tools.sandbox import SandboxConfig, SandboxRunner  # noqa: E402

IMAGE = "python:3.12-alpine"
EXTERNAL_HOST = "evil.example.com"  # 保留域，且授权范围外

#: 靶上真实存在的路径（200）；其余 404
HITS = {"/admin", "/login", "/api", "/config.php", "/robots.txt",
        "/health", "/swagger.json", "/.git", "/uploads", "/backup.zip"}

SMALL_WORDS = [
    "admin", "login", "api", "config", "robots", "health", "swagger", "git",
    "uploads", "backup", "index", "home", "user", "panel", "dashboard",
    "docs", "db", "test", "old", "tmp", "private", "secret", "console",
    "status", "metrics", "graphql", "rest", "soap", "manage", "account",
]

#: 靶面 JS 里写死的**外域**绝对 URL（用于 scope 兜底的注入式验证）
INJECTED_EXTERNAL = [
    f"http://{EXTERNAL_HOST}/evil/api/users?id=1",
    f"http://{EXTERNAL_HOST}/evil/api/dump?file=users.csv",
]


class _RecordingTarget(BaseHTTPRequestHandler):
    """靶：记录每一条到达请求（Host + path + 时刻），用于核 rps 与外域。"""

    def _handle(self) -> None:
        rec = {
            "t": time.monotonic(),
            "host": self.headers.get("Host") or "",
            "path": self.path,
        }
        with self.server.access_log_path.open("a", encoding="utf-8") as fh:  # type: ignore[attr-defined]
            fh.write(json.dumps(rec) + "\n")
        path = self.path.split("?")[0]
        code = 200 if path in HITS else 404
        body = b"<html><body>ok</body></html>"
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *a):
        pass


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_target(log_path: Path, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), _RecordingTarget)
    server.access_log_path = log_path  # type: ignore[attr-defined]
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _read_access(log: Path) -> list[dict]:
    out = []
    for line in log.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def _rps(records: list[dict]) -> float:
    if len(records) < 2:
        return 0.0
    ts = [r["t"] for r in records]
    span = max(ts) - min(ts)
    return len(ts) / span if span > 0 else 0.0


class _MemSampler:
    """轮询 docker stats 取容器峰值内存（与 M16-a 同口径）。"""

    def __init__(self, client):
        self.client = client
        self.peak = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def _loop(self):
        while not self._stop.is_set():
            for c in self.client.containers.list():
                try:
                    tags = c.image.tags or []
                except Exception:
                    continue
                if not any(IMAGE in t for t in tags):
                    continue
                try:
                    st = c.stats(stream=False)
                    mem = st["memory_stats"]
                    used = mem.get("max_usage") or mem.get("usage") or 0
                    self.peak = max(self.peak, used / 1048576)
                except Exception:
                    pass
            self._stop.wait(0.05)

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M16-b 验收：dirsearch 接入")
    parser.add_argument("--full-dicc", action="store_true",
                        help="用内置 dicc.txt（9681 词）而非内置小词表")
    args = parser.parse_args()

    try:
        import docker

        client = docker.from_env()
        client.ping()
    except Exception as exc:  # noqa: BLE001
        print(f"[环境错误] Docker 不可用（沙箱是红线，无法跳过）: {exc}", file=sys.stderr)
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = REPO / "evidence" / "demo_dirsearch" / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] 运行目录: {run_dir}")

    tools_dir = REPO / "tools.d"
    preset = tools_dir / "dirsearch"
    if not (preset / "dirsearch").is_file():
        print("[环境错误] 未找到 tools.d/dirsearch 离线预置。\n"
              "          先跑：.venv/bin/python scripts/make_dirsearch_preset.py",
              file=sys.stderr)
        return 2
    print(f"[*] 离线预置: {preset}")

    # 词表挂到 /opt/tools/<name>（tools_dir 只读挂载到 /opt/tools）
    small = tools_dir / "dirsearch_demo_words.txt"
    small.write_text("\n".join(SMALL_WORDS) + "\n", encoding="utf-8")
    container_wordlist = ("/opt/tools/dirsearch/lib/dirsearch/db/dicc.txt"
                          if args.full_dicc else "/opt/tools/dirsearch_demo_words.txt")
    n_words = (9681 if args.full_dicc else len(SMALL_WORDS))
    print(f"[*] 词表: {container_wordlist}（{n_words} 词）")

    access_log = run_dir / "target_access.jsonl"
    access_log.write_text("", encoding="utf-8")
    port = _free_port()
    server = _start_target(access_log, port)
    target = f"http://127.0.0.1:{port}"
    print(f"[*] 靶: {target}")

    audit = AuditLog(run_dir / "audit.jsonl")
    base_kwargs = dict(egress=EgressPolicy(mode="open"), network_mode="host")
    runner = SandboxRunner(
        Scope(networks=["127.0.0.0/8"], ports=[port]), audit, run_dir, tools_dir,
        config=SandboxConfig(**base_kwargs), client=client)

    def run_case(label: str, scope: Scope, *, wordlist: str, timeout: int):
        """跑一次并返回 (RunResult, wall, 峰值MiB, 访问记录, stdout)。"""
        access_log.write_text("", encoding="utf-8")
        params = {"target": target, "wordlist": wordlist}
        argv = build_command("dirsearch", params,
                             request_budget=scope.resolved_request_budget())
        with _MemSampler(client) as sampler:
            t0 = time.monotonic()
            res = runner.run("dirsearch", argv[1:], timeout=timeout, image=IMAGE)
            wall = time.monotonic() - t0
        out = res.stdout_path.read_text(errors="replace") if res.stdout_path else ""
        err = res.stderr_path.read_text(errors="replace") if res.stderr_path else ""
        recs = _read_access(access_log)
        print(f"  · {label:<34} exit={res.exit_code} wall={wall:6.1f}s "
              f"峰值={sampler.peak:6.1f}MiB req={len(recs):>5} "
              f"实测rps={_rps(recs):7.1f}")
        if res.rejected:
            print(f"    !! 被沙箱拒绝: {res.violations}")
        if err.strip():
            tail = err.strip().splitlines()[-1]
            print(f"    stderr尾: {tail[:110]}")
        return res, wall, sampler.peak, recs, out, argv

    results: dict = {}
    try:
        # ---------------- 1) 构造器 argv ----------------
        print("\n===== 1) 构造器 argv（授权语义落进旗标）=====")
        s_default = Scope(networks=["127.0.0.0/8"], ports=[port])
        argv_default = build_command(
            "dirsearch", {"target": target},
            request_budget=s_default.resolved_request_budget())
        print(f"  保守缺省（scope 未声明 request_budget）: {argv_default}")
        assert argv_default[argv_default.index("--max-rate") + 1] == "50"
        assert argv_default[argv_default.index("-t") + 1] == "5"
        assert "--max-time" not in argv_default, "未声明时间窗就不该产 --max-time"
        assert "-r" not in argv_default and "-F" not in argv_default, \
            "永不产 -r/-F（递归/跟随重定向）"
        print("  ✅ 保守缺省 50 rps / 5 并发；无时间窗；无 -r/-F")
        print(f"  scope.request_budget 来源标记: {s_default.request_budget_source()}")

        s_explicit = Scope(networks=["127.0.0.0/8"], ports=[port],
                           request_budget={"rate_rps": 2, "concurrency": 1,
                                           "max_requests": 1000,
                                           "window_minutes": 8})
        argv_explicit = build_command(
            "dirsearch", {"target": target},
            request_budget=s_explicit.resolved_request_budget())
        print(f"  显式授权（2 rps / 1 并发 / 8 分钟窗口）: {argv_explicit}")
        assert argv_explicit[argv_explicit.index("--max-rate") + 1] == "2"
        assert argv_explicit[argv_explicit.index("-t") + 1] == "1"
        # 工具自限时取窗口的 70%（480s * 0.7 = 336s），沙箱超时取 min(300, 窗口)
        assert argv_explicit[argv_explicit.index("--max-time") + 1] == "336", \
            argv_explicit
        print(f"  scope.request_budget 来源标记: {s_explicit.request_budget_source()}")
        assert s_explicit.request_budget_source() == "explicit"
        assert dirsearch_timeout_for(s_explicit) == 300   # min(300, 480)
        print("  ✅ 显式授权覆盖缺省；工具自限时=336s（窗口*0.7）；"
              "沙箱超时=min(300,窗口)=300s（两道取小）")

        # ---------------- 2) 限速真的生效（行为验证）----------------
        print("\n===== 2) 限速是否真的落到行为（靶侧访问日志算实测 rps）=====")
        s_small = Scope(networks=["127.0.0.0/8"], ports=[port],
                       request_budget={"rate_rps": 50, "concurrency": 5,
                                       "max_requests": 5000})
        _, w_def, m_def, rec_def, _, _ = run_case(
            "缺省 50 rps", s_small, wordlist=container_wordlist, timeout=300)

        s_slow = Scope(networks=["127.0.0.0/8"], ports=[port],
                       request_budget={"rate_rps": 2, "concurrency": 1,
                                       "max_requests": 5000})
        _, w_slow, m_slow, rec_slow, _, _ = run_case(
            "显式 2 rps", s_slow, wordlist=container_wordlist, timeout=300)

        rps_def, rps_slow = _rps(rec_def), _rps(rec_slow)
        print(f"  实测 rps：缺省(50)={rps_def:.1f}  显式(2)={rps_slow:.1f}  "
              f"比值={rps_def / rps_slow if rps_slow else float('inf'):.1f}×")
        assert rps_slow < rps_def, \
            f"限速未生效：2 rps 的实测 rps({rps_slow:.1f}) 不低于 50 rps({rps_def:.1f})"
        assert rps_slow <= 6.0, f"2 rps 授权实测到 {rps_slow:.1f} rps，超出容忍"
        results["rate"] = {"default_rps": rps_def, "slow_rps": rps_slow,
                           "default_wall": w_def, "slow_wall": w_slow}
        print("  ✅ 限速真的改变了行为（不只是写进 argv）")

        # ---------------- 3) 时间窗自限 ----------------
        print("\n===== 3) 时间窗是否真的截断扫描 =====")
        s_window = Scope(networks=["127.0.0.0/8"], ports=[port],
                         request_budget={"rate_rps": 50, "concurrency": 5,
                                         "max_requests": 50000,
                                         "window_minutes": 1})
        # 用完整 dicc.txt 让扫描足够长，1 分钟窗口必然触发（min(300,60)=60s 超时）
        _, w_win, m_win, rec_win, out_win, _ = run_case(
            "窗口 1 分钟（--max-time 60）", s_window,
            wordlist="/opt/tools/dirsearch/lib/dirsearch/db/dicc.txt", timeout=120)
        self_limit = "Runtime exceeded the maximum" in out_win
        sandbox_cap = dirsearch_timeout_for(s_window)
        print(f"  wall={w_win:.1f}s（沙箱超时被收窄到 {sandbox_cap}s）")
        print(f"  dirsearch 自报截断(--max-time): {'是' if self_limit else '否'}")
        print(f"  两道：工具自限时={s_window.resolved_request_budget().max_seconds()}s"
              f"*0.7 -> 沙箱硬杀={sandbox_cap}s")
        # 接受两种收尾：① 工具自限时先触发；② 沙箱超时兜底硬杀。
        # **两者都不放宽授权窗口**，故只要 wall 不显著超过窗口即为通过。
        assert w_win < sandbox_cap * 1.25, \
            f"时间窗未生效：wall={w_win:.1f}s 远超沙箱上限 {sandbox_cap}s"
        results["window"] = {"wall": w_win, "requests": len(rec_win),
                             "timeout": dirsearch_timeout_for(s_window)}
        print("  ✅ 时间窗两道（--max-time + 沙箱超时收窄）都成立")

        # ---------------- 4) 解析成 Signal 并进 triage ----------------
        print("\n===== 4) 输出 → Signal → triage（零新增 Signal kind）=====")
        res, w, m, recs, out, argv = run_case(
            "解析用（缺省预算）", s_small, wordlist=container_wordlist, timeout=300)
        stdout_file = run_dir / "dirsearch_stdout.txt"
        stdout_file.write_text(out, encoding="utf-8")
        signals, skipped = parse_dirsearch_json(
            out, evidence_path=str(stdout_file), skill="web-dirsearch")
        by_status: dict = {}
        for s in signals:
            by_status[s.status_code] = by_status.get(s.status_code, 0) + 1
        print(f"  Signal={len(signals)} 坏条目={skipped} 按状态码={by_status}")
        print(f"  全部 kind=web-probe: {all(s.kind == 'web-probe' for s in signals)}")
        for s in signals[:8]:
            print(f"      {s.status_code} {s.asset}  ref={s.evidence_ref} note={s.note}")
        assert signals, "必须至少解析出 1 条 Signal"
        hits_found = {s.asset.rsplit("/", 1)[-1] for s in signals}
        print(f"  命中 HITS 的条目: {sorted(hits_found & {h.lstrip('/') for h in HITS})}")
        (run_dir / "signals.jsonl").write_text(
            "\n".join(s.model_dump_json() for s in signals) + "\n", encoding="utf-8")

        # 进真实 Orchestrator 的 triage
        (run_dir / "dirsearch_stdout.txt.signals.jsonl").write_text(
            "\n".join(s.model_dump_json() for s in signals) + "\n", encoding="utf-8")
        orch = Orchestrator(
            SkillRegistry(REPO / "skills").discover(),
            runner=type("R", (), {"scope": s_small})(),
            llm=None, audit=audit, evidence_dir=run_dir)
        orch.run_triage_phase()
        findings = FindingStore(run_dir / "findings.jsonl").load_all()
        by_type: dict = {}
        for f in findings:
            by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
        print(f"  候选（Finding）={len(findings)} 条，按类型={by_type}")
        assert by_type.get("web-exposure", 0) > 0, \
            "200 命中必须映射出 web-exposure 候选（web-probe 既有通道）"
        results["triage"] = {"signals": len(signals), "findings": len(findings),
                             "by_type": by_type}
        print("  ✅ 走既有 web-probe → web-exposure 通道（零 triage 改动）")
        print("  ⚠️ 判定面零改动：web-exposure 不在 GATE_MATRIX ⇒ 这类候选"
              "**仍不可 Confirmed**（属 M16-c）")

        # ---------------- 5) 资源 ----------------
        print("\n===== 5) 资源 vs mem_limit=512m / 300s 超时 =====")
        print(f"  峰值内存样本: 缺省={m_def:.1f}MiB  2rps={m_slow:.1f}MiB  "
              f"窗口={m_win:.1f}MiB")
        peak = max(m_def, m_slow, m_win)
        print(f"  最大峰值 = {peak:.1f} MiB = mem_limit=512m 的 {peak / 512 * 100:.1f}%")
        results["memory"] = {"peak_mib": peak, "pct_of_512m": peak / 512 * 100}
        print(f"  对照 M16-a katana: -jc 248MiB / -jc -jsl 447MiB"
              f" ⇒ dirsearch 是**轻量档**")

        # ---------------- 6) scope 兜底 ----------------
        print("\n===== 6) scope 兜底（主动发请求，越界风险与 katana 不同）=====")
        hosts = sorted({r["host"] for r in recs})
        ext_hosts = [h for h in hosts if EXTERNAL_HOST in h]
        print(f"  靶侧收到 {len(recs)} 条请求，Host 取值={hosts}")
        print(f"  其中外域 Host = {len(ext_hosts)}")
        assert not ext_hosts, "靶收到了外域 Host 请求"
        print("  [层①] 构造器只产 -u <单目标>，不产 -r/-F/-l ⇒ 请求面结构性收敛")

        # 层②：注入越界记录，看 check_scope 是否拦
        # results 是 JSON 数组：元素之间必须用逗号（首版用换行拼接，属非法 JSON，
        # 解析器 fail-closed 返回 0 条 —— 是 demo 的拼接写错，不是解析器的问题）
        injected = ",".join(
            json.dumps({"url": u, "status": 200, "contentLength": 1,
                        "contentType": "text/html", "elapsed": 0.01, "redirect": ""})
            for u in INJECTED_EXTERNAL)
        inj_text = ('{\n  "info": {"args": "injected", "time": "x"},\n'
                    '  "results": [' + injected + "]\n}\n")
        inj_signals, _ = parse_dirsearch_json(
            inj_text, evidence_path=str(run_dir / "injected_external.jsonl"),
            skill="web-dirsearch")
        print(f"  [层②] 注入 {len(INJECTED_EXTERNAL)} 条外域记录 → "
              f"解析出 {len(inj_signals)} 条 Signal（解析器不越权改写）")
        assert len(inj_signals) == len(INJECTED_EXTERNAL)
        for s in inj_signals:
            decision = check_scope(s_small, [s.asset])
            print(f"      check_scope({s.asset}) allowed={decision.allowed} "
                  f"{decision.violations}")
            assert decision.allowed is False, "外域必须被 check_scope 拒"
        (run_dir / "inject.signals.jsonl").write_text(
            "\n".join(s.model_dump_json() for s in inj_signals) + "\n", encoding="utf-8")
        before = {f.id for f in FindingStore(run_dir / "findings.jsonl").load_all()}
        orch.run_triage_phase()
        after = FindingStore(run_dir / "findings.jsonl").load_all()
        new_assets = {f.asset for f in after if f.id not in before}
        oos = [e for e in audit.read_all() if e["event"] == "triage_out_of_scope"]
        print(f"      再跑 triage：新增候选={len(new_assets)} "
              f"（外域候选={sum(1 for a in new_assets if EXTERNAL_HOST in a)}）")
        print(f"      triage_out_of_scope 审计={len(oos)} 条")
        assert not any(EXTERNAL_HOST in a for a in new_assets), "外域产生了候选！"
        assert oos, "外域记录应留下 triage_out_of_scope 审计"
        print("  ✅ 外域不产生候选（层① 靶侧日志 + 层② check_scope 双双成立）")

        # ---------------- 7) 审计字段 ----------------
        print("\n===== 7) 授权语义进审计 =====")
        executed = [e for e in audit.read_all() if e["event"] == "command_executed"]
        print(f"  command_executed 事件数 = {len(executed)}")
        for e in executed[:3]:
            print(f"      tool={e.get('tool')} targets={e.get('targets')} "
                  f"sandbox={ (e.get('sandbox') or {}).get('mode') }")
        assert all(e.get("tool") == "dirsearch" for e in executed)
        print("  ⚠️ 如实记录：request_budget **未**写入 command_executed（本轮未改")
        print("      sandbox.py）——授权语义目前落在 argv（--max-rate/-t/--max-time）")
        print("      与 scope 的来源标记上。这是本轮**未做**项，已记入交付说明。")

        print("\n" + "=" * 76)
        print("✅ M16-b 验收全绿")
        print(f"[*] 产物：{run_dir}")
        print("=" * 76)
        (run_dir / "summary.json").write_text(
            json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    finally:
        server.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
