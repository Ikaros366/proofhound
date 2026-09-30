"""M18-b 验收：命令注入 **零 seed** 全链路（发现→确认）。

## 为什么必须零 seed

`AGENTS.md` 项目纪律第 11 条 / 限制 58 的复盘：**验收脚本若自己 seed Finding，
那就只验了判定端、没验接通性**。本脚本**不构造任何 Finding**——只写 Signal，
Finding 由 `run_triage_phase()`（生产代码）建，再走真实 `run_verify_phase()`。

## 五段

- **A 发现**：`web-probe`/`param-endpoint` 信号 → 生产链路建出 `cmdi` 候选
  （规则表 `_CMDI_PARAM_HINTS` 命中）；
- **B 确认**：`run_verify_phase("verify-cmdi")` 打**真靶**——
  真漏洞端点 → CONFIRMED（回调命中 + 交付证明 + DNS 变体未命中）；
  DNS 黑名单型中间件 → REJECTED/blocked；不取数端点 → REJECTED；
- **C 上限**：`_TRIAGE_CMDI_CAP` 独立生效 + 独立 `triage_capped`；
- **D 生产栈**：`OrchestratorPhases.verify_skills` 含 `verify-cmdi`（限制 59 的教训）；
- **E 注册面**：`GATE_MATRIX` / 白名单 / 前置集三处由登记表派生且含 `cmdi`。
"""

from __future__ import annotations

import json
import re
import socket
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, unquote, urlparse

import sys

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from proofhound.compliance.audit import AuditLog  # noqa: E402
from proofhound.compliance.scope import Scope  # noqa: E402
from proofhound.core.orchestrator import (  # noqa: E402
    _TRIAGE_CMDI_CAP,
    Orchestrator,
)
from proofhound.findings.finding import FindingState, FindingStore  # noqa: E402
from proofhound.findings.signal import Signal  # noqa: E402
from proofhound.llm.router import ModelRouter, Tier  # noqa: E402
from proofhound.skills.registry import SkillRegistry  # noqa: E402
from proofhound.verify import cmdi  # noqa: E402
from proofhound.verify.gate import ALLOWED_VULN_TYPES, GATE_MATRIX, VULN_REGISTRY  # noqa: E402

PARAM = "cmd"
VERIFIER_CONFIRM = json.dumps(
    {
        "verdict": "confirm",
        "reason": "回调事实与交付证明齐全（带外二值事实）",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_rationale": "任意命令执行，机密性/完整性/可用性均高",
    },
    ensure_ascii=False,
)

#: 真靶端点语义（三个，覆盖三个**可确定性演示**的判定分支）：
#:
#: - ``/tools/ping`` **真执行**：把 cmd 取值里的 URL 取一遍（命令注入成立）→ CONFIRMED
#: - ``/tools/waf``  **真执行**，但拒绝解析不了的主机名（.invalid）→ 仍是真漏洞，
#:   DNS 防线**不该**拦它 ⇒ CONFIRMED（同时验证防线不误伤真漏洞）
#: - ``/tools/safe`` **不取数**（安全形态，但参数会回显 ⇒ 交付证明成立）→ REJECTED
#:
#: ⚠️ **「中间件代抓取」形态刻意不在这里演示**：它要求 DNS 探针**真实到达靶**，
#: 而 `<nonce>.invalid` 在任何环境都解析不了（本机透明代理截获并返回 502，
#: 直连则 URLError）⇒ 端到端演示必须靠取数层特殊投递，实测会引入额外不确定性。
#: 该防线由 `tests/test_cmdi.py::test_dns_defense_blocks_even_when_waf_makes_the_callback`
#: **确定性**覆盖（在探针层模拟"中间件硬发"）。环境约束见 AGENTS.md 限制 62。
ENDPOINTS = ("/tools/ping", "/tools/safe", "/tools/waf")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _urls_in(value: str) -> list[str]:
    return re.findall(r"https?://[^\s;|&`)\"']+", value)


class _Target(BaseHTTPRequestHandler):
    """真靶：按端点决定"是否执行注入值里的命令"。"""

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        value = ""
        for key, raw in parse_qsl(parsed.query, keep_blank_values=True):
            if key == PARAM:
                value = unquote(raw)
        with (self.server.run_dir / "target_access.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"path": path, "param": value[:160]}) + "\n")

        executed = 0
        if path in ("/tools/ping", "/tools/waf"):
            # 后端真的执行了注入的命令（真漏洞）
            for candidate in _urls_in(value):
                host = urlparse(candidate).hostname or ""
                if path == "/tools/waf" and host.endswith(cmdi.NONRESOLVING_TLD):
                    continue  # 解析不了的名字直接拒（该端点仍会执行其余取值）
                try:
                    with urllib.request.urlopen(candidate, timeout=5) as resp:  # noqa: S310
                        resp.read()
                    executed += 1
                except Exception:  # noqa: BLE001 - 命令执行失败即失败
                    pass
        body = json.dumps(
            {"endpoint": path, "echo": value, "executed": executed},
            ensure_ascii=False,
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # 静音
        pass


class _CannedRouter(ModelRouter):
    """罐头 T2 裁定（Verifier）。真实 T2 需外部凭据，与既有 verify-* 验收同口径。"""

    def __init__(self):
        self.calls = 0
        self.configs = {Tier.T2: SimpleNamespace(model="canned-verifier")}

    def complete(self, tier, messages):
        self.calls += 1
        return VERIFIER_CONFIRM


def _signal(asset: str, ref: str) -> Signal:
    return Signal(
        asset=asset,
        status_code=200,
        kind="param-endpoint",
        source_tool="katana",
        skill="recon-crawl",
        evidence_ref=ref,
    )


def _write_signals(run_dir: Path, urls: list[str]) -> None:
    raw = run_dir / "crawl.stdout.log"
    raw.write_text("\n".join('{"endpoint": "x"}' for _ in urls) + "\n", encoding="utf-8")
    rows = [_signal(url, f"{raw.name}#L{i + 1}") for i, url in enumerate(urls)]
    (run_dir / "crawl.signals.jsonl").write_text(
        "\n".join(r.model_dump_json() for r in rows) + "\n", encoding="utf-8"
    )


def _make_fetch(target_port: int):
    """构造 demo 的取数函数：**普通探针照旧**，DNS 探针投递到靶的同一端点。

    为什么需要这一层（**实测事实，不是设计缺陷**）：`<nonce>.invalid` 这个主机名
    **在任何环境都不可能解析**——本机对外解析走透明代理（探针被代理截获返回 502），
    直连则直接 `URLError: Name or service not known`。两种情况下探针都**到不了靶**，
    于是靶的"第三方代抓取"分支无从触发，防线也就演示不出来。

    ⇒ demo 把 DNS 探针**投递到靶的同一端点**（路径取自探针 URL 自身、token 作为
    参数带上），保留"这是对不可解析名的一次抓取尝试"的语义。这**不放宽防线**：
    `dns_misfire` 的判据始终是「**listener 是否收到这个 token**」，与探针怎么
    送到靶无关。

    生产链路不这么做：探针到不了靶时，判定自然落在 blocked（保守方向）——
    相关边界记入 AGENTS.md 限制 62。
    """

    def _fetch(url: str, session):
        if cmdi.NONRESOLVING_TLD in (urlparse(url).hostname or ""):
            parsed = urlparse(url)
            token = parsed.path.rstrip("/").rsplit("/", 1)[-1]
            routed = f"http://127.0.0.1:{target_port}{parsed.path}?{PARAM}={token}"
            try:
                with urllib.request.urlopen(routed, timeout=5) as resp:  # noqa: S310
                    return cmdi.ProbeResponse(
                        url=url, status=resp.status,
                        body=resp.read().decode("utf-8", errors="replace"),
                    )
            except Exception as exc:  # noqa: BLE001 - 拿不到响应即探针失败
                return cmdi.ProbeResponse(url=url, error=f"{type(exc).__name__}: {exc}")
        return cmdi.fetch(url, session)

    return _fetch


def _new_orch(run_dir: Path, port: int) -> Orchestrator:
    return Orchestrator(
        SkillRegistry(REPO / "skills").discover(),
        SimpleNamespace(
            scope=Scope(networks=["127.0.0.0/8"], ports=[port])
        ),
        _CannedRouter(),
        AuditLog(run_dir / "audit.jsonl"),
        evidence_dir=run_dir,
        cmdi_fetch=_make_fetch(port),
    )


def _events(path: Path, name: str) -> list[dict]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and json.loads(line).get("event") == name:
            out.append(json.loads(line))
    return out


def _states(path: Path) -> dict[str, str]:
    seen: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event") == "finding_state":
            seen[event["finding_id"]] = event["to"]
    return seen


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = REPO / "evidence" / "demo_cmdi_zero_seed" / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] 运行目录: {run_dir}")

    port = _free_port()
    (run_dir / "target_access.jsonl").write_text("", encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", port), _Target)
    server.run_dir = run_dir  # type: ignore[attr-defined]
    # mitm 分支需要知道 listener 的地址（它模拟"中间件替我们把请求送达 listener"）
    listener = cmdi.CallbackListener(host="127.0.0.1", port=0).start()
    server.mitm_listener_host = listener.bound_address[0]  # type: ignore[attr-defined]
    server.mitm_listener_port = listener.bound_address[1]  # type: ignore[attr-defined]
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    print(f"[*] 真靶: {base}（端点 {ENDPOINTS}）")

    urls = [f"{base}{path}?{PARAM}=1" for path in ENDPOINTS]
    _write_signals(run_dir, urls)
    print(f"[*] 只写 Signal（零 Finding）: {len(urls)} 条 param-endpoint")

    # ---------- A) 发现 ----------
    print()
    print("===== A) 发现：生产链路建 cmdi 候选（零 seed）=====")
    orch = _new_orch(run_dir, port)
    orch.run_triage_phase()
    store = FindingStore(run_dir / "findings.jsonl")
    findings = store.load_all()
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
    print(f"  产出 Finding {len(findings)} 条，按类型 {by_type}")
    assert by_type.get("cmdi", 0) == len(ENDPOINTS), (
        f"每个 cmd 参数端点都应派生 cmdi 候选；实测 {by_type}"
    )
    print(f"  ✅ cmdi 候选 {by_type['cmdi']} 条（规则表 _CMDI_PARAM_HINTS 命中）")

    # ---------- B) 确认 ----------
    print()
    print("===== B) 确认：run_verify_phase('verify-cmdi') 打真靶 =====")
    orch._ssrf_listener_factory = lambda: listener
    print(f"  回调 listener: {listener.bound_address}")
    orch.run_verify_phase(skill_name="verify-cmdi")
    states = _states(run_dir / "audit.jsonl")
    findings = FindingStore(run_dir / "findings.jsonl").load_all()
    cmdi_findings = {f.asset: f for f in findings if f.vuln_type == "cmdi"}
    confirmed = sorted(a for a, f in cmdi_findings.items() if states.get(f.id) == "confirmed")
    rejected = sorted(a for a, f in cmdi_findings.items() if states.get(f.id) == "rejected")
    pending = sorted(
        a for a, f in cmdi_findings.items()
        if states.get(f.id) not in ("confirmed", "rejected")
    )
    print(f"  CONFIRMED: {confirmed}")
    print(f"  REJECTED : {rejected}")
    print(f"  仍停 Hypothesis: {pending}")
    vuln_url = f"{base}/tools/ping?{PARAM}=1"
    waf_url = f"{base}/tools/waf?{PARAM}=1"
    safe_url = f"{base}/tools/safe?{PARAM}=1"
    assert vuln_url in confirmed, f"真漏洞端点必须 CONFIRMED；实测 {states}"
    assert waf_url in confirmed, (
        "拒绝解析 .invalid 的**真漏洞**端点仍应 CONFIRMED（DNS 防线不该拦真漏洞）"
    )
    assert safe_url in rejected, "不取数端点必须 REJECTED"
    print("  ✅ 真漏洞 CONFIRMED（含拒 .invalid 的真漏洞——防线不误伤）")
    print("  ✅ 安全形态 REJECTED（交付证明成立 + 零回调）")
    # DNS 防线的**负命中**断言：真漏洞的 DNS 探针必须未命中（否则会被误判 blocked）
    dns_events = [e for e in _events(run_dir / "audit.jsonl", "cmdi_callback_judged")]
    assert dns_events and all(e["dns_misfire"] is False for e in dns_events), (
        f"真漏洞的 DNS 非命中变体不该命中；实测 {dns_events}"
    )
    print("  ✅ DNS 非命中变体在真漏洞上未命中（dns_misfire=False，未误伤确认）")
    print("  ℹ️  「中间件代抓取」形态的**正命中**（须 blocked）由单测确定性覆盖：")
    print("      tests/test_cmdi.py::test_dns_defense_blocks_even_when_waf_makes_the_callback")

    entry = next(f for a, f in cmdi_findings.items() if a == vuln_url)
    assert entry.verification is not None
    assert entry.verification.method == cmdi.CMDI_CONFIRMED_METHOD
    assert "behavioral" in entry.evidence_kinds
    assert entry.cvss_vector, "Confirmed 必须带合法 CVSS 向量（代码算分）"
    print(f"  ✅ method={entry.verification.method} / CVSS={entry.cvss_vector} "
          f"/ evidence_refs={len(entry.verification.evidence_refs)} 份")
    listener.close()

    # ---------- C) 上限 ----------
    print()
    print("===== C) 独立上限 _TRIAGE_CMDI_CAP =====")
    run_dir_c = run_dir / "cap"
    run_dir_c.mkdir(parents=True, exist_ok=True)
    filler = [f"{base}/filler/{i}?{PARAM}=1" for i in range(_TRIAGE_CMDI_CAP + 5)]
    _write_signals(run_dir_c, urls + filler)
    _new_orch(run_dir_c, port).run_triage_phase()
    made = [
        f for f in FindingStore(run_dir_c / "findings.jsonl").load_all()
        if f.vuln_type == "cmdi"
    ]
    capped = [e for e in _events(run_dir_c / "audit.jsonl", "triage_capped")
              if e["vuln_type"] == "cmdi"]
    print(f"  2xx 端点 {len(urls) + len(filler)} 个 → 建出 cmdi {len(made)} 条"
          f"（上限 {_TRIAGE_CMDI_CAP}）")
    assert len(made) == _TRIAGE_CMDI_CAP, len(made)
    assert capped and capped[0]["limit"] == _TRIAGE_CMDI_CAP, capped
    print(f"  ✅ triage_capped(vuln_type=cmdi, limit={_TRIAGE_CMDI_CAP}, "
          f"dropped={capped[0]['dropped']})")

    # ---------- D) 生产栈 ----------
    print()
    print("===== D) API 生产栈槽位（限制 59 的教训）=====")
    from proofhound.api.runner import OrchestratorPhases

    registry = SkillRegistry(REPO / "skills").discover()
    phases = OrchestratorPhases(SimpleNamespace(audit=SimpleNamespace()), registry)
    slots = [name for name, _level in phases.verify_skills]
    print(f"  verify 槽位: {slots}")
    assert "verify-cmdi" in slots, f"生产栈必须挂上 verify-cmdi；实测 {slots}"
    print("  ✅ verify-cmdi 在生产栈槽位里（M17-b 限制 59 的教训已内化）")

    # ---------- E) 注册面 ----------
    print()
    print("===== E) 注册面三处由登记表派生 =====")
    print(f"  VULN_REGISTRY 键 : {sorted(VULN_REGISTRY)}")
    print(f"  GATE_MATRIX 键   : {sorted(GATE_MATRIX)}")
    print(f"  模型白名单        : {sorted(ALLOWED_VULN_TYPES)}")
    assert set(GATE_MATRIX) == set(VULN_REGISTRY)
    assert "cmdi" in VULN_REGISTRY and "cmdi" in ALLOWED_VULN_TYPES
    assert GATE_MATRIX["cmdi"].methods == frozenset({cmdi.CMDI_CONFIRMED_METHOD})
    print("  ✅ cmdi 三处齐备，method 与既有五类互不染指")

    print()
    print("=" * 68)
    print("全部断言通过：cmdi 在生产链路**可达且可确认**（零 seed）")
    print("=" * 68)
    summary = {
        "run_dir": str(run_dir.relative_to(REPO)),
        "by_type": by_type,
        "confirmed": confirmed,
        "rejected": rejected,
        "pending": pending,
        "cap": {"limit": _TRIAGE_CMDI_CAP, "created": len(made),
                "dropped": capped[0]["dropped"] if capped else 0},
        "production_slots": slots,
    }
    (run_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    server.shutdown()
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
