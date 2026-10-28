"""M22-b 实弹验收：verify-ssti —— 真 jinja2 靶上的**三态各一**。

## 这份脚本证明什么

1. **真引擎、真 HTTP**：靶用 jinja2 真的把参数拼进页面源码后求值（不是正则仿真），
   判定器经**真实** `run_verify_phase("verify-ssti")` 走完全链路
   （基线 → 逐语法探针 → 畸形对照 → 差分判定 → 证据门 → Verifier）。
2. **三态都被真的走一遍**（**零 seed**：只写 Signal，Finding 由生产代码建）：

   | 端点 | 形态 | 期望终态 |
   |---|---|---|
   | `/render` | 真模板求值 | **confirmed**（两个乘积 + 基线干净 + 畸形对照不成立） |
   | `/echo` | 只回显不求值（形对照） | **rejected**（真阴性，绝不误报） |
   | `/calc` | strip 非数字后**强算**（畸形对照也出数） | **blocked**（判不了，停在 Hypothesis） |

   第三态是本轮的核心诚实点：它的三个探针**全中**，但"少一个右括号也能算"恰恰
   证明不了是模板引擎算的 —— 差分判据必须把它判 `blocked` 而不是 `confirmed`。

3. **预算**：confirmed 只用 **4** 次只读 GET（1 基线 + 2 表达式 + 1 畸形对照），
   rejected 用 7 次（不补畸形对照），全程 ≤ 8。

## 用法

```bash
.venv/bin/python scripts/demo_ssti.py            # 真 T2 终审（需 PROOFHOUND_T2_*）
.venv/bin/python scripts/demo_ssti.py --canned   # 罐头 T2 裁定（离线/省费用）
```

产物落 `evidence/demo_ssti/<时间戳>/`（gitignored）。
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
from types import SimpleNamespace

import jinja2

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from proofhound.compliance.audit import AuditLog  # noqa: E402
from proofhound.compliance.scope import Scope  # noqa: E402
from proofhound.core.orchestrator import Orchestrator  # noqa: E402
from proofhound.findings.finding import FindingStore  # noqa: E402
from proofhound.findings.signal import Signal  # noqa: E402
from proofhound.llm.client import LLMError  # noqa: E402
from proofhound.llm.router import ModelRouter, Tier  # noqa: E402
from proofhound.skills.registry import SkillRegistry  # noqa: E402
from proofhound.verify import ssti  # noqa: E402

REPO = REPO_ROOT
PARAM = "template"
#: 三态靶：路径 → 期望终态（见模块 docstring 的表）
EXPECTED = {"/render": "confirmed", "/echo": "rejected", "/calc": "hypothesis"}
CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

#: 罐头 T2 裁定（--canned 时用；与既有 verify-* 验收同口径：真实 T2 需外部凭据）
CANNED_CONFIRM = json.dumps(
    {
        "verdict": "confirm",
        "reason": "两个不同乘积都被算出，基线干净、畸形模板对照未出数",
        "cvss_vector": CVSS,
        "cvss_rationale": "模板注入可致服务端任意代码执行，按证据定指标",
    },
    ensure_ascii=False,
)

_JINJA = jinja2.Environment(autoescape=False)


class _Target(BaseHTTPRequestHandler):
    """真靶：三个端点的差异只在「怎么处理参数」，参数名完全不参与分支。"""

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        value = (query.get(PARAM) or [""])[0]
        if parsed.path == "/render":
            body = _render_template(value)
        elif parsed.path == "/echo":
            body = f"<html><body><h1>主题预览</h1><div>{value}</div></body></html>"
        elif parsed.path == "/calc":
            body = _naive_calc(value)
        else:
            body = "<html><body><h1>404</h1></body></html>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            payload = body.encode("utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # 静音
        pass


def _render_template(value: str) -> str:
    """真 SSTI：把取值拼进页面源码后**用 jinja2 求值**（语法错误 → 200 错误页）。"""
    source = f"<html><body><h1>模板预览</h1><div>{value}</div></body></html>"
    try:
        return _JINJA.from_string(source).render()
    except Exception as exc:  # noqa: BLE001 —— 模板错误只意味着"没算出来"
        return f"<html><body><h1>模板错误</h1><p>{type(exc).__name__}</p></body></html>"


def _naive_calc(value: str) -> str:
    """「strip 非数字后强算」的端點：畸形模板也照样出乘积（⇒ 判不了）。"""
    cleaned = "".join(ch for ch in value if ch.isdigit() or ch == "*")
    left, _, right = cleaned.partition("*")
    try:
        product = int(left) * int(right)
    except ValueError:
        return "<html><body><h1>无法计算</h1></body></html>"
    return f"<html><body><h1>计算结果</h1><div>{product}</div></body></html>"


class _CannedRouter(ModelRouter):
    """罐头 T2 裁定（`--canned`）。"""

    def __init__(self) -> None:
        self.calls = 0
        self.configs = {Tier.T2: SimpleNamespace(model="canned-verifier")}

    def complete(self, tier, messages):
        self.calls += 1
        return CANNED_CONFIRM


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


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
        "\n".join(row.model_dump_json() for row in rows) + "\n", encoding="utf-8"
    )


def _new_orch(run_dir: Path, port: int, router) -> Orchestrator:
    return Orchestrator(
        SkillRegistry(REPO / "skills").discover(),
        SimpleNamespace(scope=Scope(networks=["127.0.0.0/8"], ports=[port])),
        router,
        AuditLog(run_dir / "audit.jsonl"),
        evidence_dir=run_dir,
        ssti_fetch=ssti.fetch,
    )


def _events(path: Path, name: str) -> list[dict]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event") == name:
            out.append(event)
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
    parser = argparse.ArgumentParser(description="ProofHound M22-b verify-ssti 实弹验收")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument(
        "--canned",
        action="store_true",
        help="用罐头 T2 裁定（不调真实模型；与既有 verify-* 验收同口径）",
    )
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = REPO / "evidence" / "demo_ssti" / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] 运行目录: {run_dir}")

    if args.canned:
        router = _CannedRouter()
        print("[*] T2 裁定：罐头（--canned）")
    else:
        try:
            router = ModelRouter.from_env(args.env_file)
        except LLMError as exc:
            print(f"[配置错误] {exc}", file=sys.stderr)
            return 2
        if Tier.T2 not in router.configs:
            print("[配置错误] 需要 T2 档（Verifier）：PROOFHOUND_T2_*（或用 --canned）",
                  file=sys.stderr)
            return 2
        print(f"[*] T2 裁定：真实模型 {router.configs[Tier.T2].model}")

    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), _Target)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    print(f"[*] 真 jinja2 靶: {base}（/render 求值 · /echo 只回显 · /calc 强算）")

    try:
        urls = [f"{base}{path}?{PARAM}=1" for path in EXPECTED]
        _write_signals(run_dir, urls)
        print(f"[*] 只写 Signal（零 Finding）: {len(urls)} 条 param-endpoint")

        # ---------- A) 发现 ----------
        print()
        print("===== A) 发现：生产链路建 ssti 候选（零 seed）=====")
        orch = _new_orch(run_dir, port, router)
        orch.run_triage_phase()
        findings = FindingStore(run_dir / "findings.jsonl").load_all()
        by_type: dict[str, int] = {}
        for finding in findings:
            by_type[finding.vuln_type] = by_type.get(finding.vuln_type, 0) + 1
        print(f"  产出 Finding {len(findings)} 条，按类型 {by_type}")
        assert by_type.get("ssti", 0) == len(EXPECTED), (
            f"三个 template 参数端点都应派生 ssti 候选；实测 {by_type}"
        )
        print(f"  ✅ ssti 候选 {by_type['ssti']} 条（规则表 _SSTI_PARAM_HINTS 命中）")

        # ---------- B) 判定 ----------
        print()
        print("===== B) 判定：run_verify_phase('verify-ssti') 打真靶 =====")
        orch.run_verify_phase(skill_name="verify-ssti")
        audit_path = run_dir / "audit.jsonl"
        states = _states(audit_path)
        findings = FindingStore(run_dir / "findings.jsonl").load_all()
        ssti_findings = {
            urllib.parse.urlparse(f.asset).path: f
            for f in findings
            if f.vuln_type == "ssti"
        }
        for path, expected in EXPECTED.items():
            finding = ssti_findings[path]
            state = states.get(finding.id, "?")
            print(f"  {path:9} → {state}")
            assert state == expected, f"{path} 期望 {expected}，实测 {state}"

        # 三态的书面证据
        confirmed = ssti_findings["/render"]
        assert confirmed.verification is not None
        assert confirmed.verification.method == ssti.SSTI_CONFIRMED_METHOD
        assert ssti.SSTI_EVALUATION_EVIDENCE_KIND in confirmed.evidence_kinds
        assert confirmed.verification.claim and confirmed.verification.actual
        assert confirmed.cvss_score is not None and confirmed.cvss_score > 0
        print(
            f"  ✅ /render CONFIRMED：method={confirmed.verification.method}、"
            f"evidence_kind={ssti.SSTI_EVALUATION_EVIDENCE_KIND}、"
            f"CVSS={confirmed.cvss_score}（{confirmed.cvss_vector}）"
        )

        rejected = ssti_findings["/echo"]
        assert "差分求值不成立" in (rejected.rejection_reason or "")
        print(f"  ✅ /echo REJECTED：{rejected.rejection_reason[:60]}…")

        blocked = ssti_findings["/calc"]
        assert blocked.state.value == "hypothesis"
        print("  ✅ /calc 停 Hypothesis（blocked：畸形对照也出数 ⇒ 判不了）")

        # 按次审计与预算
        attempts = _events(audit_path, "ssti_probe_attempt")
        by_finding: dict[str, list[dict]] = {}
        for event in attempts:
            by_finding.setdefault(event["finding_id"], []).append(event)
        render_attempts = by_finding[confirmed.id]
        echo_attempts = by_finding[rejected.id]
        calc_attempts = by_finding[blocked.id]
        print(
            f"  探针次数：/render={len(render_attempts)}、/echo={len(echo_attempts)}、"
            f"/calc={len(calc_attempts)}（预算 {ssti.PROBE_BUDGET}）"
        )
        assert len(render_attempts) == 4, "confirmed 只需 1 基线 + 2 表达式 + 1 畸形对照"
        assert len(echo_attempts) == 7, "未命中不补畸形对照：1 + 3×2"
        assert len(calc_attempts) == 4, "强算端点在第一族就全中并补对照"
        assert max(len(v) for v in by_finding.values()) <= ssti.PROBE_BUDGET

        judged = _events(audit_path, "ssti_judged")
        verdicts = {e["finding_id"]: e["verdict"] for e in judged}
        assert verdicts[confirmed.id] == "confirmed"
        assert verdicts[rejected.id] == "rejected"
        assert verdicts[blocked.id] == "blocked"
        blocked_events = _events(audit_path, "verify_blocked")
        assert any("畸形模板对照" in e["reason"] for e in blocked_events)

        # 证据链：判定 JSON 落盘且不含凭据（本 demo 无会话，故只查结构）
        judgment_path = run_dir / f"ssti_{confirmed.id}_judgment.json"
        assert judgment_path.is_file(), "判定 JSON 未落盘"
        judgment = json.loads(judgment_path.read_text(encoding="utf-8"))
        assert judgment["verdict"] == "confirmed"
        assert judgment["baseline_clean"] is True
        assert judgment["malformed_clean"] is True
        assert judgment["products_observed"] == ["36481", "36672"]
        refs = confirmed.verification.evidence_refs
        assert len(refs) == 5, f"证据引用应为 4 探针 + 判定 JSON；实测 {refs}"
        for ref in refs:
            assert Path(ref).is_file(), f"证据引用不存在：{ref}"
        print(f"  ✅ 证据链：{len(refs)} 个文件可离线调出（含判定 JSON）")

        # 探针 URL 打印（报告里要能照抄复现）
        print("\n[*] 复现用的探针（/render，真 jinja2 靶）：")
        for event in render_attempts:
            print(f"    [{event['kind']:10}] {event['label']:24} "
                  f"status={event['status']} products={event['products']}")

        summary = {
            "stamp": stamp,
            "target": base,
            "t2": "canned" if args.canned else router.configs[Tier.T2].model,
            "states": {path: states.get(f.id) for path, f in ssti_findings.items()},
            "probe_counts": {
                "/render": len(render_attempts),
                "/echo": len(echo_attempts),
                "/calc": len(calc_attempts),
            },
            "judged": verdicts,
            "cvss_vector": confirmed.cvss_vector,
            "cvss_score": confirmed.cvss_score,
            "judgment": judgment,
        }
        (run_dir / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    finally:
        server.shutdown()
        print("\n[*] 真靶已停止")

    print("\n" + "=" * 72)
    print(f"[验收通过] M22-b verify-ssti 差分求值三态实弹（产物目录: {run_dir}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
