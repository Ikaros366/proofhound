"""M23 实弹验收：verify-error-disclosure —— 五个本地靶、五态各一。

## 这份脚本证明什么

1. **裸 TCP 真的把畸形请求发出去了**：靶是**裸 socket 服务器**，它记录收到的
   原始请求行；脚本断言 ``…``（``E2 80 A6``）字节确实到达了服务器——urllib /
   httpx 在客户端就会拒绝，根本走不到这里。
2. **五态都被真的走一遍**（**零 seed**：只写 web-probe Signal，Finding 由生产
   代码按 host 派生）：

   | 靶 | 行为 | 期望终态 |
   |---|---|---|
   | ``tomcat-like`` | 畸形请求 → 400 + Java 堆栈 + ``Apache Tomcat/9.0.x`` | **confirmed** |
   | ``php-like`` | 畸形请求 → 500 + ``Fatal error:`` + 源码路径 + ``#0`` | **confirmed** |
   | ``generic`` | 畸形请求 → 400 + 通用 "Bad Request"（带 nginx 版本头） | **rejected** |
   | ``waf`` | 畸形请求 → 403 + "Request blocked" | **rejected** |
   | ``noisy-baseline`` | 正常页里本来就贴了一段示例堆栈 | **blocked** |

   第三/第四态是诚实点：**版本头不是证据**（generic 靶有 ``Server: nginx/1.25.3``
   仍判 rejected）；WAF 的 403 页同样是零标记 ⇒ 真阴性。
3. **预算**：confirmed 只用 2 次请求（1 基线 + 1 命中探针，命中即停）；rejected
   用满 6 次（1 + 5，零标记必须全部跑完才敢驳回）；baseline 被污染的 blocked
   只花 1 次（反事实不成立，不再发探针）。

> 如实标注：``tomcat-like`` / ``php-like`` 是**形态仿真**——回显的堆栈是罐头，
> 不是真 Tomcat/PHP。真实中间件行为由交接单 §1 的抓包案例佐证；要真靶可
> ``docker run tomcat:9``（需镜像可拉取）。

## 用法

```bash
.venv/bin/python scripts/demo_error_disclosure.py            # 真 T2 终审（需 PROOFHOUND_T2_*）
.venv/bin/python scripts/demo_error_disclosure.py --canned   # 罐头 T2 裁定（离线/省费用）
```

产物落 ``evidence/demo_error_disclosure/<时间戳>/``（gitignored）。
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

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
from proofhound.verify import error_disclosure as ed  # noqa: E402

CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

#: 罐头 T2 裁定（--canned 时用；与既有 verify-* 验收同口径：真实 T2 需外部凭据）
CANNED_CONFIRM = json.dumps(
    {
        "verdict": "confirm",
        "reason": "基线干净、畸形请求的错误页命中 ≥2 类技术披露标记",
        "cvss_vector": CVSS,
        "cvss_rationale": "错误页回显内部堆栈/路径，机密性受影响，无完整性与可用性影响",
    },
    ensure_ascii=False,
)

#: 五靶 → 期望终态（见模块 docstring 的表）
EXPECTED = {
    "tomcat-like": "confirmed",
    "php-like": "confirmed",
    "generic": "rejected",
    "waf": "rejected",
    "noisy-baseline": "hypothesis",
}

HOME = "<html><body><h1>ProofHound error-disclosure fixture</h1></body></html>"

TOMCAT_PAGE = (
    "<html><head><title>Apache Tomcat/9.0.65 - Error report</title></head><body>"
    "<h1>HTTP Status 400 – Bad Request</h1>"
    "<p><b>Message</b> Invalid character found in the request target.</p>"
    "<pre>java.lang.IllegalArgumentException: Invalid character found in the request "
    "target.\n    [0xe2 0x80 0xa6]. The valid characters are defined in RFC 7230 "
    "and RFC 3986\n"
    "\tat org.apache.coyote.http11.Http11InputBuffer.parseRequestLine"
    "(Http11InputBuffer.java:505)\n"
    "\tat org.apache.coyote.http11.Http11Protocol$Http11ConnectionHandler.process"
    "(Http11Protocol.java:670)\n</pre>"
    "<hr><h3>Apache Tomcat/9.0.65</h3></body></html>"
)

PHP_PAGE = (
    "<html><body><br />\n<b>Fatal error</b>: Uncaught RuntimeException: invalid "
    "request in /var/www/html/app/index.php:12\nStack trace:\n"
    "#0 /var/www/html/app/index.php(5): handler()\n"
    "#1 /var/www/html/app/index.php(9): dispatch()\n#2 {main}\n</body></html>"
)

NOISY_HOME = (
    "<html><body><h1>示例：一段服务端异常长什么样</h1><pre>"
    "java.lang.IllegalStateException: sample stack shown in documentation\n"
    "\tat com.example.demo.Handler.run(Handler.java:42)\n"
    "</pre><p>（本站的正常页面里本来就有这段示例）</p></body></html>"
)


def _http_response(
    status: int, reason: str, body: str, extra_headers: str = ""
) -> bytes:
    payload = body.encode("utf-8")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n"
        f"{extra_headers}"
        "\r\n"
    )
    return head.encode("ascii") + payload


def _is_normal_request(request: bytes) -> bool:
    line = request.split(b"\r\n", 1)[0]
    return line == b"GET / HTTP/1.1"


def _behavior(name: str):
    """靶名 → ``(request_bytes) -> response_bytes``（形态仿真，堆栈是罐头）。"""

    def tomcat(request: bytes) -> bytes:
        if _is_normal_request(request):
            return _http_response(200, "OK", HOME)
        return _http_response(
            400, "Bad Request", TOMCAT_PAGE, "Server: Apache-Coyote/1.1\r\n"
        )

    def php(request: bytes) -> bytes:
        if _is_normal_request(request):
            return _http_response(200, "OK", HOME)
        return _http_response(
            500, "Internal Server Error", PHP_PAGE, "Server: Apache/2.4.52 (Ubuntu)\r\n"
        )

    def generic(request: bytes) -> bytes:
        if _is_normal_request(request):
            return _http_response(200, "OK", HOME, "Server: nginx/1.25.3\r\n")
        return _http_response(
            400,
            "Bad Request",
            "<html><body><h1>400 Bad Request</h1></body></html>",
            "Server: nginx/1.25.3\r\n",
        )

    def waf(request: bytes) -> bytes:
        if _is_normal_request(request):
            return _http_response(200, "OK", HOME)
        return _http_response(
            403,
            "Forbidden",
            "<html><body><h1>Request blocked</h1>"
            "<p>Request ID 8f2a-4c1b</p></body></html>",
        )

    def noisy(request: bytes) -> bytes:
        if _is_normal_request(request):
            # 正常页里**本来就有**示例堆栈 ⇒ 基线已污染，无法归因
            return _http_response(200, "OK", NOISY_HOME)
        return _http_response(400, "Bad Request", NOISY_HOME)

    return {
        "tomcat-like": tomcat,
        "php-like": php,
        "generic": generic,
        "waf": waf,
        "noisy-baseline": noisy,
    }[name]


class RawTarget(threading.Thread):
    """裸 socket 靶：只解析到请求头结束，回罐头响应，并记录原始请求字节。"""

    def __init__(self, name: str) -> None:
        super().__init__(daemon=True)
        self.name = name
        self._behavior = _behavior(name)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self.requests: list[bytes] = []

    def run(self) -> None:  # noqa: D102
        while True:
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(3.0)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                self.requests.append(data)
                conn.sendall(self._behavior(data))
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


class _CannedRouter(ModelRouter):
    """罐头 T2 裁定（`--canned`）。"""

    def __init__(self) -> None:
        self.calls = 0
        self.configs = {Tier.T2: SimpleNamespace(model="canned-verifier")}

    def complete(self, tier, messages):
        self.calls += 1
        return CANNED_CONFIRM


def _signal(base: str, ref: str) -> Signal:
    return Signal(
        asset=f"{base}/",
        status_code=200,
        kind="web-probe",
        source_tool="httpx",
        skill="web-scan",
        evidence_ref=ref,
    )


def _write_signals(run_dir: Path, bases: dict[str, str]) -> None:
    raw = run_dir / "web-scan.stdout.log"
    raw.write_text("\n".join('{"status_code": 200, "title": "fixture"}' for _ in bases) + "\n", encoding="utf-8")
    rows = [_signal(base, f"{raw.name}#L{i + 1}") for i, base in enumerate(bases.values())]
    (run_dir / "web-scan.signals.jsonl").write_text(
        "\n".join(row.model_dump_json() for row in rows) + "\n", encoding="utf-8"
    )


def _new_orch(run_dir: Path, ports: list[int], router) -> Orchestrator:
    return Orchestrator(
        SkillRegistry(REPO_ROOT / "skills").discover(),
        SimpleNamespace(scope=Scope(networks=["127.0.0.0/8"], ports=ports)),
        router,
        AuditLog(run_dir / "audit.jsonl"),
        evidence_dir=run_dir,
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
    parser = argparse.ArgumentParser(description="ProofHound M23 verify-error-disclosure 实弹验收")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument(
        "--canned",
        action="store_true",
        help="用罐头 T2 裁定（不调真实模型；与既有 verify-* 验收同口径）",
    )
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = REPO_ROOT / "evidence" / "demo_error_disclosure" / stamp
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

    targets = {name: RawTarget(name) for name in EXPECTED}
    for target in targets.values():
        target.start()
    bases = {name: f"http://127.0.0.1:{t.port}" for name, t in targets.items()}
    ports = [t.port for t in targets.values()]
    for name, base in bases.items():
        print(f"[*] 靶 {name:14} {base}")
    print("[*] 形态仿真：堆栈是罐头，不是真 Tomcat/PHP（见脚本 docstring）")

    try:
        _write_signals(run_dir, bases)
        print(f"[*] 只写 Signal（零 Finding）: {len(bases)} 条 web-probe")

        # ---------- A) 发现 ----------
        print()
        print("===== A) 发现：生产链路按 host 派生 error-disclosure 候选（零 seed）=====")
        orch = _new_orch(run_dir, ports, router)
        orch.run_triage_phase()
        findings = FindingStore(run_dir / "findings.jsonl").load_all()
        ed_findings = [f for f in findings if f.vuln_type == "error-disclosure"]
        by_asset = {f.asset: f for f in ed_findings}
        assert len(ed_findings) == len(EXPECTED), (
            f"每个 host 应各派生一条候选；实测 {[f.asset for f in ed_findings]}"
        )
        for name, base in bases.items():
            assert base in by_asset, f"{name} 未派生候选：{sorted(by_asset)}"
        print(f"  ✅ error-disclosure 候选 {len(ed_findings)} 条（按 origin 去重）")

        # ---------- B) 判定 ----------
        print()
        print("===== B) 判定：run_verify_phase('verify-error-disclosure') 打真裸 TCP 靶 =====")
        orch.run_verify_phase(skill_name="verify-error-disclosure")
        audit_path = run_dir / "audit.jsonl"
        states = _states(audit_path)
        findings = FindingStore(run_dir / "findings.jsonl").load_all()
        ed_findings = {f.asset: f for f in findings if f.vuln_type == "error-disclosure"}
        for name, base in bases.items():
            finding = ed_findings[base]
            state = states.get(finding.id, "?")
            print(f"  {name:14} → {state}")
            assert state == EXPECTED[name], f"{name} 期望 {EXPECTED[name]}，实测 {state}"

        tomcat = ed_findings[bases["tomcat-like"]]
        php = ed_findings[bases["php-like"]]
        generic = ed_findings[bases["generic"]]
        waf = ed_findings[bases["waf"]]
        noisy = ed_findings[bases["noisy-baseline"]]

        # 三态的书面证据
        for label, finding in (("tomcat-like", tomcat), ("php-like", php)):
            assert finding.verification is not None
            assert finding.verification.method == ed.ERROR_DISCLOSURE_CONFIRMED_METHOD
            assert ed.ERROR_TRACE_EVIDENCE_KIND in finding.evidence_kinds
            assert finding.verification.claim and finding.verification.actual
            assert finding.cvss_score is not None and finding.cvss_score > 0
            print(
                f"  ✅ {label} CONFIRMED：method={finding.verification.method}、"
                f"CVSS={finding.cvss_score}（{finding.cvss_vector}）"
            )
        assert "报错信息泄露不成立" in (generic.rejection_reason or "")
        assert "报错信息泄露不成立" in (waf.rejection_reason or "")
        print(f"  ✅ generic REJECTED：{generic.rejection_reason[:56]}…")
        print(f"  ✅ waf REJECTED：{waf.rejection_reason[:56]}…")
        assert noisy.state.value == "hypothesis"
        print("  ✅ noisy-baseline 停 Hypothesis（blocked：基线自带示例堆栈 ⇒ 不可归因）")

        # 版本头不是证据：generic 靶明明有 nginx 版本头，仍然 rejected
        header_events = _events(audit_path, "server_header_disclosed")
        assert any("nginx/1.25.3" in (e.get("header") or "") for e in header_events), (
            "generic 靶的版本头应被单独审计"
        )
        assert generic.state.value == "rejected", "版本头不得把 rejected 抬成 confirmed"
        print("  ✅ 版本头只进审计：generic 靶有 nginx/1.25.3 仍判 rejected")

        # 裸 TCP 真的把畸形字节送到了服务器
        saw_ellipsis = any(
            b"\xe2\x80\xa6" in request
            for target in targets.values()
            for request in target.requests
        )
        assert saw_ellipsis, "… 字节没有到达任何靶——裸 TCP 发送链路失效"
        print("  ✅ 畸形请求原样到达：靶侧记录到 E2 80 A6 字节")
        assert not any(
            b"Cookie" in request
            for target in targets.values()
            for request in target.requests
        ), "探针不得携带任何凭据"

        # 按次审计与预算
        attempts = _events(audit_path, "error_disclosure_probe_attempt")
        by_finding: dict[str, list[dict]] = {}
        for event in attempts:
            by_finding.setdefault(event["finding_id"], []).append(event)
        counts = {
            "tomcat-like": len(by_finding[tomcat.id]),
            "php-like": len(by_finding[php.id]),
            "generic": len(by_finding[generic.id]),
            "waf": len(by_finding[waf.id]),
            "noisy-baseline": len(by_finding[noisy.id]),
        }
        print(f"  探针次数：{counts}（预算 1 基线 + ≤{ed.PROBE_BUDGET} 探针）")
        assert counts["tomcat-like"] == 2, "命中即停：1 基线 + 1 探针"
        assert counts["php-like"] == 2
        assert counts["generic"] == 1 + ed.PROBE_BUDGET, "零标记必须跑满才敢驳回"
        assert counts["noisy-baseline"] == 1, "基线污染 ⇒ 不再发探针"

        judged = _events(audit_path, "error_disclosure_judged")
        verdicts = {e["finding_id"]: e["verdict"] for e in judged}
        assert verdicts[tomcat.id] == "confirmed"
        assert verdicts[php.id] == "confirmed"
        assert verdicts[generic.id] == "rejected"
        assert verdicts[waf.id] == "rejected"
        assert verdicts[noisy.id] == "blocked"
        blocked_events = _events(audit_path, "verify_blocked")
        assert any("基线响应本身命中" in e["reason"] for e in blocked_events)

        # 证据链：判定 JSON 落盘且不含响应正文
        for finding, name in ((tomcat, "tomcat-like"), (php, "php-like")):
            judgment_path = run_dir / f"error_disclosure_{finding.id}_judgment.json"
            assert judgment_path.is_file(), f"{name} 判定 JSON 未落盘"
            raw = judgment_path.read_bytes()
            assert b"java.lang.IllegalArgumentException" not in raw, name
            assert b"Fatal error" not in raw, name
            judgment = json.loads(raw.decode("utf-8"))
            assert judgment["verdict"] == "confirmed"
            assert len(judgment["matched_classes"]) >= 2, name
            assert judgment["baseline"]["classes"] == [], name
            refs = finding.verification.evidence_refs
            assert len(refs) == 3, f"{name} 证据引用应为 基线 + 命中探针 + 判定 JSON"
            for ref in refs:
                assert Path(ref).is_file(), f"{name} 证据引用不存在：{ref}"
        print("  ✅ 证据链：基线 + 命中探针 + 判定 JSON 均可离线调出（正文不进判定 JSON）")

        # 复现用的探针（报告里要能照抄）
        print("\n[*] tomcat-like 的探针序列：")
        for event in by_finding[tomcat.id]:
            print(
                f"    {event['label']:14} status={event['status']} "
                f"classes={event['classes']} sha256={str(event['request_sha256'])[:12]}"
            )

        summary = {
            "stamp": stamp,
            "method": "形态仿真（罐头堆栈；真实中间件行为见交接单 §1 抓包案例）",
            "t2": "canned" if args.canned else router.configs[Tier.T2].model,
            "targets": bases,
            "states": {name: states.get(ed_findings[base].id) for name, base in bases.items()},
            "probe_counts": counts,
            "judged": verdicts,
            "matched_classes": {
                "tomcat-like": json.loads(
                    (run_dir / f"error_disclosure_{tomcat.id}_judgment.json").read_text(
                        encoding="utf-8"
                    )
                )["matched_classes"],
                "php-like": json.loads(
                    (run_dir / f"error_disclosure_{php.id}_judgment.json").read_text(
                        encoding="utf-8"
                    )
                )["matched_classes"],
            },
            "server_header_disclosed": [e.get("header") for e in header_events],
            "cvss": {name: ed_findings[base].cvss_score for name, base in bases.items()},
        }
        (run_dir / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    finally:
        for target in targets.values():
            target.stop()
        print("\n[*] 五个裸 TCP 靶已停止")

    print("\n" + "=" * 72)
    print(f"[验收通过] M23 verify-error-disclosure 五态实弹（产物目录: {run_dir}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
