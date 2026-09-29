#!/usr/bin/env python3
"""M16-c 验收：`unauth-exposure` 判定通道（真靶 + **真实 HTTP** + 真证据链）。

M16-c 的单元/全链路测试用的是**替身 fetch**（`tests/test_unauth_judge.py`），
证明的是编排逻辑、证据门、四段式、状态迁移与红线 3 边界——但**没有见过一次真实
HTTP**。本脚本补上这一段：靶是真实 `ThreadingHTTPServer`，两侧请求走
`verify/idor.py::fetch`（真实 stdlib 请求），Verifier 用罐头裁定（T2 需外部模型）。
**唯一替身是敏感度判定器**（T1）——理由与边界见下"如实的接缝说明"。

三个形态各一个靶端点，一次跑完：

| 形态 | 靶行为 | 期望终态 |
|---|---|---|
| ① 真暴露 | 有无会话都返回**同一份**敏感内容 | **Confirmed** |
| ② 受保护 | 匿名被拒（302 → 登录页） | **Rejected**（资源本就要求认证） |
| ③ 视图不同 | 匿名得公开首页、已认证得敏感内容 | **blocked**（停 Hypothesis） |

产物落 ``evidence/demo_verify_unauth/<时间戳>/``（gitignored）。

如实的接缝说明
--------------
- **判定器是替身**：真实 T1 调用需要外部凭据与预算，且**它不构成证据**
  （`GATE_MATRIX` 只认前置门产物），故用替身不影响任何终态；
  这与 M16-c "判定器判错不可能造成误确认" 的设计一致。
- **Verifier 是罐头**：T2 终审同样需要外部模型。罐头 confirm 用于形态 ①②③
  的**终态断言**；`cvss_vector` 合法（由代码算分）。
- 靶跑在宿主 `127.0.0.1`，而两侧请求是**宿主 stdlib 直连**（`verify/idor.py::fetch`
  与 verify-idor 同范式，不经 Docker 沙箱）——故本脚本**不建沙箱**。
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
from types import SimpleNamespace

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from proofhound.compliance.audit import AuditLog  # noqa: E402
from proofhound.compliance.scope import Scope  # noqa: E402
from proofhound.compliance.session import SessionConfig  # noqa: E402
from proofhound.core.orchestrator import Orchestrator  # noqa: E402
from proofhound.findings.dedup import compute_dedup_key  # noqa: E402
from proofhound.findings.finding import (  # noqa: E402
    Finding,
    FindingState,
    FindingStore,
)
from proofhound.llm.router import ModelRouter, Tier  # noqa: E402
from proofhound.skills.registry import SkillRegistry  # noqa: E402
from proofhound.verify.unauth_control import (  # noqa: E402
    UNAUTH_CONFIRMED_METHOD,
    UNAUTH_EQUIVALENCE_EVIDENCE_KIND,
)
from proofhound.verify.unauth_judge import UnauthJudgmentResult  # noqa: E402

#: 会话 Cookie 名/值（靶据此区分已认证与匿名）
COOKIE_NAME = "PHPSESSID"
COOKIE_VALUE = "auth0001deadbeef"

#: 敏感内容（两种角色看到的是**同一份**时才算暴露）
SECRET_BODY = json.dumps(
    {
        "config": {
            "db_password": "REAL_SECRET_PASSWORD_123",
            "api_key": "sk-live-ABCDEF123456",
            "internal_host": "10.0.0.7:5432",
        },
        "users": [{"id": 1, "email": "ceo@corp.example", "role": "admin"}],
    },
    ensure_ascii=False,
    indent=2,
)

#: 形态 ③ 的匿名视图（公开首页，与上面**不相似**）
PUBLIC_BODY = "<html><body><h1>Welcome to our public site</h1></body></html>"

#: 形态 ② 的重定向目标
LOGIN_BODY = "<html><body>Please log in to continue</body></html>"

ENDPOINTS = {
    "/leaky/config": "exposed",     # ① 有无会话都返回 SECRET_BODY
    "/protected/admin": "protected",  # ② 匿名 302，已认证 SECRET_BODY
    "/mixed/dashboard": "mixed",    # ③ 匿名 PUBLIC_BODY，已认证 SECRET_BODY
}

CVSS_UNAUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


class _Target(BaseHTTPRequestHandler):
    """真实靶：按端点 × 是否带会话决定响应。同时记录每条请求供核对。"""

    def _has_session(self) -> bool:
        cookie = self.headers.get("Cookie") or ""
        return f"{COOKIE_NAME}={COOKIE_VALUE}" in cookie

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        authed = self._has_session()
        with self.server.access_log_path.open("a", encoding="utf-8") as fh:  # type: ignore[attr-defined]
            fh.write(json.dumps({"path": path, "authenticated": authed}) + "\n")

        kind = ENDPOINTS.get(path)
        if kind is None:
            self._send(404, "text/html; charset=utf-8", "<html>404</html>")
            return

        if kind == "exposed":
            # 真暴露：有无会话都拿到同一份敏感内容
            self._send(200, "application/json; charset=utf-8", SECRET_BODY)
            return

        if kind == "protected":
            if authed:
                self._send(200, "application/json; charset=utf-8", SECRET_BODY)
            else:
                # 匿名被拒：302 → 登录页（不跟随重定向，状态码即证据）
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Content-Length", str(len(LOGIN_BODY.encode())))
                self.end_headers()
                self.wfile.write(LOGIN_BODY.encode())
            return

        # mixed：匿名得公开首页，已认证得敏感内容（两者不相似）
        if authed:
            self._send(200, "application/json; charset=utf-8", SECRET_BODY)
        else:
            self._send(200, "text/html; charset=utf-8", PUBLIC_BODY)

    def _send(self, code: int, ctype: str, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


class _MockRouter(ModelRouter):
    """罐头 T2 裁定（Verifier）；T1 不会被用到（判定器是替身）。"""

    def __init__(self, verdict: str = "confirm"):
        self._verdict = verdict
        self.configs = {
            Tier.T1: SimpleNamespace(model="fake-t1"),
            Tier.T2: SimpleNamespace(model="fake-t2-verifier"),
        }

    def complete(self, tier, messages):
        if tier is Tier.T1:  # pragma: no cover - 不应被调用
            return ('{"sensitive": true, "category": "credentials", "anchors": [], '
                    '"reason": "x", "confidence": 0.9}')
        if self._verdict == "confirm":
            return json.dumps({
                "verdict": "confirm",
                "reason": "匿名/已认证响应等价，未授权暴露成立",
                "cvss_vector": CVSS_UNAUTH,
                "cvss_rationale": "匿名可读内部配置与口令，机密性高",
            })
        return json.dumps({"verdict": "reject", "reason": "证据不足"})


class _FakeJudge:
    """替身敏感度判定器（**不构成证据**，只影响报告分类）。"""

    def __init__(self, sensitive: bool = True, truncated: bool = False):
        self.sensitive = sensitive
        self.truncated = truncated
        self.calls = 0

    def judge(self, body, *, finding_id, url, secrets=None):
        self.calls += 1
        return UnauthJudgmentResult(
            sensitive=self.sensitive,
            category="credentials" if self.sensitive else "none",
            anchors=["L4", "L5"] if self.sensitive else [],
            reason="响应内含数据库口令与 API 密钥",
            confidence=0.92,
            model="fake-t1",
            truncated=self.truncated,
            sent_chars=len(body),
        )


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _seed(store: FindingStore, audit: AuditLog, asset: str) -> Finding:
    f = Finding(
        id=store.next_id(), state=FindingState.SIGNAL,
        vuln_type="unauth-exposure", severity="medium",
        asset=asset, param=None, confidence="low",
        evidence_kinds=["status-code"],
        dedup_key=compute_dedup_key(asset, "unauth-exposure", None),
        source_signal_refs=[],
        created_at="2026-09-29T00:00:00.000+00:00",
        updated_at="2026-09-29T00:00:00.000+00:00",
        audit=audit,
    )
    f.transition(FindingState.HYPOTHESIS, actor="triage", reason="M16-c 验收种子")
    store.append(f)
    return f


def main() -> int:
    ap = argparse.ArgumentParser(description="ProofHound M16-c 验收：unauth-exposure")
    ap.add_argument("--skip-verifier", action="store_true",
                    help="形态 ① 用 reject 罐头（验证 Verifier 能否推翻）")
    args = ap.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = REPO / "evidence" / "demo_verify_unauth" / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] 运行目录: {run_dir}")

    port = _free_port()
    access_log = run_dir / "target_access.jsonl"
    access_log.write_text("", encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", port), _Target)
    server.access_log_path = access_log  # type: ignore[attr-defined]
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    print(f"[*] 真靶: {base}（端点 {list(ENDPOINTS)}）")

    audit = AuditLog(run_dir / "audit.jsonl")
    scope = Scope(networks=["127.0.0.0/8"], ports=[port],
                  session=SessionConfig(cookies={COOKIE_NAME: COOKIE_VALUE}))
    registry = SkillRegistry(REPO / "skills").discover()
    store = FindingStore(run_dir / "findings.jsonl")

    seeds = {}
    for endpoint, kind in ENDPOINTS.items():
        seeds[endpoint] = _seed(store, audit, f"{base}{endpoint}")

    judge = _FakeJudge()
    orch = Orchestrator(
        registry, SimpleNamespace(scope=scope), _MockRouter(
            "reject" if args.skip_verifier else "confirm"),
        audit, evidence_dir=run_dir,
        unauth_judge_factory=lambda: judge,
    )

    # blocked 的**终态是 hypothesis**（`_verify_unauth` 在 blocked 时只记
    # `verify_blocked` 审计、不迁移状态——fail-closed，既不驳回也不确认）
    expected = {
        "/leaky/config": "confirmed",
        "/protected/admin": "rejected",
        "/mixed/dashboard": "hypothesis",
    }
    expected_audit = {
        "/leaky/config": None,
        "/protected/admin": "unauth_control_rejected",
        "/mixed/dashboard": "verify_blocked",
    }

    print("\n" + "=" * 78)
    print("跑 verify-unauth（真实 HTTP：宿主 stdlib 直连 → 真靶）")
    print("=" * 78)
    try:
        orch.run_verify_phase(skill_name="verify-unauth")
    finally:
        server.shutdown()

    findings = {f.asset: f for f in store.load_all()}
    ok = True
    for endpoint, kind in ENDPOINTS.items():
        asset = f"{base}{endpoint}"
        f = findings[asset]
        state = f.state.value
        want = expected[endpoint]
        mark = "✅" if state == want else "❌"
        if state != want:
            ok = False
        print(f"  {mark} {endpoint:<20} 形态={kind:<10} 终态={state:<12} 期望={want}")
        if state == "confirmed":
            v = f.verification
            print(f"        method={v.method}")
            print(f"        evidence_kinds={f.evidence_kinds}")
            print(f"        cvss={f.cvss_score} ({f.severity})")
            print(f"        证据 {len(v.evidence_refs)} 件: "
                  f"{[Path(p).name for p in v.evidence_refs]}")
            print(f"        claim: {v.claim}")
            print(f"        actual: {v.actual}")
        elif state == "rejected":
            print(f"        驳回理由: {f.rejection_reason[:120]}")
        else:
            blocked = [e for e in audit.read_all()
                       if e["event"] == "verify_blocked" and e.get("finding_id") == f.id]
            if blocked:
                print(f"        blocked 理由: {blocked[-1]['reason'][:140]}")
            assert blocked, (
                f"{endpoint} 停在 hypothesis 但没有 verify_blocked 审计"
                "（blocked 必须留痕）"
            )

    print("\n" + "=" * 78)
    print("红线 3 核查：送 Verifier 的确定性摘要里有没有响应体原文？")
    print("=" * 78)
    print("  判据：`*_control.json` 是送 Verifier 的摘要 ⇒ **不得**含原文；")
    print("        `*_sent.txt` 是「判定器实际看到了什么」的证据留痕 ⇒ **应当**含原文")
    print("        （它是审计产物，不是 prompt——红线 3 约束的是 Verifier 的输入）")
    for name in ("control.json", "sent.txt"):
        for p in sorted(run_dir.glob(f"unauth_*{name}")):
            text = p.read_text(encoding="utf-8", errors="replace")
            has = "REAL_SECRET_PASSWORD_123" in text
            if name == "control.json":
                tag = "✅ 无原文" if not has else "❌ 泄漏原文"
                if has:
                    ok = False
            else:
                tag = "✅ 留痕正确（本就该有）" if has else "⚠️ 留痕为空"
            print(f"  {p.name:<44} 含口令原文={has}  {tag}")

    print("\n" + "=" * 78)
    print("靶侧访问记录（核对真的发了请求，且匿名侧确实匿名）")
    print("=" * 78)
    records = [json.loads(l) for l in access_log.read_text().splitlines() if l.strip()]
    by_path: dict[str, list[bool]] = {}
    for rec in records:
        by_path.setdefault(rec["path"], []).append(rec["authenticated"])
    for path, authed_flags in sorted(by_path.items()):
        print(f"  {path:<20} 请求 {len(authed_flags)} 次，"
              f"带会话={sum(authed_flags)} 匿名={len(authed_flags) - sum(authed_flags)}")
    total = len(records)
    print(f"  合计 {total} 次真实 HTTP 请求")

    print("\n" + "=" * 78)
    print("中心主张复验：判定器判 not-sensitive 时，真暴露**照样** Confirmed")
    print("=" * 78)
    store2_dir = run_dir / "judge_false"
    store2_dir.mkdir(exist_ok=True)
    audit2 = AuditLog(store2_dir / "audit.jsonl")
    store2 = FindingStore(store2_dir / "findings.jsonl")
    # 复用同一靶需要重启；这里直接用与形态 ① 相同的响应行为
    server2 = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    port2 = server2.server_address[1]
    log2 = store2_dir / "target_access.jsonl"
    log2.write_text("", encoding="utf-8")
    server2.access_log_path = log2  # type: ignore[attr-defined]
    server2.daemon_threads = True
    threading.Thread(target=server2.serve_forever, daemon=True).start()
    base2 = f"http://127.0.0.1:{port2}"
    scope2 = Scope(networks=["127.0.0.0/8"], ports=[port2],
                   session=SessionConfig(cookies={COOKIE_NAME: COOKIE_VALUE}))
    _seed(store2, audit2, f"{base2}/leaky/config")
    judge_false = _FakeJudge(sensitive=False)
    orch2 = Orchestrator(
        registry, SimpleNamespace(scope=scope2), _MockRouter("confirm"),
        audit2, evidence_dir=store2_dir,
        unauth_judge_factory=lambda: judge_false,
    )
    try:
        orch2.run_verify_phase(skill_name="verify-unauth")
    finally:
        server2.shutdown()
    f2 = store2.load_all()[0]
    print(f"  判定器 sensitive=False、category=none、anchors=[]")
    print(f"  → 终态 = {f2.state.value}（期望 confirmed）")
    print(f"  → 判定器调用次数 = {judge_false.calls}")
    assert f2.state is FindingState.CONFIRMED, (
        "判定器判 not-sensitive 时不该影响确认——证据应来自确定性前置门"
    )
    print("  ✅ 证据来自前置门，不来自判定器")

    print("\n" + "=" * 78)
    if ok:
        print("✅ M16-c 验收全绿（真实 HTTP）")
    else:
        print("❌ M16-c 验收有未达期望的形态")
    print(f"[*] 产物：{run_dir}")
    print("=" * 78)
    (run_dir / "summary.json").write_text(
        json.dumps({a: findings[a].state.value for a in findings},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
