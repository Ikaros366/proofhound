#!/usr/bin/env python
"""M17-b 验收：`unauth-exposure` **零 seed** 全链路（发现→确认）。

## 为什么单独有这么一个脚本

M16-c 的验收脚本 `demo_verify_unauth.py` 里，Finding 是**手写 seed** 的
（它的 `_seed()`）。那次「真靶真 HTTP 全绿」验的是**判定通道自身**，**没有验
「功能真接上了」**——真实扫描当时根本产不出该类型的 Finding（AGENTS.md 已知
限制 58）。交接单项目纪律第 11 条就此立规：

    **验收脚本若自己 seed Finding，那就只验了判定端、没验接通性。**

本脚本是那条纪律的落地：**全程零构造 Finding**。流程是

    合成 Signal（只写 signals.jsonl）
      → `run_triage_phase()`（**生产代码**建 Finding，含新派生）
      → `run_verify_phase("verify-unauth")`
      → 真实 HTTP 打真靶（确定性 `judge_unauth` 产证据）
      → 证据门 → Verifier → CONFIRMED

并额外覆盖三件 M16-c 脚本覆盖不到的事：

1. **有会话才派生**：同批 Signal 在「有会话 / 无会话」两个 scope 下各跑一次，
   断言无会话时**一个** `unauth-exposure` 都不产（回退行为）；
2. **上限生效**：超过 `_TRIAGE_UNAUTH_CAP` 的信号数记 `triage_capped`；
3. **前置门不吃配额**：无会话下候选一次也不进贵验证档（`verify_type_unavailable`）。

真靶、靶上端点语义、罐头判定器/Verifier 全部**复用** `demo_verify_unauth.py`
（`from ... import`，零复制）。判定器与 Verifier 是替身（不构成证据），
但**证据本身来自真实 HTTP 响应**的确定性判定。
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from proofhound.compliance.audit import AuditLog  # noqa: E402
from proofhound.compliance.scope import Scope  # noqa: E402
from proofhound.compliance.session import SessionConfig  # noqa: E402
from proofhound.core.orchestrator import (  # noqa: E402
    _TRIAGE_UNAUTH_CAP,
    Orchestrator,
)
from proofhound.findings.finding import FindingState, FindingStore  # noqa: E402
from proofhound.findings.signal import Signal  # noqa: E402
from proofhound.skills.registry import SkillRegistry  # noqa: E402
from proofhound.verify.unauth_control import (  # noqa: E402
    UNAUTH_CONFIRMED_METHOD,
    UNAUTH_EQUIVALENCE_EVIDENCE_KIND,
)

# 真靶 + 端点语义 + 罐头判定器/Verifier：全部复用 M16-c 的验收脚本（零复制）
from demo_verify_unauth import (  # noqa: E402
    COOKIE_NAME,
    COOKIE_VALUE,
    ENDPOINTS,
    _FakeJudge,
    _MockRouter,
    _Target,
    _free_port,
)

#: 本轮的「发现侧」输入：`web-probe` 存活信号（httpx/dirsearch 的产出形态）。
#: **只写 Signal**——不构造任何 Finding。
SCANNED_PATHS = ["/leaky/config", "/protected/admin", "/mixed/dashboard"]

#: 额外用于压上限的路径（同一信号批次里多产候选，验证 triage_capped）
_CAP_FILLER = [f"/filler/{i}" for i in range(_TRIAGE_UNAUTH_CAP + 3)]


def _signal(asset: str, status: int, ref: str) -> Signal:
    """一条 `web-probe` 存活 Signal（发现侧的真实产出形态）。"""
    return Signal(
        asset=asset,
        status_code=status,
        kind="web-probe",
        source_tool="httpx",
        skill="web-scan",
        evidence_ref=ref,
    )


def _write_signals(run_dir: Path, base: str, paths: list[str]) -> Path:
    """把合成 Signal 落盘成编排器会加载的 `*.signals.jsonl`（零 Finding）。"""
    raw = run_dir / "scan.stdout.log"
    raw.write_text("\n".join('{"status_code": 200}' for _ in paths) + "\n",
                   encoding="utf-8")
    rows = [
        _signal(f"{base}{path}", 200, f"{raw.name}#L{i + 1}")
        for i, path in enumerate(paths)
    ]
    signals_path = run_dir / "scan.signals.jsonl"
    signals_path.write_text(
        "\n".join(row.model_dump_json() for row in rows) + "\n", encoding="utf-8"
    )
    return signals_path


def _new_orch(run_dir: Path, scope: Scope) -> Orchestrator:
    """按本 run 目录建编排器（证据目录即 run 目录，审计同源）。"""
    return Orchestrator(
        SkillRegistry(REPO / "skills").discover(),
        runner=SimpleNamespace(scope=scope),
        llm=_MockRouter(),
        audit=AuditLog(run_dir / "audit.jsonl"),
        evidence_dir=run_dir,
        unauth_judge_factory=lambda: _FakeJudge(),
    )


def _events(audit_path: Path, name: str) -> list[dict]:
    out = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event") == name:
            out.append(event)
    return out


def _production_stack_verify_skills(registry):
    """API 生产栈实际会调用的 verify 槽位清单（限制 59 的那处接线）。

    直接构造 `OrchestratorPhases`（用假编排器 + 真 registry，不需要 Docker），
    取它的 `verify_skills`——这正是 `default_phases_factory` 最后一行做的事。
    """
    from proofhound.api.runner import OrchestratorPhases

    phases = OrchestratorPhases(SimpleNamespace(audit=SimpleNamespace()), registry)
    return [name for name, _level in phases.verify_skills]


def _count_by_type(findings) -> dict[str, int]:
    """按 vuln_type 计数（**同一个 asset 会有多条 Finding**，不可按 asset 建字典）。"""
    out: dict[str, int] = {}
    for finding in findings:
        out[finding.vuln_type] = out.get(finding.vuln_type, 0) + 1
    return out


def _pick(findings, asset: str, vuln_type: str):
    """取指定 (asset, vuln_type) 的那一条 Finding。"""
    for finding in findings:
        if finding.asset == asset and finding.vuln_type == vuln_type:
            return finding
    raise AssertionError(f"找不到 Finding: {asset} / {vuln_type}")


def _state_machine(run_dir: Path) -> dict[str, str]:
    """按 Finding 的审计事件还原「最终状态」（比对新旧 snapshot）。"""
    states: dict[str, str] = {}
    for line in (run_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event") == "finding_state":
            states[event["finding_id"]] = event["to"]
    return states


def main() -> int:
    ap = argparse.ArgumentParser(
        description="ProofHound M17-b 验收：unauth-exposure 零 seed 全链路"
    )
    ap.add_argument("--keep-evidence", action="store_true",
                    help="保留产物（缺省也保留；本开关仅作显式声明）")
    args = ap.parse_args()  # noqa: F841

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = REPO / "evidence" / "demo_unauth_zero_seed" / stamp
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

    signals_path = _write_signals(run_dir, base, SCANNED_PATHS)
    print(f"[*] 只写 Signal（零 Finding）: {signals_path.name}")

    # ---------- A) 有会话：必须派生 unauth-exposure ----------
    print()
    print("===== A) 有预置会话：发现→确认全链路（零 seed）=====")
    scope = Scope(networks=["127.0.0.0/8"], ports=[port],
                  session=SessionConfig(cookies={COOKIE_NAME: COOKIE_VALUE}))
    orch = _new_orch(run_dir, scope)
    print("发现：run_triage_phase()（生产代码建 Finding）")
    orch.run_triage_phase()

    store = FindingStore(run_dir / "findings.jsonl")
    findings = store.load_all()  # 同一 asset 会有多条 Finding，故用 list
    by_type = _count_by_type(findings)
    print(f"  产出 Finding {len(findings)} 条，按类型 {by_type}")
    assert by_type.get("unauth-exposure", 0) == len(SCANNED_PATHS), (
        f"有会话时必须为每个 2xx 端点派生 unauth-exposure 候选；实测 {by_type}"
    )
    # 并存验证：web-exposure 一条都不能少（维护者裁定的 A-变体）
    assert by_type.get("web-exposure", 0) == len(SCANNED_PATHS), (
        f"web-exposure 必须与之一并存（不取代）；实测 {by_type}"
    )
    assert all(f.state is FindingState.HYPOTHESIS for f in findings), (
        "triage 阶段全部候选应停在 Hypothesis"
    )
    print("  ✅ 每个 2xx 端点：web-exposure（信息类观察）+ unauth-exposure（可确认）并存")

    print("确认：run_verify_phase('verify-unauth')（真实 HTTP 打真靶）")
    orch.run_verify_phase(skill_name="verify-unauth")
    states = _state_machine(run_dir)
    print(f"  终态: {states}")

    leaky = f"{base}/leaky/config"
    protected = f"{base}/protected/admin"
    mixed = f"{base}/mixed/dashboard"
    # 只看 unauth-exposure 那一家（web-exposure 无 handler，停在 Hypothesis 是设计）
    confirmed = sorted(
        f.asset
        for f in findings
        if f.vuln_type == "unauth-exposure" and states.get(f.id) == "confirmed"
    )
    rejected = sorted(
        f.asset
        for f in findings
        if f.vuln_type == "unauth-exposure" and states.get(f.id) == "rejected"
    )
    blocked_states = sorted(
        f.asset
        for f in findings
        if f.vuln_type == "unauth-exposure"
        and states.get(f.id) not in ("confirmed", "rejected")
    )
    assert leaky in confirmed, f"匿名与已认证等价 ⇒ 必须 CONFIRMED；实测 {states}"
    assert protected in rejected, f"匿名被拒（302）⇒ 必须 REJECTED；实测 {states}"
    assert mixed not in confirmed, f"匿名只见公开页 ⇒ 不得 CONFIRMED；实测 {states}"
    print(f"  ✅ CONFIRMED: {confirmed}")
    print(f"  ✅ REJECTED : {rejected}")
    print(f"  ⏸  仍停 Hypothesis（覆盖不全）: {blocked_states}")

    # web-exposure 无 verify handler ⇒ 必须一条都没被这个 phase 动过
    web_exposure_states = {
        states.get(f.id, "hypothesis")
        for f in findings
        if f.vuln_type == "web-exposure"
    }
    assert web_exposure_states == {"hypothesis"}, (
        f"web-exposure 不得被 verify-unauth 触及；实测 {web_exposure_states}"
    )
    print("  ✅ web-exposure 全部停在 Hypothesis（无 handler，且未被本 phase 触及）")

    # 四段式与证据门（Confirmed 必须齐备）。
    # ⚠️ 必须**重新加载 store**：`run_verify_phase` 从 findings.jsonl 回放 Finding、
    # 改的是另一份实例再 append 回去，triage 时加载的内存对象不会被更新。
    findings = FindingStore(run_dir / "findings.jsonl").load_all()
    entry = _pick(findings, leaky, "unauth-exposure")
    assert entry.verification is not None
    assert entry.verification.method == UNAUTH_CONFIRMED_METHOD
    assert UNAUTH_EQUIVALENCE_EVIDENCE_KIND in entry.evidence_kinds
    assert entry.verification.evidence_refs
    print(f"  ✅ method={entry.verification.method} / evidence_kinds={entry.evidence_kinds}")
    print(f"  ✅ 证据 {len(entry.verification.evidence_refs)} 份 + 证据门通过 + Verifier confirm")

    # 真靶访问日志：匿名那次**没带任何凭据**（判定前提）
    rows = [
        json.loads(x)
        for x in access_log.read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]
    anon_hits = [r for r in rows if not r["authenticated"]]
    auth_hits = [r for r in rows if r["authenticated"]]
    assert anon_hits and auth_hits, f"靶必须同时收到匿名与已认证请求；实测 {rows}"
    print(f"  ✅ 真靶访问日志：匿名 {len(anon_hits)} 次 / 已认证 {len(auth_hits)} 次")

    # ---------- B) 无会话：一个都不许派生 ----------
    print()
    print("===== B) 无预置会话：不得派生（回退行为）=====")
    run_dir_b = run_dir / "no_session"
    run_dir_b.mkdir(parents=True, exist_ok=True)
    _write_signals(run_dir_b, base, SCANNED_PATHS)
    scope_b = Scope(networks=["127.0.0.0/8"], ports=[port])  # 无 session
    orch_b = _new_orch(run_dir_b, scope_b)
    orch_b.run_triage_phase()
    findings_b = FindingStore(run_dir_b / "findings.jsonl").load_all()
    types_b: dict[str, int] = {}
    for f in findings_b:
        types_b[f.vuln_type] = types_b.get(f.vuln_type, 0) + 1
    print(f"  产出 Finding {len(findings_b)} 条，按类型 {types_b}")
    assert "unauth-exposure" not in types_b, (
        f"无会话时不得派生 unauth-exposure（前置不可满足）；实测 {types_b}"
    )
    assert types_b.get("web-exposure", 0) == len(SCANNED_PATHS), (
        f"web-exposure 必须照常产出（信息类记录不丢）；实测 {types_b}"
    )
    print("  ✅ 零 unauth-exposure；web-exposure 照常（无回退、不丢信息类记录）")

    # ---------- C) 前置门不吃贵验证配额 ----------
    print()
    print("===== C) 无会话跑 verify：前置门不吃贵验证配额 =====")
    # 该 scope 无会话 ⇒ 手工把一条 unauth-exposure 塞进来也无从验证……
    # 但本脚本纪律是「零构造 Finding」，故改为验证**前置判据方法**本身：
    reason = orch_b.verify_precondition_blocked("unauth-exposure")
    reason_ssrf = orch_b.verify_precondition_blocked("ssrf")
    reason_sqli = orch_b.verify_precondition_blocked("sqli")
    assert reason and "预置会话" in reason, reason
    assert reason_ssrf, "ssrf 同样需要会话 baseline"
    assert reason_sqli is None, "sqli 不依赖会话，不得被前置门拦下"
    print(f"  无会话时：unauth-exposure -> {reason}")
    print(f"            ssrf            -> {reason_ssrf}")
    print("            sqli            -> None（不拦）")
    assert orch.verify_precondition_blocked("unauth-exposure") is None, (
        "有会话时不得被前置门拦下"
    )
    print("  ✅ 有会话时不拦；无会话时整类拦下（handler 内也必然 blocked，语义不变）")

    # ---------- D) 上限生效 ----------
    print()
    print("===== D) 独立上限 _TRIAGE_UNAUTH_CAP 生效 =====")
    run_dir_d = run_dir / "cap"
    run_dir_d.mkdir(parents=True, exist_ok=True)
    _write_signals(run_dir_d, base, SCANNED_PATHS + _CAP_FILLER)
    orch_d = _new_orch(run_dir_d, scope)
    orch_d.run_triage_phase()
    capped = _events(run_dir_d / "audit.jsonl", "triage_capped")
    unauth_capped = [e for e in capped if e["vuln_type"] == "unauth-exposure"]
    made = [
        f
        for f in FindingStore(run_dir_d / "findings.jsonl").load_all()
        if f.vuln_type == "unauth-exposure"
    ]
    print(f"  Signal 里 2xx 端点 {len(SCANNED_PATHS) + len(_CAP_FILLER)} 个；"
          f"建出 unauth-exposure {len(made)} 条（上限 {_TRIAGE_UNAUTH_CAP}）")
    assert len(made) == _TRIAGE_UNAUTH_CAP, (
        f"新建数必须正好等于上限；实测 {len(made)}"
    )
    assert unauth_capped and unauth_capped[0]["limit"] == _TRIAGE_UNAUTH_CAP, (
        f"必须记独立 triage_capped 事件；实测 {capped}"
    )
    print(f"  ✅ triage_capped(vuln_type=unauth-exposure, limit={_TRIAGE_UNAUTH_CAP}, "
          f"dropped={unauth_capped[0]['dropped']})")

    # ---------- E) 生产栈接线（限制 59 的守护） ----------
    print()
    print("===== E) API 生产栈真的会调用 verify-unauth（限制 59）=====")
    registry = SkillRegistry(REPO / "skills").discover()
    slots = _production_stack_verify_skills(registry)
    print(f"  生产栈 verify 槽位: {slots}")
    assert "verify-unauth" in slots, (
        f"生产栈必须挂上 verify-unauth，否则经 API/控制台跑的 engagement 永不调用它"
        f"（这正是 AGENTS.md 限制 59）；实测 {slots}"
    )
    print("  ✅ verify-unauth 在生产栈槽位里（限制 59 已修且被本脚本盯住）")

    print()
    print("=" * 68)
    print("全部断言通过：unauth-exposure 在生产链路**可达且可确认**（零 seed）")
    print("=" * 68)
    summary = {
        "run_dir": str(run_dir.relative_to(REPO)),
        "signals": len(SCANNED_PATHS),
        "by_type": by_type,
        "final_states": states,
        "confirmed": sorted(confirmed),
        "rejected": sorted(rejected),
        "no_session_by_type": types_b,
        "cap": {
            "limit": _TRIAGE_UNAUTH_CAP,
            "created": len(made),
            "dropped": unauth_capped[0]["dropped"] if unauth_capped else 0,
        },
        "target_requests": {"anonymous": len(anon_hits), "authenticated": len(auth_hits)},
    }
    (run_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
