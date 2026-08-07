"""verify 阶段全链路测试（M3b）：run_verify_phase + verify-sqli 垂直切片。

mock T2 路由 + FakeRunner（预制工具输出、零真实执行），覆盖：
- 正例全链：Hypothesis →（带会话 baseline → sqlmap 确认）→ Reproduced →
  证据门 → Verifier confirm → Confirmed；verification 全字段、behavioral
  标签、证据包刷新、审计序列完整；
- 反例：sqlmap 未确认 → REJECTED(actor=verify-sqli)，Verifier 零调用；
  Verifier reject → REJECTED(actor=verifier)；Verifier 非法输出 → 停
  Reproduced（fail-closed）；version-cve + 纯 status-code 种子 → 工具零
  调用 + 证据门 fail-closed + 状态机铁律拦截（铁律 e2e 再现）；
- 脱敏专项：全审计链与 findings.jsonl 无 Cookie 原文（仅 sha256 标记）。
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings import (
    Finding,
    FindingState,
    FindingStore,
    IronRuleViolationError,
    compute_dedup_key,
)
from proofhound.llm.router import ModelRouter, Tier
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.sandbox import RunResult
from proofhound.verify.gate import check as gate_check

FIXTURES = Path(__file__).parent / "fixtures"
ASSET = "http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit"
PHPSESSID = "df6a4b9c0e1f2a3b4c5d6e7f890abcde"
SESSION = SessionConfig(cookies={"PHPSESSID": PHPSESSID, "security": "low"})


class FakeRunner:
    """按工具名弹出预制输出；写真实 stdout/stderr 证据文件，零执行。"""

    def __init__(self, scope: Scope, evidence_dir: Path, script: dict[str, list]):
        self.scope = scope
        self.evidence_dir = evidence_dir
        self.script = {tool: list(responses) for tool, responses in script.items()}
        self.calls: list[tuple[str, list[str]]] = []
        self.egress_proxy_url = None
        self._seq = 0

    def run(self, tool, args, timeout=300, image=None):
        self.calls.append((tool, args))
        responses = self.script.get(tool) or []
        if not responses:
            raise AssertionError(f"FakeRunner 未预制 {tool} 的输出")
        stdout_text, exit_code = responses.pop(0)
        self._seq += 1
        stdout_path = self.evidence_dir / f"fake{self._seq}.stdout.log"
        stderr_path = self.evidence_dir / f"fake{self._seq}.stderr.log"
        stdout_path.write_text(stdout_text, encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        return RunResult(
            rejected=False,
            command=[tool, *args],
            exit_code=exit_code,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )


class MockRouter(ModelRouter):
    """罐头 T2 路由（继承 ModelRouter 过 ensure_router 的 isinstance 闸）。"""

    def __init__(self, reply: str):
        self.reply = reply  # 不调 super().__init__：不建 HTTP 客户端
        self.calls: list[tuple] = []
        self.configs = {Tier.T2: SimpleNamespace(model="kimi-k3-test")}

    def complete(self, tier, messages):
        self.calls.append((tier, messages))
        return self.reply


def _httpx_line(status: int) -> str:
    return json.dumps({"url": ASSET, "status_code": status, "title": "DVWA"}) + "\n"


def _confirmed_stdout() -> str:
    return (FIXTURES / "sqlmap_confirmed_1_10.txt").read_text(encoding="utf-8")


def _negative_stdout() -> str:
    return (FIXTURES / "sqlmap_negative_1_10.txt").read_text(encoding="utf-8")


def _seed(store: FindingStore, audit: AuditLog, **overrides) -> Finding:
    base = dict(
        vuln_type="sqli",
        asset=ASSET,
        param="id",
        title="DVWA sqli",
        evidence_kinds=["status-code"],
    )
    base.update(overrides)
    finding = Finding(
        id=store.next_id(),
        state=FindingState.SIGNAL,
        severity="medium",
        confidence="low",
        dedup_key=compute_dedup_key(base["asset"], base["vuln_type"], base.get("param")),
        created_at="2026-08-07T00:00:00.000+00:00",
        updated_at="2026-08-07T00:00:00.000+00:00",
        audit=audit,
        **base,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="seed", reason="测试种子")
    store.append(finding)
    return finding


@pytest.fixture
def env(tmp_path, make_skill_dir):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    audit = AuditLog(evidence_dir / "audit.jsonl")
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080], session=SESSION)
    registry = SkillRegistry(
        make_skill_dir(name="verify-sqli", tools=("httpx", "sqlmap"))
    ).discover()
    store = FindingStore(evidence_dir / "findings.jsonl")
    return SimpleNamespace(
        evidence_dir=evidence_dir,
        audit=audit,
        scope=scope,
        registry=registry,
        store=store,
        tmp_path=tmp_path,
    )


def _orch(env, script, router_reply='{"verdict": "confirm", "reason": "证据链完整"}'):
    runner = FakeRunner(env.scope, env.evidence_dir, script)
    router = MockRouter(router_reply)
    orch = Orchestrator(env.registry, runner, router, env.audit, evidence_dir=env.evidence_dir)
    return orch, runner, router


def test_positive_full_chain_to_confirmed(env):
    seed = _seed(env.store, env.audit)
    orch, runner, router = _orch(
        env,
        {
            "httpx": [(_httpx_line(200), 0)],
            "sqlmap": [(_confirmed_stdout(), 0)],
        },
    )
    processed = orch.run_verify_phase(skill_name="verify-sqli")

    assert [f.id for f in processed] == [seed.id]
    finding = processed[0]
    assert finding.state is FindingState.CONFIRMED
    assert finding.confidence == "confirmed"  # §5.5：确认即提升置信度
    assert "behavioral" in finding.evidence_kinds
    verification = finding.verification
    assert verification.method == "sqlmap-confirmed"
    assert verification.verified_by == "verify-sqli@1.0.0"
    assert len(verification.evidence_refs) == 2
    assert any("#L" in ref for ref in verification.evidence_refs)
    assert "boolean-based blind" in verification.baseline_diff
    assert len(verification.reproduction_steps) == 4
    assert finding.verifier.verdict == "confirm"
    assert finding.verifier.model == "kimi-k3-test"

    # 工具调用序列：baseline(httpx) → sqlmap；sqlmap 走 python 镜像覆盖
    assert [tool for tool, _ in runner.calls] == ["httpx", "sqlmap"]
    sqlmap_args = runner.calls[1][1]
    assert "--cookie" in sqlmap_args  # 真实 argv 带凭据（容器执行用）
    assert PHPSESSID in sqlmap_args[sqlmap_args.index("--cookie") + 1]

    # 审计序列：reproduced → verifier_verdict → confirmed
    events = env.audit.read_all()
    kinds = [(e["event"], e.get("to")) for e in events]
    assert ("finding_state", "reproduced") in kinds
    assert ("finding_state", "confirmed") in kinds
    verdict_events = [e for e in events if e["event"] == "verifier_verdict"]
    assert len(verdict_events) == 1 and verdict_events[0]["verdict"] == "confirm"
    completed = [e for e in events if e["event"] == "verify_completed"][0]
    assert completed["confirmed"] == 1 and completed["processed"] == 1

    # 证据包刷新：manifest 含 baseline + sqlmap 原文，finding.json 含 verifier
    pack = env.evidence_dir / "findings" / seed.id
    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["items"]) == 2
    assert all(item["sha256"] for item in manifest["items"])
    snapshot = json.loads((pack / "finding.json").read_text(encoding="utf-8"))
    assert snapshot["state"] == "confirmed"
    assert snapshot["verifier"]["verdict"] == "confirm"
    assert (pack / "reproduction_steps.md").is_file()


def test_full_audit_chain_has_no_cookie(env):
    """脱敏专项：audit.jsonl / findings.jsonl / 全部产物文件无 Cookie 原文。"""
    _seed(env.store, env.audit)
    orch, _, _ = _orch(
        env,
        {
            "httpx": [(_httpx_line(200), 0)],
            "sqlmap": [(_confirmed_stdout(), 0)],
        },
    )
    orch.run_verify_phase(skill_name="verify-sqli")

    for path in env.evidence_dir.rglob("*"):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        assert PHPSESSID.encode() not in raw, f"{path} 泄漏 Cookie 原文"
        assert b"security=low" not in raw
    steps = env.store.get(env.store.load_all()[0].id).verification.reproduction_steps
    assert any("sha256:" in step for step in steps)


def test_sqlmap_not_confirmed_rejects_without_verifier(env):
    _seed(env.store, env.audit)
    orch, _, router = _orch(
        env,
        {
            "httpx": [(_httpx_line(200), 0)],
            "sqlmap": [(_negative_stdout(), 0)],
        },
    )
    processed = orch.run_verify_phase(skill_name="verify-sqli")

    finding = processed[0]
    assert finding.state is FindingState.REJECTED
    assert "未确认注入" in finding.rejection_reason
    assert router.calls == []  # sqlmap 未确认不进 Verifier 环节
    events = env.audit.read_all()
    rejected = [e for e in events if e["event"] == "finding_state" and e["to"] == "rejected"]
    assert rejected[0]["actor"] == "verify-sqli"
    completed = [e for e in events if e["event"] == "verify_completed"][0]
    assert completed["rejected"] == 1


def test_verifier_reject_transitions_rejected(env):
    _seed(env.store, env.audit)
    orch, _, _ = _orch(
        env,
        {
            "httpx": [(_httpx_line(200), 0)],
            "sqlmap": [(_confirmed_stdout(), 0)],
        },
        router_reply='{"verdict": "reject", "reason": "更平凡解释：错误页差异"}',
    )
    processed = orch.run_verify_phase(skill_name="verify-sqli")

    finding = processed[0]
    assert finding.state is FindingState.REJECTED
    events = env.audit.read_all()
    rejected = [e for e in events if e["event"] == "finding_state" and e["to"] == "rejected"]
    assert rejected[0]["actor"] == "verifier"
    assert "更平凡解释" in rejected[0]["reason"]


def test_verifier_invalid_output_stays_reproduced(env):
    """非法 verdict 拒收：fail-closed 停于 Reproduced，不得晋级。"""
    _seed(env.store, env.audit)
    orch, _, _ = _orch(
        env,
        {
            "httpx": [(_httpx_line(200), 0)],
            "sqlmap": [(_confirmed_stdout(), 0)],
        },
        router_reply="这不是 JSON",
    )
    processed = orch.run_verify_phase(skill_name="verify-sqli")

    finding = processed[0]
    assert finding.state is FindingState.REPRODUCED
    assert finding.verifier is None
    events = env.audit.read_all()
    assert any(e["event"] == "verify_blocked" for e in events)
    assert not any(e["event"] == "finding_state" and e["to"] == "confirmed" for e in events)


def test_version_cve_seed_never_confirmed(env):
    """反例铁律 e2e 再现：version-cve + 纯 status-code 拒转 Confirmed。"""
    seed = _seed(
        env.store,
        env.audit,
        vuln_type="version-cve",
        param=None,
        asset="http://127.0.0.1:8080/",
    )
    orch, runner, _ = _orch(
        env,
        {  # 即使预制了"确认"输出，也不允许被消费
            "httpx": [(_httpx_line(200), 0)],
            "sqlmap": [(_confirmed_stdout(), 0)],
        },
    )
    processed = orch.run_verify_phase(skill_name="verify-sqli")

    assert processed == []
    assert runner.calls == []  # 无 handler，工具零调用
    events = env.audit.read_all()
    assert any(e["event"] == "verify_skipped" for e in events)

    finding = env.store.get(seed.id)
    assert finding.state is FindingState.HYPOTHESIS
    gate = gate_check(finding)
    assert not gate.passed  # 证据门 fail-closed：version-cve 无矩阵项
    finding.audit = env.audit
    finding.transition(FindingState.REPRODUCED, actor="test", reason="推进到铁律闸前")
    with pytest.raises(IronRuleViolationError):
        finding.transition(FindingState.CONFIRMED, actor="test", reason="铁律反例")


def test_baseline_failure_blocks_before_sqlmap(env):
    """会话失效（302 登录跳转）→ baseline 失败，sqlmap 不得执行。"""
    _seed(env.store, env.audit)
    orch, runner, _ = _orch(env, {"httpx": [(_httpx_line(302), 0)]})
    processed = orch.run_verify_phase(skill_name="verify-sqli")

    assert processed[0].state is FindingState.HYPOTHESIS
    assert [tool for tool, _ in runner.calls] == ["httpx"]
    events = env.audit.read_all()
    assert any(e["event"] == "verify_baseline_failed" for e in events)


def test_missing_session_blocks(env):
    """scope 未配置预置会话：fail-closed，Finding 停留原态。"""
    _seed(env.store, env.audit)
    env.scope = Scope(networks=["127.0.0.0/8"], ports=[8080])  # 无 session
    orch, runner, _ = _orch(env, {})
    processed = orch.run_verify_phase(skill_name="verify-sqli")

    assert processed[0].state is FindingState.HYPOTHESIS
    assert runner.calls == []
    events = env.audit.read_all()
    blocked = [e for e in events if e["event"] == "verify_blocked"]
    assert any("预置会话" in e["reason"] for e in blocked)


def test_sqlmap_tool_failure_keeps_hypothesis(env):
    _seed(env.store, env.audit)
    orch, _, _ = _orch(
        env,
        {
            "httpx": [(_httpx_line(200), 0)],
            "sqlmap": [("sqlmap: command crashed", 1)],
        },
    )
    processed = orch.run_verify_phase(skill_name="verify-sqli")
    assert processed[0].state is FindingState.HYPOTHESIS
    events = env.audit.read_all()
    assert any(e["event"] == "verify_tool_failed" for e in events)
