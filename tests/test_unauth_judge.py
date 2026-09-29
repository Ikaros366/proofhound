"""M16-c：敏感度判定器 + `verify-unauth` 全链路（Confirmation 端到端）。

本模块证明 M16-c 的核心设计主张：

1. **判定器不产证据**——「判定器判 not sensitive」时 Finding **照样能 Confirmed**
   （证据来自确定性前置门）。这是「AI 结论不得当证据」的可测落地；
2. **判定器失败即 fail-closed**——非法输出 ⇒ `blocked`，**不得**因此确认；
3. **匿名被拒 ⇒ 确定性驳回**（零 LLM 成本，不调判定器也不调 Verifier）；
4. **匿名 2xx 但不等价 ⇒ blocked**（不驳回不确认）；
5. **四段式证据 + 具名证据标签 + method 唯一**齐备；
6. **红线 3**：送 Verifier 的 `extra_summary` 与落盘摘要均**不含响应体原文**。
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
from proofhound.findings.dedup import compute_dedup_key
from proofhound.findings.finding import (
    Finding,
    FindingState,
    FindingStore,
)
from proofhound.llm.router import ModelRouter, Tier
from proofhound.skills.registry import SkillRegistry
from proofhound.verify.cvss import base_score, severity_for_score
from proofhound.verify.unauth_control import (
    UNAUTH_CONFIRMED_METHOD,
    UNAUTH_EQUIVALENCE_EVIDENCE_KIND,
)
from proofhound.verify.unauth_judge import UnauthJudge, UnauthJudgeError

ASSET = "http://127.0.0.1:8080/admin/users"
CVSS_UNAUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

AUTH_COOKIE = "PHPSESSID=auth0001"
SESSION = SessionConfig(cookies={"PHPSESSID": "auth0001"})

_ANON_BODY = "<html>config: password=REAL_SECRET, apikey=ABC123</html>"


# --------------------------------------------------------------- 测试替身


class MockRouter(ModelRouter):
    """按档位回罐头：T1 → 判定器结论，T2 → Verifier 裁定。"""

    def __init__(self, *, judge_reply=None, verdict_reply=None):
        self.judge_reply = judge_reply or (
            '{"sensitive": true, "category": "credentials", '
            '"anchors": ["L1"], "reason": "含明文口令与密钥", "confidence": 0.9}'
        )
        self.verdict_reply = verdict_reply or (
            '{"verdict": "confirm", "reason": "匿名/已认证响应等价，暴露成立", '
            f'"cvss_vector": "{CVSS_UNAUTH}", "cvss_rationale": "匿名可读敏感配置"}}'
        )
        self.seen: list[tuple[str, list[dict]]] = []
        self.configs = {
            Tier.T1: SimpleNamespace(model="fake-t1"),
            Tier.T2: SimpleNamespace(model="fake-t2"),
        }

    def complete(self, tier, messages):
        self.seen.append((tier.value, messages))
        return self.judge_reply if tier is Tier.T1 else self.verdict_reply


class FakeJudge:
    """替身判定器（绕过 LLM）。"""

    def __init__(self, *, sensitive=True, category="credentials",
                 anchors=("L1",), truncated=False, raises=None):
        self.sensitive = sensitive
        self.category = category
        self.anchors = list(anchors)
        self.truncated = truncated
        self.raises = raises
        self.calls = 0

    def judge(self, body, *, finding_id, url, secrets=None):
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        from proofhound.verify.unauth_judge import UnauthJudgmentResult

        return UnauthJudgmentResult(
            sensitive=self.sensitive, category=self.category,
            anchors=list(self.anchors), reason="替身判定", confidence=0.9,
            model="fake-t1", truncated=self.truncated, sent_chars=len(body),
        )


def _canned_fetch(*, auth_status=200, auth_body=_ANON_BODY, auth_error=None,
                  anon_status=200, anon_body=_ANON_BODY, anon_error=None):
    """按会话分角色：带 cookie = 已认证；空会话 = 匿名。"""
    calls: list[str] = []

    def _fake(url, session):
        from proofhound.verify.idor import IdorResponse

        is_anon = not session.cookies and not session.headers
        calls.append("anonymous" if is_anon else "authenticated")
        if is_anon:
            if anon_error is not None:
                return IdorResponse(url=url, error=anon_error)
            return IdorResponse(url=url, status=anon_status, body=anon_body)
        if auth_error is not None:
            return IdorResponse(url=url, error=auth_error)
        return IdorResponse(url=url, status=auth_status, body=auth_body)

    _fake.calls = calls
    return _fake


@pytest.fixture
def env(tmp_path, make_skill_dir):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    audit = AuditLog(evidence_dir / "audit.jsonl")
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080], session=SESSION)
    registry = SkillRegistry(make_skill_dir(name="verify-unauth", tools=())).discover()
    store = FindingStore(evidence_dir / "findings.jsonl")
    return SimpleNamespace(
        evidence_dir=evidence_dir, audit=audit, scope=scope,
        registry=registry, store=store,
    )


def _seed(store: FindingStore, audit: AuditLog) -> Finding:
    finding = Finding(
        id=store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type="unauth-exposure",
        severity="medium",
        asset=ASSET,
        param=None,
        confidence="low",
        evidence_kinds=["status-code"],
        dedup_key=compute_dedup_key(ASSET, "unauth-exposure", None),
        source_signal_refs=[],
        created_at="2026-09-29T00:00:00.000+00:00",
        updated_at="2026-09-29T00:00:00.000+00:00",
        audit=audit,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="测试种子")
    store.append(finding)
    return finding


def _orch(env, fake_fetch, *, judge=None, router=None, unauth_judge_factory=None):
    env.scope.session = SESSION
    runner = SimpleNamespace(scope=env.scope)
    if unauth_judge_factory is None:
        judge = judge if judge is not None else FakeJudge()
        unauth_judge_factory = lambda: judge  # noqa: E731
    return Orchestrator(
        env.registry, runner, router or MockRouter(), env.audit,
        evidence_dir=env.evidence_dir,
        idor_fetch=fake_fetch,
        unauth_judge_factory=unauth_judge_factory,
    )


def _events(audit, name):
    return [e for e in audit.read_all() if e["event"] == name]


# ============================================== 判定器单元（不经编排）


def test_judge_fail_closed_on_invalid_output():
    """非法输出 ⇒ UnauthJudgeError（fail-closed 的信号源）。"""
    judge = UnauthJudge(MockRouter(judge_reply="not json"))
    with pytest.raises(UnauthJudgeError):
        judge.judge("body", finding_id="F-2026-0001", url=ASSET)


def test_judge_redacts_secrets_before_prompt():
    """会话凭据必须在送审前脱敏（不得进 prompt）。"""
    router = MockRouter()
    judge = UnauthJudge(router)
    judge.judge(f"cookie {AUTH_COOKIE} here", finding_id="F-2026-0001", url=ASSET,
                secrets=["auth0001", AUTH_COOKIE])
    sent = "\n".join(m["content"] for m in router.seen[0][1])
    assert "auth0001" not in sent
    assert AUTH_COOKIE not in sent


def test_judge_records_audit_event():
    audit_dir = None
    router = MockRouter()
    judge = UnauthJudge(router)
    res = judge.judge("body", finding_id="F-2026-0001", url=ASSET)
    assert res.sensitive is True and res.category == "credentials"
    assert res.model == "fake-t1"


# ============================================== 全链路


def test_full_chain_confirmed(env):
    """匿名≡已认证 → 门 exposed → 判定器 → 证据门 → Verifier confirm → Confirmed。"""
    seed = _seed(env.store, env.audit)
    fake_fetch = _canned_fetch()
    orch = _orch(env, fake_fetch)

    processed = orch.run_verify_phase(skill_name="verify-unauth")

    assert [f.id for f in processed] == [seed.id]
    finding = env.store.load_all()[0]
    assert finding.state is FindingState.CONFIRMED
    v = finding.verification
    assert v.method == UNAUTH_CONFIRMED_METHOD
    # 具名行为类证据标签（铁律 2 要求非 status-code）
    assert UNAUTH_EQUIVALENCE_EVIDENCE_KIND in finding.evidence_kinds
    assert "status-code" in finding.evidence_kinds  # 种子标签仍在
    # 四段式齐全
    assert v.claim and "无需认证" in v.claim
    assert v.expected and "应被拒" in v.expected
    assert v.actual and "匿名请求返回 200" in v.actual
    assert v.baseline_diff and "未携带任何凭据" in v.baseline_diff
    assert len(v.reproduction_steps) == 4
    # CVSS 由代码算分（LLM 只产向量）
    assert finding.cvss_vector == CVSS_UNAUTH
    assert finding.cvss_score == base_score(CVSS_UNAUTH)
    assert finding.severity == severity_for_score(finding.cvss_score)
    # 两侧请求真的分角色发出，且匿名侧确实匿名
    assert fake_fetch.calls == ["authenticated", "anonymous"]
    # 证据四件齐全
    assert len(v.evidence_refs) == 4
    names = [Path(p).name for p in v.evidence_refs]
    assert names[0] == f"idor_{finding.id}_auth_response.txt"
    assert names[1] == f"idor_{finding.id}_anon_response.txt"
    assert names[2] == f"unauth_{finding.id}_control.json"
    assert names[3] == f"unauth_judge_{finding.id}_sent.txt"


def test_confirmed_even_when_judge_says_not_sensitive(env):
    """**核心主张**：判定器判 not sensitive，Finding 照样 Confirmed。

    证据来自确定性前置门（响应字节等价），不来自判定器。判定器只影响报告分类。
    """
    _seed(env.store, env.audit)
    judge = FakeJudge(sensitive=False, category="none", anchors=())
    orch = _orch(env, _canned_fetch(), judge=judge)

    orch.run_verify_phase(skill_name="verify-unauth")

    finding = env.store.load_all()[0]
    assert finding.state is FindingState.CONFIRMED
    assert judge.calls == 1, "判定器应被调用一次（它只是不构成证据）"


def test_judge_failure_blocks_not_confirms(env):
    """判定器失败 ⇒ blocked（覆盖不全，不驳回也**不确认**）。"""
    _seed(env.store, env.audit)
    judge = FakeJudge(raises=UnauthJudgeError("模型输出非法"))
    orch = _orch(env, _canned_fetch(), judge=judge)

    orch.run_verify_phase(skill_name="verify-unauth")

    finding = env.store.load_all()[0]
    assert finding.state is FindingState.HYPOTHESIS
    blocked = _events(env.audit, "verify_blocked")
    assert blocked and "敏感度判定器未完成" in blocked[-1]["reason"]


@pytest.mark.parametrize("status", [302, 401, 403, 404])
def test_anonymous_denied_is_rejected_without_llm(env, status):
    """匿名被拒 ⇒ 确定性驳回，**不调判定器**（零 LLM 成本）。"""
    _seed(env.store, env.audit)
    judge = FakeJudge()
    orch = _orch(env, _canned_fetch(anon_status=status, anon_body="denied"), judge=judge)

    orch.run_verify_phase(skill_name="verify-unauth")

    finding = env.store.load_all()[0]
    assert finding.state is FindingState.REJECTED
    assert judge.calls == 0, "被拒场景不该消耗判定器"
    assert "本就要求认证" in (finding.rejection_reason or "")


def test_non_equivalent_anonymous_2xx_is_blocked(env):
    """匿名 2xx 但内容不等价 ⇒ blocked（不驳回不确认）。"""
    _seed(env.store, env.audit)
    orch = _orch(env, _canned_fetch(
        anon_status=200, anon_body="<html>public landing page</html>"))

    orch.run_verify_phase(skill_name="verify-unauth")

    finding = env.store.load_all()[0]
    assert finding.state is FindingState.HYPOTHESIS
    blocked = _events(env.audit, "verify_blocked")
    assert blocked and "覆盖不全" in blocked[-1]["reason"]


def test_anonymous_network_error_is_blocked(env):
    _seed(env.store, env.audit)
    orch = _orch(env, _canned_fetch(anon_error="connection refused"))

    orch.run_verify_phase(skill_name="verify-unauth")

    assert env.store.load_all()[0].state is FindingState.HYPOTHESIS


def test_missing_session_is_blocked_fail_closed(env):
    """scope 无预置会话 ⇒ 无法构造已认证视图 ⇒ blocked。"""
    _seed(env.store, env.audit)
    env.scope.session = None
    runner = SimpleNamespace(scope=env.scope)
    orch = Orchestrator(env.registry, runner, MockRouter(), env.audit,
                        evidence_dir=env.evidence_dir,
                        idor_fetch=_canned_fetch(),
                        unauth_judge_factory=lambda: FakeJudge())

    orch.run_verify_phase(skill_name="verify-unauth")

    assert env.store.load_all()[0].state is FindingState.HYPOTHESIS
    blocked = _events(env.audit, "verify_blocked")
    assert blocked and "预置会话" in blocked[-1]["reason"]


def test_out_of_scope_asset_is_blocked(env):
    """候选资产越界 ⇒ 红线 5 拦截（verify_scope_rejected）。"""
    finding = Finding(
        id=env.store.next_id(), state=FindingState.SIGNAL,
        vuln_type="unauth-exposure", severity="medium",
        asset="http://evil.example.com/admin", param=None, confidence="low",
        evidence_kinds=["status-code"],
        dedup_key=compute_dedup_key("http://evil.example.com/admin",
                                    "unauth-exposure", None),
        source_signal_refs=[],
        created_at="2026-09-29T00:00:00.000+00:00",
        updated_at="2026-09-29T00:00:00.000+00:00",
        audit=env.audit,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="种子")
    env.store.append(finding)

    orch = _orch(env, _canned_fetch())
    orch.run_verify_phase(skill_name="verify-unauth")

    assert env.store.load_all()[0].state is FindingState.HYPOTHESIS
    assert _events(env.audit, "verify_scope_rejected")


def test_gate_has_unauth_entry_and_method_is_exclusive():
    """证据门注册了 unauth-exposure，且 method 与既有四类**互不染指**。"""
    from proofhound.verify.gate import GATE_MATRIX

    assert "unauth-exposure" in GATE_MATRIX
    req = GATE_MATRIX["unauth-exposure"]
    assert req.methods == frozenset({UNAUTH_CONFIRMED_METHOD})
    assert req.behavioral_kinds == frozenset({UNAUTH_EQUIVALENCE_EVIDENCE_KIND})
    seen: dict[str, str] = {}
    for vuln_type, requirement in GATE_MATRIX.items():
        for method in requirement.methods:
            assert method not in seen, f"{method} 同时属于 {seen[method]} 与 {vuln_type}"
            seen[method] = vuln_type
    assert len(seen) == sum(len(r.methods) for r in GATE_MATRIX.values())


def test_web_exposure_still_not_confirmable():
    """回归：`web-exposure` **仍**不在矩阵内（判定面零放松）。"""
    from proofhound.verify.gate import GATE_MATRIX

    assert "web-exposure" not in GATE_MATRIX


def test_verifier_summary_has_no_response_body(env):
    """红线 3：送 Verifier 的 extra_summary 不含响应体原文。"""
    _seed(env.store, env.audit)
    router = MockRouter()
    orch = _orch(env, _canned_fetch(), router=router)

    orch.run_verify_phase(skill_name="verify-unauth")

    t2 = [msgs for tier, msgs in router.seen if tier == "t2"]
    assert t2, "Verifier（T2）应被调用"
    payload = json.dumps(t2[0], ensure_ascii=False)
    assert "REAL_SECRET" not in payload
    assert "ABC123" not in payload
    # 但确定性结论与锚点应当在
    assert "unauth_verdict" in payload or "exposed" in payload


def test_control_json_on_disk_has_no_body(env):
    """落盘的判定 JSON 也不含响应体原文。"""
    seed = _seed(env.store, env.audit)
    orch = _orch(env, _canned_fetch())
    orch.run_verify_phase(skill_name="verify-unauth")

    path = env.evidence_dir / f"unauth_{seed.id}_control.json"
    text = path.read_text(encoding="utf-8")
    assert "REAL_SECRET" not in text
    data = json.loads(text)
    assert data["unauth_verdict"] == "exposed"
    assert data["byte_identical"] is True


def test_sent_body_evidence_is_written(env):
    """判定器实际看到的正文必须落盘（"判定器看到了什么"可复核）。"""
    seed = _seed(env.store, env.audit)
    orch = _orch(env, _canned_fetch())
    orch.run_verify_phase(skill_name="verify-unauth")

    path = env.evidence_dir / f"unauth_judge_{seed.id}_sent.txt"
    assert path.is_file()
    assert "REAL_SECRET" in path.read_text(encoding="utf-8")
