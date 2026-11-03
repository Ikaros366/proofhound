"""M35：黑盒未授权判定（匿名敏感数据 + 无效凭据对照）的纯函数与编排测试。"""

import json
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings import Finding, FindingState, FindingStore, Verification
from proofhound.findings.dedup import compute_dedup_key
from proofhound.skills.registry import SkillRegistry
from proofhound.verify.idor import IdorResponse
from proofhound.verify.unauth_anon import (
    ANON_BLOCKED,
    ANON_CONFIRMED,
    ANON_REJECTED,
    UNAUTH_ANON_METHOD,
    collect_sensitive,
    judge_anon_data,
    parse_structured,
)

BODY = json.dumps(
    {
        "data": {
            "users": [
                {"id": 1, "email": "alice@corp.example", "phone": "13800000001"},
                {"id": 2, "email": "bob@corp.example", "phone": "13800000002"},
            ]
        }
    }
)


def _resp(status=200, body=BODY, error=None):
    return IdorResponse(url="https://h/api/v1/users", status=status, body=body, error=error)


# ---------------------------------------------------------------- 纯函数


def test_parse_structured_only_accepts_json():
    assert parse_structured(BODY) is not None
    assert parse_structured("<html>nope</html>") is None
    assert parse_structured("") is None


def test_collect_sensitive_finds_nonempty_sensitive_fields():
    hits = collect_sensitive(parse_structured(BODY))
    fields = {h["field"] for h in hits}
    assert fields == {"email", "phone"}
    assert len(hits) == 4  # 两条记录各 email + phone


def test_collect_sensitive_ignores_empty_values():
    payload = {"data": {"user": {"email": "", "phone": "   "}}}
    assert collect_sensitive(payload) == []


def test_confirmed_when_anon_equals_invalid_credential_control():
    judgment = judge_anon_data(_resp(), _resp())
    assert judgment.verdict == ANON_CONFIRMED
    assert judgment.byte_identical is True
    assert len(judgment.sensitive_hits) == 4


def test_blocked_when_control_differs():
    """对照不同 ⇒ 判不了（可能每次响应都不一样，也可能无效凭据被当成了某个身份）。"""
    judgment = judge_anon_data(_resp(), _resp(body=BODY + " "))
    assert judgment.verdict == ANON_BLOCKED
    assert judgment.byte_identical is False


def test_rejected_when_anonymous_denied():
    judgment = judge_anon_data(_resp(status=401, body=""), _resp(status=401, body=""))
    assert judgment.verdict == ANON_REJECTED


def test_rejected_when_no_sensitive_value():
    """匿名能拿到 JSON 但里面没有敏感值 ⇒ 测过且干净，驳回（不硬凑成确认）。"""
    body = json.dumps({"data": {"version": "1.0.0", "ok": True}})
    judgment = judge_anon_data(_resp(body=body), _resp(body=body))
    assert judgment.verdict == ANON_REJECTED


def test_blocked_on_network_error_or_non_json():
    assert judge_anon_data(_resp(error="timeout"), _resp()).verdict == ANON_BLOCKED
    html = "<html><body>login</body></html>"
    assert judge_anon_data(_resp(body=html), _resp(body=html)).verdict == ANON_BLOCKED


# ---------------------------------------------------------------- 编排


@pytest.fixture
def registry(make_skill_dir):
    return SkillRegistry(make_skill_dir(name="verify-unauth", tools=())).discover()


def _seed(store, audit, *, url="https://h/api/v1/users"):
    finding = Finding(
        id=store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type="unauth-exposure",
        severity="medium",
        confidence="low",
        asset=url,
        title="api endpoint",
        evidence_kinds=["status-code"],
        dedup_key=compute_dedup_key(url, "unauth-exposure", None),
        created_at="2026-11-03T00:00:00.000+00:00",
        updated_at="2026-11-03T00:00:00.000+00:00",
        audit=audit,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="seed", reason="测试种子")
    store.append(finding)
    return finding


def _orch(tmp_path, registry, fetch, audit):
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080], domains=["h"])
    runner = SimpleNamespace(scope=scope, egress_proxy_url=None)
    return Orchestrator(
        registry,
        runner,
        object(),  # 本测试不走 Verifier（_gate_and_review 被替换）
        audit,
        evidence_dir=tmp_path / "evidence",
        idor_fetch=fetch,
    )


def test_blackbox_confirms_without_session(tmp_path, registry):
    """无会话也能确认：匿名拿到敏感数据且无效凭据对照逐字节相同。"""

    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    store = FindingStore(tmp_path / "evidence" / "findings.jsonl")
    finding = _seed(store, audit)

    seen_sessions = []

    def fetch(url, session):
        seen_sessions.append(session)
        return _resp()

    orch = _orch(tmp_path, registry, fetch, audit)
    orch._gate_and_review = lambda *args, **kwargs: "confirmed"

    outcome = orch._verify_unauth_anon(
        finding, registry.get("verify-unauth"), store
    )

    assert outcome == "confirmed"
    assert finding.verification is not None
    assert finding.verification.method == UNAUTH_ANON_METHOD
    assert len(finding.verification.evidence_refs) == 3
    assert "unauth-response-equivalence" in finding.evidence_kinds
    # 第二次请求只多了无效凭据
    assert seen_sessions[0] is not None and not seen_sessions[0].cookie_header()
    assert "ph_invalid" in (seen_sessions[1].cookie_header() or "")


def test_blackbox_rejects_when_anonymous_denied(tmp_path, registry):
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    store = FindingStore(tmp_path / "evidence" / "findings.jsonl")
    finding = _seed(store, audit)

    orch = _orch(tmp_path, registry, lambda url, s: _resp(status=401, body=""), audit)

    outcome = orch._verify_unauth_anon(
        finding, registry.get("verify-unauth"), store
    )

    assert outcome == "rejected"
    assert finding.state is FindingState.REJECTED
