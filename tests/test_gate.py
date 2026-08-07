"""证据门单元测试（M3b，§5.4.2）：各漏洞类型 Confirmed 最低验收标准。

覆盖：sqli 通过；method 不在白名单 / 缺行为类标签 / 无 verification /
evidence_refs 空 / 未知 vuln_type（fail-closed）；missing 缺项清单内容。
"""

from __future__ import annotations

from proofhound.findings import Finding, FindingState, Verification
from proofhound.verify.gate import GATE_MATRIX, check


def _finding(**overrides) -> Finding:
    base = dict(
        id="F-2026-0001",
        state=FindingState.REPRODUCED,
        vuln_type="sqli",
        asset="http://127.0.0.1:8080/vulnerabilities/sqli/?id=1",
        param="id",
        evidence_kinds=["status-code", "behavioral"],
        verification=Verification(
            method="sqlmap-confirmed",
            evidence_refs=["evidence/x.log#L24"],
        ),
        dedup_key="sha256:deadbeef",
        created_at="2026-08-07T00:00:00.000+00:00",
        updated_at="2026-08-07T00:00:00.000+00:00",
    )
    base.update(overrides)
    return Finding(**base)


def test_sqli_passes_with_sqlmap_confirmed_and_behavioral():
    result = check(_finding())
    assert result.passed, result.missing
    assert result.missing == []


def test_sqli_passes_with_alternative_methods():
    for method in ("boolean-diff", "time-blind-diff"):
        f = _finding()
        f.verification.method = method
        assert check(f).passed


def test_method_not_in_whitelist_fails():
    f = _finding()
    f.verification.method = "scanner-banner"
    result = check(f)
    assert not result.passed
    assert any("白名单" in item for item in result.missing)


def test_missing_behavioral_kind_fails():
    f = _finding(evidence_kinds=["status-code"])
    result = check(f)
    assert not result.passed
    assert any("行为类" in item for item in result.missing)


def test_missing_verification_fails():
    result = check(_finding(verification=None))
    assert not result.passed
    assert any("verification" in item for item in result.missing)


def test_empty_evidence_refs_fails():
    f = _finding()
    f.verification = Verification(method="sqlmap-confirmed", evidence_refs=["x"])
    f.verification.evidence_refs = []
    result = check(f)
    assert not result.passed
    assert any("evidence_refs" in item for item in result.missing)


def test_unknown_vuln_type_fail_closed():
    result = check(_finding(vuln_type="version-cve"))
    assert not result.passed
    assert any("无证据门定义" in item for item in result.missing)


def test_multiple_missing_items_all_listed():
    f = _finding(verification=None, evidence_kinds=["status-code"])
    result = check(f)
    assert not result.passed
    assert len(result.missing) == 2  # 缺 verification + 缺行为类标签


def test_gate_matrix_declares_sqli_contract():
    req = GATE_MATRIX["sqli"]
    assert {"sqlmap-confirmed", "boolean-diff", "time-blind-diff"} <= req.methods
    assert "behavioral" in req.behavioral_kinds
