"""M20-b 覆盖截图测试：类型→镜头表与登记表双向锁定、URL/会话选择纯函数，
以及编排层「候选一进验证就留图（不论判定结果）、引用进 coverage_refs、
每类型/每 phase 上限与缺 reference 的跳过路径」。

零真实浏览器：截图器走 ``screenshot_factory`` 注入的 FakeCapturer。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings import Finding, FindingState, FindingStore
from proofhound.findings.evidence import assemble_evidence_pack
from proofhound.skills.registry import SkillRegistry
from proofhound.verify import coverage
from proofhound.verify.gate import VULN_REGISTRY
from proofhound.verify.screenshot import PNG_SIGNATURE, ScreenshotResult

BASE = "http://127.0.0.1:8080"
SCOPE = Scope(networks=["127.0.0.0/8"], ports=[8080])
SESSION = SessionConfig(cookies={"PHPSESSID": "0123456789abcdef"})


class FakeLLM:
    def complete(self, messages):
        raise AssertionError("覆盖截图链路不得调用 LLM")


def _png(width: int = 1280, height: int = 800) -> bytes:
    return (
        PNG_SIGNATURE
        + (13).to_bytes(4, "big")
        + b"IHDR"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + b"\x00" * 16
    )


class FakeCapturer:
    """记录每次 (url, name, session)；按镜头名写一张合法 PNG 头。"""

    def __init__(self, out_dir: Path):
        self._out = Path(out_dir)
        self.calls: list[tuple[str, str, object]] = []
        self.closed = False

    def capture(self, url: str, *, name: str, session=None) -> ScreenshotResult:
        self.calls.append((url, name, session))
        path = self._out / f"{name}.png"
        data = _png()
        path.write_bytes(data)
        return ScreenshotResult(
            url=url,
            path=path,
            status=200,
            width=1280,
            height=800,
            bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )

    def close(self) -> None:
        self.closed = True


# ---- 纯函数 / 单一真相源 ----


def test_every_registered_type_has_fixed_shots():
    """镜头表与 VULN_REGISTRY 双向锁定：注册了类型就必须有镜头表，反之亦然。"""
    assert set(coverage.COVERAGE_SHOTS) == set(VULN_REGISTRY)


def test_shot_labels_are_unique_within_each_type():
    for vuln_type, shots in coverage.COVERAGE_SHOTS.items():
        labels = [shot.label for shot in shots]
        assert len(labels) == len(set(labels)), vuln_type


def test_xss_probe_is_a_visible_marker():
    """xss 覆盖探针必须**可见**：只改 JS 变量的探针在截图上等于没测。"""
    probe = {shot.label: shot for shot in coverage.COVERAGE_SHOTS["xss"]}["probe"]
    payload = probe.param_value or ""
    assert "ProofHound XSS probe" in payload
    assert "<h2" in payload
    assert "<script" not in payload  # 纯 HTML：CSP 也拦不住


def test_plan_for_unknown_type_is_none():
    assert coverage.plan_for("nope") is None


def test_build_url_baseline_keeps_asset_and_probe_rewrites_param():
    asset = f"{BASE}/sqli/?id=1&Submit=Submit"
    baseline = coverage.CoverageShot("baseline")
    assert coverage.build_url(asset, "id", baseline) == asset

    probe = coverage.CoverageShot("probe", param_value="1'")
    url = coverage.build_url(asset, "id", probe)
    assert parse_qs(urlparse(url).query)["id"] == ["1'"]
    assert parse_qs(urlparse(url).query)["Submit"] == ["Submit"]  # 其余参数保留


def test_build_url_probe_without_param_raises():
    with pytest.raises(ValueError, match="没有 param"):
        coverage.build_url(f"{BASE}/x", None, coverage.CoverageShot("probe", param_value="1"))


def test_select_session_roles():
    reference = SessionConfig(cookies={"pid": "reference-value"})
    with_ref = SessionConfig(cookies={"pid": "primary-value"}, reference=reference)

    assert coverage.select_session(with_ref, "primary") == (with_ref, None)
    assert coverage.select_session(with_ref, "anonymous") == (None, None)
    assert coverage.select_session(with_ref, "reference") == (reference, None)

    plain = SessionConfig(cookies={"pid": "only-primary"})
    selected, reason = coverage.select_session(plain, "reference")
    assert selected is None and "第二身份会话" in (reason or "")

    with pytest.raises(ValueError, match="未知会话角色"):
        coverage.select_session(plain, "root")


# ---- 编排层 ----


def _reject_handler(finding, skill, store):
    finding.transition(FindingState.REJECTED, actor=skill.name, reason="测试：判定不成立")
    store.append(finding)
    return "rejected"


@pytest.fixture
def cov_env(tmp_path, make_skill_dir):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    audit = AuditLog(evidence / "audit.jsonl")
    orch = Orchestrator(
        SkillRegistry(make_skill_dir("verify-xss")).discover(),
        runner=SimpleNamespace(scope=SCOPE),
        llm=FakeLLM(),
        audit=audit,
        evidence_dir=evidence,
    )
    return orch, audit, evidence


def _seed(evidence: Path, audit: AuditLog, *, vuln_type="xss", asset=None, param="name"):
    store = FindingStore(evidence / "findings.jsonl")
    finding = Finding(
        id="F-2026-0901",
        state=FindingState.HYPOTHESIS,
        vuln_type=vuln_type,
        severity="medium",
        asset=asset or f"{BASE}/vulnerabilities/xss_r/?name=1",
        param=param,
        evidence_kinds=["crawl-endpoint"],
        dedup_key="sha256:deadbeef",
        created_at="2026-10-28T00:00:00.000+00:00",
        updated_at="2026-10-28T00:00:00.000+00:00",
        audit=audit,
    )
    store.append(finding)
    return finding


def test_rejected_candidate_still_gets_coverage_shots(
    monkeypatch, cov_env, tmp_path
):
    """判定为 rejected 也留图：证明「这条端点测过」，与结果无关。"""
    orch, audit, evidence = cov_env
    capturer = FakeCapturer(evidence)
    orch.screenshots = True
    orch.screenshot_factory = lambda: capturer
    _seed(evidence, audit)
    monkeypatch.setattr(
        orch, "_verify_handlers", lambda: {"verify-xss": (frozenset({"xss"}), _reject_handler)}
    )

    processed = orch.run_verify_phase(skill_name="verify-xss")

    assert [f.id for f in processed] == ["F-2026-0901"]
    names = [call[1] for call in capturer.calls]
    assert names == ["cover_F-2026-0901_baseline", "cover_F-2026-0901_probe"]
    assert all(call[2] is None for call in capturer.calls)  # 无预置会话 ⇒ 匿名取证
    assert capturer.closed  # phase 收尾释放

    reloaded = FindingStore(evidence / "findings.jsonl").load_all()[-1]
    assert reloaded.state is FindingState.REJECTED
    assert len(reloaded.coverage_refs) == 2
    assert all(ref.endswith(".png") for ref in reloaded.coverage_refs)

    events = [e for e in audit.read_all() if e["event"] == "coverage_shot_captured"]
    assert len(events) == 2
    assert {e["label"] for e in events} == {"baseline", "probe"}
    assert all(e["vuln_type"] == "xss" for e in events)
    assert (evidence / "coverage_F-2026-0901.json").is_file()

    # 覆盖截图进证据包（可离线调出），但不进确认证据链
    finding = FindingStore(evidence / "findings.jsonl").load_all()[-1]
    finding.audit = audit
    pack = assemble_evidence_pack(finding, evidence_base=evidence)
    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    names = [item["file"] for item in manifest["items"]]
    assert any(name and name.endswith(".png") for name in names)
    assert finding.verification is None


def test_probe_shot_rewrites_param_value(cov_env):
    orch, audit, evidence = cov_env
    capturer = FakeCapturer(evidence)
    orch.screenshots = True
    orch.screenshot_factory = lambda: capturer
    finding = _seed(evidence, audit, vuln_type="sqli", asset=f"{BASE}/sqli/?id=1")
    finding.param = "id"

    orch._capture_coverage(finding, FindingStore(evidence / "findings.jsonl"))

    probe_url = capturer.calls[1][0]
    assert parse_qs(urlparse(probe_url).query)["id"] == ["1'"]
    assert capturer.calls[0][0] == f"{BASE}/sqli/?id=1"


def test_idor_missing_reference_skips_only_reference_shot(cov_env):
    orch, audit, evidence = cov_env
    orch.runner.scope = Scope(
        networks=["127.0.0.0/8"], ports=[8080], session=SESSION
    )
    capturer = FakeCapturer(evidence)
    orch.screenshots = True
    orch.screenshot_factory = lambda: capturer
    finding = _seed(evidence, audit, vuln_type="idor", asset=f"{BASE}/invoice?id=1001")

    orch._capture_coverage(finding, FindingStore(evidence / "findings.jsonl"))

    assert [call[1] for call in capturer.calls] == ["cover_F-2026-0901_attacker"]
    assert capturer.calls[0][2] is SESSION
    skipped = [e for e in audit.read_all() if e["event"] == "coverage_shot_skipped"]
    assert skipped and "第二身份会话" in skipped[0]["reason"]
    assert len(finding.coverage_refs) == 1


def test_per_type_cap_records_capped_event(cov_env):
    orch, audit, evidence = cov_env
    orch.screenshots = True
    orch.screenshot_factory = lambda: FakeCapturer(evidence)
    orch._coverage_by_type["xss"] = coverage.CAP_PER_TYPE
    finding = _seed(evidence, audit)

    orch._capture_coverage(finding, FindingStore(evidence / "findings.jsonl"))

    capped = [e for e in audit.read_all() if e["event"] == "coverage_shot_capped"]
    assert capped and "每类型上限" in capped[0]["reason"]
    assert finding.coverage_refs == []


def test_phase_total_cap_records_capped_event(cov_env):
    orch, audit, evidence = cov_env
    orch.screenshots = True
    orch.screenshot_factory = lambda: FakeCapturer(evidence)
    orch._coverage_total = coverage.CAP_TOTAL
    finding = _seed(evidence, audit)

    orch._capture_coverage(finding, FindingStore(evidence / "findings.jsonl"))

    capped = [e for e in audit.read_all() if e["event"] == "coverage_shot_capped"]
    assert capped and "本 phase 上限" in capped[0]["reason"]


def test_coverage_disabled_by_default(cov_env):
    orch, audit, evidence = cov_env
    finding = _seed(evidence, audit)

    orch._capture_coverage(finding, FindingStore(evidence / "findings.jsonl"))

    assert finding.coverage_refs == []
    assert audit.read_all() == []
