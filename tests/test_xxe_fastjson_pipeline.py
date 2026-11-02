"""M30：XXE / 不安全反序列化（fastjson 系）接入编排主链路。

覆盖三层：
1. **生产者**：响应 Content-Type 命中 xml/soap / json 时，规则表真的建出候选；
2. **handler**：三态（confirmed / rejected / blocked）各自的迁移与审计，
   以及结构性失败（listener 起不来 / 观察通道未配）必须 blocked 而不是驳回；
3. **授权**：asset 越界时零请求。

驱动（`xxeprobe` / `fastjsonprobe`）用假实现替换——它们自己的契约由
`tests/test_xxeprobe.py` / `test_fastjsonprobe.py` 负责；这里只测接线。
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings.dedup import compute_dedup_key
from proofhound.findings.finding import Finding, FindingState, FindingStore
from proofhound.skills.registry import SkillRegistry
from proofhound.verify.fastjson import (
    FASTJSON_CONFIRMED_METHOD,
    FASTJSON_EVIDENCE_KIND,
)
from proofhound.verify.xxe import (
    XXE_CALLBACK_METHOD,
    XXE_EVIDENCE_KIND,
    XXE_FILE_METHOD,
)
from proofhound.xxeprobe import XxeProbeError

REPO = Path(__file__).resolve().parent.parent
ASSET = "http://127.0.0.1:8080/api/ws"


class _Runner:
    egress_proxy_url = None

    def __init__(self, scope):
        self.scope = scope


class _Skill:
    name = "verify-xxe"


@pytest.fixture
def env(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080])
    audit = AuditLog(evidence / "audit.jsonl")
    orch = Orchestrator(
        SkillRegistry(REPO / "skills").discover(),
        _Runner(scope),
        SimpleNamespace(),  # 走不到 Verifier（_gate_and_review 被替换）
        audit,
        evidence_dir=evidence,
    )
    store = FindingStore(evidence / "findings.jsonl")
    return SimpleNamespace(
        orch=orch, audit=audit, store=store, evidence=evidence, scope=scope
    )


def _finding(store: FindingStore, *, vuln_type="xxe", asset=ASSET) -> Finding:
    finding = Finding(
        id=store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type=vuln_type,
        severity="medium",
        asset=asset,
        param=None,
        confidence="low",
        evidence_kinds=["status-code"],
        dedup_key=compute_dedup_key(asset, vuln_type, None),
        source_signal_refs=[],
        created_at="2026-11-02T00:00:00.000+00:00",
        updated_at="2026-11-02T00:00:00.000+00:00",
    )
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="测试种子")
    store.append(finding)
    return finding


def _report(out_dir: Path, *, verdict: str, channels=(), reasons=("罐头理由",)):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.md").write_text("# summary\n", encoding="utf-8")
    (out_dir / "judgment.json").write_text(
        json.dumps({"verdict": verdict}), encoding="utf-8"
    )
    judgment = SimpleNamespace(
        verdict=verdict,
        channels=tuple(channels),
        reasons=list(reasons),
        confirmed=verdict == "confirmed",
    )
    return SimpleNamespace(
        judgment=judgment,
        out_dir=out_dir,
        summary={"probes": [{"probe": "file", "status": 200}]},
    )


# =====================================================================
# 一、生产者
# =====================================================================


@pytest.mark.parametrize(
    "content_type,expected",
    [
        ("application/xml; charset=utf-8", "xxe"),
        ("text/xml", "xxe"),
        ("application/json", "fastjson"),
        ("text/html", None),
        (None, None),
    ],
)
def test_content_type_rules_produce_candidates(content_type, expected):
    from proofhound.core.orchestrator import _triage_candidates
    from proofhound.findings.signal import Signal

    signal = Signal(
        asset="http://h/api",
        status_code=200,
        kind="web-probe",
        source_tool="httpx",
        skill="web-scan",
        evidence_ref="x#L1",
        content_type=content_type,
    )
    candidates = _triage_candidates(signal)
    produced = {c.vuln_type for c in candidates}
    if expected is None:
        assert "xxe" not in produced and "fastjson" not in produced
    else:
        assert expected in produced
        # 探针 POST 的是具体端点：候选必须保留完整 URL，不能被 origin 抹掉路径
        matched = [c for c in candidates if c.vuln_type == expected]
        assert matched and matched[0].asset == "http://h/api"


# =====================================================================
# 二、XXE handler
# =====================================================================


def test_xxe_confirmed_uses_file_method(env, monkeypatch):
    import proofhound.core.orchestrator as orch_mod

    captured = {}

    def fake_gate(finding, skill, store, **kwargs):
        captured["finding"] = finding
        captured["summary"] = kwargs.get("summary")
        return "confirmed"

    monkeypatch.setattr(env.orch, "_gate_and_review", fake_gate)
    monkeypatch.setattr(
        orch_mod,
        "run_xxeprobe",
        lambda config: _report(config.out_dir, verdict="confirmed", channels=("file",)),
    )
    finding = _finding(env.store)

    outcome = env.orch._verify_xxe(finding, _Skill(), env.store)

    assert outcome == "confirmed"
    assert finding.state is FindingState.REPRODUCED
    assert finding.verification.method == XXE_FILE_METHOD
    assert XXE_EVIDENCE_KIND in finding.evidence_kinds
    assert finding.verification.evidence_refs
    assert captured["finding"] is finding
    judged = [
        e for e in env.audit.read_all() if e["event"] == "xxe_judged"
    ]
    assert judged and judged[0]["verdict"] == "confirmed"


def test_xxe_callback_channel_uses_callback_method(env, monkeypatch):
    import proofhound.core.orchestrator as orch_mod

    monkeypatch.setattr(env.orch, "_gate_and_review", lambda *a, **k: "confirmed")
    monkeypatch.setattr(
        orch_mod,
        "run_xxeprobe",
        lambda config: _report(
            config.out_dir, verdict="confirmed", channels=("callback",)
        ),
    )
    finding = _finding(env.store)

    env.orch._verify_xxe(finding, _Skill(), env.store)

    assert finding.verification.method == XXE_CALLBACK_METHOD


def test_xxe_rejected_is_terminal(env, monkeypatch):
    import proofhound.core.orchestrator as orch_mod

    monkeypatch.setattr(
        orch_mod,
        "run_xxeprobe",
        lambda config: _report(config.out_dir, verdict="rejected"),
    )
    finding = _finding(env.store)

    assert env.orch._verify_xxe(finding, _Skill(), env.store) == "rejected"
    assert finding.state is FindingState.REJECTED
    # 驳回必须能被 store 回放出来
    assert FindingStore(env.store.path).get(finding.id).state is FindingState.REJECTED


def test_xxe_blocked_keeps_hypothesis(env, monkeypatch):
    import proofhound.core.orchestrator as orch_mod

    monkeypatch.setattr(
        orch_mod,
        "run_xxeprobe",
        lambda config: _report(
            config.out_dir, verdict="blocked", reasons=("探针出错",)
        ),
    )
    finding = _finding(env.store)

    assert env.orch._verify_xxe(finding, _Skill(), env.store) == "blocked"
    assert finding.state is FindingState.HYPOTHESIS
    blocked = [e for e in env.audit.read_all() if e["event"] == "verify_blocked"]
    assert blocked and "覆盖不全" in blocked[-1]["reason"]


def test_xxe_structural_failure_is_blocked_not_rejected(env, monkeypatch):
    import proofhound.core.orchestrator as orch_mod

    def boom(config):
        raise XxeProbeError("listener 不可用")

    monkeypatch.setattr(orch_mod, "run_xxeprobe", boom)
    finding = _finding(env.store)

    assert env.orch._verify_xxe(finding, _Skill(), env.store) == "blocked"
    assert finding.state is FindingState.HYPOTHESIS
    blocked = [e for e in env.audit.read_all() if e["event"] == "verify_blocked"]
    assert "结构性失败" in blocked[-1]["reason"]


def test_xxe_out_of_scope_never_sends(env, monkeypatch):
    import proofhound.core.orchestrator as orch_mod

    called = []
    monkeypatch.setattr(orch_mod, "run_xxeprobe", lambda config: called.append(config))
    finding = _finding(env.store, asset="http://198.51.100.7/api")

    assert env.orch._verify_xxe(finding, _Skill(), env.store) == "blocked"
    assert called == []
    rejected = [
        e for e in env.audit.read_all() if e["event"] == "verify_scope_rejected"
    ]
    assert rejected


# =====================================================================
# 三、fastjson handler
# =====================================================================


def test_fastjson_confirmed(env, monkeypatch):
    import proofhound.core.orchestrator as orch_mod

    monkeypatch.setattr(env.orch, "_gate_and_review", lambda *a, **k: "confirmed")
    monkeypatch.setattr(
        orch_mod,
        "run_fastjsonprobe",
        lambda config: _report(config.out_dir, verdict="confirmed", channels=("dns",)),
    )
    finding = _finding(env.store, vuln_type="fastjson")

    assert env.orch._verify_fastjson(finding, _Skill(), env.store) == "confirmed"
    assert finding.state is FindingState.REPRODUCED
    assert finding.verification.method == FASTJSON_CONFIRMED_METHOD
    assert FASTJSON_EVIDENCE_KIND in finding.evidence_kinds
    judged = [e for e in env.audit.read_all() if e["event"] == "fastjson_judged"]
    assert judged and judged[0]["channels"] == ["dns"]


def test_fastjson_missing_observer_blocks_with_reason(env, monkeypatch):
    import proofhound.core.orchestrator as orch_mod
    from proofhound.fastjsonprobe import FastjsonProbeError

    def boom(config):
        raise FastjsonProbeError("观察通道不可用：未配置 DNSLog provider，TCP 监听也起不来")

    monkeypatch.setattr(orch_mod, "run_fastjsonprobe", boom)
    finding = _finding(env.store, vuln_type="fastjson")

    assert env.orch._verify_fastjson(finding, _Skill(), env.store) == "blocked"
    assert finding.state is FindingState.HYPOTHESIS
    blocked = [e for e in env.audit.read_all() if e["event"] == "verify_blocked"]
    assert "观察通道不可用" in blocked[-1]["reason"]
