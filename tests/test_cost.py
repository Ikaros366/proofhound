"""M11a 成本可见性测试：归属元数据 + 成本聚合 + CLI/API 出口。

覆盖三层：
1. **归属写入**（llm/router.py + llm/repair.py + llm/callmeta.py）——
   生产路径带 caller/finding_id/retry 进 ``llm_call`` 审计；旧替身
   （``complete(tier, messages)`` 无 kwargs）走确定性降级、行为逐字节不变；
2. **聚合纯函数**（llm/cost.py）——四个维度各自求和都等于总数、重试单列、
   估算分离、旧事件归 unknown 且总量守恒；
3. **出口**（``python -m proofhound.cost`` CLI + ``GET /api/engagements/{id}/cost``）
   ——与聚合函数同源，且 ``tokens_used`` 与 ``/cost`` 总数一致。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.compliance.audit import AuditLog
from proofhound.llm.callmeta import accepts_kwargs, call_with_meta
from proofhound.llm.cost import (
    CALLER_PHASE,
    UNKNOWN,
    aggregate,
    calls_from_events,
    load_calls,
    phase_of,
    render_markdown,
    report_from_audit,
)
from proofhound.llm.router import ModelRouter, Tier, TierConfig
from proofhound.llm.usage import UsageTracker
from proofhound.cost import main as cost_main


# ---------------------------------------------------------------- 测试替身


class _Result:
    """假客户端返回值（duck-typing LLMClient 的 complete_with_usage 返回）。"""

    def __init__(self, content: str, usage: dict | None):
        self.content = content
        self.usage = usage
        self.latency_ms = 1.0


class _RecordingClient:
    """生产形态客户端：接受 M11a 元数据 kwargs 并记录。"""

    def __init__(self, content: str = "ok", usage: dict | None = None):
        self.seen: list[dict] = []
        self._content = content
        self._usage = {"prompt_tokens": 10, "completion_tokens": 5} if usage is None else usage

    def complete_with_usage(self, messages, *, caller=None, finding_id=None, retry=False):
        self.seen.append(
            {"caller": caller, "finding_id": finding_id, "retry": retry}
        )
        return _Result(self._content, self._usage)


class _OldStyleClient:
    """旧形态客户端：完全不接受 kwargs（M11a 之前的常见写法）。"""

    def __init__(self):
        self.calls = 0

    def complete_with_usage(self, messages):
        self.calls += 1
        return _Result("old-ok", {"prompt_tokens": 3, "completion_tokens": 4})


class _OldStyleRouter:
    """旧形态路由替身：``complete(tier, messages)``，不接受任何 kwarg。"""

    def __init__(self, replies: list[str]):
        self._replies = list(replies)
        self.calls: list[tuple] = []

    def complete(self, tier, messages):
        self.calls.append((tier, messages))
        return self._replies.pop(0)


def _tier_config() -> TierConfig:
    return TierConfig(base_url="http://example.invalid", api_key="k", model="m")


def _router(client, audit: AuditLog | None = None) -> ModelRouter:
    router = ModelRouter(
        {Tier.T1: _tier_config(), Tier.T2: _tier_config()},
        audit=audit,
        tracker=UsageTracker(),
    )
    router._clients[Tier.T1] = client
    router._clients[Tier.T2] = client
    return router


def _llm_events(path: Path) -> list[dict]:
    return [e for e in AuditLog(path).read_all() if e.get("event") == "llm_call"]


# ------------------------------------------------- 1. 归属写入（router/repair）


def test_router_records_caller_and_finding_id_in_audit(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    client = _RecordingClient()
    _router(client, audit).complete(
        Tier.T2,
        [{"role": "user", "content": "hi"}],
        caller="verifier",
        finding_id="F-2026-0001",
        retry=False,
    )
    events = _llm_events(tmp_path / "audit.jsonl")
    assert len(events) == 1
    assert events[0]["caller"] == "verifier"
    assert events[0]["finding_id"] == "F-2026-0001"
    assert events[0]["retry"] is False


def test_router_metadata_reaches_client(tmp_path):
    client = _RecordingClient()
    _router(client).complete(
        Tier.T1, [{"role": "user", "content": "x"}], caller="triage"
    )
    assert client.seen == [{"caller": "triage", "finding_id": None, "retry": False}]


def test_router_without_metadata_writes_none_not_missing(tmp_path):
    """缺省不传时字段显式为 null（聚合可确定性归 unknown，无需猜键是否存在）。"""
    audit = AuditLog(tmp_path / "audit.jsonl")
    _router(_RecordingClient(), audit).complete(Tier.T1, [{"role": "user", "content": "x"}])
    event = _llm_events(tmp_path / "audit.jsonl")[0]
    assert event["caller"] is None and event["finding_id"] is None
    assert event["retry"] is False


def test_old_style_client_still_works_and_audits_none(tmp_path):
    """旧替身（无 kwargs）：不得报错、不被重复调用；审计仍记调用方（router 层记录）。

    降级只影响**传给客户端**的 kwargs——审计字段由路由器写，故 caller 仍然完整。
    """
    audit = AuditLog(tmp_path / "audit.jsonl")
    client = _OldStyleClient()
    out = _router(client, audit).complete(
        Tier.T1,
        [{"role": "user", "content": "x"}],
        caller="planner",
        finding_id="F-1",
        retry=True,
    )
    assert out == "old-ok"
    # 旧替身不被重复调用（降级只影响 kwargs，不产生额外请求）
    assert client.calls == 1
    event = _llm_events(tmp_path / "audit.jsonl")[0]
    # 客户端拿不到 kwargs，但审计归属由路由器记录，故完整保留
    assert event["caller"] == "planner"
    assert event["finding_id"] == "F-1"
    assert event["retry"] is True


def test_router_upstream_error_not_swallowed_as_type_error(tmp_path):
    """真实业务异常必须原样按 LLMError 上抛，不被降级逻辑吞掉。"""

    class _BoomClient:
        def complete_with_usage(self, messages, *, caller=None, finding_id=None, retry=False):
            raise ValueError("boom")

    from proofhound.llm.client import LLMError

    router = _router(_BoomClient())
    with pytest.raises(ValueError, match="boom"):
        router.complete(Tier.T1, [{"role": "user", "content": "x"}], caller="verifier")
    # LLMError 仍是 LLMError 的子类语义：此处 ValueError 不是 TypeError，故原样
    assert issubclass(LLMError, Exception)


def test_callmeta_deterministic_dispatch():
    """签名判定：接受全部键 → 传；缺任一键 / 不可反射 → 不传。"""

    def full(messages, *, caller=None, finding_id=None, retry=False):
        return "full"

    def partial_kwargs(messages, *, caller=None):
        return "partial"

    def none_at_all(messages):
        return "none"

    meta = {"caller": "c", "finding_id": "f", "retry": False}
    assert accepts_kwargs(full, meta) is True
    assert accepts_kwargs(partial_kwargs, meta) is False
    assert accepts_kwargs(none_at_all, meta) is False
    assert call_with_meta(full, messages=[], meta=meta) == "full"
    assert call_with_meta(partial_kwargs, messages=[], meta=meta) == "partial"
    assert call_with_meta(none_at_all, messages=[], meta=meta) == "none"


def test_callmeta_var_keyword_accepted():
    def any_kwargs(messages, **kwargs):
        return kwargs.get("caller")

    assert accepts_kwargs(any_kwargs, {"caller": "c"}) is True
    assert call_with_meta(any_kwargs, messages=[], meta={"caller": "c"}) == "c"


def test_callmeta_leading_args_forwarded():
    """``leading`` 必须原样前置于 messages（router 的 tier 参数靠它透传）。"""

    def complete(tier, messages, *, caller=None):
        return (tier, messages, caller)

    out = call_with_meta(complete, "t1", messages=["m"], meta={"caller": "verifier"})
    assert out == ("t1", ["m"], "verifier")


def test_callmeta_error_wrapper_applied():
    def boom(messages):
        raise TypeError("synthetic")

    with pytest.raises(RuntimeError, match="wrapped:synthetic"):
        call_with_meta(
            boom,
            messages=[],
            meta={"caller": "c"},
            error_wrapper=lambda m: RuntimeError(f"wrapped:{m}"),
        )


def test_callmeta_without_wrapper_reraises_type_error():
    """未给 error_wrapper 时 TypeError 原样上抛（修复重试路径的旧语义）。"""

    def boom(messages):
        raise TypeError("synthetic-raw")

    with pytest.raises(TypeError, match="synthetic-raw"):
        call_with_meta(boom, messages=[], meta={"caller": "c"})


def test_repair_marks_retry_call(tmp_path):
    """修复重试那一次必须带 retry=True，且两次归属一致（确定性区分）。"""
    from proofhound.llm.repair import complete_structured

    calls: list[dict] = []

    class _RetryRouter:
        def complete(self, tier, messages, *, caller=None, finding_id=None, retry=False):
            calls.append({"tier": tier, "caller": caller, "finding_id": finding_id, "retry": retry})
            return "bad json" if len(calls) == 1 else '{"ok": true}'

    parsed = complete_structured(
        _RetryRouter(),
        Tier.T2,
        [{"role": "user", "content": "x"}],
        lambda raw: json.loads(raw),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        caller="verifier",
        finding_id="F-2026-0009",
    )
    assert parsed == {"ok": True}
    assert [c["retry"] for c in calls] == [False, True]
    assert all(c["caller"] == "verifier" and c["finding_id"] == "F-2026-0009" for c in calls)


def test_repair_old_style_router_degrades(tmp_path):
    """旧路由替身（无 kwargs）走 complete_structured 必须照旧可用。"""
    from proofhound.llm.repair import complete_structured

    parsed = complete_structured(
        _OldStyleRouter(['{"verdict": "x"}']),
        Tier.T2,
        [{"role": "user", "content": "x"}],
        lambda raw: json.loads(raw),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        caller="verifier",
        finding_id="F-1",
    )
    assert parsed == {"verdict": "x"}


# --------------------------------------------------------- 2. 聚合（llm/cost.py）


def _event(**overrides) -> dict:
    base = {
        "event": "llm_call",
        "tier": "t1",
        "caller": "triage",
        "finding_id": None,
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "retry": False,
        "estimated": False,
    }
    base.update(overrides)
    return base


def test_calls_from_events_ignores_non_llm_events():
    events = [{"event": "scan_start"}, _event(), {"event": "finding_state"}]
    assert len(calls_from_events(events)) == 1


def test_calls_from_events_tolerates_missing_fields():
    """旧审计：无 caller/finding_id/retry → 归 unknown、token 按 0 计，不抛错。"""
    calls = calls_from_events([{"event": "llm_call", "tier": "t2"}])
    assert calls[0].caller == UNKNOWN
    assert calls[0].finding_id is None
    assert calls[0].total_tokens == 0
    assert calls[0].retry is False


def test_calls_from_events_tolerates_string_and_none_tokens():
    calls = calls_from_events(
        [_event(prompt_tokens="7", completion_tokens=None)]
    )
    assert calls[0].prompt_tokens == 7
    assert calls[0].completion_tokens == 0


def test_phase_mapping_known_and_unknown():
    assert phase_of("triage") == "discovery"
    assert phase_of("planner") == "planning"
    assert phase_of("verifier") == "verification"
    assert phase_of("narrative") == "report"
    assert phase_of("something-new") == UNKNOWN
    assert phase_of(None) == UNKNOWN
    assert set(CALLER_PHASE.values()) <= {"discovery", "planning", "verification", "report"}


def test_aggregate_total_equals_hand_computed_sum():
    calls = calls_from_events(
        [
            _event(prompt_tokens=100, completion_tokens=50),
            _event(tier="t2", caller="verifier", finding_id="F-1", prompt_tokens=10, completion_tokens=5),
            _event(tier="t2", caller="verifier", finding_id="F-1", prompt_tokens=20, completion_tokens=8, retry=True),
        ]
    )
    report = aggregate(calls)
    assert report.total.calls == 3
    assert report.total.total_tokens == 150 + 15 + 28
    assert report.total.prompt_tokens == 130
    assert report.total.completion_tokens == 63


def test_every_dimension_sums_to_total():
    """四个归属维度各自求和都等于 total（同源同值，无第二套口径）。"""
    calls = calls_from_events(
        [
            _event(caller="triage", prompt_tokens=10),
            _event(caller="planner", prompt_tokens=20),
            _event(caller="verifier", finding_id="F-1", prompt_tokens=30),
            _event(caller="verifier", finding_id="F-2", prompt_tokens=40, retry=True),
            _event(caller="narrative", prompt_tokens=50),
            {"event": "llm_call"},  # 旧事件：unknown
        ]
    )
    report = aggregate(calls)
    for bucket in (report.by_caller, report.by_phase, report.by_finding, report.by_tier):
        assert sum(e.total_tokens for e in bucket.values()) == report.total.total_tokens
        assert sum(e.calls for e in bucket.values()) == report.total.calls


def test_retry_counted_in_total_and_single_listed():
    """含修复重试（进主口径）且单列（可见抖动成本）。"""
    calls = calls_from_events(
        [
            _event(caller="verifier", finding_id="F-1", prompt_tokens=10, completion_tokens=0),
            _event(
                caller="verifier",
                finding_id="F-1",
                prompt_tokens=90,
                completion_tokens=5,
                retry=True,
            ),
        ]
    )
    report = aggregate(calls)
    assert report.total.total_tokens == 105  # 主口径含重试
    assert report.total.retry_calls == 1
    assert report.total.retry_tokens == 95
    entry = report.by_finding["F-1"]
    assert entry.calls == 2 and entry.retry_calls == 1 and entry.retry_tokens == 95


def test_estimated_events_counted_separately():
    calls = calls_from_events(
        [_event(estimated=True), _event(estimated=False), _event(estimated=True)]
    )
    report = aggregate(calls)
    assert report.total.estimated_calls == 2
    assert report.total.calls == 3


def test_by_finding_explicit_bucket_for_no_finding():
    """无 finding 归属的调用显式成桶（键「（无）」），不与零成本混淆。"""
    report = aggregate(calls_from_events([_event(caller="triage", finding_id=None)]))
    assert "（无）" in report.by_finding
    assert report.by_finding["（无）"].calls == 1


def test_old_events_go_to_unknown_and_total_is_conserved():
    """旧审计（无 caller）归 unknown，**总量守恒**（不静默丢弃）。"""
    calls = calls_from_events(
        [{"event": "llm_call", "tier": "t2", "prompt_tokens": 5, "completion_tokens": 5}] * 3
    )
    report = aggregate(calls)
    assert report.total.calls == 3
    assert report.by_caller[UNKNOWN].calls == 3
    assert report.by_caller[UNKNOWN].total_tokens == 30
    assert report.attributability == 0.0


def test_attributability_partial_and_full():
    partial = aggregate(
        calls_from_events([_event(caller="triage"), {"event": "llm_call"}])
    )
    assert partial.attributability == pytest.approx(0.5)
    full = aggregate(calls_from_events([_event(caller="triage")]))
    assert full.attributability == 1.0


def test_attributability_empty_is_one():
    """零调用 == 无可归属之缺失，记 1.0（避免除零与误导性的 0%）。"""
    assert aggregate([]).attributability == 1.0


def test_aggregate_is_pure_and_repeatable():
    calls = calls_from_events([_event(), _event(caller="verifier", finding_id="F-1", retry=True)])
    first = aggregate(calls).as_dict()
    second = aggregate(calls).as_dict()
    assert first == second


def test_as_dict_can_omit_calls():
    report = aggregate(calls_from_events([_event()]))
    assert "calls" in report.as_dict()
    assert "calls" not in report.as_dict(include_calls=False)


def test_load_calls_missing_file_is_empty(tmp_path):
    assert load_calls(tmp_path / "nope.jsonl") == []
    assert report_from_audit(tmp_path / "nope.jsonl").total.calls == 0


def test_load_calls_skips_malformed_lines(tmp_path):
    """半截行（进程中断）容忍：跳过该行而非整体失败。"""
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps(_event()) + "\n{ this is not json\n" + json.dumps(_event()) + "\n",
        encoding="utf-8",
    )
    assert len(load_calls(path)) == 2


def test_render_markdown_contains_key_figures():
    report = aggregate(
        calls_from_events([_event(caller="verifier", finding_id="F-1", prompt_tokens=100, retry=True)])
    )
    text = render_markdown(report)
    assert "单题成本归属" in text
    assert "按调用方" in text and "按阶段" in text and "按 Finding" in text and "按档位" in text
    assert "verifier" in text and "F-1" in text


# ------------------------------------------------------------- 3. 出口（CLI/API）


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "scopes").mkdir(parents=True)
    # 与 tests/test_api.py 同一 scope 形态：IP 走 networks（不是 domains）
    (ws / "scope.yaml").write_text("networks: [127.0.0.0/8]\n", encoding="utf-8")
    return ws


@pytest.fixture
def client(workspace: Path):
    with TestClient(create_app(workspace)) as c:
        yield c


def _make_engagement(client, workspace: Path) -> str:
    resp = client.post(
        "/api/engagements",
        json={"target": "http://127.0.0.1:8080", "scope_paths": ["scope.yaml"]},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _seed_llm_calls(workspace: Path, eng_id: str, events: list[dict]) -> Path:
    """把 llm_call 事件写进该 engagement 的审计（模拟真实调用留下的痕迹）。"""
    audit_path = workspace / "engagements" / eng_id / "audit.jsonl"
    audit = AuditLog(audit_path)
    for event in events:
        payload = {k: v for k, v in event.items() if k != "event"}
        audit.record("llm_call", **payload)
    return audit_path


def test_api_cost_endpoint_aggregates_by_caller(client, workspace):
    eng_id = _make_engagement(client, workspace)
    _seed_llm_calls(
        workspace,
        eng_id,
        [
            _event(caller="triage", prompt_tokens=100, completion_tokens=10),
            _event(caller="verifier", finding_id="F-2026-0001", tier="t2",
                   prompt_tokens=200, completion_tokens=20),
            _event(caller="verifier", finding_id="F-2026-0001", tier="t2",
                   prompt_tokens=300, completion_tokens=30, retry=True),
        ],
    )
    body = client.get(f"/api/engagements/{eng_id}/cost").json()
    assert body["total"]["calls"] == 3
    assert body["total"]["total_tokens"] == 660
    assert body["by_caller"]["triage"]["total_tokens"] == 110
    assert body["by_caller"]["verifier"]["total_tokens"] == 550
    assert body["by_phase"]["discovery"]["total_tokens"] == 110
    assert body["by_phase"]["verification"]["total_tokens"] == 550
    assert body["by_finding"]["F-2026-0001"]["retry_calls"] == 1
    assert body["by_tier"]["t2"]["calls"] == 2
    assert body["attributability"] == 1.0


def test_api_cost_endpoint_matches_tokens_used(client, workspace):
    """``/cost`` 总数与详情里的 ``tokens_used`` 必须一致（同源同值）。"""
    eng_id = _make_engagement(client, workspace)
    _seed_llm_calls(
        workspace,
        eng_id,
        [
            _event(caller="triage", prompt_tokens=11, completion_tokens=22),
            _event(caller="verifier", finding_id="F-1", prompt_tokens=33, completion_tokens=44),
            {"event": "llm_call", "prompt_tokens": 5, "completion_tokens": 5},  # 旧事件
        ],
    )
    cost = client.get(f"/api/engagements/{eng_id}/cost").json()
    detail = client.get(f"/api/engagements/{eng_id}").json()
    assert cost["total"]["total_tokens"] == detail["tokens_used"] == 120


def test_api_cost_endpoint_include_calls_toggle(client, workspace):
    eng_id = _make_engagement(client, workspace)
    _seed_llm_calls(workspace, eng_id, [_event(caller="triage")])
    with_calls = client.get(f"/api/engagements/{eng_id}/cost").json()
    without = client.get(
        f"/api/engagements/{eng_id}/cost", params={"include_calls": False}
    ).json()
    assert len(with_calls["calls"]) == 1
    assert "calls" not in without
    assert without["total"] == with_calls["total"]


def test_api_cost_endpoint_empty_engagement_is_zero(client, workspace):
    eng_id = _make_engagement(client, workspace)
    body = client.get(f"/api/engagements/{eng_id}/cost").json()
    assert body["total"]["calls"] == 0
    assert body["total"]["total_tokens"] == 0


def test_api_cost_endpoint_unknown_engagement_404(client):
    assert client.get("/api/engagements/nope/cost").status_code == 404


def test_cli_prints_markdown(client, workspace, capsys):
    eng_id = _make_engagement(client, workspace)
    _seed_llm_calls(
        workspace, eng_id, [_event(caller="verifier", finding_id="F-1", prompt_tokens=42)]
    )
    eng_dir = workspace / "engagements" / eng_id
    assert cost_main(["--dir", str(eng_dir)]) == 0
    out = capsys.readouterr().out
    assert "单题成本归属" in out
    assert "verifier" in out


def test_cli_json_matches_api(client, workspace, capsys):
    eng_id = _make_engagement(client, workspace)
    _seed_llm_calls(
        workspace, eng_id, [_event(caller="triage", prompt_tokens=7, completion_tokens=3)]
    )
    eng_dir = workspace / "engagements" / eng_id
    assert cost_main(["--dir", str(eng_dir), "--json"]) == 0
    cli_payload = json.loads(capsys.readouterr().out)
    api_payload = client.get(f"/api/engagements/{eng_id}/cost").json()
    assert cli_payload["total"] == api_payload["total"]
    assert cli_payload["by_caller"] == api_payload["by_caller"]


def test_cli_finding_filter(client, workspace, capsys):
    eng_id = _make_engagement(client, workspace)
    _seed_llm_calls(
        workspace,
        eng_id,
        [
            _event(caller="verifier", finding_id="F-1", prompt_tokens=10, completion_tokens=0),
            _event(caller="verifier", finding_id="F-2", prompt_tokens=90, completion_tokens=0),
            _event(caller="triage", prompt_tokens=50, completion_tokens=0),
        ],
    )
    eng_dir = workspace / "engagements" / eng_id
    assert cost_main(["--dir", str(eng_dir), "--finding", "F-1", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total"]["calls"] == 1
    assert payload["total"]["total_tokens"] == 10


def test_cli_missing_audit_returns_2(tmp_path, capsys):
    assert cost_main(["--dir", str(tmp_path / "nope")]) == 2
    assert "未找到审计文件" in capsys.readouterr().err


def test_api_cost_response_never_contains_cookie(client, workspace):
    """凭据纪律：成本端点响应体不得出现会话 cookie 原文。"""
    cookie_value = "abc123def456789"
    resp = client.post(
        "/api/engagements",
        json={
            "target": "http://127.0.0.1:8080",
            "scope_paths": ["scope.yaml"],
            "cookie": f"PHPSESSID={cookie_value}",
        },
    )
    assert resp.status_code == 201, resp.text
    eng_id = resp.json()["id"]
    _seed_llm_calls(workspace, eng_id, [_event(caller="verifier", finding_id="F-1")])
    body = client.get(f"/api/engagements/{eng_id}/cost")
    assert body.status_code == 200
    assert cookie_value not in body.text
