"""用量计量与预算硬闸单元测试（M2c）：零真实网络，urllib 层一律 mock。

覆盖：真实 usage 计量、无 usage 时字符估算（estimated）、tracker 合计、
预算超限（总量/分档/0 上限）→ BudgetExceededError 且不发 HTTP 不写 llm_call、
llm_call 审计事件字段、TokenBudget.from_env 解析。
"""

import json

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.llm.client import LLMError
from proofhound.llm.router import ModelRouter, Tier, TierConfig
from proofhound.llm.usage import (
    BudgetExceededError,
    TokenBudget,
    UsageTracker,
    estimate_tokens,
)

_BUDGET_VARS = [
    "PROOFHOUND_MAX_TOKENS_PER_RUN",
    "PROOFHOUND_MAX_TOKENS_PER_RUN_T0",
    "PROOFHOUND_MAX_TOKENS_PER_RUN_T1",
    "PROOFHOUND_MAX_TOKENS_PER_RUN_T2",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _BUDGET_VARS:
        monkeypatch.delenv(name, raising=False)


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self) -> bytes:
        return self._body


def _body(content="OK", usage=None):
    data = {"choices": [{"message": {"content": content}}]}
    if usage is not None:
        data["usage"] = usage
    return json.dumps(data).encode()


def _router(monkeypatch, body: bytes, **kwargs) -> ModelRouter:
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda req, timeout=None: _FakeResponse(body)
    )
    configs = {
        Tier.T0: TierConfig(base_url="https://t0.example/v1", api_key="k0", model="m0"),
        Tier.T1: TierConfig(base_url="https://t1.example/v1", api_key="k1", model="m1"),
    }
    return ModelRouter(configs, **kwargs)


_MESSAGES = [{"role": "user", "content": "探活这个目标"}]


def test_usage_recorded_from_response(monkeypatch, tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    tracker = UsageTracker()
    router = _router(
        monkeypatch,
        _body(usage={"prompt_tokens": 12, "completion_tokens": 5}),
        tracker=tracker,
        audit=audit,
    )
    out = router.complete(Tier.T1, _MESSAGES)
    assert out == "OK"

    (rec,) = tracker.records
    assert rec.tier == "t1"
    assert rec.model == "m1"
    assert rec.prompt_tokens == 12
    assert rec.completion_tokens == 5
    assert rec.estimated is False
    assert rec.latency_ms >= 0

    (event,) = [e for e in audit.read_all() if e["event"] == "llm_call"]
    assert event["tier"] == "t1"
    assert event["model"] == "m1"
    assert event["prompt_tokens"] == 12
    assert event["completion_tokens"] == 5
    assert event["estimated"] is False
    assert "latency_ms" in event


def test_usage_estimated_when_absent(monkeypatch, tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    tracker = UsageTracker()
    router = _router(monkeypatch, _body("x" * 40), tracker=tracker, audit=audit)
    router.complete(Tier.T0, _MESSAGES)

    (rec,) = tracker.records
    assert rec.estimated is True
    assert rec.prompt_tokens == estimate_tokens("探活这个目标")
    assert rec.completion_tokens == estimate_tokens("x" * 40)
    (event,) = [e for e in audit.read_all() if e["event"] == "llm_call"]
    assert event["estimated"] is True


def test_tracker_totals_per_tier(monkeypatch):
    tracker = UsageTracker()
    router = _router(
        monkeypatch,
        _body(usage={"prompt_tokens": 6, "completion_tokens": 4}),
        tracker=tracker,
    )
    router.complete(Tier.T0, _MESSAGES)
    router.complete(Tier.T1, _MESSAGES)
    router.complete(Tier.T1, _MESSAGES)
    assert tracker.total_tokens() == 30
    assert tracker.total_tokens("t0") == 10
    assert tracker.total_tokens("t1") == 20


def test_budget_zero_blocks_before_http(monkeypatch, tmp_path):
    """0 上限：首次调用前即被闸——不发 HTTP、不写 llm_call。"""
    audit = AuditLog(tmp_path / "audit.jsonl")
    tracker = UsageTracker()
    called = []

    def forbidden_urlopen(req, timeout=None):
        called.append(req)
        raise AssertionError("预算超限不应发起 HTTP 请求")

    monkeypatch.setattr("urllib.request.urlopen", forbidden_urlopen)
    configs = {
        Tier.T1: TierConfig(base_url="https://t1.example/v1", api_key="k1", model="m1")
    }
    router = ModelRouter(
        configs, tracker=tracker, audit=audit, budget=TokenBudget(max_total=0)
    )
    with pytest.raises(BudgetExceededError) as excinfo:
        router.complete(Tier.T1, _MESSAGES)
    exc = excinfo.value
    assert exc.tier == "t1" and exc.used == 0 and exc.limit == 0 and exc.scope == "run"
    assert called == []
    assert tracker.records == []
    assert audit.read_all() == []


def test_budget_total_cap_stops_third_call(monkeypatch):
    tracker = UsageTracker()
    router = _router(
        monkeypatch,
        _body(usage={"prompt_tokens": 6, "completion_tokens": 4}),
        tracker=tracker,
        budget=TokenBudget(max_total=20),
    )
    router.complete(Tier.T1, _MESSAGES)  # 已用 10
    router.complete(Tier.T1, _MESSAGES)  # 已用 20
    with pytest.raises(BudgetExceededError) as excinfo:
        router.complete(Tier.T1, _MESSAGES)  # 20 >= 20 → 闸
    assert excinfo.value.scope == "run"
    assert len(tracker.records) == 2  # 第三次未发生


def test_budget_per_tier_cap(monkeypatch):
    tracker = UsageTracker()
    router = _router(
        monkeypatch,
        _body(usage={"prompt_tokens": 6, "completion_tokens": 4}),
        tracker=tracker,
        budget=TokenBudget(max_per_tier={"t1": 10}),
    )
    router.complete(Tier.T1, _MESSAGES)  # t1 已用 10
    router.complete(Tier.T0, _MESSAGES)  # t0 无上限，放行
    with pytest.raises(BudgetExceededError) as excinfo:
        router.complete(Tier.T1, _MESSAGES)
    assert excinfo.value.scope == "t1"
    assert excinfo.value.limit == 10


def test_budget_error_is_not_llm_error():
    """预算异常必须独立于 LLMError（否则会被编排器当规划失败置 failed）。"""
    assert not issubclass(BudgetExceededError, LLMError)


def test_budget_from_env(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "PROOFHOUND_MAX_TOKENS_PER_RUN=1000\n"
        "PROOFHOUND_MAX_TOKENS_PER_RUN_T1=300\n",
        encoding="utf-8",
    )
    budget = TokenBudget.from_env(env)
    assert budget.max_total == 1000
    assert budget.max_per_tier == {"t1": 300}


def test_budget_from_env_unset_returns_none(tmp_path):
    assert TokenBudget.from_env(tmp_path / ".env") is None


def test_budget_from_env_invalid_raises(tmp_path):
    env = tmp_path / ".env"
    env.write_text("PROOFHOUND_MAX_TOKENS_PER_RUN=abc\n", encoding="utf-8")
    with pytest.raises(LLMError, match="PROOFHOUND_MAX_TOKENS_PER_RUN"):
        TokenBudget.from_env(env)
