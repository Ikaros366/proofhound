"""模型路由单元测试（M2c）：零真实网络，urllib 层一律 mock。

覆盖：分档选路（model/url/key 各走各档）、temperature/max_tokens 透传、
缺配置清晰报错、部分配置即报错、未配置档位调用报错、T1==T2 同模型被允许并记
审计（M9b：红线 4 改为约束 agent 独立性，不再约束模型身份）、旧式客户端适配器。
"""

import json
import warnings

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.llm.client import LLMError
from proofhound.llm.router import (
    ModelRouter,
    Tier,
    TierConfig,
    ensure_router,
)

_TIER_VARS = [
    f"PROOFHOUND_{t}_{suffix}"
    for t in ("T0", "T1", "T2")
    for suffix in ("BASE_URL", "API_KEY", "MODEL", "TEMPERATURE", "MAX_TOKENS")
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _TIER_VARS:
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


def _ok_body(content="OK"):
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode()


def _configs() -> dict[Tier, TierConfig]:
    return {
        Tier.T0: TierConfig(
            base_url="https://t0.example/v1", api_key="k0", model="m0"
        ),
        Tier.T1: TierConfig(
            base_url="https://t1.example/v1", api_key="k1", model="m1"
        ),
    }


def test_routes_per_tier(monkeypatch):
    """T0/T1 各自打到自己的 endpoint/model/key。"""
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req)
        return _FakeResponse(_ok_body())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    router = ModelRouter(_configs())
    messages = [{"role": "user", "content": "hi"}]

    assert router.complete(Tier.T0, messages) == "OK"
    assert router.complete("t1", messages) == "OK"  # 字符串档位也可用

    payload0 = json.loads(calls[0].data.decode())
    assert calls[0].full_url == "https://t0.example/v1/chat/completions"
    assert payload0["model"] == "m0"
    assert calls[0].get_header("Authorization") == "Bearer k0"

    payload1 = json.loads(calls[1].data.decode())
    assert calls[1].full_url == "https://t1.example/v1/chat/completions"
    assert payload1["model"] == "m1"
    assert calls[1].get_header("Authorization") == "Bearer k1"


def test_temperature_max_tokens_passthrough(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured.update(json.loads(req.data.decode()))
        return _FakeResponse(_ok_body())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    configs = {
        Tier.T1: TierConfig(
            base_url="https://t1.example/v1",
            api_key="k1",
            model="m1",
            temperature=0.2,
            max_tokens=512,
        )
    }
    ModelRouter(configs).complete(Tier.T1, [{"role": "user", "content": "x"}])
    assert captured["temperature"] == 0.2
    assert captured["max_tokens"] == 512


def test_tier_config_from_env_missing_lists_names(tmp_path):
    with pytest.raises(LLMError) as excinfo:
        TierConfig.from_env(Tier.T1, tmp_path / ".env")
    msg = str(excinfo.value)
    assert "PROOFHOUND_T1_BASE_URL" in msg
    assert "PROOFHOUND_T1_API_KEY" in msg
    assert "PROOFHOUND_T1_MODEL" in msg


def test_tier_config_from_env_reads_dotenv(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "PROOFHOUND_T1_BASE_URL=https://file.example/v1/\n"
        "PROOFHOUND_T1_API_KEY=fk\n"
        "PROOFHOUND_T1_MODEL=fm\n"
        "PROOFHOUND_T1_TEMPERATURE=0.5\n",
        encoding="utf-8",
    )
    cfg = TierConfig.from_env(Tier.T1, env)
    assert cfg.base_url == "https://file.example/v1"
    assert cfg.model == "fm"
    assert cfg.temperature == 0.5
    assert cfg.max_tokens is None


def test_router_from_env_partial_config_raises(tmp_path):
    """某档只配了部分变量 → from_env 立即报清晰错。"""
    env = tmp_path / ".env"
    env.write_text("PROOFHOUND_T1_BASE_URL=https://t1.example/v1\n", encoding="utf-8")
    with pytest.raises(LLMError, match="PROOFHOUND_T1_API_KEY"):
        ModelRouter.from_env(env)


def test_router_from_env_skips_absent_tiers(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "PROOFHOUND_T1_BASE_URL=https://t1.example/v1\n"
        "PROOFHOUND_T1_API_KEY=k1\n"
        "PROOFHOUND_T1_MODEL=m1\n",
        encoding="utf-8",
    )
    router = ModelRouter.from_env(env)
    assert set(router.configs) == {Tier.T1}


def test_complete_unconfigured_tier_raises():
    router = ModelRouter(_configs())
    with pytest.raises(LLMError, match="T2|t2"):
        router.complete(Tier.T2, [{"role": "user", "content": "x"}])


def test_same_model_t1_t2_is_allowed(tmp_path):
    """M9b：T1 与 T2 允许同模型，且不再发任何警告。"""
    configs = _configs()
    configs[Tier.T2] = TierConfig(
        base_url="https://t2.example/v1", api_key="k2", model="m1"  # 与 T1 同模型
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        router = ModelRouter(configs, audit=audit)
    assert caught == [], [str(w.message) for w in caught]
    assert router.shared_model_across_tiers == "m1"
    assert "llm_tiers_share_model" in [e["event"] for e in audit.read_all()]


def test_same_model_without_audit_still_works():
    """无 audit 时同模型也不得抛错（审计是可选旁路）。"""
    configs = _configs()
    configs[Tier.T2] = TierConfig(
        base_url="https://t2.example/v1", api_key="k2", model="m1"
    )
    router = ModelRouter(configs)
    assert router.shared_model_across_tiers == "m1"


def test_different_model_t1_t2_no_warning(recwarn, tmp_path):
    configs = _configs()
    configs[Tier.T2] = TierConfig(
        base_url="https://t2.example/v1", api_key="k2", model="m2"
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    router = ModelRouter(configs, audit=audit)
    assert [w for w in recwarn.list if "相同模型" in str(w.message)] == []
    assert router.shared_model_across_tiers is None
    assert "llm_tiers_share_model" not in [e["event"] for e in audit.read_all()]


def test_ensure_router_wraps_legacy_client():
    """旧式单模型客户端（complete(messages)）自动适配，忽略档位。"""

    class FakeLLM:
        def __init__(self):
            self.calls = []

        def complete(self, messages):
            self.calls.append(messages)
            return "legacy"

    legacy = FakeLLM()
    router = ensure_router(legacy)
    assert router.complete(Tier.T1, [{"role": "user", "content": "x"}]) == "legacy"
    assert len(legacy.calls) == 1
    # ModelRouter 原样返回
    real = ModelRouter(_configs())
    assert ensure_router(real) is real
