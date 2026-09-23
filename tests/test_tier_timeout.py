"""M10a 前置修复：LLM 分档读超时（T2 放宽 + ``PROOFHOUND_<TIER>_TIMEOUT`` 覆盖）。

## 为什么需要这个文件

M10a Step 3 的实测暴露一个**精度问题**：``TierConfig`` 的 timeout 缺省 60s，
而前沿推理档（kimi-k3）的 Verifier 终审延迟落在 **55~65s**——正好压在线上。
后果是间歇性 ``verify_blocked``（fail-closed，语义正确）把"未能判定"混进
Confirmed 级指标：单臂 12 条真漏洞里 **3 条**纯因超时丢失（检出率 50%，
本可 75%），而同一次运行里其它 T2 调用均正常返回，即**逐次随机**。

故 T2 缺省放宽到 180s（T0/T1 保持 60s），并支持 ``PROOFHOUND_<TIER>_TIMEOUT``
按档覆盖。本文件把这三件事钉死：**分档缺省**、**env 覆盖**、**非法值 fail-closed**。
"""

from __future__ import annotations

import pytest

from proofhound.llm.client import LLMError
from proofhound.llm.router import DEFAULT_TIMEOUTS, ModelRouter, Tier, TierConfig


def _set_required(monkeypatch, tier: Tier) -> None:
    prefix = f"PROOFHOUND_{tier.name}_"
    monkeypatch.setenv(prefix + "BASE_URL", "https://example.invalid/v1")
    monkeypatch.setenv(prefix + "API_KEY", "test-key")
    monkeypatch.setenv(prefix + "MODEL", "test-model")
    monkeypatch.delenv(prefix + "TIMEOUT", raising=False)


@pytest.fixture
def env_file(tmp_path):
    """不存在的 env 文件：确保配置只来自 monkeypatch 的环境变量。"""
    return tmp_path / "absent.env"


def test_tier_default_timeouts_declared():
    """分档缺省表：T0/T1 保持 60s，T2 放宽到 180s。"""
    assert DEFAULT_TIMEOUTS[Tier.T0] == 60.0
    assert DEFAULT_TIMEOUTS[Tier.T1] == 60.0
    assert DEFAULT_TIMEOUTS[Tier.T2] == 180.0


@pytest.mark.parametrize(
    ("tier", "expected"),
    [(Tier.T0, 60.0), (Tier.T1, 60.0), (Tier.T2, 180.0)],
)
def test_from_env_applies_tier_default(monkeypatch, env_file, tier, expected):
    """未设 ``PROOFHOUND_<TIER>_TIMEOUT`` 时取该档缺省。"""
    _set_required(monkeypatch, tier)
    config = TierConfig.from_env(tier, env_file)
    assert config.timeout == expected


def test_timeout_env_overrides_default(monkeypatch, env_file):
    """``PROOFHOUND_T2_TIMEOUT`` 覆盖该档缺省（运维可自行收紧或放宽）。"""
    _set_required(monkeypatch, Tier.T2)
    monkeypatch.setenv("PROOFHOUND_T2_TIMEOUT", "45")
    assert TierConfig.from_env(Tier.T2, env_file).timeout == 45.0


def test_timeout_env_is_per_tier(monkeypatch, env_file):
    """按档隔离：改 T2 的超时不影响 T1。"""
    for tier in (Tier.T1, Tier.T2):
        _set_required(monkeypatch, tier)
    monkeypatch.setenv("PROOFHOUND_T2_TIMEOUT", "240")
    configs = ModelRouter.from_env(env_file).configs
    assert configs[Tier.T2].timeout == 240.0
    assert configs[Tier.T1].timeout == 60.0


def test_timeout_non_numeric_fails_closed(monkeypatch, env_file):
    """非法值 fail-closed：不静默回落到缺省。"""
    _set_required(monkeypatch, Tier.T2)
    monkeypatch.setenv("PROOFHOUND_T2_TIMEOUT", "not-a-number")
    with pytest.raises(LLMError, match="TIMEOUT"):
        TierConfig.from_env(Tier.T2, env_file)


def test_timeout_reaches_llm_client_config(monkeypatch, env_file):
    """超时必须真正传到 ``LLMConfig``——否则只是装饰。"""
    _set_required(monkeypatch, Tier.T2)
    config = TierConfig.from_env(Tier.T2, env_file)
    assert config.to_llm_config().timeout == 180.0


def test_router_from_env_gives_t2_longer_timeout(monkeypatch, env_file):
    """端到端：``ModelRouter.from_env`` 建出的 T2 客户端拿到 180s。

    这是 M10a 那 3 条超时丢失的直接修复点——路由器是编排层的唯一入口。
    """
    for tier in (Tier.T0, Tier.T1, Tier.T2):
        _set_required(monkeypatch, tier)
    router = ModelRouter.from_env(env_file)
    assert router.configs[Tier.T2].timeout == 180.0
    assert router.configs[Tier.T1].timeout == 60.0
    assert router.configs[Tier.T0].timeout == 60.0
