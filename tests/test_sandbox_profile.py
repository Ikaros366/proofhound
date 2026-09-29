"""沙箱隔离硬化档的配置与逃生阀测试（M12；**非** docker 标记）。

硬化档在真实容器里的**落实**由 ``tests/test_sandbox_hardening.py``（docker 标记）
负责；本文件只钉住不需要守护进程的性质：缺省严格、放宽可退、非法值 fail-closed、
审计摘要形态。放在这里而非 test_sandbox.py，是因为那个文件整体带 docker 标记，
无 Docker 环境下会被整文件跳过——而这些断言恰恰应该在任何环境都跑。
"""

from __future__ import annotations

import pytest

from proofhound.api.runner import sandbox_hardening
from proofhound.tools.sandbox import SCRATCH_DIR, SCRATCH_USER, SandboxConfig


def test_hardening_is_on_by_default():
    """缺省严格：不显式放宽就是硬化的（fail-closed 方向）。"""
    assert SandboxConfig().hardening is True


def test_profile_lists_every_enforced_boundary():
    profile = SandboxConfig().isolation_profile()

    assert profile["mode"] == "strict"
    assert profile["user"] == SCRATCH_USER == "65534:65534"
    assert profile["read_only_rootfs"] is True
    assert profile["no_new_privileges"] is True
    assert profile["cap_drop"] == ["ALL"]
    assert profile["pids_limit"] == 512
    assert profile["nofile_limit"] == 4096
    assert profile["tmpfs"] == f"{SCRATCH_DIR}:rw,nosuid,size=64m,mode=1777"


def test_relaxed_profile_is_explicit_not_empty():
    """放宽档也要可审计：不是一个空 dict，而是显式的 relaxed 标记。"""
    assert SandboxConfig(hardening=False).isolation_profile() == {"mode": "relaxed"}


def test_profile_follows_custom_limits():
    config = SandboxConfig(pids_limit=64, nofile_limit=128, scratch_size="8m")
    profile = config.isolation_profile()

    assert profile["pids_limit"] == 64
    assert profile["nofile_limit"] == 128
    assert "size=8m" in profile["tmpfs"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, True),  # 未设 = strict
        ("", True),  # 空串 = strict
        ("strict", True),
        ("STRICT", True),
        ("  strict  ", True),
        ("relaxed", False),
        ("RELAXED", False),
    ],
)
def test_hardening_env_valve(value, expected):
    environ = {} if value is None else {"PROOFHOUND_SANDBOX_HARDENING": value}

    assert sandbox_hardening(environ) is expected


@pytest.mark.parametrize("value", ["off", "0", "false", "False", "loose", "stricter", "1"])
def test_illegal_hardening_value_fails_closed(value):
    """非法值不得静默回落（既不默认严格也不默认放宽），必须抛错。"""
    with pytest.raises(ValueError, match="PROOFHOUND_SANDBOX_HARDENING"):
        sandbox_hardening({"PROOFHOUND_SANDBOX_HARDENING": value})


def test_hardening_valve_reads_real_environ(monkeypatch):
    monkeypatch.setenv("PROOFHOUND_SANDBOX_HARDENING", "relaxed")
    assert sandbox_hardening() is False

    monkeypatch.setenv("PROOFHOUND_SANDBOX_HARDENING", "strict")
    assert sandbox_hardening() is True

    monkeypatch.delenv("PROOFHOUND_SANDBOX_HARDENING")
    assert sandbox_hardening() is True
