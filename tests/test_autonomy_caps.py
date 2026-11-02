"""M29：无人值守档放大**能力**配额，授权类硬闸与模式无关。

无人值守意味着"没人盯着"，配额卡住只会让任务停在那里等一个不存在的人工升级，
所以候选上限 / 贵验证配额 / 同类失败重试按系数放大。但**授权**（scope 范围、
request_budget、tls_verify、token 预算）必须由操作员显式声明——模式不改变它。
本文件既测放大，也把这个界限钉成断言，防后来者顺手把授权也挂到模式上。
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.api.runner import OrchestratorPhases, capability_scale_for
from proofhound.autonomy import AutonomyMode
from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import RequestBudget, Scope
from proofhound.core.failures import DEFAULT_LIMIT_PER_CATEGORY, FailureBudget
from proofhound.core.orchestrator import (
    UNATTENDED_CAP_SCALE,
    Orchestrator,
    _TRIAGE_CAPS,
    _TRIAGE_EXPENSIVE_CAP,
)
from proofhound.skills.registry import SkillRegistry


class _LLM:
    def complete(self, messages):
        raise AssertionError("本测试不应触发 LLM 调用")


@pytest.fixture
def registry(make_skill_dir):
    return SkillRegistry(make_skill_dir()).discover()


@pytest.fixture
def real_registry():
    """真实 skills 目录：``OrchestratorPhases`` 要按名取到全部内置 skill。"""
    return SkillRegistry(Path(__file__).resolve().parent.parent / "skills").discover()


def _orch(tmp_path, registry, **kwargs) -> Orchestrator:
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    runner = SimpleNamespace(scope=None, egress_proxy_url=None)
    return Orchestrator(
        registry,
        runner,
        _LLM(),
        audit,
        evidence_dir=tmp_path / "evidence",
        **kwargs,
    )


# =====================================================================
# 一、能力放大
# =====================================================================


def test_capability_scale_for_modes():
    def fake(mode):
        return SimpleNamespace(current_mode=lambda: mode)

    assert capability_scale_for(fake(AutonomyMode.SUPERVISED)) == 1
    assert capability_scale_for(fake(AutonomyMode.SEMI_AUTO)) == 1
    assert capability_scale_for(fake(AutonomyMode.UNATTENDED)) == UNATTENDED_CAP_SCALE


def test_unattended_scale_doubles_capability_quotas(tmp_path, registry):
    orch = _orch(tmp_path, registry, cap_scale=UNATTENDED_CAP_SCALE)

    assert orch.triage_caps == {
        vuln_type: limit * UNATTENDED_CAP_SCALE
        for vuln_type, limit in _TRIAGE_CAPS.items()
    }
    assert orch.expensive_cap == _TRIAGE_EXPENSIVE_CAP * UNATTENDED_CAP_SCALE
    assert (
        orch.budget.limit_per_category
        == DEFAULT_LIMIT_PER_CATEGORY * UNATTENDED_CAP_SCALE
    )


def test_default_scale_leaves_quotas_unchanged(tmp_path, registry):
    orch = _orch(tmp_path, registry)

    assert orch.cap_scale == 1
    assert orch.triage_caps == dict(_TRIAGE_CAPS)
    assert orch.expensive_cap == _TRIAGE_EXPENSIVE_CAP
    assert orch.budget.limit_per_category == DEFAULT_LIMIT_PER_CATEGORY


def test_explicit_quotas_are_not_scaled(tmp_path, registry):
    """显式传入的配额由调用方自己说了算——放大只作用于缺省值。"""
    budget = FailureBudget(limit_per_category=7)
    orch = _orch(
        tmp_path, registry, cap_scale=UNATTENDED_CAP_SCALE, expensive_cap=1, budget=budget
    )

    assert orch.expensive_cap == 1
    assert orch.budget.limit_per_category == 7


# =====================================================================
# 二、界限：授权类硬闸不看自治模式
# =====================================================================


def test_dirsearch_still_requires_explicit_budget_under_unattended(
    real_registry, tmp_path
):
    """无人值守**不会**自动开启字典爆破：没声明 request_budget 就仍不挂 dirsearch。"""
    audit = AuditLog(tmp_path / "audit.jsonl")

    without_budget = OrchestratorPhases(
        SimpleNamespace(
            audit=audit,
            runner=SimpleNamespace(scope=Scope(networks=["127.0.0.0/8"])),
        ),
        real_registry,
    )
    with_budget = OrchestratorPhases(
        SimpleNamespace(
            audit=audit,
            runner=SimpleNamespace(
                scope=Scope(
                    networks=["127.0.0.0/8"],
                    request_budget=RequestBudget(
                        rate_rps=10, concurrency=2, max_requests=100
                    ),
                )
            ),
        ),
        real_registry,
    )

    assert "web-dirsearch" not in [name for name, _ in without_budget.scan_skills]
    assert "web-dirsearch" in [name for name, _ in with_budget.scan_skills]


def test_tls_verify_defaults_strict_regardless_of_mode():
    """TLS 策略来自 scope 声明，没有任何按模式放开的路径。"""
    assert Scope().tls_verify == "strict"
    assert Scope(tls_verify="insecure").tls_verify == "insecure"


def test_capability_scale_does_not_touch_scope(real_registry, tmp_path):
    """放大能力不会改动 scope 里的任何授权字段。"""
    scope = Scope(networks=["127.0.0.0/8"])
    orchestrator = SimpleNamespace(
        audit=AuditLog(tmp_path / "audit2.jsonl"),
        runner=SimpleNamespace(scope=scope),
    )
    OrchestratorPhases(orchestrator, real_registry)

    assert scope.request_budget is None
    assert scope.tls_verify == "strict"
    assert scope.domains == []
