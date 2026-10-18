"""M19-c：dirsearch 的生产链路可达性 + 请求量授权预算的可审计来源。

这两件事是同一轮修复的两半：
- **可达性**：M16-b 交付的构造器/解析器/83 个测试从一开始就**没有任何 skill
  声明 dirsearch** ⇒ `Planner._validate_semantics` 拒绝一切 `run_tool(dirsearch)`，
  真实扫描永远用不到它（与 AGENTS.md 限制 58 同一类失败模式，此前无人记录）；
- **可审计**：限制 54 声称"缺省放行不等于无痕放行，因为审计能分辨
  `source=default/explicit`"，但 `Scope.request_budget_source()` 此前只有测试与
  demo 在调——生产链路一次也没记过。

opt-in 语义（本轮的保守取舍）：skill 与生产栈槽位都存在，但**只有 scope 显式声明
`request_budget`** 时才挂进扫描阶段——字典爆破是 L1「按词表主动发请求」，
不声明请求量上限就默认开始爆破，不可接受。
"""

from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

from proofhound.api.runner import OrchestratorPhases
from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import RequestBudget, Scope
from proofhound.core.plan import Plan, PlanAction
from proofhound.core.planner import Planner
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.build import build_command, known_tools

REPO = Path(__file__).resolve().parent.parent
SKILLS = REPO / "skills"


def _registry() -> SkillRegistry:
    return SkillRegistry(SKILLS).discover()


# ==========================================================================
# 一、可达性：规划器必须接受 run_tool(dirsearch)
# ==========================================================================


def test_dirsearch_is_declared_by_exactly_one_builtin_skill():
    registry = _registry()
    owners = [s.name for s in registry.enabled() if "dirsearch" in (s.manifest.required_tools or [])]
    assert owners == ["web-dirsearch"], (
        "dirsearch 必须由且仅由 web-dirsearch 声明（否则规划器仍会拒绝，"
        f"或造成两处真相源）；实际={owners}"
    )


def test_planner_accepts_run_tool_dirsearch(tmp_path):
    """真实规划器的语义校验必须放行 `run_tool(dirsearch)`（M19-c 的核心回归）。"""
    registry = _registry()
    planner = Planner(
        None,  # 只测语义校验，不调模型
        registry,
        set(known_tools()),
        AuditLog(tmp_path / "audit.jsonl"),
    )
    plan = Plan(
        actions=[
            PlanAction(
                action="run_tool",
                skill="web-dirsearch",
                tool="dirsearch",
                params={"target": "http://127.0.0.1:9/"},
                expected_output="web-probe Signals",
            )
        ]
    )
    planner._validate_semantics(plan)  # 不抛即通过


def test_every_known_tool_is_reachable_through_some_skill():
    """每个有命令构造器的工具，都必须被**至少一条内置 skill** 声明。

    把"工具接入"的定义从「能构造命令」改成「能被规划出来」——只做前一半正是
    dirsearch 这次的实际形态。
    """
    registry = _registry()
    declared: set[str] = set()
    for skill in registry.enabled():
        declared |= set(skill.manifest.required_tools or [])
    missing = sorted(set(known_tools()) - declared)
    assert not missing, (
        "以下工具没有任何内置 skill 声明（规划器会拒绝一切 run_tool 动作，"
        "生产链路上等于不存在）：" + str(missing)
    )


# ==========================================================================
# 二、请求量预算：来源可审计 + 真的传进构造器
# ==========================================================================


def _orch_stub(tmp_path, scope):
    audit = AuditLog(tmp_path / "audit.jsonl")
    return SimpleNamespace(
        audit=audit,
        runner=SimpleNamespace(scope=scope, egress_proxy_url=None),
    )


def test_resolve_request_budget_records_default_source(tmp_path):
    """未声明 request_budget ⇒ 用保守缺省值，但审计必须记 `source="default"`。"""
    from proofhound.core.orchestrator import Orchestrator

    scope = Scope(domains=["h"])  # request_budget 未声明
    audit = AuditLog(tmp_path / "audit.jsonl")
    orch = Orchestrator(
        _registry(),
        runner=SimpleNamespace(scope=scope, egress_proxy_url=None),
        llm=None,
        audit=audit,
        evidence_dir=tmp_path,
    )
    budget = orch._resolve_request_budget(SimpleNamespace(id="n1"), "dirsearch")
    assert (budget.rate_rps, budget.concurrency, budget.max_requests) == (50, 5, 5000)

    events = [e for e in audit.read_all() if e["event"] == "request_budget_resolved"]
    assert events, "缺失 request_budget_resolved 审计 ⇒ 限制 54 的『可分辨来源』不成立"
    assert events[-1]["source"] == "default"
    assert events[-1]["max_requests"] == 5000


def test_resolve_request_budget_records_explicit_source(tmp_path):
    from proofhound.core.orchestrator import Orchestrator

    scope = Scope(
        domains=["h"],
        request_budget=RequestBudget(rate_rps=2, concurrency=1, max_requests=100),
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    orch = Orchestrator(
        _registry(),
        runner=SimpleNamespace(scope=scope, egress_proxy_url=None),
        llm=None,
        audit=audit,
        evidence_dir=tmp_path,
    )
    budget = orch._resolve_request_budget(SimpleNamespace(id="n1"), "dirsearch")
    events = [e for e in audit.read_all() if e["event"] == "request_budget_resolved"]
    assert events[-1]["source"] == "explicit"
    assert events[-1]["rate_rps"] == 2
    # 不消费预算的工具既不该拿到预算，也不该产生事件
    assert orch._resolve_request_budget(SimpleNamespace(id="n2"), "httpx") is None
    assert len([e for e in audit.read_all() if e["event"] == "request_budget_resolved"]) == 1
    assert budget.max_requests == 100


def test_resolve_request_budget_fails_closed_without_scope(tmp_path):
    from proofhound.core.orchestrator import Orchestrator

    audit = AuditLog(tmp_path / "audit.jsonl")
    orch = Orchestrator(
        _registry(),
        runner=SimpleNamespace(scope=None, egress_proxy_url=None),
        llm=None,
        audit=audit,
        evidence_dir=tmp_path,
    )
    class _Node:
        id = "n1"

        def __init__(self):
            self.transitions = []

        def transition(self, status, *, reason):
            self.transitions.append((status, reason))

    node = _Node()
    assert orch._resolve_request_budget(node, "dirsearch") is None
    assert node.transitions, "没有授权来源时节点必须迁移到 failed（fail-closed）"
    assert any(
        e["event"] == "request_budget_unavailable" for e in audit.read_all()
    ), "没有授权来源时必须留痕，不能静默失败"


def test_exec_run_tool_plumbs_budget_into_constructor():
    """接线守护：`_exec_run_tool` 必须把预算真的传给 `build_command`。

    用 `inspect.getsource` 取**真实源码**（本仓库既有的守护手法），因为把这条链路
    完整跑起来需要一个真沙箱容器；而"传没传参数"是可以用源码确定性回答的。
    """
    from proofhound.core.orchestrator import Orchestrator

    src = inspect.getsource(Orchestrator._exec_run_tool)
    assert "REQUEST_BUDGET_TOOLS" in src, "必须按登记表判断，不得再写 tool == 'dirsearch'"
    assert "request_budget=request_budget" in src, (
        "没把预算传给 build_command ⇒ dirsearch 构造器会 fail-closed 报错"
    )


def test_budget_actually_reaches_the_command_line():
    """预算落到 argv：显式 2 rps / 1 并发必须体现在旗标上。"""
    argv = build_command(
        "dirsearch",
        {"target": "http://127.0.0.1:9/"},
        request_budget=RequestBudget(rate_rps=2, concurrency=1, max_requests=100),
    )
    assert "--max-rate" in argv and argv[argv.index("--max-rate") + 1] == "2"
    assert "-t" in argv and argv[argv.index("-t") + 1] == "1"
    assert "-r" not in argv and "-F" not in argv


# ==========================================================================
# 三、opt-in：只有 scope 显式声明 request_budget 才挂进扫描阶段
# ==========================================================================


def test_dirsearch_scan_skill_absent_when_budget_not_declared(tmp_path):
    scope = Scope(domains=["h"])  # 未声明 request_budget
    orch = _orch_stub(tmp_path, scope)
    phases = OrchestratorPhases(orch, _registry())
    assert [name for name, _ in phases.scan_skills] == ["web-scan", "recon-crawl"], (
        "未声明请求量授权时不得自动开始字典爆破（opt-in）"
    )
    skipped = [
        e
        for e in orch.audit.read_all()
        if e["event"] == "scan_skill_skipped" and e["skill"] == "web-dirsearch"
    ]
    assert skipped, "跳过必须留审计（否则『没跑』与『没接』不可分辨）"
    assert "request_budget" in skipped[-1]["reason"]


def test_dirsearch_scan_skill_present_when_budget_explicit(tmp_path):
    scope = Scope(
        domains=["h"],
        request_budget=RequestBudget(rate_rps=5, concurrency=2, max_requests=200),
    )
    orch = _orch_stub(tmp_path, scope)
    phases = OrchestratorPhases(orch, _registry())
    names = [name for name, _ in phases.scan_skills]
    assert names == ["web-scan", "recon-crawl", "web-dirsearch"], names
    risk = dict(phases.scan_skills)["web-dirsearch"]
    assert risk == "L1", "字典爆破是主动发现，风险级必须 L1"
    assert phases.mutating_by_skill["web-dirsearch"] is True


def test_empty_dirsearch_slot_disables_it_silently(tmp_path):
    """空字符串 = 显式不启用：不挂栈、也不产生 skipped 噪音。"""
    orch = _orch_stub(
        tmp_path,
        Scope(
            domains=["h"],
            request_budget=RequestBudget(rate_rps=5, concurrency=2, max_requests=200),
        ),
    )
    phases = OrchestratorPhases(orch, _registry(), scan_dirsearch_skill="")
    assert [name for name, _ in phases.scan_skills] == ["web-scan", "recon-crawl"]
    assert not [
        e for e in orch.audit.read_all() if e["event"] == "scan_skill_skipped"
    ]
