"""规划器单元测试（M2b）：LLM 一律 mock；schema + 语义校验 + 审计。"""

import json

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.plan import PlanValidationError
from proofhound.core.planner import Planner
from proofhound.skills.registry import SkillRegistry


class FakeLLM:
    """按队列返回罐头回复的 mock LLM。"""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def complete(self, messages):
        self.calls.append(messages)
        if not self.replies:
            raise AssertionError("FakeLLM 回复队列已空")
        return self.replies.pop(0)


def _plan_json(**overrides):
    action = {
        "action": "run_tool",
        "skill": "web-scan",
        "tool": "httpx",
        "params": {"target": "http://127.0.0.1:8000"},
        "expected_output": "signals",
    }
    action.update(overrides)
    return json.dumps({"actions": [action]})


@pytest.fixture
def registry(make_skill_dir):
    return SkillRegistry(make_skill_dir()).discover()


def _make_planner(registry, tmp_path, replies, tools=("httpx",)):
    audit = AuditLog(tmp_path / "audit.jsonl")
    llm = FakeLLM(replies)
    return Planner(llm, registry, set(tools), audit), llm, audit


def test_plan_success(registry, tmp_path):
    planner, llm, audit = _make_planner(registry, tmp_path, [_plan_json()])
    skill = registry.get("web-scan")
    state = {"target": "http://127.0.0.1:8000", "attempts": 0}
    plan = planner.plan(state, skill)

    assert plan.actions[0].tool == "httpx"
    # prompt 注入：skill 正文 SOP + 结构化状态 + 工具清单
    user_msg = llm.calls[0][1]["content"]
    assert "SOP 正文：先探活" in user_msg
    assert "http://127.0.0.1:8000" in user_msg
    assert "httpx" in user_msg
    assert "shell" in llm.calls[0][0]["content"]  # system 声明禁令

    events = audit.read_all()
    assert [e["event"] for e in events] == ["plan_generated"]
    assert events[0]["action_kinds"] == ["run_tool"]


def test_invalid_json_rejected(registry, tmp_path):
    planner, _, audit = _make_planner(registry, tmp_path, ["随便说点什么，没有 JSON"])
    with pytest.raises(PlanValidationError):
        planner.plan({}, registry.get("web-scan"))
    events = audit.read_all()
    assert [e["event"] for e in events] == ["plan_rejected"]


def test_unknown_skill_rejected(registry, tmp_path):
    planner, _, _ = _make_planner(
        registry, tmp_path, [_plan_json(skill="no-such-skill")]
    )
    with pytest.raises(PlanValidationError, match="未注册"):
        planner.plan({}, registry.get("web-scan"))


def test_tool_without_builder_rejected(registry, tmp_path):
    planner, _, _ = _make_planner(registry, tmp_path, [_plan_json(tool="nuclei")])
    with pytest.raises(PlanValidationError, match="无命令构造器"):
        planner.plan({}, registry.get("web-scan"))


def test_tool_outside_required_tools_rejected(make_skill_dir, tmp_path):
    registry = SkillRegistry(make_skill_dir(tools=("httpx",))).discover()
    # skill 只声明 httpx，LLM 却要用 curl——且 curl 有构造器（越过第一层）
    planner, _, _ = _make_planner(
        registry, tmp_path, [_plan_json(tool="curl")], tools=("httpx", "curl")
    )
    with pytest.raises(PlanValidationError, match="required_tools"):
        planner.plan({}, registry.get("web-scan"))


def test_disabled_skill_rejected(make_skill_dir, tmp_path):
    registry = SkillRegistry(make_skill_dir()).discover()
    registry.disable("web-scan")
    planner, _, _ = _make_planner(registry, tmp_path, [_plan_json()])
    with pytest.raises(PlanValidationError, match="未启用"):
        planner.plan({}, registry.get("web-scan"))
