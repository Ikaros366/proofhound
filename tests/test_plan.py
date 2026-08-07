"""计划 schema 单元测试（M2b）：非法 JSON / 非法动作必校验失败。"""

import pytest

from proofhound.core.plan import PlanValidationError, parse_plan

VALID = {
    "actions": [
        {
            "action": "run_tool",
            "skill": "web-scan",
            "tool": "httpx",
            "params": {"target": "http://127.0.0.1:8000"},
            "expected_output": "signals",
        }
    ]
}


def test_valid_plan():
    import json

    plan = parse_plan(json.dumps(VALID))
    assert len(plan.actions) == 1
    action = plan.actions[0]
    assert action.action == "run_tool"
    assert action.tool == "httpx"
    assert action.params["target"] == "http://127.0.0.1:8000"


def test_fenced_json_tolerated():
    import json

    raw = f"好的，计划如下：\n```json\n{json.dumps(VALID)}\n```\n请查收。"
    plan = parse_plan(raw)
    assert plan.actions[0].tool == "httpx"


def test_prose_around_json_tolerated():
    import json

    raw = f"分析结论：需要探活。{json.dumps(VALID)} 以上。"
    assert parse_plan(raw).actions[0].action == "run_tool"


def test_invalid_json_rejected():
    with pytest.raises(PlanValidationError):
        parse_plan("这不是 JSON")


def test_truncated_json_rejected():
    with pytest.raises(PlanValidationError):
        parse_plan('{"actions": [{"action": "run_tool",')


def test_unknown_action_rejected():
    import json

    bad = {"actions": [{"action": "rm_rf", "skill": "web-scan", "expected_output": "x"}]}
    with pytest.raises(PlanValidationError):
        parse_plan(json.dumps(bad))


def test_run_tool_requires_tool_and_params():
    import json

    missing_tool = {
        "actions": [
            {"action": "run_tool", "skill": "web-scan",
             "params": {"target": "x"}, "expected_output": "signals"}
        ]
    }
    with pytest.raises(PlanValidationError):
        parse_plan(json.dumps(missing_tool))

    empty_params = {
        "actions": [
            {"action": "run_tool", "skill": "web-scan", "tool": "httpx",
             "params": {}, "expected_output": "signals"}
        ]
    }
    with pytest.raises(PlanValidationError):
        parse_plan(json.dumps(empty_params))


def test_finish_must_not_carry_tool():
    import json

    bad = {
        "actions": [
            {"action": "finish", "skill": "web-scan", "tool": "httpx",
             "expected_output": "done"}
        ]
    }
    with pytest.raises(PlanValidationError):
        parse_plan(json.dumps(bad))


def test_empty_actions_rejected():
    import json

    with pytest.raises(PlanValidationError):
        parse_plan(json.dumps({"actions": []}))


def test_non_object_rejected():
    with pytest.raises(PlanValidationError):
        parse_plan('["run httpx -u example.com"]')


def test_shell_command_has_no_place():
    """红线 1：计划里出现 command 字段不影响 schema，但也绝不会被使用——
    这里确认 schema 不定义任何命令字段，命令只能由构造器产出。"""
    import json

    plan = parse_plan(json.dumps(VALID))
    assert not hasattr(plan.actions[0], "command")
