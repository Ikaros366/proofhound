"""失败分类规则表与失败预算单元测试（M2b）。"""

import pytest

from proofhound.core.failures import (
    FailureBudget,
    FailureCategory,
    classify,
)
from proofhound.core.tasks import TaskNode


@pytest.mark.parametrize(
    "output,expected",
    [
        ("HTTP/1.1 401 Unauthorized\nauthentication failed", FailureCategory.AUTH),
        ("invalid credentials, login required", FailureCategory.AUTH),
        ("Please solve the reCAPTCHA to continue", FailureCategory.CAPTCHA),
        ("检测到人机验证，停止", FailureCategory.CAPTCHA),
        ("429 Too Many Requests", FailureCategory.RATELIMIT),
        ("rate limit exceeded, slow down", FailureCategory.RATELIMIT),
        ("Account locked after too many attempts", FailureCategory.LOCKOUT),
        ("账号锁定，请联系管理员", FailureCategory.LOCKOUT),
        ("dial tcp: connection refused", FailureCategory.NETWORK),
        ("read: connection reset by peer", FailureCategory.NETWORK),
        ("i/o timeout", FailureCategory.NETWORK),
        ("temporary failure in name resolution", FailureCategory.NETWORK),
        ("some totally opaque error", FailureCategory.UNKNOWN),
        ("", FailureCategory.UNKNOWN),
    ],
)
def test_classify(output, expected):
    assert classify(output) == expected


def test_lockout_beats_ratelimit_wording():
    """"too many attempts"（锁定）不得被 "too many requests"（限流）吞掉。"""
    assert classify("too many login attempts") == FailureCategory.LOCKOUT
    assert classify("too many requests") == FailureCategory.RATELIMIT


def test_budget_exhausted_at_limit():
    node = TaskNode(name="t")
    budget = FailureBudget()  # 默认同类 2 次
    assert budget.record(node, FailureCategory.NETWORK) is False
    assert budget.record(node, FailureCategory.NETWORK) is True
    assert node.failure_counts == {"network": 2}


def test_budget_per_category_independent():
    node = TaskNode(name="t")
    budget = FailureBudget()
    assert budget.record(node, FailureCategory.NETWORK) is False
    assert budget.record(node, FailureCategory.AUTH) is False  # 不同类别重新计
    assert budget.record(node, FailureCategory.NETWORK) is True


def test_hard_block_categories_immediate():
    node = TaskNode(name="t")
    budget = FailureBudget()
    assert budget.record(node, FailureCategory.CAPTCHA) is True  # 一次即耗尽
    node2 = TaskNode(name="t2")
    assert budget.record(node2, FailureCategory.LOCKOUT) is True


def test_custom_limit():
    node = TaskNode(name="t")
    budget = FailureBudget(limit_per_category=3)
    assert budget.record(node, FailureCategory.UNKNOWN) is False
    assert budget.record(node, FailureCategory.UNKNOWN) is False
    assert budget.record(node, FailureCategory.UNKNOWN) is True


def test_invalid_limit():
    with pytest.raises(ValueError):
        FailureBudget(limit_per_category=0)
