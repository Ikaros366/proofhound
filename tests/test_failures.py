"""失败分类规则表与失败预算单元测试（M2b）。"""

import pytest

from proofhound.core.failures import (
    EXIT_CODE_CATEGORIES,
    FALSE_SUCCESS_SIGNATURES,
    FailureBudget,
    FailureCategory,
    classify,
    false_success_signature,
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


# =====================================================================
# M31-e：tool_missing / tool_broken + 假成功签名
# =====================================================================


@pytest.mark.parametrize("exit_code", [126, 127])
def test_exit_code_alone_proves_tool_missing(exit_code):
    """126/127 是 shell 对"不可执行 / 找不到"的固定回答，比任何文案都权威。"""
    assert EXIT_CODE_CATEGORIES[exit_code] is FailureCategory.TOOL_MISSING
    assert classify("", exit_code=exit_code) is FailureCategory.TOOL_MISSING
    # 退出码优先于文本规则（文案可能只是被 echo 出来的靶侧页面）
    assert classify("429 Too Many Requests", exit_code=exit_code) is (
        FailureCategory.TOOL_MISSING
    )


def test_tool_missing_text_signature():
    assert classify("sh: 1: dirsearch: command not found") is (
        FailureCategory.TOOL_MISSING
    )
    assert classify("exec: /opt/tools/katana: executable file not found") is (
        FailureCategory.TOOL_MISSING
    )


def test_unknown_nonzero_exit_is_tool_broken_not_unknown():
    """回归：exit 1 + 认不出的文案，旧实现判 unknown，于是 task_blocked 把锅甩给
    规划器（"你无权自行给出 rate_rps/concurrency/max_requests"）——纯误导。"""
    assert classify("something opaque happened", exit_code=1) is (
        FailureCategory.TOOL_BROKEN
    )


def test_text_rules_still_win_over_the_nonzero_fallback():
    """非零退出码不得吞掉更具体的原因（限流/凭证/网络仍是原类别）。"""
    assert classify("429 Too Many Requests", exit_code=1) is FailureCategory.RATELIMIT
    assert classify("dial tcp: connection refused", exit_code=1) is (
        FailureCategory.NETWORK
    )
    assert classify("Invalid credentials", exit_code=1) is FailureCategory.AUTH


def test_classify_without_exit_code_keeps_legacy_contract():
    """不传退出码时行为不变（老调用方/V2 之前语义）：无命中即 unknown。"""
    assert classify("some totally opaque error") is FailureCategory.UNKNOWN
    assert classify("") is FailureCategory.UNKNOWN


# ---- 假成功（exit 0 但整轮没跑起来）--------------------------------------


def test_dirsearch_proxy_failure_is_registered_as_false_success():
    """实测原文（eng-20261102T093506Z-aac47e3a 的 39 字节 stdout）。"""
    out = "Cannot establish the proxy connection"
    assert "dirsearch" in FALSE_SUCCESS_SIGNATURES
    assert false_success_signature("dirsearch", out) == out
    # 分类：调用方已知这次执行失败 ⇒ tool_broken（不是 unknown）
    assert classify(out, exit_code=0, assume_failed=True) is (
        FailureCategory.TOOL_BROKEN
    )


def test_dirsearch_ssl_verification_failure_is_false_success():
    out = (
        "SSL certificate verification failed: [SSL: CERTIFICATE_VERIFY_FAILED] "
        "certificate verify failed: self-signed certificate in certificate chain"
    )
    assert false_success_signature("dirsearch", out) is not None
    assert classify(out, exit_code=0, assume_failed=True) is (
        FailureCategory.TOOL_BROKEN
    )


@pytest.mark.parametrize(
    "output",
    [
        "",
        # --max-time 到点是**正常收尾**，不是失败（实测成功扫描也打这句）
        "Runtime exceeded the maximum set by the user\n",
        # 真结果行
        "[09:44:21] 404 -    19B - https://h:8443/login/x\n"
        "[09:44:24] 200 -   27B - https://h:8443/admin\n",
        # 单条路径的连接失败会出现在正常扫描里，不能当整轮致命
        "Cannot connect to: 100.80.4.50:8443",
        "Request timeout: https://h/login/x",
    ],
)
def test_healthy_dirsearch_output_is_not_flagged_as_false_success(output):
    assert false_success_signature("dirsearch", output) is None


def test_generic_crash_is_false_success_for_any_tool():
    """进程活着但工具自己崩了：与工具无关，任何工具都算假成功。"""
    out = (
        "Traceback (most recent call last):\n"
        '  File "/opt/tools/x/x.py", line 1, in <module>\n'
        "ModuleNotFoundError: No module named 'foo'\n"
    )
    assert false_success_signature("httpx", out) is not None
    assert false_success_signature("katana", out) is not None


def test_false_success_lookup_ignores_unknown_tool_names():
    assert false_success_signature("no-such-tool", "all good") is None
