"""M16-b：请求量授权语义（scope.RequestBudget）+ dirsearch 构造器。

本模块锁三件事：

1. ``Scope.request_budget`` 的**值语义**与**来源标记**（``default``/``explicit``）——
   缺省保守但**有痕**，非法值一律显式抛错；
2. ``DirsearchParams`` / ``_build_dirsearch`` 的 argv 形态：速率、并发、时间窗
   **只从 scope 预算来**，且**永不产** ``-r``（递归）/``-F``（跟随重定向）；
3. 授权语义**不可被静默绕过**：缺预算报错、params 夹带预算键报错、
   给不消费的工具传预算报错。
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from proofhound.compliance.scope import (
    DEFAULT_CONCURRENCY,
    DEFAULT_MAX_REQUESTS,
    DEFAULT_RATE_RPS,
    RequestBudget,
    Scope,
    check_scope,
    default_request_budget,
)
from proofhound.tools.build import (
    DirsearchParams,
    build_command,
    dirsearch_timeout_for,
    dirsearch_wordlist_head,
    known_tools,
)

TARGET = "http://127.0.0.1:8080"

EXT_DEFAULT = "php,asp,aspx,jsp,html,htm"


def _scope(**kw) -> Scope:
    return Scope(networks=["127.0.0.0/8"], ports=[8080], **kw)


# --------------------------------------------------------------- RequestBudget


def test_request_budget_conservative_defaults():
    """缺省是**保守值**（维护者裁定：开箱即用但保守），不是 None-即拒绝。"""
    b = default_request_budget()
    assert b.rate_rps == DEFAULT_RATE_RPS == 50
    assert b.concurrency == DEFAULT_CONCURRENCY == 5
    assert b.max_requests == DEFAULT_MAX_REQUESTS == 5000
    assert b.window_minutes is None
    assert b.max_seconds() is None


def test_scope_without_budget_is_marked_default_not_explicit():
    """缺省放行**不等于**无痕放行：来源必须可分辨（M16-b 的诚实性要求）。"""
    s = _scope()
    assert s.request_budget is None
    assert s.request_budget_source() == "default"
    # 取值仍是保守缺省
    assert s.resolved_request_budget().rate_rps == 50


def test_scope_with_budget_is_marked_explicit():
    s = _scope(request_budget={"rate_rps": 2, "concurrency": 1,
                               "max_requests": 100, "window_minutes": 8})
    assert s.request_budget_source() == "explicit"
    b = s.resolved_request_budget()
    assert (b.rate_rps, b.concurrency, b.max_requests) == (2, 1, 100)
    assert b.max_seconds() == 480


@pytest.mark.parametrize(
    "kw, field",
    [
        ({"rate_rps": 0}, "rate_rps"),
        ({"rate_rps": 201}, "rate_rps"),
        ({"rate_rps": -1}, "rate_rps"),
        ({"concurrency": 0}, "concurrency"),
        ({"concurrency": 21}, "concurrency"),
        ({"max_requests": 0}, "max_requests"),
        ({"max_requests": 50001}, "max_requests"),
        ({"window_minutes": 0}, "window_minutes"),
        ({"window_minutes": 1441}, "window_minutes"),
    ],
)
def test_invalid_budget_values_raise_explicitly(kw, field):
    """非法值必须**显式抛错**，绝不静默回落到放宽值（既有纪律）。"""
    with pytest.raises(ValidationError) as exc:
        _scope(request_budget=kw)
    assert any(e["loc"][-1] == field for e in exc.value.errors())


def test_unknown_budget_key_rejected():
    """extra="forbid"：拼错的键名要炸，不能静默忽略授权意图。"""
    with pytest.raises(ValidationError):
        _scope(request_budget={"rate": 10})  # 应为 rate_rps


def test_budget_yaml_roundtrip_and_backward_compat(tmp_path):
    import yaml

    f = tmp_path / "s.yaml"
    f.write_text(yaml.safe_dump({
        "networks": ["127.0.0.0/8"], "ports": [8080],
        "request_budget": {"rate_rps": 20, "concurrency": 3, "max_requests": 900},
    }), encoding="utf-8")
    s = Scope.from_file(f)
    assert s.request_budget_source() == "explicit"
    assert s.resolved_request_budget().rate_rps == 20

    # 旧 scope 文件（无 request_budget）必须照常可加载
    f2 = tmp_path / "s2.yaml"
    f2.write_text("networks: [127.0.0.0/8]\nports: [8080]\n", encoding="utf-8")
    s2 = Scope.from_file(f2)
    assert s2.request_budget_source() == "default"


# ------------------------------------------------------------- 构造器 argv


def test_dirsearch_argv_golden_conservative_default():
    """缺省 argv 黄金：保守 50 rps / 5 并发；无时间窗；无 -r/-F。"""
    s = _scope()
    argv = build_command("dirsearch", {"target": TARGET},
                         request_budget=s.resolved_request_budget())
    assert argv == [
        "dirsearch", "-u", TARGET,
        "-t", "5", "--max-rate", "50",
        "--wordlists", "/opt/tools/dicc.txt",
        "-e", EXT_DEFAULT,
        "-q", "--no-color", "-O", "json", "-o", "/tmp/ds_report.json",
    ]


def test_dirsearch_never_emits_recursive_or_follow_redirects():
    """`-r`（递归）与 `-F`（跟随重定向）会放大请求面/越界面 ⇒ 永不产。"""
    s = _scope(request_budget={"rate_rps": 5, "concurrency": 2,
                               "max_requests": 1000, "window_minutes": 3})
    argv = build_command("dirsearch", {"target": TARGET},
                         request_budget=s.resolved_request_budget())
    assert "-r" not in argv and "--recursive" not in argv
    assert "-F" not in argv and "--follow-redirects" not in argv
    # 也不产目标文件类旗标（目标面结构性收敛为单 -u）
    assert "-l" not in argv and "--urls-file" not in argv


def test_dirsearch_explicit_budget_wins_over_default():
    """**回归**：显式授权不得被构造器缺省静默覆盖（实现期踩到的真缺陷）。"""
    s = _scope(request_budget={"rate_rps": 2, "concurrency": 1,
                               "max_requests": 100, "window_minutes": 8})
    argv = build_command("dirsearch", {"target": TARGET},
                         request_budget=s.resolved_request_budget())
    assert argv[argv.index("--max-rate") + 1] == "2"
    assert argv[argv.index("-t") + 1] == "1"
    # 工具自限时 = 窗口 * 0.7（留 30% 余量给工具自己收尾，见 build.py 说明）
    assert argv[argv.index("--max-time") + 1] == "336"


def test_dirsearch_window_absent_means_no_max_time():
    s = _scope(request_budget={"rate_rps": 5, "concurrency": 2,
                               "max_requests": 100})
    argv = build_command("dirsearch", {"target": TARGET},
                         request_budget=s.resolved_request_budget())
    assert "--max-time" not in argv


def test_dirsearch_requires_explicit_request_budget():
    """不传预算 → 报错（不是静默用别的值）。"""
    with pytest.raises(ValueError, match="request_budget"):
        build_command("dirsearch", {"target": TARGET})


def test_dirsearch_rejects_smuggled_budget_in_params():
    """params 里夹带预算键 → 报错（防"以为授了限速、其实被覆盖"）。"""
    with pytest.raises(ValueError, match="不得放进 params"):
        build_command("dirsearch", {"target": TARGET, "rate_rps": 999},
                      request_budget=RequestBudget())


def test_request_budget_rejected_for_non_consuming_tool():
    """给不消费预算的工具传预算 → 报错（不能假装限速生效）。"""
    with pytest.raises(ValueError, match="不消费 request_budget"):
        build_command("katana", {"target": TARGET},
                      request_budget=RequestBudget())
    # 不传则照旧
    assert build_command("katana", {"target": TARGET})[0] == "katana"


def test_dirsearch_proxy_and_session_injected():
    from proofhound.compliance.session import SessionConfig

    s = _scope()
    argv = build_command(
        "dirsearch",
        {"target": TARGET, "with_session": True},
        request_budget=s.resolved_request_budget(),
        egress_proxy_url="http://127.0.0.1:18080",
        session=SessionConfig(cookies={"PHPSESSID": "abc12345"}),
    )
    assert argv[argv.index("--proxy") + 1] == "http://127.0.0.1:18080"
    assert "Cookie: PHPSESSID=abc12345" in argv


def test_dirsearch_with_session_without_session_is_fail_closed():
    s = _scope()
    with pytest.raises(ValueError):
        build_command("dirsearch", {"target": TARGET, "with_session": True},
                      request_budget=s.resolved_request_budget(), session=None)


# ------------------------------------------------------------- 校验与边界


def test_dirsearch_target_flag_injection_rejected():
    with pytest.raises(ValidationError):
        build_command("dirsearch", {"target": "-o /etc/passwd"},
                      request_budget=RequestBudget())


@pytest.mark.parametrize("ext", ["php;rm -rf /", "php asp", "php,", ",php",
                                 "php\nasp", ""])
def test_dirsearch_bad_extensions_rejected(ext):
    with pytest.raises(ValidationError):
        build_command("dirsearch",
                      {"target": TARGET, "extensions": ext},
                      request_budget=RequestBudget())


def test_dirsearch_wordlist_flag_injection_rejected():
    with pytest.raises(ValidationError):
        build_command("dirsearch", {"target": TARGET, "wordlist": "-o /tmp/x"},
                      request_budget=RequestBudget())


@pytest.mark.parametrize(
    "kw, field",
    [
        ({"rate_rps": 0, "concurrency": 1, "max_requests": 10}, "rate_rps"),
        ({"rate_rps": 1, "concurrency": 21, "max_requests": 10}, "concurrency"),
        ({"rate_rps": 1, "concurrency": 1, "max_requests": 50001}, "max_requests"),
    ],
)
def test_request_budget_bounds_at_scope_layer(kw, field):
    """上限由 scope 层挡住（不在构造器层重复实现）。"""
    with pytest.raises(ValidationError):
        _scope(request_budget=kw)


# ------------------------------------------------------- max_requests 硬闸


@pytest.mark.parametrize(
    "max_requests, extensions, expected",
    [
        (5000, "php,asp,aspx,jsp,html,htm", 714),   # 6 扩展 → 每词 7 请求
        (100, "php,asp,aspx,jsp,html,htm", 14),
        (12, "php,asp,aspx,jsp,html,htm", 1),       # 至少 1 词
        (1, "php", 1),
        (50000, "php", 25000),
    ],
)
def test_wordlist_head_is_conservative_upper_bound(max_requests, extensions, expected):
    """词表截断必须**不超过**授权请求量：head * (1+n_ext) <= max_requests。"""
    p = DirsearchParams(target=TARGET, rate_rps=50, concurrency=5,
                        max_requests=max_requests, extensions=extensions)
    head = dirsearch_wordlist_head(p)
    assert head == expected
    n_ext = len([e for e in extensions.split(",") if e])
    assert head * (1 + n_ext) <= max_requests or head == 1


# ------------------------------------------------------- 时间窗 / 沙箱超时


@pytest.mark.parametrize(
    "window_minutes, expected_timeout",
    [(None, 300), (1, 60), (2, 120), (5, 300), (6, 300), (1440, 300)],
)
def test_sandbox_timeout_never_exceeds_cap(window_minutes, expected_timeout):
    """沙箱超时 = min(300, 窗口秒数)：时间窗**只会收窄**，永不放宽。"""
    s = _scope(request_budget={"window_minutes": window_minutes}
               if window_minutes else {})
    assert dirsearch_timeout_for(s) == expected_timeout


# --------------------------------------------------------- 注册与 schema


def test_dirsearch_registered_in_constructor_registry():
    """M16-b 新增 dirsearch 构造器（本用例与 test_build 的清单锁定互为印证）。"""
    assert known_tools() == ["dirsearch", "httpx", "katana", "sqlmap"]


def test_dirsearch_params_schema_exposed_for_planner():
    from proofhound.tools.build import params_schema

    schema = params_schema("dirsearch")
    assert schema is not None
    assert "target" in schema["properties"]


# ------------------------------------------- scope 校验不吃掉词表/输出路径


def test_scope_sees_only_the_target_not_wordlist_or_output_paths():
    """`--wordlists <path>` 与 `-o <path>` 的值**不得**被当成扫描目标。

    实测过：它们是普通文件路径，`_parse_token` 不认（无 scheme、非 IP:port），
    故只会剩 `-u` 的单目标。本用例把"行为"钉住，防后续有人把路径写进
    scope 提取面。
    """
    s = _scope()
    argv = build_command("dirsearch", {"target": TARGET},
                         request_budget=s.resolved_request_budget())
    decision = check_scope(s, argv[1:], base_dir=".")
    assert decision.allowed, decision.violations
    assert [(t.host, t.port) for t in decision.targets] == [("127.0.0.1", 8080)]
    assert decision.file_targets == []
