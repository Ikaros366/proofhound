"""M33：JS 接口 → ``api-endpoint`` 信号 + triage 到 ``unauth-exposure``。

背景（实测 ``eng-20261103T070135Z-6c0988e8``）：目标是一个 SPA + JSON API，
128 个唯一 URL 一条漏洞候选都没产出——因为候选只认「URL 带 query 参数」和
「HTML 表单」两种形态，而真实面 ``/api/v1/*`` 两种都不是。

M33 把 M24-a 抽到却一直没消费的那部分接进生产候选：从 katana 抓回来的 JS 正文
里抽路径（复用 ``jsimport.extract``，不新增第二套正则），只产**像接口**的路径。
"""

import json

from proofhound.core.orchestrator import _triage_candidates
from proofhound.findings.signal import Signal
from proofhound.tools.parsers.katana_jsonl import parse_katana_jsonl


def _record(endpoint: str, body: str, *, status: int = 200) -> str:
    return json.dumps(
        {
            "request": {"method": "GET", "endpoint": endpoint},
            "response": {"status_code": status, "body": body},
        }
    )


def _parse(*records: str):
    return parse_katana_jsonl(
        "\n".join(records), evidence_path="/tmp/katana.log", skill="recon-crawl"
    )


#: 典型 SPA 客户端：baseURL 常量 + 若干调用点（含模板串与页面路由）
JS_BUNDLE = (
    'var c={baseURL:"/api/v1"};'
    'c.get("/info");'
    'c.get("/dashboard");'
    'c.get("/users/${id}");'
    'axios.get("/auth/login");'
    'route("/settings/providers/new");'
)


def test_js_bundle_yields_api_endpoint_via_base_url():
    """根路径字面量 + 显式 baseURL ⇒ 真实接口地址（``/api/v1/info``）。"""
    signals, skipped = _parse(_record("https://h/assets/app.js", JS_BUNDLE))

    assets = {s.asset for s in signals if s.kind == "api-endpoint"}
    assert "https://h/api/v1/info" in assets
    assert "https://h/api/v1/dashboard" in assets
    assert skipped == 0


def test_base_url_constant_is_not_an_endpoint():
    """``/api/v1`` 是基址常量本身，不是端点。"""
    signals, _ = _parse(_record("https://h/assets/app.js", JS_BUNDLE))
    assets = {s.asset for s in signals if s.kind == "api-endpoint"}
    assert "https://h/api/v1" not in assets


def test_path_template_is_not_emitted():
    """路径模板（``/users/{param}``）没有观测实例，不产候选。"""
    signals, _ = _parse(_record("https://h/assets/app.js", JS_BUNDLE))
    assert not [s for s in signals if "{param}" in s.asset]


def test_login_path_is_excluded_by_shared_word_list():
    """``login`` 在 jsimport 的公开端点词表里（与 M24-a 同一把尺子）。"""
    signals, _ = _parse(_record("https://h/assets/app.js", JS_BUNDLE))
    assert not [s for s in signals if "login" in s.asset]


def test_non_js_body_never_yields_api_endpoint():
    """只有 JS 正文才抽接口（HTML/JSON 不是接口清单来源）。"""
    signals, _ = _parse(_record("https://h/page", "<html>/api/v1/info</html>"))
    assert not [s for s in signals if s.kind == "api-endpoint"]


def test_query_keys_produce_param_endpoint():
    """JS 里写死的 query 参数另产 param-endpoint（接既有的 sqli/xss 提示表）。"""
    js = 'c.get("/api/v1/orders?status=1&id=2");'
    signals, _ = _parse(_record("https://h/assets/app.js", js))
    kinds = {(s.kind, s.asset) for s in signals}
    assert ("param-endpoint", "https://h/api/v1/orders?status=1&id=1") in kinds


def test_malformed_literal_does_not_kill_the_bundle():
    """畸形字面量（``http://[${host}]``）只丢该条，不作废整份 bundle（M33 实测缺陷）。"""
    js = 'var u="http://[${host}]/x"; c.get("/api/v1/info");'
    signals, _ = _parse(_record("https://h/assets/app.js", js))
    assert "https://h/api/v1/info" in {s.asset for s in signals}


# ---------------------------------------------------------------- triage 映射


def _signal(asset: str) -> Signal:
    return Signal(
        asset=asset,
        kind="api-endpoint",
        source_tool="katana",
        skill="recon-crawl",
        evidence_ref="/tmp/katana.log#L1",
    )


def test_api_endpoint_maps_to_unauth_exposure():
    candidates = _triage_candidates(_signal("https://h/api/v1/info"))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.vuln_type == "unauth-exposure"
    assert candidate.source == "api_endpoint"
    assert candidate.asset == "https://h/api/v1/info"


def test_api_endpoint_maps_even_without_session():
    """缺会话时**仍然**派生——让 ``verify_type_unavailable`` 把"给个 Cookie"写进审计，
    而不是静默不产候选（与 web-probe 分支的差别，M33 刻意选择）。"""
    candidates = _triage_candidates(_signal("https://h/api/v1/info"))
    assert [c.vuln_type for c in candidates] == ["unauth-exposure"]
