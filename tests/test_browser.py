"""M8b 浏览器验证器单元测试（零真实浏览器）+ marker e2e（真实 Chromium）。

覆盖验收点：token 生成、payload 模板集（≤6、三类载体、token 内嵌）、
payload_url 构造（值替换/urlencode/缺参 fail-closed）、same_origin 归一化、
allow_request 双重防线（跨 origin abort、越 scope abort）、canary 事件判定
（token 匹配/他 token 不计/marker 信道）、FakePage/FakeRoute 全序（探针注入/
route 拦截/证据落盘脱敏）、超时 error 语义；真实 Chromium 端到端用
``browser`` marker（无浏览器环境自动 skip，仿 docker 套件先例）。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig, secret_marker
from proofhound.verify.browser import (
    PAYLOAD_TEMPLATES,
    BrowserProbeResult,
    BrowserVerifier,
    allow_request,
    canary_events,
    new_token,
    payload_url,
    same_origin,
)

SCOPE = Scope(networks=["127.0.0.0/8"], ports=[8080])
COOKIE_VALUE = "abc123def456789"  # 测试凭据：任何证据文件都不得出现该值
SESSION = SessionConfig(cookies={"PHPSESSID": COOKIE_VALUE, "security": "low"})


# ---- 纯函数：token / payload 集 / URL 构造 ----


def test_new_token_format_and_uniqueness():
    token = new_token()
    assert token.startswith("phxss_")
    suffix = token.removeprefix("phxss_")
    assert len(suffix) == 12
    int(suffix, 16)  # 纯 hex
    assert new_token() != token  # 每次尝试唯一


def test_payload_templates_fixed_set():
    assert len(PAYLOAD_TEMPLATES) <= 6
    token = new_token()
    rendered = [t.replace("{token}", token) for t in PAYLOAD_TEMPLATES]
    assert all(token in r for r in rendered)  # token 内嵌
    carriers = "".join(rendered)
    assert "<script>" in carriers  # script 标签载体
    assert "onerror" in carriers  # img onerror 载体
    assert "onload" in carriers  # svg onload 载体


def test_payload_url_replaces_value_urlencoded():
    url = payload_url(
        "http://127.0.0.1:8080/p?name=1&Submit=Submit", "NAME", "<script>alert(1)</script>"
    )
    assert url.startswith("http://127.0.0.1:8080/p?")
    assert "%3Cscript%3E" in url  # payload urlencode
    assert "name=%3Cscript%3E" in url  # 大小写不敏感命中并替换
    assert "Submit=Submit" in url  # 其余参数原样保留


def test_payload_url_missing_param_fail_closed():
    with pytest.raises(ValueError, match="不在 URL query"):
        payload_url("http://127.0.0.1:8080/p?id=1", "name", "x")


# ---- 纯函数：origin / scope 防线 ----


def test_same_origin_normalization():
    assert same_origin("http://127.0.0.1/x", "http://127.0.0.1:80/y")  # 默认端口抹平
    assert same_origin("https://a.b/c", "https://a.b:443/d")
    assert not same_origin("http://127.0.0.1:8080/x", "http://127.0.0.1:9090/y")
    assert not same_origin("http://a.b/x", "https://a.b/x")  # 跨 scheme
    assert not same_origin("http://a.b/x", "http://sub.a.b/x")  # 跨 host


def test_allow_request_double_defense():
    page = "http://127.0.0.1:8080/vulnerabilities/xss_r/?name=1"
    assert allow_request(page, page, SCOPE)  # 同源 + 在 scope
    assert not allow_request("http://127.0.0.1:9090/x", page, SCOPE)  # 跨 origin
    assert not allow_request("http://10.9.9.9:8080/x", page, SCOPE)  # 跨 origin 且越 scope
    # 同源但越 scope（scope 不含该网段）
    outside = "http://10.9.9.9:8080/x"
    assert not allow_request(outside, outside, SCOPE)


# ---- 纯函数：canary 事件判定 ----


def test_canary_events_token_match_only():
    token = "phxss_aabbccddeeff"
    raw = [
        {"type": "alert", "args": [f"hi {token}"], "ts": 1},
        {"type": "alert", "args": ["phxss_001122334455"], "ts": 2},  # 他 token
        {"type": "log", "args": ["nothing"], "ts": 3},
    ]
    matched = canary_events(raw, False, token, url="http://x/", payload="p")
    assert len(matched) == 1
    assert matched[0]["type"] == "alert"
    assert matched[0]["token"] == token
    assert matched[0]["url"] == "http://x/" and matched[0]["payload"] == "p"
    assert not canary_events([], False, token)
    assert not canary_events(None, False, token)


def test_canary_events_marker_channel():
    token = "phxss_aabbccddeeff"
    matched = canary_events([], True, token)
    assert [e["type"] for e in matched] == ["marker"]


# ---- FakePage/FakeRoute：probe 全序（零真实浏览器） ----


class FakeRequest:
    def __init__(self, url, method="GET", resource_type="document"):
        self.url = url
        self.method = method
        self.resource_type = resource_type


class FakeRoute:
    def __init__(self, url, **kwargs):
        self.request = FakeRequest(url, **kwargs)
        self.action = None

    def continue_(self):
        self.action = "continue"

    def abort(self):
        self.action = "abort"


class FakePage:
    """最小 page 假身：回放罐头路由、按 evaluate 表达式回罐头数据。"""

    def __init__(self, *, marker, events, dom, routes=(), goto_error=None):
        self.marker = marker
        self.events = events
        self.dom = dom
        self.routes = list(routes)
        self.goto_error = goto_error
        self.init_scripts: list[str] = []
        self.goto_calls: list[tuple] = []
        self.settle_ms: int | None = None

    def route(self, pattern, handler):
        assert pattern == "**/*"
        for route in self.routes:
            handler(route)

    def add_init_script(self, script):
        self.init_scripts.append(script)

    def on(self, event, handler):
        pass  # console/response 监听器注册即够（罐头不回放）

    def goto(self, url, timeout=None):
        self.goto_calls.append((url, timeout))
        if self.goto_error is not None:
            raise self.goto_error

    def wait_for_timeout(self, ms):
        self.settle_ms = ms

    def evaluate(self, expr, arg=None):
        if "window[k]" in expr:
            return "1" if self.marker else None
        return self.events

    def content(self):
        return self.dom


class FakeContext:
    def __init__(self, page):
        self._page = page
        self.cookies = None
        self.headers = None
        self.closed = False

    def add_cookies(self, cookies):
        self.cookies = cookies

    def set_extra_http_headers(self, headers):
        self.headers = headers

    def new_page(self):
        return self._page

    def close(self):
        self.closed = True


def _fake_verifier(tmp_path, page) -> tuple[BrowserVerifier, FakeContext]:
    context = FakeContext(page)
    verifier = BrowserVerifier(
        scope=SCOPE,
        evidence_dir=tmp_path,
        session=SESSION,
        context_factory=lambda: context,
    )
    return verifier, context


def test_probe_full_sequence_with_fakes(tmp_path):
    """探针注入/route 拦截/会话注入/证据落盘脱敏 全序断言。"""
    token = new_token()
    page_url = "http://127.0.0.1:8080/vulnerabilities/xss_r/?name=payload"
    cross = FakeRoute("http://127.0.0.2:9/tracker.png", resource_type="image")
    same = FakeRoute(page_url)
    page = FakePage(
        marker=True,
        events=[{"type": "alert", "args": [token], "ts": 1}],
        dom=f"<html>leak {COOKIE_VALUE}</html>",  # 模拟页面回显凭据
        routes=[cross, same],
    )
    verifier, context = _fake_verifier(tmp_path, page)

    result = verifier.probe(
        finding_id="F-2026-0001", seq=1, url=page_url, payload="p", token=token
    )

    assert result.error is None and result.canary is True
    assert {e["type"] for e in result.events} == {"alert", "marker"}  # 双信道
    # 探针注入（alert/confirm/prompt 钩子 + 事件数组）
    assert page.init_scripts and "__phxss_events" in page.init_scripts[0]
    # goto 以目标 URL 调用；驻留默认 500ms
    assert page.goto_calls == [(page_url, 15_000)]
    assert page.settle_ms == 500
    # route 拦截：跨 origin abort 入链；同源 continue
    assert cross.action == "abort" and same.action == "continue"
    # 会话注入：Cookie 按 origin 绑定
    assert context.cookies[0]["name"] == "PHPSESSID"
    assert context.cookies[0]["url"] == "http://127.0.0.1:8080"
    assert context.closed  # 每次 probe 后 context 关闭
    # 四份证据落盘且凭据已脱敏
    for path in (
        result.canary_path,
        result.dom_path,
        result.console_path,
        result.requests_path,
    ):
        assert path.is_file() and path.stat().st_size > 0
        assert COOKIE_VALUE.encode() not in path.read_bytes()
    dom_bytes = result.dom_path.read_bytes()
    assert secret_marker(COOKIE_VALUE).encode() in dom_bytes  # 脱敏标记替代
    canary_doc = json.loads(result.canary_path.read_text(encoding="utf-8"))
    assert canary_doc["canary"] is True and canary_doc["token"] == token
    requests = json.loads(result.requests_path.read_text(encoding="utf-8"))
    aborted = [r for r in requests if r["aborted"]]
    assert [r["url"] for r in aborted] == ["http://127.0.0.2:9/tracker.png"]


def test_probe_timeout_error_semantics(tmp_path):
    """导航超时：result.error 非空、不抛异常、canary=False、局部证据照落。"""
    page = FakePage(marker=False, events=[], dom="", goto_error=TimeoutError("timeout"))
    verifier, _context = _fake_verifier(tmp_path, page)
    result = verifier.probe(
        finding_id="F-2026-0002", seq=1,
        url="http://127.0.0.1:8080/p?name=x", payload="p", token=new_token(),
    )
    assert result.error is not None and "超时" in result.error
    assert result.canary is False
    assert result.canary_path.is_file()  # 错误尝试的证据同样落盘


def test_probe_navigation_scope_self_check_fail_closed(tmp_path):
    """导航目标越 scope：自检拦截（fail-closed），不创建 context 不加载。"""
    page = FakePage(marker=False, events=[], dom="")
    verifier, _context = _fake_verifier(tmp_path, page)
    result = verifier.probe(
        finding_id="F-2026-0003", seq=1,
        url="http://10.9.9.9:8080/p?name=x", payload="p", token=new_token(),
    )
    assert result.error is not None and "scope" in result.error
    assert page.goto_calls == []  # 未发生加载


# ---- 真实 Chromium e2e（browser marker；无浏览器环境自动 skip） ----


class _ReflectHandler(BaseHTTPRequestHandler):
    """把 ?name= 原样反射进 HTML 的本地服务（e2e 靶页）。"""

    def do_GET(self):
        name = parse_qs(urlparse(self.path).query).get("name", [""])[0]
        extra = ""
        if self.path.startswith("/with-img"):
            extra = '<img src="http://127.0.0.2:9/tracker.png">'
        body = f"<html><body>Hello {name}{extra}</body></html>"
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def reflect_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join(timeout=5)


@pytest.mark.browser
def test_e2e_chromium_canary_execution(chromium, reflect_server, tmp_path):
    """真实 Chromium：反射页 + script 载体 → canary 命中 + 四份证据落盘。"""
    scope = Scope(networks=["127.0.0.0/8"])
    verifier = BrowserVerifier(
        scope=scope, evidence_dir=tmp_path, context_factory=chromium.new_context
    )
    token = new_token()
    payload = PAYLOAD_TEMPLATES[1].replace("{token}", token)  # alert 载体
    url = payload_url(f"{reflect_server}/?name=1", "name", payload)

    result = verifier.probe(
        finding_id="F-2026-0009", seq=1, url=url, payload=payload, token=token
    )

    assert result.error is None
    assert result.canary is True
    assert any(e["type"] == "alert" and e["token"] == token for e in result.events)
    for path in (
        result.canary_path,
        result.dom_path,
        result.console_path,
        result.requests_path,
    ):
        assert path.is_file() and path.stat().st_size > 0


@pytest.mark.browser
def test_e2e_chromium_cross_origin_aborted(chromium, reflect_server, tmp_path):
    """真实 Chromium：页面引外源子资源 → route abort 阻断并记入请求链。"""
    scope = Scope(networks=["127.0.0.0/8"])  # 127.0.0.2 在 scope 内但跨 origin
    verifier = BrowserVerifier(
        scope=scope, evidence_dir=tmp_path, context_factory=chromium.new_context
    )
    token = new_token()
    url = f"{reflect_server}/with-img?name=hello"

    result = verifier.probe(
        finding_id="F-2026-0010", seq=1, url=url, payload="", token=token
    )

    assert result.error is None and result.canary is False
    requests = json.loads(result.requests_path.read_text(encoding="utf-8"))
    aborted = [r for r in requests if r["aborted"]]
    assert any("127.0.0.2:9" in r["url"] for r in aborted), requests
