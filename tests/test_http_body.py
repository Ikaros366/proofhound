"""M25-a：POST 传输层（``proofhound/verify/http_body.py``）的单元测试。

这份文件钉住四件事：

1. **body 原样到达**（字节，不是字符串）+ ``Content-Type`` 到位；
2. **会话注入**：Cookie / 额外请求头由代码拼进头部，且 ``content_type`` 覆盖
   会话里的同名头（操作员显式给的类型必须生效）；
3. **不跟随重定向**：3xx 原样作为状态码返回（跟随会把网关登录页读成"端点正常"）；
4. **失败可归因**：连接被拒 / 超时落 ``error``，不抛；正文超限截断并置
   ``truncated``；4xx/5xx 是响应不是错误。

全部用**本机罐头 HTTP 服务**，零真实外网。
"""

from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from proofhound.compliance.session import SessionConfig
from proofhound.verify import http_body


class CannedServer:
    """一个只收 POST 的罐头服务（记录请求，按 responder 回包）。"""

    def __init__(self, responder):
        self.requests: list[dict] = []
        self._responder = responder
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # noqa: D102 - 静默
                return

            def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler 约定
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                owner.requests.append(
                    {
                        "path": self.path,
                        "body": body,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                    }
                )
                status, headers, payload = owner._responder(self.path, body)
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        self._httpd.handle_error = lambda *args: None  # type: ignore[method-assign]
        self._httpd.owner = self  # type: ignore[attr-defined]
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        try:
            self._httpd.shutdown()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._httpd.server_close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self) -> "CannedServer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def reply(status: int = 200, body: bytes = b"ok", headers: dict | None = None):
    def responder(_path: str, _body: bytes):
        return status, headers or {}, body

    return responder


# =====================================================================
# 基本投递
# =====================================================================


def test_post_sends_bytes_and_content_type():
    with CannedServer(reply(200, b"<ok/>")) as server:
        response = http_body.post(server.url, b"<r>&x;</r>", timeout=5)
    assert response.status == 200
    assert response.body == b"<ok/>"
    assert response.ok and response.error is None
    assert len(server.requests) == 1
    sent = server.requests[0]
    assert sent["body"] == b"<r>&x;</r>"
    assert sent["headers"]["content-type"] == http_body.DEFAULT_CONTENT_TYPE


def test_post_accepts_str_body_as_utf8():
    with CannedServer(reply()) as server:
        http_body.post(server.url, "<r>中文</r>", timeout=5)
    assert server.requests[0]["body"] == "<r>中文</r>".encode("utf-8")


def test_post_injects_cookie_and_session_headers():
    session = SessionConfig(
        cookies={"phsess": "abc123xyz", "security": "low"},
        headers={"Authorization": "Bearer tok-123"},
    )
    with CannedServer(reply()) as server:
        http_body.post(server.url, b"<r/>", session=session, timeout=5)
    headers = server.requests[0]["headers"]
    assert headers["cookie"] == "phsess=abc123xyz; security=low"
    assert headers["authorization"] == "Bearer tok-123"


def test_content_type_flag_beats_session_header():
    session = SessionConfig(headers={"Content-Type": "text/plain"})
    with CannedServer(reply()) as server:
        http_body.post(
            server.url, b"<r/>", content_type="application/xml", session=session, timeout=5
        )
    assert server.requests[0]["headers"]["content-type"] == "application/xml"


def test_extra_headers_are_sent_last():
    with CannedServer(reply()) as server:
        http_body.post(
            server.url,
            b"<r/>",
            extra_headers={"X-Probe": "xxe", "Content-Type": "text/xml"},
            timeout=5,
        )
    assert server.requests[0]["headers"]["content-type"] == "application/xml"


def test_build_headers_without_session_only_sets_content_type():
    assert http_body.build_headers() == {"Content-Type": http_body.DEFAULT_CONTENT_TYPE}


# =====================================================================
# 不跟随重定向 / 错误状态
# =====================================================================


def test_post_does_not_follow_redirect():
    calls: list[str] = []

    def responder(path: str, _body: bytes):
        calls.append(path)
        if path == "/start":
            return 302, {"Location": "/login"}, b""
        return 200, {}, b"<html>login</html>"

    with CannedServer(responder) as server:
        response = http_body.post(server.url + "/start", b"<r/>", timeout=5)
    assert response.status == 302
    assert response.header("location") == "/login"
    assert calls == ["/start"]  # 一次请求，没有跟随
    assert len(server.requests) == 1


def test_post_treats_4xx_and_5xx_as_responses():
    with CannedServer(reply(500, b"<faultstring>boom</faultstring>")) as server:
        response = http_body.post(server.url, b"<r/>", timeout=5)
    assert response.status == 500
    assert response.body == b"<faultstring>boom</faultstring>"
    assert response.error is None
    assert response.ok


# =====================================================================
# 截断与失败归因
# =====================================================================


def test_post_truncates_large_response():
    with CannedServer(reply(200, b"A" * 5000)) as server:
        response = http_body.post(server.url, b"<r/>", max_bytes=1000, timeout=5)
    assert len(response.body) == 1000
    assert response.truncated is True


def test_post_does_not_mark_exact_limit_as_truncated():
    with CannedServer(reply(200, b"B" * 1000)) as server:
        response = http_body.post(server.url, b"<r/>", max_bytes=1000, timeout=5)
    assert len(response.body) == 1000
    assert response.truncated is False


def test_post_returns_error_on_connection_refused():
    # 占一个端口再释放：几乎必然无人监听
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    response = http_body.post(f"http://127.0.0.1:{port}/", b"<r/>", timeout=2)
    assert response.status is None
    assert response.error and not response.ok


def test_post_returns_error_on_timeout():
    def slow(_path: str, _body: bytes):
        time.sleep(1.0)
        return 200, {}, b"late"

    with CannedServer(slow) as server:
        response = http_body.post(server.url, b"<r/>", timeout=0.2)
    assert response.error is not None
    assert response.status is None


def test_post_rejects_non_positive_max_bytes():
    with pytest.raises(ValueError):
        http_body.post("http://127.0.0.1:1/", b"<r/>", max_bytes=0)


# =====================================================================
# 摘要不含正文
# =====================================================================


def test_response_summary_excludes_body():
    with CannedServer(reply(200, b"<secret>root:x:0:0</secret>")) as server:
        response = http_body.post(server.url, b"<r/>", timeout=5)
    summary = response.summary()
    rendered = json.dumps(summary)
    assert "root:x:0:0" not in rendered
    assert summary["status"] == 200
    assert summary["bytes"] == len(response.body)
    assert summary["sha256"] == hashlib.sha256(response.body).hexdigest()


def test_response_text_decodes_replacement():
    with CannedServer(reply(200, b"\xff\xfeok")) as server:
        response = http_body.post(server.url, b"<r/>", timeout=5)
    assert "\ufffd" in response.text
