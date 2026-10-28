"""M23：裸 TCP HTTP 发送器（``proofhound/verify/raw_http.py``）的单元测试。

## 这份文件钉住什么

1. **字节原样**：``…``（E2 80 A6）、``%zz``、``HTTP/9.9``、``G\\x01ET`` 必须
   **原封不动**到达服务器——这正是 urllib/httpx 做不到、而本类型必须自己发
   socket 的原因（交接单 §5：本任务 80% 的坑）。
2. **解析**：状态行宽容（无 reason）、重复头合并、按 Content-Length 读、
   无 CL 读到关闭、256KB 截断。
3. **错误可归因**：连接被拒 / 重置 / 超时 / 空响应 / 非 HTTP 垃圾各自有
   ``error_kind``——编排层要靠它把 blocked 归因到具体层，而不是笼统"失败了"。
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from proofhound.verify import raw_http

# ---------------------------------------------------------------------------
# 极简裸 socket 服务器（只收一次请求、按 responder 回字节）
# ---------------------------------------------------------------------------


class RawServer:
    def __init__(self, responder):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self.requests: list[bytes] = []
        self._responder = responder
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(2.0)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                self.requests.append(data)
                self._responder(conn, data)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def _reply(data: bytes):
    def responder(conn, _request):
        conn.sendall(data)

    return responder


def _reset_after_read(conn, _request):
    # SO_LINGER 0 → close 时发 RST；客户端应看到 reset（而不是干净的 EOF）
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    conn.close()


def _silent(conn, _request):
    time.sleep(1.0)


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture
def server():
    servers: list[RawServer] = []

    def _make(responder) -> RawServer:
        srv = RawServer(responder)
        servers.append(srv)
        return srv

    yield _make
    for srv in servers:
        srv.close()


# ---------------------------------------------------------------------------
# 一、字节原样（本模块存在的理由）
# ---------------------------------------------------------------------------


def test_send_raw_delivers_malformed_bytes_untouched(server):
    body = b"<html>400 Bad Request</html>"
    srv = server(
        _reply(
            b"HTTP/1.1 400 Bad Request\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
    )
    payload = (
        b"GET /\xe2\x80\xa6 HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Connection: close\r\n\r\n"
    )

    response = raw_http.send_raw("127.0.0.1", srv.port, payload, timeout=2.0)

    assert srv.requests and srv.requests[0] == payload, (
        "发送器改写了请求字节——畸形请求将永远到不了服务器"
    )
    assert response.status == 400
    assert response.reason == "Bad Request"
    assert response.body == body
    assert response.error is None


def test_control_char_and_bad_version_stay_raw(server):
    srv = server(_reply(b"HTTP/1.1 400 \r\nContent-Length: 0\r\n\r\n"))
    payload = b"G\x01ET / HTTP/9.9\r\nHost: h\r\n\r\n"

    raw_http.send_raw("127.0.0.1", srv.port, payload, timeout=2.0)

    assert srv.requests[0] == payload
    assert b"\x01" in srv.requests[0]


# ---------------------------------------------------------------------------
# 二、解析
# ---------------------------------------------------------------------------


def test_parse_head_tolerates_status_line_without_reason():
    status, reason, headers = raw_http.parse_head(
        b"HTTP/1.1 400\r\nContent-Length: 0"
    )
    assert status == 400
    assert reason == ""
    assert headers["content-length"] == "0"


def test_parse_head_merges_duplicate_headers():
    status, _reason, headers = raw_http.parse_head(
        b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2"
    )
    assert status == 200
    assert headers["set-cookie"] == "a=1, b=2"


def test_parse_head_rejects_non_http_status_line():
    status, _reason, _headers = raw_http.parse_head(b"NOT-HTTP/1.1\r\nX: y")
    assert status is None


def test_body_truncated_at_max_body(server):
    body = b"x" * 5000
    srv = server(
        _reply(
            b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
    )
    response = raw_http.send_raw("127.0.0.1", srv.port, b"GET / HTTP/1.1\r\n\r\n", timeout=2.0, max_body=1024)

    assert len(response.body) == 1024
    assert response.truncated is True


def test_missing_content_length_reads_until_close(server):
    srv = server(_reply(b"HTTP/1.1 400 Bad Request\r\n\r\nshort body"))
    response = raw_http.send_raw("127.0.0.1", srv.port, b"GET / HTTP/1.1\r\n\r\n", timeout=2.0)

    assert response.status == 400
    assert response.body == b"short body"


def test_header_cap_reports_protocol_error(server):
    # 超过 MAX_HEADER_BYTES 仍没有 \r\n\r\n
    srv = server(_reply(b"A" * (raw_http.MAX_HEADER_BYTES + 4096)))
    response = raw_http.send_raw("127.0.0.1", srv.port, b"GET / HTTP/1.1\r\n\r\n", timeout=2.0)

    assert response.error is not None
    assert response.error_kind == raw_http.ERROR_PROTOCOL


# ---------------------------------------------------------------------------
# 三、错误可归因
# ---------------------------------------------------------------------------


def test_connection_refused_is_connect_error():
    response = raw_http.send_raw(
        "127.0.0.1", _free_port(), b"GET / HTTP/1.1\r\n\r\n", timeout=1.0
    )
    assert response.error is not None
    assert response.error_kind == raw_http.ERROR_CONNECT
    assert response.status is None


def test_connection_reset_is_reset_error(server):
    srv = server(_reset_after_read)
    response = raw_http.send_raw(
        "127.0.0.1", srv.port, b"GET / HTTP/1.1\r\n\r\n", timeout=1.0
    )
    assert response.error is not None
    assert response.error_kind in (raw_http.ERROR_RESET, raw_http.ERROR_EMPTY)


def test_read_timeout_is_timeout_error(server):
    srv = server(_silent)
    response = raw_http.send_raw(
        "127.0.0.1", srv.port, b"GET / HTTP/1.1\r\n\r\n", timeout=0.3
    )
    assert response.error is not None
    assert response.error_kind == raw_http.ERROR_TIMEOUT


def test_empty_response_is_empty_error(server):
    srv = server(_reply(b""))
    response = raw_http.send_raw(
        "127.0.0.1", srv.port, b"GET / HTTP/1.1\r\n\r\n", timeout=2.0
    )
    assert response.error is not None
    assert response.error_kind == raw_http.ERROR_EMPTY


def test_garbage_is_protocol_error(server):
    srv = server(_reply(b"THIS IS NOT HTTP\r\n\r\n"))
    response = raw_http.send_raw(
        "127.0.0.1", srv.port, b"GET / HTTP/1.1\r\n\r\n", timeout=2.0
    )
    assert response.error is not None
    assert response.error_kind == raw_http.ERROR_PROTOCOL
