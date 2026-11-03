"""M31-d：EgressProxy 必须容忍非标准 CONNECT（带 scheme / 路径）。

真实缺陷：dirsearch（httpx 客户端）走 restricted 出口代理时发的是

    CONNECT https://100.80.4.50:8443/login/<word> HTTP/1.1

而不是标准的 ``CONNECT host:port``。旧实现用 ``uri.partition(":")``，于是

* ``host`` 被解析成 ``"https"``；
* 端口回落 443；
* 白名单按 ``("https", 443)`` 判定 —— 越界 → 403；
* dirsearch 侧只看到 ``httpx.ProxyError: Cannot establish the proxy connection``。

本文件既钉住解析函数，也在 socket 层验证"该形态能被放行"（不依赖 Docker：
用假 docker client 让代理绑到 127.0.0.1）。
"""

from __future__ import annotations

import socket
import threading

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.tools.egress import EgressPolicy, EgressProxy


@pytest.mark.parametrize(
    "uri,expected",
    [
        ("100.80.4.50:8443", ("100.80.4.50", 8443)),
        # ↓ 实测抓到的原始请求行形态
        (
            "https://100.80.4.50:8443/login/exosecize_meganetary_neocorium",
            ("100.80.4.50", 8443),
        ),
        ("http://h.tld/path?q=1", ("h.tld", 80)),
        ("https://h.tld", ("h.tld", 443)),
        ("h.tld:8080/abc", ("h.tld", 8080)),
        # 旧实现会把这些解析成 host="https" / "/login/..."
        ("https://h.tld:8443/a/b/c", ("h.tld", 8443)),
        # ↓ M31-e 实测抓到的原始请求行形态：origin-form，**请求行里没有主机名**
        #   （httpx 的 TunnelHTTPConnection 把请求 target 覆盖进了 CONNECT 行），
        #   目标只在 Host 头里 ⇒ 解析结果必须是空 host，好让 caller 回落 Host。
        ("/login/cybercorance_dynalithance", ("", 443)),
        ("/", ("", 443)),
        ("", ("", 443)),
        ("?q=1", ("", 443)),
        # 空主机名 + 显式端口：端口仍应被读出来（回落 Host 时要按 HTTPS 缺省）
        (":8443", ("", 8443)),
        # IPv6 / userinfo
        ("[::1]:8443", ("::1", 8443)),
        ("[::1]", ("::1", 443)),
        ("2001:db8::1", ("2001:db8::1", 443)),
        ("http://user:pa%40ss@h.tld:81/x", ("h.tld", 81)),
    ],
)
def test_connect_target_parsing(uri, expected):
    assert EgressProxy._parse_connect_target(uri) == expected


class _FakeNetwork:
    attrs = {"IPAM": {"Config": [{"Gateway": "127.0.0.1"}]}}

    def reload(self):
        return None


class _FakeNetworks:
    def get(self, name):
        return _FakeNetwork()

    def create(self, name, **kwargs):  # pragma: no cover - get 已够用
        return _FakeNetwork()


class _FakeDocker:
    networks = _FakeNetworks()


@pytest.fixture
def upstream():
    """一个假上游：接受连接后随手写点东西。

    **收尾顺序是有讲究的（M31-e 实测的跨用例污染）**：`accept()` 用短超时 +
    停止标志，`yield` 之后先 `stop`、`join`，**最后**才 `srv.close()`。

    反面教材是旧写法（`yield port` 之后直接 `srv.close()`）：线程那时正阻塞在
    `accept()` 里，关闭监听并不会唤醒它。实测这个残留线程会去 `accept()` **后面
    用例**（`tests/test_installer.py` 的 `http_server`）的新连接，并用这里的固定
    应答 `200 + Content-Length: 0` 把人家答掉 —— installer 于是下载到 0 字节、
    sha256 变成空串的摘要（`e3b0c442…`），紧接着那个用例的 `server.shutdown()`
    永久挂死（`shutdown()` 会一直等一个已经不再 serve 的循环）。
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    srv.settimeout(0.2)  # 关键：不能无限期阻塞在 accept() 里
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    yield port
    stop.set()
    thread.join(timeout=5)  # 先让线程退出
    srv.close()  # 再关监听


def _start_proxy(tmp_path, port: int) -> EgressProxy:
    scope = Scope(networks=["127.0.0.1/32"], ports=[port])
    proxy = EgressProxy(scope, EgressPolicy(), AuditLog(tmp_path / "audit.jsonl"))
    proxy.start(_FakeDocker())
    return proxy


def _send_connect(proxy: EgressProxy, uri: str) -> bytes:
    url = proxy.proxy_url
    host, port = url.removeprefix("http://").split(":")
    sock = socket.create_connection((host, int(port)), timeout=5)
    try:
        sock.sendall(f"CONNECT {uri} HTTP/1.1\r\nHost: {uri}\r\n\r\n".encode())
        return sock.recv(256)
    finally:
        sock.close()


def test_nonstandard_connect_with_scheme_and_path_is_allowed(tmp_path, upstream):
    """回归：带 scheme+路径的 CONNECT 必须被放行（旧实现解析成 host="https" ⇒ 403）。"""
    proxy = _start_proxy(tmp_path, upstream)
    try:
        reply = _send_connect(proxy, f"https://127.0.0.1:{upstream}/login/word")
    finally:
        proxy.close()
    assert b"200" in reply, reply


def _send_raw(proxy: EgressProxy, request: str) -> bytes:
    """发一条**原始**请求（自己拼请求行与头部），返回响应前 256 字节。"""
    url = proxy.proxy_url
    host, port = url.removeprefix("http://").split(":")
    sock = socket.create_connection((host, int(port)), timeout=5)
    try:
        sock.sendall(request.encode("latin-1"))
        return sock.recv(256)
    finally:
        sock.close()


def _audit_denied(tmp_path) -> list[dict]:
    """取 ``egress_denied`` 事件；一次拒绝都没有时审计文件根本不会创建。"""
    import json

    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [
        row
        for row in (json.loads(line) for line in path.read_text(
            encoding="utf-8").splitlines() if line.strip())
        if row["event"] == "egress_denied"
    ]


def test_origin_form_connect_is_allowed_via_host_header(tmp_path, upstream):
    """M31-e 主回归：``CONNECT /login/<word>``（请求行无主机名）+ 正确的 ``Host:``
    头 ⇒ 必须放行。此前一律被判 ``目标为空`` ⇒ 403 ⇒ dirsearch 打
    ``Cannot establish the proxy connection`` 后**以 exit 0 退出**（假成功）。
    """
    proxy = _start_proxy(tmp_path, upstream)
    try:
        reply = _send_raw(
            proxy,
            "CONNECT /login/someword HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{upstream}\r\n"
            "Accept: */*\r\n"
            "\r\n",
        )
    finally:
        proxy.close()
    assert b"200" in reply, reply
    assert _audit_denied(tmp_path) == []


def test_origin_form_connect_without_host_header_is_denied(tmp_path, upstream):
    """没有 Host 头就没有目标 —— 仍然拒绝，绝不瞎猜。"""
    proxy = _start_proxy(tmp_path, upstream)
    try:
        reply = _send_raw(proxy, "CONNECT /login/someword HTTP/1.1\r\n\r\n")
    finally:
        proxy.close()
    assert b"403" in reply, reply
    denied = _audit_denied(tmp_path)
    assert denied[0]["reason"] == "目标为空"
    # 取证：请求行原文进审计（下次出现新形态不必改代码等了）
    assert denied[0]["request_line"] == "CONNECT /login/someword HTTP/1.1"


def test_host_header_fallback_still_goes_through_whitelist(tmp_path, upstream):
    """回落 Host 头**不等于**放宽白名单：Host 越界照样 403。"""
    proxy = _start_proxy(tmp_path, upstream)
    other = upstream + 1
    try:
        reply = _send_raw(
            proxy,
            "CONNECT /login/someword HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{other}\r\n"
            "\r\n",
        )
    finally:
        proxy.close()
    assert b"403" in reply, reply
    denied = _audit_denied(tmp_path)
    assert (denied[0]["host"], denied[0]["port"]) == ("127.0.0.1", other)


def test_origin_form_plain_request_is_allowed_via_host_header(tmp_path, upstream):
    """普通请求的 origin-form（``GET /path``）同样靠 Host 头定位；转发路径原样。"""
    proxy = _start_proxy(tmp_path, upstream)
    try:
        reply = _send_raw(
            proxy,
            "GET /a/b HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{upstream}\r\n"
            "\r\n",
        )
    finally:
        proxy.close()
    assert b"200" in reply, reply
    assert _audit_denied(tmp_path) == []


def test_out_of_scope_port_still_denied(tmp_path, upstream):
    """放行解析不等于放宽白名单：端口不在 scope 里仍然 403。"""
    proxy = _start_proxy(tmp_path, upstream)
    other = upstream + 1
    try:
        reply = _send_connect(proxy, f"https://127.0.0.1:{other}/x")
    finally:
        proxy.close()
    assert b"403" in reply, reply
