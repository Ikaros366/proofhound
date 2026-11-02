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
    """一个假上游：接受连接后随手写点东西。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def loop():
        try:
            while True:
                conn, _ = srv.accept()
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                conn.close()
        except OSError:
            return

    threading.Thread(target=loop, daemon=True).start()
    yield port
    srv.close()


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


def test_out_of_scope_port_still_denied(tmp_path, upstream):
    """放行解析不等于放宽白名单：端口不在 scope 里仍然 403。"""
    proxy = _start_proxy(tmp_path, upstream)
    other = upstream + 1
    try:
        reply = _send_connect(proxy, f"https://127.0.0.1:{other}/x")
    finally:
        proxy.close()
    assert b"403" in reply, reply
