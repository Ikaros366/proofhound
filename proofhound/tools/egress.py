"""沙箱网络出口白名单（§5.2：网络出口限速+白名单；M2a 最小强制实现）。

Docker 原生网络能力无法按域名/IP 白名单限制容器出口。本模块采用可真正
强制的最小方案：

- 专用 Docker 网络 ``proofhound-egress``（``internal=True``）：无网关/NAT，
  容器无法直连任何外部地址，只能到达网桥网关（宿主机）；
- 宿主机进程内运行最小正向代理 ``EgressProxy``（HTTP absolute-URI 转发 +
  CONNECT 隧道，不解析 TLS），绑定到该网络的网关 IP；逐连接按白名单判定，
  白名单 = scope（域名/网段/端口，复用 :meth:`Scope.check_target`）+
  安装白名单源（``extra_allowed_hosts``，默认取安装器
  ``DEFAULT_ALLOWED_HOSTS``）；拒绝即 403 并记 ``egress_denied`` 审计。

已知限制：
- 非 HTTP 的原始 TCP 流量在 restricted 模式下被 internal 网络整体阻断
  （fail-closed）；完整协议覆盖待 §5.10 mitmproxy 代理链（M2 后续切片）。
- proxy 环境变量对不尊重它的工具不生效，但 internal 网络保证其直连同样
  失败，fail-closed 方向不变。
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope, Target
from proofhound.tools.installer import DEFAULT_ALLOWED_HOSTS

EGRESS_NETWORK_NAME = "proofhound-egress"

_BUF = 65536


class EgressPolicy(BaseModel):
    """沙箱出口策略：restricted（默认，白名单代理）/ open / none。"""

    mode: Literal["restricted", "open", "none"] = "restricted"
    extra_allowed_hosts: list[str] = Field(
        default_factory=lambda: list(DEFAULT_ALLOWED_HOSTS)
    )


def ensure_egress_network(client) -> str:
    """幂等创建 internal 出口网络，返回其网关 IP（代理绑定地址）。"""
    try:
        network = client.networks.get(EGRESS_NETWORK_NAME)
    except Exception:
        network = client.networks.create(
            EGRESS_NETWORK_NAME, driver="bridge", internal=True
        )
    network.reload()
    configs = (network.attrs.get("IPAM") or {}).get("Config") or []
    gateway = configs[0].get("Gateway") if configs else None
    if not gateway:
        raise RuntimeError(f"出口网络 {EGRESS_NETWORK_NAME} 无网关地址")
    return gateway


@dataclass
class _Connection:
    sock: socket.socket
    thread: threading.Thread


class EgressProxy:
    """绑定在出口网络网关上的最小白名单正向代理。

    线程模型：一个 accept 线程 + 每连接一个处理线程；``close()`` 幂等。
    """

    def __init__(self, scope: Scope, policy: EgressPolicy, audit: AuditLog):
        self.scope = scope
        self.policy = policy
        self.audit = audit
        self._server: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._connections: list[_Connection] = []
        self._lock = threading.Lock()
        self._closed = False

    # ---- 生命周期 ----

    def start(self, client) -> None:
        """确保出口网络存在并启动监听；重复调用为 no-op。"""
        if self._server is not None:
            return
        gateway = ensure_egress_network(client)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((gateway, 0))
        server.listen(64)
        server.settimeout(0.5)
        self._server = server
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    @property
    def proxy_url(self) -> str:
        if self._server is None:
            raise RuntimeError("EgressProxy 尚未启动")
        host, port = self._server.getsockname()[:2]
        return f"http://{host}:{port}"

    @property
    def allowed_hosts(self) -> list[str]:
        """审计用：白名单的人类可读摘要。"""
        return [
            *self.scope.domains,
            *self.scope.networks,
            *self.policy.extra_allowed_hosts,
        ]

    def close(self) -> None:
        self._closed = True
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2)
            self._accept_thread = None
        with self._lock:
            conns = list(self._connections)
            self._connections.clear()
        for conn in conns:
            try:
                conn.sock.close()
            except OSError:
                pass
            conn.thread.join(timeout=2)

    def __enter__(self) -> "EgressProxy":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- accept / 连接处理 ----

    def _accept_loop(self) -> None:
        while not self._closed:
            try:
                client_sock, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._handle, args=(client_sock,), daemon=True
            )
            with self._lock:
                self._connections.append(_Connection(client_sock, thread))
            thread.start()

    def _handle(self, client_sock: socket.socket) -> None:
        try:
            client_sock.settimeout(30)
            request = self._read_headers(client_sock)
            if request is None:
                return
            head, leftover = request
            lines = head.split("\r\n")
            method, uri, _version = (lines[0].split(" ", 2) + ["", "", ""])[:3]
            if method.upper() == "CONNECT":
                host, _, port_s = uri.partition(":")
                port = int(port_s) if port_s.isdigit() else 443
                self._handle_connect(client_sock, host, port)
            else:
                self._handle_plain(client_sock, method, uri, head, leftover)
        except (OSError, ValueError):
            pass
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

    @staticmethod
    def _read_headers(sock: socket.socket) -> tuple[str, bytes] | None:
        """读到头部结束（\\r\\n\\r\\n），返回 (头部文本, 多余的 body 字节)。"""
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(_BUF)
            if not chunk:
                return None
            data += chunk
            if len(data) > 1 << 20:  # 头部上限 1 MiB，防内存打满
                return None
        head, _, rest = data.partition(b"\r\n\r\n")
        return head.decode("latin-1"), rest

    # ---- CONNECT 隧道 ----

    def _handle_connect(self, client_sock: socket.socket, host: str, port: int) -> None:
        reason = self._check(host, port)
        if reason is not None:
            self._deny(client_sock, host, port, reason)
            return
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._tunnel(client_sock, upstream)

    # ---- 普通 HTTP（absolute-URI）----

    def _handle_plain(
        self,
        client_sock: socket.socket,
        method: str,
        uri: str,
        head: str,
        leftover: bytes,
    ) -> None:
        from urllib.parse import urlparse

        parsed = urlparse(uri)
        host = parsed.hostname or ""
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            port = 80
        reason = self._check(host, port)
        if reason is not None:
            self._deny(client_sock, host, port, reason)
            return
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        # 转为 origin-form 转发，剥掉 Proxy-* 头
        path = uri[len(parsed.scheme) + 3 + len(parsed.netloc):] or "/"
        lines = [line for line in head.split("\r\n")[1:] if not line.lower().startswith("proxy-")]
        upstream.sendall(
            f"{method} {path} HTTP/1.1\r\n".encode("latin-1")
            + "\r\n".join(lines).encode("latin-1")
            + b"\r\n\r\n"
            + leftover
        )
        self._tunnel(client_sock, upstream)

    # ---- 白名单判定与审计 ----

    def _check(self, host: str, port: int) -> str | None:
        """返回 None 表示放行，否则返回拒绝原因。"""
        if not host:
            return "目标为空"
        host_l = host.rstrip(".").lower()
        for extra in self.policy.extra_allowed_hosts:
            extra_l = extra.rstrip(".").lower()
            if host_l == extra_l or host_l.endswith("." + extra_l):
                return None
        try:
            ipaddress.ip_address(host_l)
            is_ip = True
        except ValueError:
            is_ip = False
        target = Target(host=host_l, port=port, is_ip=is_ip)
        return self.scope.check_target(target)

    def _deny(
        self, client_sock: socket.socket, host: str, port: int, reason: str
    ) -> None:
        self.audit.record(
            "egress_denied", host=host, port=port, reason=reason
        )
        body = f"egress denied: {reason}".encode("utf-8")
        client_sock.sendall(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
            + body
        )

    # ---- 双向转发 ----

    def _tunnel(self, client_sock: socket.socket, upstream: socket.socket) -> None:
        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(_BUF)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t = threading.Thread(target=pump, args=(upstream, client_sock), daemon=True)
        t.start()
        pump(client_sock, upstream)
        t.join(timeout=5)
        try:
            upstream.close()
        except OSError:
            pass
