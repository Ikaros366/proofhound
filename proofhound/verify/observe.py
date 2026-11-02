"""不安全反序列化的**观察点**（M26-a）：自建 TCP + DNSLog provider 抽象。

## 这个模块存在的理由

反序列化（CWE-502）唯一能当"二值事实"的东西是：**目标真的去解析了我们给的主机名**——
DNS 查询或 TCP 连接到达我们的观察点。这与 SSRF/cmdi/XXE 的回调通道同构，但**观测介质
有两类**，且各自的归因强度不同：

| 介质 | 我们能证明的 | 归因 |
|---|---|---|
| TCP（自建） | 连接到达 + **源 IP 就是目标** | 强 |
| DNSLog（第三方） | 唯一 token 出现在记录里 | 中（源 IP 是**递归解析器**） |

故本模块只做三件事：**收连接 / 收记录 / 返回统一 :class:`Observation`**。判定（
三态与对照）在 ``verify/fastjson.py``，本模块**不含任何判定**，也**不含任何投递**。

## 只观察、不投递（结构性约束，不靠调用方自觉）

:class:`TcpObserver` **没有**"发送任意字节"的 API：回包只有一个构造期固定的常量
（缺省 ``b""`` = 直接关闭）。因此它**结构上不可能**返回类字节、``javaCodebase``、
``javaFactory`` 或 LDAP referral——那不是"调用方小心一点"，而是"没有这条路"。

## TCP 归因：端口为主、token 为辅（M26-a 裁定 C3-P1）

交接单附录 B 假设"token 在首包里是 ASCII 明文，正则抽即可"。实测语义下这条对两个主力
gadget 都**不成立**：

- ``JdbcRowSetImpl`` 的 JNDI/LDAP：URL 路径是"要查的名字"，JNDI 通常先发**匿名 simple
  bind**（DN 为空），要等**服务端回 BindResponse 之后**才发带 base DN 的 SearchRequest
  ——即 token 在第二个客户端包里，而观察点按设计**不回应**；
- ``BasicDataSource`` 的 JDBC/MySQL：协议是**服务端先说话**，客户端在收到 greeting 前
  一个字节都不发。

所以本模块的归因主判据是 **probe-scoped 临时端口**：:meth:`TcpObserver.allocate` 为每个
探针独占一个监听端口，连接到达该端口 + 源 IP + 时间窗就是该探针的事实；能读到 token 时
另记 :attr:`Observation.detail` 里的 ``attribution="token"`` 作为**佐证**。端口是随机的、
生命周期只有一次探测，故"别人的流量恰好连上它"在实践上不可能——这一点写进限制说明。

## DNSLog provider

:class:`DnsLogProvider` 是一个 **Protocol**：``allocate(token)`` 给出要嵌进 payload 的
qname，``poll(token)`` 返回该窗口内的记录。四个实现：

- :class:`DnslogCnProvider`（无账号，取域名 + 轮询记录）；
- :class:`CeyeProvider`（token 子域 + 事件 API）；
- :class:`InteractshProvider`（**未实现**：注册与事件需要 RSA/AES，本里程碑不新增第三方
  依赖，故显式 ``available() == False``，绝不以"没记录"冒充）；
- :class:`LocalStubProvider`（本机 HTTP，模仿 ``getdomain``/``getrecords``，**只给 demo
  与单测**，零外网）。

**未配置 / 启动失败 / 响应非法一律 :class:`ObserverError`**，由调用方记
``observer_unavailable`` ⇒ 该通道零覆盖。**绝不允许**把"provider 没配好"读成"目标没漏洞"。

## token

``phfj_<32hex>`` 是内部形态；**DNS label 不能用下划线**，故主机名形态是 ``phfj<32hex>``
（:func:`host_label`）。两种形态都归一到同一 :func:`canonical_token`，比较**全等**——
provider 记录里常混别人的查询，``startswith`` 会把别人的记录算成自己的。
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import json
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol

from proofhound.compliance.session import secret_marker

#: 内部 token 前缀（LDAP 路径里可用下划线形态）。
TOKEN_PREFIX = "phfj_"

#: 主机名形态前缀（DNS label 只许小写字母数字）。
HOST_PREFIX = "phfj"

#: token 随机部分的十六进制长度（128 位）。
TOKEN_HEX_LEN = 32

#: 从原始字节里抽 token：LDAP bind DN / 搜索 base / 任意协议里的 ASCII 片段都适用。
#: 注意前缀的**可选下划线**——同一 token 的两种形态都要能认出来。
_TOKEN_IN_BYTES = re.compile(rb"phfj_?([0-9a-f]{32})")

#: 从字符串里抽 token（provider 记录的主机名 / 裸 32 位 hex）。
_TOKEN_IN_TEXT = re.compile(r"(?i)phfj_?([0-9a-f]{32})")

#: 裸 32 位 hex（调用方可能只拿到随机部分）。
_BARE_HEX = re.compile(r"(?i)^[0-9a-f]{32}$")

#: 读首包的缺省超时（秒）——LDAP bind 是客户端先说话，1.5s 足够。
DEFAULT_READ_TIMEOUT = 1.5

#: 首包最多读多少字节（防"大包打满内存"；§5.2 的 8KB）。
MAX_FIRST_BYTES = 8 * 1024

#: 拿到首包后再给多久等**后续分段**（LDAP 的 bind / search 可能是两个 TCP 段）。
TAIL_GRACE_SECONDS = 0.15

#: 缺省 provider 轮询间隔（秒）。
DNS_POLL_INTERVAL = 1.0

#: 环境变量：DNSLog provider 名（缺省未设 = DNS 通道关闭，opt-in）。
ENV_DNS_PROVIDER = "PROOFHOUND_DNSLOG_PROVIDER"

#: 环境变量：provider 的基域名（ceye 的账号子域 / stub 的域名）。
ENV_DNS_DOMAIN = "PROOFHOUND_DNSLOG_DOMAIN"

#: 环境变量：provider 的 API token（ceye 需要）。
ENV_DNS_TOKEN = "PROOFHOUND_DNSLOG_TOKEN"

#: 环境变量：provider 的 API 基地址（自建 / 测试用）。
ENV_DNS_API = "PROOFHOUND_DNSLOG_API"

#: 支持的 provider 名（含别名）。``interactsh`` 在列但显式未实现（见模块 docstring）。
KNOWN_PROVIDERS = ("dnslog.cn", "ceye", "interactsh", "stub")

#: 轮询记录里"主机名"可能出现的键（各家 API 用词不同）。
_HOST_KEYS = ("domain", "name", "host", "qname", "query_name")

#: 轮询记录里"来源 IP"可能出现的键。
_SOURCE_KEYS = ("ip", "remote_addr", "remote_address", "client_ip", "source")

#: 轮询记录里"时间"可能出现的键。
_TIME_KEYS = ("time", "created_at", "timestamp", "created")


class ObserverError(RuntimeError):
    """观察点不可用（配置缺失/启动失败/provider 响应非法）—— 零覆盖，不是"没命中"。"""


# =====================================================================
# token
# =====================================================================


def new_token() -> str:
    """一条探针的唯一 token（128 位随机，不可猜）。"""
    return TOKEN_PREFIX + secrets.token_hex(16)


def canonical_token(value: str | None) -> str | None:
    """把任意形态（``phfj_<hex>`` / ``phfj<hex>`` / 裸 ``<hex>``）归一；非法返回 None。"""
    if not value:
        return None
    text = str(value).strip()
    if _BARE_HEX.match(text):
        return TOKEN_PREFIX + text.lower()
    match = _TOKEN_IN_TEXT.search(text)
    if match is None:
        return None
    return TOKEN_PREFIX + match.group(1).lower()


def host_label(token: str) -> str:
    """主机名形态：``phfj<32hex>``（**下划线不能出现在 DNS label 里**）。

    这不是洁癖：带下划线的名字会被一部分解析器直接判非法，静默得像"没漏洞"。
    """
    canonical = canonical_token(token)
    if canonical is None:
        raise ObserverError(f"不是合法的观察 token：{value_repr(token)}")
    return HOST_PREFIX + canonical[len(TOKEN_PREFIX) :]


def value_repr(value: object) -> str:
    """安全的 repr（只留前 24 字符，避免把整段垃圾打进日志）。"""
    text = repr(value)
    return text if len(text) <= 24 else text[:21] + "..."


def tokens_equal(left: str | None, right: str | None) -> bool:
    """**全等比较**（归一后逐个字符比，不 startswith）。"""
    a, b = canonical_token(left), canonical_token(right)
    return a is not None and a == b


def token_sha8(token: str | None) -> str:
    """脱敏标记：token 在证据里**只以** ``sha256:<hex8>`` 形态出现。"""
    if not token:
        return ""
    canonical = canonical_token(token) or str(token)
    return secret_marker(canonical)


def extract_token(data: bytes) -> str | None:
    """从原始字节里抽第一个 token（ASCII 明文，不需要 BER/协议解析）。"""
    if not data:
        return None
    match = _TOKEN_IN_BYTES.search(data)
    return None if match is None else TOKEN_PREFIX + match.group(1).decode("ascii")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# =====================================================================
# 统一观察记录
# =====================================================================


@dataclass(frozen=True)
class Observation:
    """一次观察（DNS 记录或 TCP 连接）。

    ``token`` 是**归因 token**：DNS 通道为 qname 里的那一个；TCP 通道为
    "读到且与端口归属一致"的那一个；端口归因（读不到 token）时为 None。
    ``detail`` 只放取证字段，**不放 token 原文**（会落进证据文件）。
    """

    channel: str
    token: str | None
    source: str
    at: str
    port: int | None = None
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """证据形态：token 只留 sha256 前 8 位。

        注意 ``token_attributed`` 只表示"包里读到了 token 并全等"；**端口归因**的
        观察（读不到 token）在这里是 False，但它依然是一次有效观测——调用方用
        "有没有归属到探针"来表达那件事。
        """
        return {
            "channel": self.channel,
            "token_sha8": token_sha8(self.token),
            "token_attributed": bool(self.token),
            "source": self.source,
            "at": self.at,
            "port": self.port,
            "detail": dict(self.detail),
        }


def _excerpt(data: bytes, *, limit: int = 96) -> str:
    """首包摘录：只留可打印 ASCII，并把 token 原文替换成脱敏标记。"""
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data[: limit * 2])
    text = text[:limit]
    token = extract_token(data)
    if token:
        text = text.replace(token, token_sha8(token)).replace(
            token.replace("_", ""), token_sha8(token)
        )
    return text


# =====================================================================
# TCP 观察点
# =====================================================================


@dataclass(frozen=True)
class TcpProbe:
    """一次 TCP 探针的观察权：**独占端口** + token + 协议语义。"""

    token: str
    kind: str
    port: int

    @property
    def channel(self) -> str:
        return f"tcp-{self.kind}"


class _TcpListener:
    """一个 probe-scoped 监听端口（accept → 读首包 → 记录 → 关闭）。"""

    def __init__(self, owner: "TcpObserver", sock: socket.socket, probe: TcpProbe):
        self._owner = owner
        self._sock = sock
        self._probe = probe
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._serve, name=f"ph-tcp-{probe.kind}-{probe.port}", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:  # pragma: no cover - 关闭失败不影响收尾
            pass
        self._thread.join(timeout=1.0)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._handle(conn, addr)
            finally:
                try:
                    conn.close()
                except OSError:  # pragma: no cover
                    pass

    def _handle(self, conn: socket.socket, addr) -> None:
        data = _read_first_bytes(
            conn,
            timeout=self._owner.read_timeout,
            max_bytes=self._owner.max_bytes,
        )
        source = str(addr[0]) if addr else ""
        extracted = extract_token(data)
        if extracted is not None and tokens_equal(extracted, self._probe.token):
            attribution = "token"
            token: str | None = self._probe.token
        elif extracted is not None:
            # 端口是我们的，但包里的 token 是别人的 ⇒ 不计命中（记录留证）。
            attribution = "mismatch"
            token = None
        else:
            attribution = "port"
            token = None
        detail: dict = {
            "protocol": self._probe.kind,
            "attribution": attribution,
            "bytes": len(data),
            "first_bytes_sha256": hashlib.sha256(data).hexdigest(),
            "excerpt": _excerpt(data),
        }
        if extracted is not None and attribution == "mismatch":
            detail["extracted_token_sha8"] = token_sha8(extracted)
        self._owner._append(
            Observation(
                channel=self._probe.channel,
                token=token,
                source=source,
                at=_now(),
                port=self._probe.port,
                detail=detail,
            )
        )
        # 只观察、不投递：回包是构造期写死的常量（缺省 b"" ⇒ 直接关闭）。
        try:
            if self._owner.refusal:
                conn.sendall(self._owner.refusal)
        except OSError:  # pragma: no cover - 对端先关
            pass


def _read_first_bytes(conn: socket.socket, *, timeout: float, max_bytes: int) -> bytes:
    """读首包（至多 ``max_bytes``），首包后再给一小段宽限等后续分段。"""
    deadline = time.monotonic() + max(0.05, float(timeout))
    chunks: list[bytes] = []
    total = 0
    while total < max_bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            conn.settimeout(remaining)
            chunk = conn.recv(min(4096, max_bytes - total))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        # 首包已到手：只再给 0.15s（bind + search 可能是两个 TCP 段）。
        deadline = min(deadline, time.monotonic() + TAIL_GRACE_SECONDS)
    return b"".join(chunks)


class TcpObserver:
    """probe-scoped TCP 观察点集合（每个探针独占一个临时端口）。

    用法::

        observer = TcpObserver(host="127.0.0.1").start()
        probe = observer.allocate(token, kind="ldap")   # 拿端口，再构造 payload
        ...                                             # 记住：不要在本类之外等连接
        records = observer.records()
        observer.stop()

    ``base_port`` 非 0 时依次尝试 ``base_port + i``（远程靶需要可预期的端口区间）；
    默认 0 = 由 OS 分配。端口全被占 ⇒ :class:`ObserverError`（结构性失败）。
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        *,
        base_port: int = 0,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        max_bytes: int = MAX_FIRST_BYTES,
        refusal: bytes = b"",
    ):
        if max_bytes <= 0:
            raise ObserverError("max_bytes 必须是正数")
        self.host = host
        self.base_port = int(base_port)
        self.read_timeout = float(read_timeout)
        self.max_bytes = int(max_bytes)
        self.refusal = bytes(refusal)
        self._listeners: list[_TcpListener] = []
        self._records: list[Observation] = []
        self._lock = threading.Lock()
        self._started = False

    # ---------------------------------------------------------- 生命周期

    def start(self) -> "TcpObserver":
        """幂等启动（真正的监听在 :meth:`allocate` 时绑定）。"""
        self._started = True
        return self

    def stop(self) -> None:
        for listener in list(self._listeners):
            listener.stop()
        self._listeners.clear()
        self._started = False

    #: ``stop`` 的别名（与 ``CallbackListener.close`` 的既有写法对齐）。
    close = stop

    def __enter__(self) -> "TcpObserver":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ---------------------------------------------------------- 分配端口

    def allocate(self, token: str, *, kind: str = "ldap") -> TcpProbe:
        """为 ``token`` 独占一个监听端口（``kind`` ∈ ``ldap``/``jdbc``）。"""
        canonical = canonical_token(token)
        if canonical is None:
            raise ObserverError(f"不是合法的观察 token：{value_repr(token)}")
        if kind not in ("ldap", "jdbc"):
            raise ObserverError(f"未知的 TCP 观察语义：{kind!r}")
        sock, port = self._bind()
        probe = TcpProbe(token=canonical, kind=kind, port=port)
        listener = _TcpListener(self, sock, probe)
        listener.start()
        self._listeners.append(listener)
        return probe

    def _bind(self) -> tuple[socket.socket, int]:
        attempts = [0] if self.base_port == 0 else list(range(8))
        last_error: OSError | None = None
        for offset in attempts:
            port = 0 if self.base_port == 0 else self.base_port + offset
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, port))
                sock.listen(8)
                sock.settimeout(0.2)
            except OSError as exc:
                last_error = exc
                try:
                    sock.close()
                except OSError:  # pragma: no cover
                    pass
                continue
            return sock, int(sock.getsockname()[1])
        raise ObserverError(f"TCP 观察点绑不上 {self.host}:{self.base_port}：{last_error}")

    # ---------------------------------------------------------- 记录

    def _append(self, observation: Observation) -> None:
        with self._lock:
            self._records.append(observation)

    def records(self) -> tuple[Observation, ...]:
        """到目前为止的全部连接记录（只读快照）。"""
        with self._lock:
            return tuple(self._records)

    @property
    def ports(self) -> dict[str, int]:
        """token → 端口（取证用；**不写进 summary.json**——端口随运行变化）。"""
        return {item._probe.token: item._probe.port for item in self._listeners}


def wait_for_tcp(observer: TcpObserver, seconds: float, *, interval: float = 0.05) -> None:
    """静置等待 ``seconds``（TCP 连接由请求同步触发，固定宽限即可）。"""
    deadline = time.monotonic() + max(0.0, float(seconds))
    while time.monotonic() < deadline:
        time.sleep(min(interval, max(0.0, deadline - time.monotonic())))


# =====================================================================
# DNSLog provider
# =====================================================================


@dataclass(frozen=True)
class DnsAllocation:
    """一次 DNS 探针的分配结果（``qname`` 是**要嵌进 payload** 的完整主机名）。"""

    provider: str
    domain: str
    token: str
    qname: str

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "domain": self.domain,
            "token_sha8": token_sha8(self.token),
            "qname_sha8": hashlib.sha256(self.qname.encode("utf-8")).hexdigest()[:8],
        }


class DnsLogProvider(Protocol):
    """DNSLog provider 的结构（``typing.Protocol``，四个实现互不继承）。"""

    name: str

    def allocate(self, token: str) -> "DnsAllocation":
        ...

    def poll(self, token: str) -> list["Observation"]:
        ...

    def close(self) -> None:
        ...


def _http_get(url: str, *, timeout: float, opener=None) -> bytes:
    """取一个 URL（provider API），任何失败都转 :class:`ObserverError`。"""
    http_opener = opener or urllib.request.build_opener()
    try:
        with http_opener.open(url, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ObserverError(f"provider 请求失败：{exc}") from None


def _as_records(payload: bytes) -> list[dict]:
    """把 provider 的响应体解析成记录列表（宽容外层容器，但**不宽容非法 JSON**）。"""
    try:
        data = json.loads(payload.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ObserverError(f"provider 响应不是合法 JSON：{exc}") from None
    if isinstance(data, dict):
        for key in ("data", "records", "result", "results"):
            value = data.get(key)
            if isinstance(value, list):
                data = value
                break
        else:
            raise ObserverError("provider 响应里没有记录列表")
    if not isinstance(data, list):
        raise ObserverError("provider 响应不是记录列表")
    return [item for item in data if isinstance(item, dict)]


def _first(record: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _normalise_host(value: str) -> str:
    """主机名归一：去尾点、小写（**全等比较**，绝不 startswith）。"""
    return value.strip().rstrip(".").lower()


def _observation_from_record(
    record: dict,
    *,
    provider: str,
    token: str,
    qname: str,
    channel: str = "dns",
) -> Observation:
    """记录 → Observation；主机名与 qname **全等**才归因到该 token。"""
    raw_host = _first(record, _HOST_KEYS)
    matched = bool(raw_host) and _normalise_host(raw_host) == _normalise_host(qname)
    detail = {
        "provider": provider,
        "qname_sha8": hashlib.sha256(qname.encode("utf-8")).hexdigest()[:8],
    }
    if raw_host and not matched:
        detail["other_host_sha8"] = hashlib.sha256(
            raw_host.encode("utf-8")
        ).hexdigest()[:8]
    return Observation(
        channel=channel,
        token=token if matched else None,
        source=_first(record, _SOURCE_KEYS),
        at=_first(record, _TIME_KEYS) or _now(),
        port=None,
        detail=detail,
    )


class DnslogCnProvider:
    """dnslog.cn：``getdomain.php`` 取域名（会话 Cookie）+ ``getrecords.php`` 轮询。"""

    name = "dnslog.cn"

    def __init__(self, *, base_url: str = "http://www.dnslog.cn", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        # 取域名与轮询**必须同一会话**：dnslog.cn 的域名绑在会话 Cookie 上。
        self._cookies = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cookies)
        )
        self._domains: dict[str, DnsAllocation] = {}

    def allocate(self, token: str) -> DnsAllocation:
        canonical = canonical_token(token)
        if canonical is None:
            raise ObserverError(f"不是合法的观察 token：{value_repr(token)}")
        if canonical in self._domains:
            return self._domains[canonical]
        payload = _http_get(
            f"{self.base_url}/getdomain.php", timeout=self.timeout, opener=self._opener
        )
        domain = payload.decode("utf-8", "replace").strip()
        if not domain or any(ch.isspace() for ch in domain) or "/" in domain:
            raise ObserverError(f"dnslog.cn 返回的域名非法：{value_repr(domain)}")
        qname = f"{host_label(canonical)}.{domain}"
        allocation = DnsAllocation(
            provider=self.name, domain=domain, token=canonical, qname=qname
        )
        self._domains[canonical] = allocation
        return allocation

    def poll(self, token: str) -> list[Observation]:
        canonical = canonical_token(token)
        allocation = self._domains.get(canonical or "")
        if allocation is None:
            raise ObserverError("poll 之前必须先 allocate")
        payload = _http_get(
            f"{self.base_url}/getrecords.php", timeout=self.timeout, opener=self._opener
        )
        return [
            _observation_from_record(
                record,
                provider=self.name,
                token=allocation.token,
                qname=allocation.qname,
            )
            for record in _as_records(payload)
        ]

    def close(self) -> None:  # pragma: no cover - 无连接池
        return None


class CeyeProvider:
    """ceye.io：``<label>.<账号 token>.ceye.io`` + 事件 API（需注册 token）。"""

    name = "ceye"

    def __init__(
        self,
        *,
        domain: str,
        token: str,
        api_base: str = "http://api.ceye.io",
        timeout: float = 10.0,
    ):
        if not domain.strip():
            raise ObserverError(f"{ENV_DNS_DOMAIN} 为空——ceye 需要账号子域")
        if not token.strip():
            raise ObserverError(f"{ENV_DNS_TOKEN} 为空——ceye 需要 API token")
        self.domain = domain.strip()
        self.token = token.strip()
        self.api_base = api_base.rstrip("/")
        self.timeout = float(timeout)
        self._allocations: dict[str, DnsAllocation] = {}

    def allocate(self, token: str) -> DnsAllocation:
        canonical = canonical_token(token)
        if canonical is None:
            raise ObserverError(f"不是合法的观察 token：{value_repr(token)}")
        qname = f"{host_label(canonical)}.{self.domain}"
        allocation = DnsAllocation(
            provider=self.name, domain=self.domain, token=canonical, qname=qname
        )
        self._allocations[canonical] = allocation
        return allocation

    def poll(self, token: str) -> list[Observation]:
        canonical = canonical_token(token)
        allocation = self._allocations.get(canonical or "")
        if allocation is None:
            raise ObserverError("poll 之前必须先 allocate")
        query = urllib.parse.urlencode(
            {"token": self.token, "type": "dns", "filter": host_label(canonical)}
        )
        payload = _http_get(f"{self.api_base}/api/v1/events?{query}", timeout=self.timeout)
        return [
            _observation_from_record(
                record,
                provider=self.name,
                token=allocation.token,
                qname=allocation.qname,
            )
            for record in _as_records(payload)
        ]

    def close(self) -> None:  # pragma: no cover
        return None


class InteractshProvider:
    """interactsh：**本里程碑显式未实现**（不是"能跑但没测"）。

    注册与事件轮询需要 RSA/AES（公钥注册 + 用 correlation id 派生密钥解密事件），
    而本里程碑**不新增第三方依赖**（裁定 1），纯 stdlib 实现一套密码学栈不属于本单。
    故 ``available()`` 恒 False、``allocate`` 直接抛错 ⇒ 调用方记
    ``observer_unavailable``，**绝不以"没有记录"冒充零命中**。
    """

    name = "interactsh"

    def available(self) -> bool:
        return False

    def allocate(self, token: str) -> DnsAllocation:
        raise ObserverError(
            "interactsh provider 未实现（需要 RSA/AES，本里程碑不新增第三方依赖）；"
            "请改用 dnslog.cn / ceye，或自建 TCP 观察点"
        )

    def poll(self, token: str) -> list[Observation]:  # pragma: no cover - 不可达
        raise ObserverError("interactsh provider 未实现")

    def close(self) -> None:  # pragma: no cover
        return None


class LocalStubProvider:
    """本机 HTTP stub（**只给 demo 与单测**，零外网）。

    模仿 dnslog.cn 的两个端点：``GET /getdomain.php``（返回域名）与
    ``GET /getrecords.php``（返回 JSON 数组），另给 demo 靶一个 ``POST /register``
    用于"登记一次查询"——靶侧的登记是**形态仿真**（真解析器由系统 resolver 发 DNS
    查询），详见 ``scripts/demo_fastjson.py`` 的披露段。
    """

    name = "stub"

    def __init__(self, *, api_base: str, timeout: float = 5.0):
        if not api_base or not api_base.strip():
            raise ObserverError(f"{ENV_DNS_API} 为空——stub provider 需要本机 API 地址")
        self.api_base = api_base.strip().rstrip("/")
        self.timeout = float(timeout)
        self._allocations: dict[str, DnsAllocation] = {}
        self._domain: str | None = None

    def _fetch_domain(self) -> str:
        if self._domain is not None:
            return self._domain
        payload = _http_get(f"{self.api_base}/getdomain.php", timeout=self.timeout)
        domain = payload.decode("utf-8", "replace").strip()
        if not domain or any(ch.isspace() for ch in domain):
            raise ObserverError(f"stub 返回的域名非法：{value_repr(domain)}")
        self._domain = domain
        return domain

    def allocate(self, token: str) -> DnsAllocation:
        canonical = canonical_token(token)
        if canonical is None:
            raise ObserverError(f"不是合法的观察 token：{value_repr(token)}")
        domain = self._fetch_domain()
        qname = f"{host_label(canonical)}.{domain}"
        allocation = DnsAllocation(
            provider=self.name, domain=domain, token=canonical, qname=qname
        )
        self._allocations[canonical] = allocation
        return allocation

    def poll(self, token: str) -> list[Observation]:
        canonical = canonical_token(token)
        allocation = self._allocations.get(canonical or "")
        if allocation is None:
            raise ObserverError("poll 之前必须先 allocate")
        payload = _http_get(f"{self.api_base}/getrecords.php", timeout=self.timeout)
        return [
            _observation_from_record(
                record,
                provider=self.name,
                token=allocation.token,
                qname=allocation.qname,
            )
            for record in _as_records(payload)
        ]

    def close(self) -> None:  # pragma: no cover
        return None


def provider_from_env(env: dict | None = None) -> DnsLogProvider | None:
    """按环境变量构造 provider；未配置返回 None（DNS 通道关闭）。

    非法/缺配置**抛** :class:`ObserverError`（fail-closed：配错了就别猜）。
    """
    import os

    source = os.environ if env is None else env
    raw = (source.get(ENV_DNS_PROVIDER) or "").strip()
    if not raw:
        return None
    name = raw.lower()
    domain = (source.get(ENV_DNS_DOMAIN) or "").strip()
    token = (source.get(ENV_DNS_TOKEN) or "").strip()
    api = (source.get(ENV_DNS_API) or "").strip()
    if name in ("dnslog.cn", "dnslogcn", "dnslog"):
        return DnslogCnProvider(base_url=api or "http://www.dnslog.cn")
    if name == "ceye":
        return CeyeProvider(domain=domain, token=token, api_base=api or "http://api.ceye.io")
    if name == "stub":
        return LocalStubProvider(api_base=api)
    if name == "interactsh":
        return InteractshProvider()
    raise ObserverError(f"未知的 DNSLog provider：{raw!r}（支持：{', '.join(KNOWN_PROVIDERS)}）")


def collect_dns(
    provider: DnsLogProvider,
    allocations: dict[str, DnsAllocation],
    *,
    wait: float,
    interval: float = DNS_POLL_INTERVAL,
) -> list[Observation]:
    """在窗口内轮询全部 token；**全部归因命中即提前返回**。

    provider 记录常有秒级~十几秒延迟，窗口太短会把"还没到"读成"没有"——故由调用方
    给足 ``wait``（CLI 的 ``--dns-wait``）。

    **未命中的记录（``token is None``）只在"只有一个 allocation"时保留**：多了以后
    同一批记录会被逐个 token 重扫一遍，"别人的查询"与"我们另一个 token 的记录"在
    ``Observation`` 里同形（都只是 token=None），保留会产生纯噪声。单个 allocation 时
    未命中就是真的陌生查询，留给判定层记 ``ignored``。
    """
    if not allocations:
        return []
    keep_unmatched = len(allocations) == 1
    deadline = time.monotonic() + max(0.0, float(wait))
    seen: dict[tuple, Observation] = {}
    pending = {canonical_token(token) for token in allocations}
    pending.discard(None)
    while True:
        for token in list(pending):
            try:
                records = provider.poll(token)
            except ObserverError:
                raise
            for record in records:
                if record.token is None and not keep_unmatched:
                    continue
                key = (
                    record.channel,
                    record.token,
                    record.source,
                    record.at,
                    record.detail.get("qname_sha8", ""),
                )
                seen.setdefault(key, record)
                if record.token is not None:
                    pending.discard(canonical_token(record.token))
        if not pending:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
    return [
        seen[key]
        for key in sorted(seen, key=lambda item: (item[0], item[2], item[3], str(item[1])))
    ]


# =====================================================================
# 本机 stub 服务（demo 与单测共用；零外网）
# =====================================================================


class _StubHandler(BaseHTTPRequestHandler):
    """stub 的 HTTP 处理器（只在本机回罐头；无外网、无凭据）。"""

    protocol_version = "HTTP/1.1"

    @property
    def _owner(self) -> "LocalStubDnsServer":
        return self.server.owner  # type: ignore[attr-defined]

    def log_message(self, *args):  # noqa: D102 - 静默
        return

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler 约定
        owner = self._owner
        if self.path.startswith("/getdomain.php"):
            self._send(200, owner.domain.encode(), "text/plain; charset=utf-8")
        elif self.path.startswith("/getrecords.php"):
            self._send(200, owner.records_json(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):  # noqa: N802
        owner = self._owner
        if not self.path.startswith("/register"):
            self._send(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            self._send(400, b"bad json", "text/plain")
            return
        qname = str(payload.get("qname") or "").strip()
        if not qname:
            self._send(400, b"missing qname", "text/plain")
            return
        owner.register(qname, ip=str(payload.get("ip") or "127.0.0.1"))
        self._send(204, b"", "text/plain")


class _StubHTTPServer(ThreadingHTTPServer):
    """把 owner 挂到 server 上（处理器因此不必闭包捕获实例）。"""

    daemon_threads = True

    def __init__(self, owner: "LocalStubDnsServer"):
        super().__init__(("127.0.0.1", 0), _StubHandler)
        self.owner = owner


class LocalStubDnsServer:
    """本机 HTTP stub：``getdomain`` / ``getrecords`` / ``register``（**仅测试与 demo**）。

    - ``GET /getdomain.php`` → 纯文本域名；
    - ``GET /getrecords.php`` → JSON 数组 ``[{"domain":..., "ip":..., "time":...}]``；
    - ``POST /register`` → 登记一条查询（body = ``{"qname": "...", "ip": "..."}``）。

    绑定 ``127.0.0.1`` 且端口随机；``records`` 可被测试直接断言。
    """

    def __init__(self, *, domain: str = "stub.local"):
        self.domain = domain
        self._records: list[dict] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ---------------------------------------------------------- 生命周期

    def start(self) -> "LocalStubDnsServer":
        self._server = _StubHTTPServer(self)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="ph-dns-stub", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def __enter__(self) -> "LocalStubDnsServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ---------------------------------------------------------- 数据

    @property
    def url(self) -> str:
        if self._server is None:
            raise ObserverError("stub 服务未启动")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def register(self, qname: str, *, ip: str = "127.0.0.1") -> None:
        """登记一次查询（**demo 靶侧的形态仿真**，见 demo docstring）。"""
        with self._lock:
            self._records.append(
                {"domain": qname.strip(), "ip": ip, "time": _now()}
            )

    def clear(self) -> None:
        """清空记录（demo 的"连跑两次"断言要一个干净的 provider）。"""
        with self._lock:
            self._records.clear()

    def records_json(self) -> bytes:
        with self._lock:
            payload = list(self._records)
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    @property
    def records(self) -> list[dict]:
        with self._lock:
            return list(self._records)


__all__ = [
    "DEFAULT_READ_TIMEOUT",
    "DNS_POLL_INTERVAL",
    "ENV_DNS_API",
    "ENV_DNS_DOMAIN",
    "ENV_DNS_PROVIDER",
    "ENV_DNS_TOKEN",
    "HOST_PREFIX",
    "KNOWN_PROVIDERS",
    "MAX_FIRST_BYTES",
    "ObserverError",
    "Observation",
    "TcpObserver",
    "TcpProbe",
    "CeyeProvider",
    "DnsAllocation",
    "DnsLogProvider",
    "DnslogCnProvider",
    "InteractshProvider",
    "LocalStubDnsServer",
    "LocalStubProvider",
    "canonical_token",
    "collect_dns",
    "extract_token",
    "host_label",
    "new_token",
    "provider_from_env",
    "token_sha8",
    "tokens_equal",
    "wait_for_tcp",
]
