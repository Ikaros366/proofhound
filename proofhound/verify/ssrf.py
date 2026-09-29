"""verify-ssrf 判定器 + 回调监听器（M16）：SSRF 的唯一确认手段 = **回调收到请求**。

## 为什么是"回调收到请求"而不是别的

SSRF 与 sqli/xss/idor 的判定形态不同：它**没有可观测的响应差异**——目标是否
替我们发了请求，答案不在目标给我们的响应里（响应里出现 callback URL 只是
**反射**，不是 SSRF）。故确认手段必须是**带外事实**：我们自己起的 listener
**收到了**那次请求。这是二值事实，没有"像不像"的余地（与 README「定位与边界」
里选 SSRF 而非 LFI 的理由一致）。

## 三道防伪（缺一不可）

1. **每探针唯一 token**（:func:`new_token`，`secrets.token_hex(16)`）+ 常量时间
   比对（:func:`hmac.compare_digest`）。token 不可猜、只出现在**我们注入的**
   payload 里 ⇒ 第三方无法伪造命中；路径不带 token 的请求一律
   :data:`IGNORED_REASON`，**不计命中**。
2. **交付证明**（delivery proof）：命中后**回取同一探测 URL**，正文里必须出现
   我们的 token/nonce ⇒ 证明目标当时收到的**就是**我们报告里那个地址。避免
   "报告里的 payload" 与 "真正起作用的 payload" 脱钩。
3. **随机地址对照探针**（:func:`new_nonce_host`）：一个**不含我们的参数**、
   谁访问都不该发出的地址（`http://<nonce>.invalid:<port>/n/<nonce>`）。它命中
   只证明"该服务端会代访客发起请求、且能到达我们的 listener"，**不依赖我们的
   参数 ⇒ 不能用来确认 SSRF**；只有它能解释"会发请求但不处理本参数"这一形态，
   把这种情形确定性判成 rejected 而不是 blocked。

## 判定分界（宁漏勿滥）

- **命中 token** → 可确认（confirmed）；
- 探针干净完成但未命中，**且交付证明成立** → rejected（真阴性：URL 已原样
  交付、目标也确实会发请求，仍未发 ⇒ 本参数不是 SSRF 入口）；
- 探针出错 / 交付证明不成立 / 前置条件不全 → **blocked**（覆盖不全，绝不驳回）。

## 这个模块不做什么

- 不解析目标响应来"猜"SSRF（反射、状态码、耗时都不入判据）；
- 不做协议/编码绕过变体（gopher/dict/@/十进制 IP 等）——那是绕过技巧，不是确认
  所需，且会扩大攻击面（见 AGENTS.md 限制 51）；
- 不发任何凭据到目标（回调 listener 只**被动接收**）。

已知限制（详见 AGENTS.md 限制 49~51）：回调需目标能回连宿主（远程靶需显式
配置回调地址）；只覆盖 GET query 参数型 SSRF，POST/表单、header 注入、无回调的
盲 SSRF 不在本轮范围。
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: 确认手段的 method 白名单值（与 sqli/xss/idor 三类**互不染指**，见 GATE_MATRIX）。
SSRF_CONFIRMED_METHOD = "ssrf-callback-confirmed"

#: token / nonce 前缀（两者都长这样：``phssrf_<32 hex>``）。
TOKEN_PREFIX = "phssrf_"

#: 回调 URL 的路径前缀（回**调**用），nonce 对照走 ``/n/``。
CALLBACK_PATH_PREFIX = "/c/"

#: nonce 对照的路径前缀。
NONCE_PATH_PREFIX = "/n/"

#: 回调 listener 的服务横幅（响应体）。刻意极短且**不含任何可变内容**——
#: 目标可能把我们的响应体回显到它自己的页面里，短横幅能确保 token/nonce 是
#: 正文里唯一可辨识的标记，交付证明因此干净。
BANNER = "proofhound-ssrf-callback-ok"

#: 路径不带 token 时记录的原因（**不计命中**，仅供取证与分析）。
IGNORED_REASON = "路径不含本次验证的 token（疑似无关流量）"

#: 未登记 token 的请求：能力失败与未知流量用不同原因，避免混读。
UNKNOWN_REASON = "token 与本次 engagement 任何探针都不匹配"
EXPIRED_REASON = "token 曾登记但已被本次 engagement 注销"

#: 单 listener 记录的丢弃上限（防被灌爆内存；超出只计数不再留存）。
MAX_RECORDS = 64

#: 每个 token 最多保留的命中条数（防单 token 被反复打）。
MAX_HITS_PER_TOKEN = 8

#: 回调 listener 读请求头的字节上限（防内存打满）。
_MAX_HEADER_BYTES = 64 * 1024

#: 交付证明在目标响应里搜索 token 的**累计字符上限**（确定性，防超大正文拖慢）。
DELIVERY_PROOF_CHARS = 262_144

#: 默认单次请求超时（秒）。
DEFAULT_TIMEOUT = 15.0

#: 环境变量：回调地址的宿主面（缺省 ``127.0.0.1``）。
ENV_CALLBACK_HOST = "PROOFHOUND_SSRF_CALLBACK_HOST"

#: 环境变量：回调端口（缺省 0 = 临时端口）。
ENV_CALLBACK_PORT = "PROOFHOUND_SSRF_CALLBACK_PORT"

#: 环境变量：本机**绑定**地址（与"告知目标的地址"解耦；缺省保守推断）。
ENV_CALLBACK_BIND = "PROOFHOUND_SSRF_CALLBACK_BIND"

#: listener 绑定非回环地址时的醒目告警（只在**配置**非回环时打印）。
NON_LOOPBACK_WARNING = (
    "⚠️  SSRF 回调 listener 绑定在非回环地址 {host}:{port}——"
    "同网段任何主机都能访问它；仅应在目标无法回连回环地址时临时启用，"
    "用完即关，切勿长期开启。"
)


class SsrfListenerError(RuntimeError):
    """回调 listener 无法启动（缺配置/端口占用等）—— 编排层据此 blocked。"""


# =====================================================================
# token / nonce
# =====================================================================


def new_token() -> str:
    """一条探针的唯一 token（128 位随机，不可猜）。"""
    return TOKEN_PREFIX + secrets.token_hex(16)


def new_nonce_host() -> str:
    """随机地址对照用的**不可解析**主机名（RFC 6761 保留 TLD ``.invalid``）。

    用它而非固定域名：任何真实流量都不可能来自该名字，故它的命中只可能由
    "目标真的替我们解析并取数"解释（见模块 docstring 第 3 条）。
    """
    return f"{secrets.token_hex(8)}.invalid"


def callback_url(host: str, port: int, token: str) -> str:
    """构造回调用 URL：``http://<host>:<port>/c/<token>``。"""
    return f"http://{host}:{port}{CALLBACK_PATH_PREFIX}{token}"


def nonce_url(host: str, port: int, nonce_host: str, nonce: str) -> str:
    """构造随机地址对照 URL：``http://<nonce_host>:<port>/n/<nonce>``。"""
    return f"http://{nonce_host}:{port}{NONCE_PATH_PREFIX}{nonce}"


def url_host_port(url: str) -> tuple[str, int] | None:
    """取 URL 的 (host, port)；缺端口时按 scheme 补缺省值，非法返回 None。"""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None
    if not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.hostname, port


def is_loopback_host(host: str) -> bool:
    """主机名是否回环（``localhost`` 或回环字面量 IP）。"""
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip()).is_loopback
    except ValueError:
        return False


def resolve_callback_host(env: dict | None = None) -> str:
    """回调地址宿主面：环境变量覆盖，缺省回环。

    非法值（键存在但为空串）**抛错**（fail-closed，与既有 ``PROOFHOUND_SANDBOX_*``
    先例一致：不给静默回退）。显式传入的 ``env`` 与真实环境**判据相同**——
    "键存在但取值为空"在任何来源下都是配置错误。
    """
    import os

    source = os.environ if env is None else env
    if ENV_CALLBACK_HOST in source:
        raw = (source.get(ENV_CALLBACK_HOST) or "").strip()
        if not raw:
            raise SsrfListenerError(
                f"{ENV_CALLBACK_HOST} 为空——要么不设，要么给一个可被目标回连的地址"
            )
        return raw
    return "127.0.0.1"


def resolve_callback_bind(host: str, env: dict | None = None) -> str:
    """本机**绑定**地址：与"告知目标的地址"解耦（容器/远程靶必须解耦）。

    典型场景：目标是容器，容器回连宿主要走 ``host.docker.internal``（或宿主 LAN
    IP），而本机**绑不上**这个名字（它不在本机接口上，getaddrinfo 直接失败）。此时
    应 ``PROOFHOUND_SSRF_CALLBACK_HOST=host.docker.internal`` +
    ``PROOFHOUND_SSRF_CALLBACK_BIND=0.0.0.0``。

    缺省规则（保守）：名字在本机**可解析**就绑该地址（回环名字 → 仍只绑回环，不
    放大暴露面）；不可解析才退到 ``0.0.0.0``（启动时打印醒目告警）。
    """
    import os
    import socket as _socket

    source = os.environ if env is None else env
    if ENV_CALLBACK_BIND in source:
        raw = (source.get(ENV_CALLBACK_BIND) or "").strip()
        if not raw:
            raise SsrfListenerError(
                f"{ENV_CALLBACK_BIND} 为空——要么不设，要么给一个本机可绑的地址"
            )
        return raw
    try:
        _socket.getaddrinfo(host, None)
    except OSError:
        return "0.0.0.0"
    return host


def resolve_callback_port(env: dict | None = None) -> int:
    """回调端口：环境变量覆盖，缺省 0（临时端口）。非法值 fail-closed 抛错。"""
    import os

    source = os.environ if env is None else env
    if ENV_CALLBACK_PORT not in source:
        return 0
    raw = (source.get(ENV_CALLBACK_PORT) or "").strip()
    if not raw:
        raise SsrfListenerError(f"{ENV_CALLBACK_PORT} 为空——要么不设，要么给端口号")
    if not raw.isdigit() or not (0 < int(raw) < 65536):
        raise SsrfListenerError(f"{ENV_CALLBACK_PORT} 非法取值 {raw!r}（需 1..65535）")
    return int(raw)


# =====================================================================
# 命中记录与判定
# =====================================================================


@dataclass
class CallbackRecord:
    """一次回调请求的结构化记录（**只记取证所需字段**，不记请求体）。"""

    token: str
    path: str
    source_ip: str
    user_agent: str
    line: str
    at: str

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "path": self.path,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "request_line": self.line,
            "at": self.at,
        }


@dataclass
class IgnoredRecord:
    """路径不含 token 的请求（**不计命中**，仅取证）。"""

    path: str
    source_ip: str
    reason: str = IGNORED_REASON

    def to_dict(self) -> dict:
        return {"path": self.path, "source_ip": self.source_ip, "reason": self.reason}


@dataclass
class CallbackListener:
    """回调 listener（宿主进程内，缺省只绑回环）。

    生命周期由编排层钉死在 verify 阶段：``_verify_ssrf`` 首次用到时启动，
    phase 收尾 ``close()``（与 M8b 的 ``_close_browser`` 同范式）。**不常驻**。
    """

    host: str = "127.0.0.1"
    port: int = 0
    _server: ThreadingHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _records: dict[str, list[CallbackRecord]] = field(
        default_factory=dict, init=False, repr=False
    )
    _known: set[str] = field(default_factory=set, init=False, repr=False)
    _expired: set[str] = field(default_factory=set, init=False, repr=False)
    _ignored: list[IgnoredRecord] = field(default_factory=list, init=False, repr=False)
    _dropped: int = field(default=0, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _request_sink: object | None = field(default=None, init=False, repr=False)

    # ---- 生命周期 ----

    def start(self) -> "CallbackListener":
        """绑定并启动（重复调用为 no-op）。不可用即抛 :class:`SsrfListenerError`。"""
        if self._server is not None:
            return self
        try:
            server = _BoundThreadingHTTPServer(
                (self.host, self.port), _CallbackHandler, self
            )
        except OSError as exc:
            raise SsrfListenerError(
                f"回调 listener 无法绑定 {self.host}:{self.port}（{type(exc).__name__}: {exc}）"
            ) from None
        server.daemon_threads = True
        self._server = server
        self.port = server.server_address[1]
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def bound_address(self) -> tuple[str, int]:
        """实际绑定地址（host, port）——回调 URL 必须与它一致（自检用）。"""
        if self._server is None:
            return self.host, self.port
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def ignored(self) -> tuple[IgnoredRecord, ...]:
        return tuple(self._ignored)

    @property
    def dropped(self) -> int:
        return self._dropped

    def close(self) -> None:
        """停止监听并清空登记（幂等；异常吞咽不遮蔽主链路）。"""
        server, self._server = self._server, None
        if server is not None:
            try:
                server.shutdown()
            except Exception:  # noqa: BLE001
                pass
            try:
                server.server_close()
            except Exception:  # noqa: BLE001
                pass
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=2)
        with self._lock:
            self._records.clear()
            self._known.clear()
            self._expired.clear()
            self._ignored.clear()

    def __enter__(self) -> "CallbackListener":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- 登记 / 注销 ----

    def register(self, token: str) -> None:
        """登记一个探针 token（只有登记过的 token 才可能被算作命中）。"""
        with self._lock:
            self._known.add(token)
            self._expired.discard(token)

    def forget(self, token: str) -> None:
        """注销 token：此后的同 token 请求记 :data:`EXPIRED_REASON`，不再算命中。"""
        with self._lock:
            self._known.discard(token)
            self._expired.add(token)
            self._records.pop(token, None)

    # ---- 查询 ----

    def hits(self, token: str) -> tuple[CallbackRecord, ...]:
        with self._lock:
            return tuple(self._records.get(token, ()))

    def has_hit(self, token: str) -> bool:
        return bool(self.hits(token))

    # ---- 服务端回调（由 handler 调用）----

    def _record_ignored(self, path: str, source_ip: str) -> None:
        """记一条"路径不含 token"的请求（不计命中，仅取证）。"""
        with self._lock:
            if len(self._ignored) < MAX_RECORDS:
                self._ignored.append(IgnoredRecord(path, source_ip))
            else:
                self._dropped += 1

    def _record(self, token: str, path: str, source_ip: str, ua: str, line: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if token not in self._known:
                reason = EXPIRED_REASON if token in self._expired else UNKNOWN_REASON
                if len(self._ignored) < MAX_RECORDS:
                    self._ignored.append(IgnoredRecord(path, source_ip, reason))
                else:
                    self._dropped += 1
                return
            bucket = self._records.setdefault(token, [])
            if len(bucket) >= MAX_HITS_PER_TOKEN:
                self._dropped += 1
                return
            bucket.append(
                CallbackRecord(
                    token=token,
                    path=path,
                    source_ip=source_ip,
                    user_agent=ua,
                    line=line,
                    at=now,
                )
            )


def _install_listener(server: ThreadingHTTPServer, listener: CallbackListener) -> None:
    """（保留占位）把 listener 挂到 server 上——实际由 ``_BoundThreadingHTTPServer``
    在构造时完成；本函数不再被 start() 使用，留作显式挂载的备用口子。"""
    server.listener = listener  # type: ignore[attr-defined]


# 带 listener 引用的 ThreadingHTTPServer（handler 经 ``self.server.listener`` 取）。
# 用子类而非 handler 类属性：同一进程可能同时存在多个 listener（多 engagement），
# 类属性会被互相覆盖。
class _BoundThreadingHTTPServer(ThreadingHTTPServer):
    """携带 :class:`CallbackListener` 引用的 HTTP 服务器。"""

    def __init__(
        self, address, handler, listener: "CallbackListener"
    ) -> None:  # noqa: D107
        self.listener = listener
        super().__init__(address, handler)


class _CallbackHandler(BaseHTTPRequestHandler):
    """只服务回调用路径；任何路径都返回同一个极短横幅（不含任何可变内容）。"""

    protocol_version = "HTTP/1.1"

    def _serve(self) -> None:  # noqa: D102
        listener: CallbackListener = self.server.listener  # type: ignore[attr-defined]
        path = self.path
        parsed = urllib.parse.urlparse(path)
        body = BANNER.encode("ascii")
        token = ""
        if parsed.path.startswith(CALLBACK_PATH_PREFIX):
            token = parsed.path[len(CALLBACK_PATH_PREFIX):]
        elif parsed.path.startswith(NONCE_PATH_PREFIX):
            token = parsed.path[len(NONCE_PATH_PREFIX):]
        if token:
            listener._record(
                token,
                path,
                str(self.client_address[0]),
                self.headers.get("User-Agent") or "",
                f"{self.command} {path}",
            )
        else:
            listener._record_ignored(path, str(self.client_address[0]))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=ascii")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _serve
    do_HEAD = _serve
    do_POST = _serve

    def log_message(self, *args):  # noqa: D102 - 静默（证据走 listener 记录与审计）
        pass


# =====================================================================
# 探针结果与判定（纯函数，零网络零 LLM）
# =====================================================================


@dataclass
class ProbeResponse:
    """一次宿主侧探测请求的结构化结果（error 只置字段不抛出）。"""

    url: str
    status: int | None = None
    body: str = ""
    error: str | None = None
    elapsed_s: float = 0.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随重定向：3xx 以状态码暴露（与 verify/idor.py 同纪律）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def fetch(url: str, session, *, timeout: float = DEFAULT_TIMEOUT) -> ProbeResponse:
    """以给定会话 GET 一个 URL（不跟随重定向）。

    与 :func:`proofhound.verify.idor.fetch` 同形：凭据由代码注入，网络/超时异常
    不抛出只置 ``error``（编排层据此 blocked）。``session`` 可为 None（匿名）。
    """
    import time

    headers: dict[str, str] = {}
    if session is not None:
        cookie = session.cookie_header()
        if cookie:
            headers["Cookie"] = cookie
        for key, value in session.headers.items():
            headers[key] = value
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_NoRedirect())
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as resp:
            return ProbeResponse(
                url=url,
                status=resp.status,
                body=resp.read().decode("utf-8", errors="replace"),
                elapsed_s=time.monotonic() - started,
            )
    except urllib.error.HTTPError as exc:  # 4xx/5xx/3xx（不跟随）也是响应
        return ProbeResponse(
            url=url,
            status=exc.code,
            body=exc.read().decode("utf-8", errors="replace"),
            elapsed_s=time.monotonic() - started,
        )
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return ProbeResponse(
            url=url,
            error=f"{type(exc).__name__}: {exc}",
            elapsed_s=time.monotonic() - started,
        )


def ok_status(status: int | None) -> bool:
    """2xx 判定（None 视为否）。"""
    return status is not None and 200 <= status < 300


def token_delivered(resp: ProbeResponse, marker: str) -> bool:
    """交付证明：目标响应里是否出现我们的标记（token / nonce）。

    只搜前 :data:`DELIVERY_PROOF_CHARS` 个字符（确定性上限，防超大正文拖慢）。
    """
    if not marker:  # 空标记会让 "in" 恒真——显式 fail-closed
        return False
    return marker in resp.body[:DELIVERY_PROOF_CHARS]


@dataclass
class SsrfJudgment:
    """SSRF 判定结论（全部依据结构化，供判定 JSON 落盘与 Verifier 摘要）。"""

    verdict: str  # confirmed / rejected / blocked
    reasons: list[str] = field(default_factory=list)
    #: 命中的探针（confirmed 时非空）
    hit_variant: str = ""
    hit_requests: list[dict] = field(default_factory=list)
    #: 对照探针是否命中（"服务端会代发请求且能到达我们"）
    control_hit: bool = False
    #: 交付证明是否成立（payload 已原样交付给目标）
    delivered: bool = False
    probes: list[dict] = field(default_factory=list)
    ignored_requests: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "hit_variant": self.hit_variant,
            "hit_requests": list(self.hit_requests),
            "control_hit": self.control_hit,
            "delivered": self.delivered,
            "probes": list(self.probes),
            "ignored_requests": list(self.ignored_requests),
        }


def judge(
    *,
    callback_hit: bool,
    hit_requests: list[dict],
    hit_variant: str = "",
    control_hit: bool = False,
    delivered: bool = False,
    probes: list[dict] | None = None,
    probes_errored: bool = False,
    ignored: list[dict] | None = None,
) -> SsrfJudgment:
    """纯判定函数：把"探针结果"映射成 confirmed / rejected / blocked。

    判定表（**宁漏勿滥**；落地说明见 docs/design.md §7.12）：

    ==========================================  ==========
    条件                                         结论
    ==========================================  ==========
    回调收到含本次 token 的请求                    confirmed
    探针出错（网络/超时/非 2xx 且非干净响应）      blocked
    交付证明不成立（正文找不到 token/nonce）      blocked
    干净未命中 + 交付证明成立                     rejected
    ==========================================  ==========
    """
    probes = list(probes or [])
    ignored = list(ignored or [])
    if callback_hit:
        return SsrfJudgment(
            verdict="confirmed",
            reasons=[
                "回调 listener 收到含本次探针 token 的请求（二值事实）",
                f"命中探针：{hit_variant or '(未标注)'}",
            ],
            hit_variant=hit_variant,
            hit_requests=list(hit_requests),
            control_hit=control_hit,
            delivered=delivered,
            probes=probes,
            ignored_requests=ignored,
        )
    if probes_errored:
        return SsrfJudgment(
            verdict="blocked",
            reasons=["探针存在错误（覆盖不全，不驳回）"],
            control_hit=control_hit,
            delivered=delivered,
            probes=probes,
            ignored_requests=ignored,
        )
    if not delivered:
        return SsrfJudgment(
            verdict="blocked",
            reasons=[
                "交付证明不成立：目标响应里找不到我们的 token/nonce，"
                "无法确认 payload 被原样接收（覆盖不全，不驳回）"
            ],
            control_hit=control_hit,
            probes=probes,
            ignored_requests=ignored,
        )
    return SsrfJudgment(
        verdict="rejected",
        reasons=[
            "探针干净完成、payload 已原样交付，但回调 listener 未收到任何请求"
            + ("（对照探针命中：目标确实会代发请求且能到达本 listener）" if control_hit else ""),
            "判定依据：没有带外请求 ⇒ 该参数不是服务端请求伪造入口",
        ],
        control_hit=control_hit,
        delivered=delivered,
        probes=probes,
        ignored_requests=ignored,
    )


def summary_for_verifier(j: SsrfJudgment, *, callback_host_port: str) -> dict:
    """确定性结论块（送 Verifier 的 ``extra_summary``）。

    只含枚举/计数/字段名/锚点——**回调请求原文与响应体一行不进 prompt**（红线 3）。
    """
    return {
        "ssrf_verdict": j.verdict,
        "callback_listener": callback_host_port,
        "callback_hit": bool(j.hit_requests),
        "callback_hit_count": len(j.hit_requests),
        "callback_hit_sources": sorted(
            {r.get("source_ip", "") for r in j.hit_requests if r.get("source_ip")}
        ),
        "control_probe_hit": j.control_hit,
        "delivery_proof_ok": j.delivered,
        "probe_count": len(j.probes),
        "ignored_request_count": len(j.ignored_requests),
        "hit_variant": j.hit_variant,
    }


__all__ = [
    "BANNER",
    "CALLBACK_PATH_PREFIX",
    "CallbackListener",
    "CallbackRecord",
    "DEFAULT_TIMEOUT",
    "DELIVERY_PROOF_CHARS",
    "ENV_CALLBACK_BIND",
    "ENV_CALLBACK_HOST",
    "ENV_CALLBACK_PORT",
    "EXPIRED_REASON",
    "IGNORED_REASON",
    "IgnoredRecord",
    "MAX_HITS_PER_TOKEN",
    "NONCE_PATH_PREFIX",
    "NON_LOOPBACK_WARNING",
    "ProbeResponse",
    "SSRF_CONFIRMED_METHOD",
    "SsrfJudgment",
    "SsrfListenerError",
    "TOKEN_PREFIX",
    "UNKNOWN_REASON",
    "callback_url",
    "fetch",
    "is_loopback_host",
    "judge",
    "new_nonce_host",
    "new_token",
    "nonce_url",
    "ok_status",
    "resolve_callback_bind",
    "resolve_callback_host",
    "resolve_callback_port",
    "summary_for_verifier",
    "token_delivered",
    "url_host_port",
]
