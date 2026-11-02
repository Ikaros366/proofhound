"""给任意端点 POST 一段 body（M25-a 的传输层，``verify/xxe.py`` 的第一个依赖）。

## 为什么需要新模块

仓库的 8 个 verifier 里没有一个能"给任意端点 POST 一段任意 body"：
sqli 走沙箱 sqlmap、xss 走无头浏览器、idor/ssrf/ssti/prefilter 全是 **GET**；
只有 ``login_probe``（表单 POST，``application/x-www-form-urlencoded``）与
``raw_http``（裸 TCP，固定畸形请求）能带 body。XML 是**合法的 HTTP 请求体**，
不需要裸 TCP，也不需要表单编码——只需要一个"POST bytes、拿回状态码/头/正文"
的最小客户端。本模块就是它。

这一层做出来之后，POST 型 SQLi/XSS/SSRF 也顺带铺了路（另立项，不在本单）。

## 边界（全是结构性的，不靠调用方自觉）

- **只发 POST**：函数签名里只有 ``body``，没有 method 参数；
- **不跟随重定向**：3xx 原样作为状态码返回（``_NoRedirect``）——跟随会把
  "被网关重定向到登录页"读成"端点正常响应"，是假证据；
- **响应只留前 ``max_bytes``（缺省 256KB）**，超出置 ``truncated``；
- **凭据由代码注入**：:class:`~proofhound.compliance.session.SessionConfig`
  的 Cookie/请求头在这里拼进头部，调用方（与 LLM）永远看不到凭据原文；
- **网络异常不抛**：一律落 ``BodyResponse.error``，由判定层转 blocked
  （覆盖不全绝不驳回）。TLS 校验证书，**不提供**"不校验"开关（同 ``raw_http``：
  给测试靶开的口子会被顺手用到真靶）。
"""

from __future__ import annotations

import hashlib
import http.client
import ssl
import urllib.error
import ssl
import urllib.request
from dataclasses import dataclass, field

from proofhound.compliance.session import SessionConfig

#: 单次请求超时（秒）。
DEFAULT_TIMEOUT = 10.0

#: 缺省请求体类型（XML；XXE 的全部探针都是它）。
DEFAULT_CONTENT_TYPE = "application/xml"

#: 响应正文保留上限（字节）。超出只留前段并置 ``truncated``。
MAX_RESPONSE_BYTES = 256 * 1024


@dataclass(frozen=True)
class BodyResponse:
    """一次 POST 的结构化结果（**正文是字节**，解码由调用方决定）。

    ``error`` 非空表示请求没有拿到任何响应（连接失败/超时/TLS 失败）；
    4xx/5xx/3xx **不是** error——它们是目标的真实响应，判定层要看见。
    """

    url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)  # 键统一小写
    body: bytes = b""
    error: str | None = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        """拿到了响应（任何状态码都算；网络失败不算）。"""
        return self.error is None and self.status is not None

    @property
    def text(self) -> str:
        """正文按 UTF-8 解码（非法字节替换，绝不抛）。"""
        return self.body.decode("utf-8", "replace")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def summary(self) -> dict:
        """结构化摘要（**不含正文**——证据落盘的默认形态）。"""
        return {
            "url": self.url,
            "status": self.status,
            "error": self.error,
            "bytes": len(self.body),
            "truncated": self.truncated,
            "sha256": hashlib.sha256(self.body).hexdigest() if self.body else "",
        }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """3xx 不跟随：返回 None 让 urllib 以 ``HTTPError`` 抛出（我们当作响应收下）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def build_headers(
    *,
    content_type: str = DEFAULT_CONTENT_TYPE,
    session: SessionConfig | None = None,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, str]:
    """渲染请求头：会话头 → Cookie → 显式 ``content_type``（最后写，优先级最高）。

    ``Content-Type`` 写在最后是为了让操作员在 CLI 上给的类型**一定**覆盖
    scope 会话里的同名头（否则"我明明指定了 application/xml"却不生效）。
    """
    headers: dict[str, str] = {}
    if session is not None:
        for key, value in session.headers.items():
            headers[key] = value
        cookie = session.cookie_header()
        if cookie:
            headers["Cookie"] = cookie
    if extra_headers:
        for key, value in extra_headers.items():
            headers[key] = value
    headers["Content-Type"] = content_type
    return headers


def _lower_headers(headers) -> dict[str, str]:
    if headers is None:
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _read_limited(stream, max_bytes: int) -> tuple[bytes, bool]:
    """读至多 ``max_bytes`` 字节；多读 1 字节用于判定是否被截断。"""
    data = stream.read(max_bytes + 1)
    if data is None:
        return b"", False
    if len(data) > max_bytes:
        return data[:max_bytes], True
    return data, False


def tls_context_for(scope) -> ssl.SSLContext | None:
    """按 scope 的 TLS 策略造 SSLContext（M30，与 ``raw_http`` 同一裁定）。

    ``strict``（缺省）返回 ``None``——调用方走系统缺省校验；只有 scope **显式**
    声明 ``tls_verify: insecure`` 才返回跳过校验的上下文。它是本模块唯一的放宽
    通道，与 ``raw_http._tls_context`` 共用同一段实现。
    """
    from proofhound.verify.raw_http import _tls_context

    if getattr(scope, "tls_verify", "strict") == "insecure":
        return _tls_context(False)
    return None


def post(
    url: str,
    body: bytes | str,
    *,
    content_type: str = DEFAULT_CONTENT_TYPE,
    session: SessionConfig | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_RESPONSE_BYTES,
    extra_headers: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> BodyResponse:
    """POST ``body`` 到 ``url``（不跟随重定向），返回 :class:`BodyResponse`。

    ``body`` 接受 ``bytes`` 或 ``str``（后者按 UTF-8 编码）。网络/TLS/超时
    异常一律吞进 ``error`` 字段，**不抛**：调用方据 ``error`` 转 blocked。
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes 必须是正数")
    payload = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    request = urllib.request.Request(
        url,
        data=payload,
        headers=build_headers(
            content_type=content_type, session=session, extra_headers=extra_headers
        ),
        method="POST",
    )
    handlers: list = [_NoRedirect()]
    if ssl_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout) as resp:
            data, truncated = _read_limited(resp, max_bytes)
            return BodyResponse(
                url=url,
                status=resp.status,
                headers=_lower_headers(resp.headers),
                body=data,
                truncated=truncated,
            )
    except urllib.error.HTTPError as exc:  # 3xx/4xx/5xx 也是响应
        try:
            data, truncated = _read_limited(exc, max_bytes)
        except (OSError, http.client.HTTPException):
            data, truncated = b"", False
        finally:
            try:
                exc.close()
            except Exception:  # noqa: BLE001 - 关闭失败不遮蔽结果
                pass
        return BodyResponse(
            url=url,
            status=exc.code,
            headers=_lower_headers(exc.headers),
            body=data,
            truncated=truncated,
        )
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        return BodyResponse(url=url, error=f"{type(exc).__name__}: {exc}")


__all__ = [
    "DEFAULT_CONTENT_TYPE",
    "tls_context_for",
    "DEFAULT_TIMEOUT",
    "MAX_RESPONSE_BYTES",
    "BodyResponse",
    "build_headers",
    "post",
]
