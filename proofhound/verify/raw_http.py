"""裸 TCP HTTP 发送器（M23，§7.26）。

## 为什么必须自己发

``urllib`` / ``httpx`` / ``requests`` 在**客户端**就会拒绝或规范化非法请求行：
非 ASCII 字节（如 ``…``）、``%zz``、控制字符、``HTTP/9.9`` 这类版本号，它们要么
直接抛 ``InvalidURL``，要么悄悄百分号编码成"合法"请求——**根本发不到服务器**。
而「服务器把内部异常回显给客户端」恰恰只在服务器真的收到畸形请求时才可能发生。

故本模块只做一件事：把**调用方给的字节**原样写进 socket，再把响应按
``\\r\\n\\r\\n`` 切开。它**不做** URL 解析、**不做**请求构造、**不做**判定——
那些在 ``verify/error_disclosure.py``（构造与标记）与编排层（scope/证据）里。

## 边界（诚实记录）

- 只支持 HTTP/1.1 明文与 TLS；不支持 HTTP/2、代理、重定向跟随（本类型的
  对照语义也不需要跟随）；
- 响应体默认只保留前 256KB（``MAX_BODY_BYTES``）——错误页可能 50KB+，整页塞进
  证据没有意义；
- 网络错误**不抛出**，一律置 ``error``/``error_kind``：编排层需要区分
  「没响应」（blocked）与「响应了但没有标记」（rejected）；
- TLS 用系统默认信任库（``ssl.create_default_context()``）**校验证书**。本模块
  **刻意不提供**「不校验证书」的开关：给测试靶开的口子一旦存在就会被顺手用到
  真靶上；自签名靶的失败表现为 ``error_kind="tls"`` 的 blocked，是可归因的。
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field

#: 响应头读取上限（防御超大/无穷头；超过即判协议错误）。
MAX_HEADER_BYTES = 64 * 1024

#: 响应体保留上限（交接单硬要求：只留前 256KB）。
MAX_BODY_BYTES = 256 * 1024

#: 默认单次请求超时（秒）；交接单硬要求 10s。
DEFAULT_TIMEOUT = 10.0

#: 错误种类（进审计与判定 JSON，让 blocked 可归因到具体层）。
ERROR_CONNECT = "connect"  # 连接被拒 / 不可达
ERROR_TIMEOUT = "timeout"  # 连接或读取超时
ERROR_TLS = "tls"  # TLS 握手/证书失败
ERROR_RESET = "reset"  # 连接被重置（对端 RST）
ERROR_EMPTY = "empty-response"  # 对端一个字节都没回
ERROR_PROTOCOL = "protocol"  # 回了东西但不是可解析的 HTTP 响应


@dataclass(frozen=True)
class RawResponse:
    """一次裸 HTTP 交换的结果（错误不抛出，置 ``error``）。"""

    status: int | None = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    #: 响应体是否因超过 ``max_body`` 被截断
    truncated: bool = False
    bytes_read: int = 0
    error: str | None = None
    error_kind: str | None = None

    @property
    def ok(self) -> bool:
        """是否拿到了一个可解析的 HTTP 响应（状态行存在即算）。"""
        return self.error is None and self.status is not None

    @property
    def body_text(self) -> str:
        """正文按 UTF-8 解码（错误字节用替换字符，**保留**可匹配的 ASCII 标记）。"""
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str) -> str | None:
        """取响应头（名大小写不敏感）；不存在返回 None。"""
        return self.headers.get(name.lower())


def parse_head(head: bytes) -> tuple[int | None, str, dict[str, str]]:
    """解析状态行与响应头（纯函数）。

    ``head`` 不含结尾的 ``\\r\\n\\r\\n``。宽容两种状态行：``HTTP/1.1 400 Bad
    Request`` 与只有状态码的 ``HTTP/1.1 400``（某些最小实现会省掉 reason）。
    返回 ``(status, reason, headers)``；状态行不可解析时 status 为 None。
    """
    text = head.decode("iso-8859-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None, "", {}
    parts = lines[0].split(" ", 2)
    status: int | None = None
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    reason = parts[2].strip() if len(parts) >= 3 else ""

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if not key:
            continue
        value = value.strip()
        # 重复头合并（本模块不区分语义；错误页场景足够）
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    return status, reason, headers


def _header_end(buffer: bytes) -> int:
    return buffer.find(b"\r\n\r\n")


def _read_until_head(
    conn: socket.socket, timeout: float
) -> tuple[bytes | None, bytes, RawResponse | None]:
    """读到响应头结束；返回 ``(head, rest, failure)``。"""
    buffer = b""
    while True:
        index = _header_end(buffer)
        if index >= 0:
            return buffer[:index], buffer[index + 4 :], None
        if len(buffer) > MAX_HEADER_BYTES:
            return None, b"", RawResponse(
                error=f"响应头超过 {MAX_HEADER_BYTES} 字节仍未结束",
                error_kind=ERROR_PROTOCOL,
                bytes_read=len(buffer),
            )
        try:
            chunk = conn.recv(8192)
        except socket.timeout:
            if not buffer:
                return None, b"", RawResponse(
                    error=f"等待响应超时（{timeout:g}s）", error_kind=ERROR_TIMEOUT
                )
            return None, b"", RawResponse(
                error=f"响应头未读完即超时（{timeout:g}s）",
                error_kind=ERROR_TIMEOUT,
                bytes_read=len(buffer),
            )
        except (ConnectionResetError, BrokenPipeError) as exc:
            return None, b"", RawResponse(
                error=f"连接被重置: {exc}",
                error_kind=ERROR_RESET,
                bytes_read=len(buffer),
            )
        except OSError as exc:
            return None, b"", RawResponse(
                error=f"{type(exc).__name__}: {exc}",
                error_kind=ERROR_CONNECT,
                bytes_read=len(buffer),
            )
        if not chunk:
            if not buffer:
                return None, b"", RawResponse(
                    error="服务器关闭连接且未返回任何字节", error_kind=ERROR_EMPTY
                )
            return None, b"", RawResponse(
                error="连接在响应头结束前关闭",
                error_kind=ERROR_PROTOCOL,
                bytes_read=len(buffer),
            )
        buffer += chunk


def _content_length(headers: dict[str, str]) -> int | None:
    raw = headers.get("content-length")
    if raw is None:
        return None
    try:
        value = int(raw.split(",")[0].strip())
    except ValueError:
        return None
    return value if value >= 0 else None


def _read_body(
    conn: socket.socket,
    headers: dict[str, str],
    buffered: bytes,
    max_body: int,
    timeout: float,
) -> tuple[bytes, bool, int]:
    """读响应体（按 Content-Length；无 CL 则读到对端关闭）。

    返回 ``(body, truncated, bytes_read)``。**读超时不视为失败**——状态行与
    响应头已经拿到，错误页正文可能刚好没读全；此时保留已读部分并按截断处理。
    读超时**只**在「状态行都没拿到」时才算错误（由 :func:`_read_until_head` 判）。
    """
    length = _content_length(headers)
    want = max_body if length is None else min(length, max_body)
    body = buffered
    truncated = bool(length is not None and length > max_body)
    bytes_read = len(buffered)
    if len(body) >= want:
        return body[:max_body], truncated, bytes_read
    while len(body) < want:
        try:
            chunk = conn.recv(min(8192, want - len(body)))
        except socket.timeout:
            # 头已拿到：当作「响应到此为止」，不把已到手的错误页判成 blocked
            return body[:max_body], truncated, bytes_read
        except (ConnectionResetError, BrokenPipeError):
            return body[:max_body], truncated, bytes_read
        except OSError:
            return body[:max_body], truncated, bytes_read
        if not chunk:
            break
        body += chunk
        bytes_read += len(chunk)
    return body[:max_body], truncated, bytes_read


def send_raw(
    host: str,
    port: int,
    payload: bytes,
    *,
    tls: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    max_body: int = MAX_BODY_BYTES,
) -> RawResponse:
    """把 ``payload`` 字节原样发给 ``host:port``，返回解析后的响应。

    **不做**任何语法检查或规范化——这正是本模块存在的理由。调用方必须**先**
    过 ``check_scope``（红线 5）；本模块不持有 scope 语义。
    """
    try:
        conn = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        return RawResponse(error=f"连接超时（{timeout:g}s）", error_kind=ERROR_TIMEOUT)
    except OSError as exc:
        return RawResponse(
            error=f"{type(exc).__name__}: {exc}", error_kind=ERROR_CONNECT
        )

    try:
        if tls:
            context = ssl.create_default_context()
            try:
                conn = context.wrap_socket(conn, server_hostname=host)
            except ssl.SSLError as exc:
                return RawResponse(
                    error=f"TLS 握手失败: {exc}", error_kind=ERROR_TLS
                )
            except OSError as exc:
                return RawResponse(
                    error=f"TLS 连接失败: {exc}", error_kind=ERROR_TLS
                )
        try:
            conn.sendall(payload)
        except socket.timeout:
            return RawResponse(
                error=f"发送超时（{timeout:g}s）", error_kind=ERROR_TIMEOUT
            )
        except (ConnectionResetError, BrokenPipeError) as exc:
            return RawResponse(
                error=f"发送时连接被重置: {exc}", error_kind=ERROR_RESET
            )
        except OSError as exc:
            return RawResponse(
                error=f"{type(exc).__name__}: {exc}", error_kind=ERROR_CONNECT
            )

        head, rest, failure = _read_until_head(conn, timeout)
        if failure is not None:
            return failure
        assert head is not None  # noqa: S101 —— 由 _read_until_head 的契约保证
        status, reason, headers = parse_head(head)
        if status is None:
            return RawResponse(
                error="响应状态行不可解析",
                error_kind=ERROR_PROTOCOL,
                bytes_read=len(head) + len(rest),
            )
        body, truncated, bytes_read = _read_body(
            conn, headers, rest, max_body, timeout
        )
        return RawResponse(
            status=status,
            reason=reason,
            headers=headers,
            body=body,
            truncated=truncated,
            bytes_read=bytes_read,
        )
    except OSError as exc:  # 兜底：任何未归类的 socket 层错误
        return RawResponse(
            error=f"{type(exc).__name__}: {exc}", error_kind=ERROR_CONNECT
        )
    finally:
        try:
            conn.close()
        except OSError:
            pass


__all__ = [
    "DEFAULT_TIMEOUT",
    "ERROR_CONNECT",
    "ERROR_EMPTY",
    "ERROR_PROTOCOL",
    "ERROR_RESET",
    "ERROR_TIMEOUT",
    "ERROR_TLS",
    "MAX_BODY_BYTES",
    "MAX_HEADER_BYTES",
    "RawResponse",
    "parse_head",
    "send_raw",
]
