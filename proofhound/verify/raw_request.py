"""原始 HTTP 请求解析（登录暴破的输入入口，M21-a）。

输入是 Burp / Yakit「复制原始请求」得到的那段文本：

```
POST /login HTTP/1.1
Host: example.com
Cookie: PHPSESSID=...
Content-Type: application/x-www-form-urlencoded

username=admin&password=123456&captcha=ab3d
```

本模块只做**纯解析**（零网络、零副作用）：拆出 method/URL/headers/body，并提供
表单字段的读取与重建。它**不判断**哪个字段是用户名/密码/验证码——那是操作员在
CLI 上显式指定的事（见 ``login_probe``），不猜。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit


class RawRequestError(ValueError):
    """原始请求无法解析（缺请求行 / 缺 Host / body 不是表单）。"""


@dataclass(frozen=True)
class RawRequest:
    """一条待重放的请求（body 保持原文，字段替换在 :meth:`with_form` 里做）。"""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)  # 键统一小写
    body: str = ""

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme or "http"

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


def parse_raw_request(text: str, *, scheme: str = "https") -> RawRequest:
    """解析原始请求文本；请求行不带 scheme 时用 ``scheme`` + ``Host`` 拼 URL。"""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise RawRequestError("空请求")
    parts = lines[0].split()
    if len(parts) < 2:
        raise RawRequestError(f"请求行无法解析: {lines[0]!r}")
    method, target = parts[0].upper(), parts[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        headers[name.strip().lower()] = value.strip()

    if target.startswith(("http://", "https://")):
        url = target
    else:
        host = headers.get("host", "")
        if not host:
            raise RawRequestError("请求行是相对路径且缺 Host 头")
        url = f"{scheme}://{host}{target}"
    return RawRequest(method=method, url=url, headers=headers, body=body)


def form_fields(body: str) -> list[tuple[str, str]]:
    """把 ``a=1&b=2`` 解析成有序字段表（保留重复键与空值）。"""
    if not body.strip():
        return []
    return parse_qsl(body, keep_blank_values=True)


def rebuild_form(fields: list[tuple[str, str]]) -> str:
    return urlencode(fields)


def with_form(
    request: RawRequest, overrides: dict[str, str]
) -> RawRequest:
    """按字段名替换表单值（大小写不敏感、只替换首个命中），其余字段原样保留。

    缺字段即抛 :class:`RawRequestError`——**不凭空追加**：验证码/用户名字段名
    是操作员声明的，猜错会制造出「看起来测过」的假证据。
    """
    if request.header("content-type") and not request.header(
        "content-type"
    ).lower().startswith("application/x-www-form-urlencoded"):
        raise RawRequestError(
            "只支持 application/x-www-form-urlencoded 表单；"
            f"当前 Content-Type = {request.header('content-type')!r}"
        )
    fields = form_fields(request.body)
    lowered = {k.lower(): i for i, (k, _v) in enumerate(fields)}
    for name, value in overrides.items():
        index = lowered.get(name.lower())
        if index is None:
            raise RawRequestError(f"表单里没有字段 {name!r}（现有字段: {list(lowered)}）")
        key = fields[index][0]
        fields[index] = (key, value)
    return RawRequest(
        method=request.method,
        url=request.url,
        headers=dict(request.headers),
        body=rebuild_form(fields),
    )


def field_names(request: RawRequest) -> list[str]:
    return [name for name, _value in form_fields(request.body)]


__all__ = [
    "RawRequest",
    "RawRequestError",
    "field_names",
    "form_fields",
    "parse_raw_request",
    "rebuild_form",
    "with_form",
]
