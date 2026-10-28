"""JS 正文 → 接口路径模板（M24-a 抽取层：第一方、确定性、零 LLM）。

抽的是**路径**，不是密钥：本模块只产出 ``path_template`` / ``query_keys`` /
锚点（JS sha256 + 正文字节偏移 + 行号 + 原字面量），**不扫 secret**（交接单
§10.12）。JS 原件仍可能含密钥，故按 0600 落盘且不进报告。

## 为什么不能只信 ``katana -jc``

限制 53：``-jc`` 对 JS 的抽取**是部分的**——同一份 JS 里
``fetch("/api/orders/1001")``、``fetch(`/api/notes/${id}`)`` **都没被抽出**。
故本模块自己从 ``response.body`` 抽路径；报告不得把"没抽到"写成"不存在"。

## 规则（交接单 §5.2，逐条对应）

1. 候选字面量：``"`` / ``'`` / ``` ` ``` 包裹；以 ``/`` 开头，或匹配
   ``^(?:api|rest|v[0-9]+|graphql)(?:/|$)``，或是绝对 URL；
2. 模板串：``${...}`` 一律归一 ``{param}``；``:id`` 这种整段冒号参数同样归一
   ``{param}``（交接单 §5.4 要求两种都认）；
3. 拼接：``"/api/" + x`` 只留前缀 ⇒ **丢弃并记 ``fragment_dropped``**（拿
   ``/api/`` 去探是纯粹的噪声）；同文件内 ``baseURL``/``API_BASE`` 这类字符串
   常量作为相对路径前缀参与 ``urljoin``（只做简单赋值，不做跨文件数据流）；
4. 转义：``\\/`` 与 ``\\u002f`` 还原成 ``/``；
5. 过滤：静态扩展名、静态目录、``javascript:``/``data:``/``mailto:``、``#``、
   ``//`` 开头、纯 ``/``；
6. 归一化：``urljoin`` 后只留 path + query 键（**丢值**）；跨域直接丢（记
   ``out_of_scope``，**不探测**）；
7. 去重键：``(origin, path_template, tuple(sorted(query_keys)))``，同键保留首次
   锚点并累加 ``occurrences``；
8. 锚点：``js_sha256`` + **正文字节偏移** + 由偏移算出的行号 + 原字面量（截断
   200）。单行 minified JS 的行号恒为 1，**偏移才是有效锚点**。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Iterable
from urllib.parse import parse_qsl, urljoin, urlparse

from proofhound.jsimport.crawl import JsDocument

#: 字面量长度上限（交接单 §5.2 规则 1 的 2..300）
MAX_LITERAL = 300
#: 锚点里原字面量的截断长度（交接单 §5.2 规则 8）
MAX_ANCHOR_LITERAL = 200
#: 引号内容的正则扫描上限：只关心 ≤300 的字面量，超出即不可能是候选
_MAX_SCAN_CONTENT = 400

#: 三引号（``"`` / ``'`` / ``` ` ```）包裹的字符串/模板串。反斜杠转义原样吃进
#: 组 2，故 ``\\/`` 与 ``\\u002f`` 能完整保留到还原阶段。
_QUOTED = re.compile(
    rb'(?s)(["\'`])((?:\\.|(?!\1)[^\\]){0,' + str(_MAX_SCAN_CONTENT).encode() + rb"})\1"
)

#: 相对路径前缀常量（交接单 §5.2 规则 3）：只认简单赋值，不做数据流
_BASE_ASSIGN = re.compile(
    rb'(?s)(?:baseURL|baseUrl|API_BASE|BASE_URL|apiBase)\s*[:=]\s*'
    rb'(["\'`])((?:\\.|(?!\1)[^\\]){0,200})\1'
)

#: 紧跟在字面量后面的字符串拼接（``+ x``，x 不是另一个字面量）⇒ 该字面量是**前缀片段**
_CONCAT_AFTER = re.compile(rb"""\s*\+\s*[^"'`\s]""")

_ABSOLUTE_RE = re.compile(r"^https?://", re.IGNORECASE)
_RELATIVE_RE = re.compile(r"^(?:api|rest|v[0-9]+|graphql)(?:/|$)", re.IGNORECASE)
_STATIC_EXT_RE = re.compile(
    r"\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff2?|map)$", re.IGNORECASE
)
_STATIC_DIRS = ("/static/", "/assets/", "/img/", "/fonts/", "/locales/")
_FORBIDDEN_PREFIXES = ("javascript:", "data:", "mailto:", "tel:", "blob:", "about:")
#: ES6 模板插值：``${id}`` / ``${obj.id}`` 一律归一 ``{param}``（不做表达式求值）
_TEMPLATE_EXPR = re.compile(r"\$\{[^{}]*\}")
#: Express 风格整段路径参数：``/api/users/:id`` 的 ``:id``
_COLON_SEGMENT = re.compile(r":[A-Za-z_][A-Za-z0-9_]*")
#: 查询键白名单（合成 URL 时直接复用；怪字符的键一律丢）
_QUERY_KEY_RE = re.compile(r"[A-Za-z0-9_.\-\[\]]{1,64}")


@dataclass(frozen=True)
class EndpointAnchor:
    """JS 正文里的位置锚点（偏移是主锚点，行号只是给人看的）。"""

    #: 正文字节偏移（字面量内容起点，不含引号）
    offset: int
    #: 由偏移算出的 1 起行号（单行 minified JS 恒为 1）
    line: int
    #: 原字面量（未归一化，截断 200）
    literal: str

    def as_dict(self) -> dict:
        return {"offset": self.offset, "line": self.line, "literal": self.literal}


@dataclass(frozen=True)
class EndpointTemplate:
    """一个归一化后的接口路径模板（去重后的单位）。"""

    js_sha256: str
    js_url: str
    origin: str
    path_template: str
    query_keys: tuple[str, ...]
    anchor: EndpointAnchor
    #: 同一去重键在 JS 里出现的次数（>1 说明多处引用，锚点仍取首次）
    occurrences: int = 1

    @property
    def key(self) -> tuple[str, str, tuple[str, ...]]:
        """去重键：``(origin, path_template, 排序后的 query 键)``。"""
        return (self.origin, self.path_template, tuple(sorted(self.query_keys)))

    @property
    def display(self) -> str:
        """人读形态：``/api/orders/{param}?status,trace``。"""
        if not self.query_keys:
            return self.path_template
        return f"{self.path_template}?{','.join(self.query_keys)}"

    def as_dict(self) -> dict:
        return {
            "key": "|".join([self.origin, self.path_template, ",".join(sorted(self.query_keys))]),
            "origin": self.origin,
            "path_template": self.path_template,
            "display": self.display,
            "query_keys": list(self.query_keys),
            "js_sha256": self.js_sha256,
            "js_url": self.js_url,
            "anchor": self.anchor.as_dict(),
            "occurrences": self.occurrences,
        }


@dataclass
class ExtractStats:
    """抽取过程的计数（进 summary 与审计；也是"没抽到"与"不存在"的分界证据）。"""

    literals: int = 0
    filtered_length: int = 0
    fragment_dropped: int = 0
    filtered_not_path: int = 0
    filtered_static: int = 0
    out_of_scope: int = 0
    duplicates: int = 0
    base: str = ""

    def as_dict(self) -> dict:
        return {
            "literals": self.literals,
            "filtered_length": self.filtered_length,
            "fragment_dropped": self.fragment_dropped,
            "filtered_not_path": self.filtered_not_path,
            "filtered_static": self.filtered_static,
            "out_of_scope": self.out_of_scope,
            "duplicates": self.duplicates,
        }


def _unescape(text: str) -> str:
    """还原 JS 字符串转义里的斜杠形态（交接单 §5.2 规则 4 / §10.4）。"""
    return re.sub(r"\\u002[fF]", "/", text.replace("\\/", "/"))


def _scan(body: bytes):
    """逐条产出 ``(起偏移, 结束偏移, 字面量字节)``（偏移都是正文字节偏移）。"""
    for match in _QUOTED.finditer(body):
        yield match.start(2), match.end(), match.group(2)


def _is_fragment(after: bytes) -> bool:
    """字面量后面紧跟 ``+ <非字面量>`` ⇒ 它只是拼接前缀（如 ``"/api/" + x``）。"""
    return bool(_CONCAT_AFTER.match(after))


def _looks_like_path(text: str) -> bool:
    """候选字面量的三种形态：绝对 URL / 根路径 / 约定前缀的相对路径。"""
    if text.startswith("#") or text.startswith("//"):
        return False
    if text.lower().startswith(_FORBIDDEN_PREFIXES):
        return False
    if _ABSOLUTE_RE.match(text) or text.startswith("/"):
        return True
    return bool(_RELATIVE_RE.match(text))


def _static_reason(path: str) -> str | None:
    """静态资源/空路径的过滤原因（``None`` 表示不是静态资源）。"""
    if path in ("", "/"):
        return "empty"
    if path.startswith("//"):
        return "protocol_relative"
    lowered = path.lower()
    if _STATIC_EXT_RE.search(lowered):
        return "static_extension"
    for prefix in _STATIC_DIRS:
        if lowered == prefix.rstrip("/") or lowered.startswith(prefix):
            return "static_dir"
    return None


def _normalize_template(text: str) -> str:
    """``${id}`` → ``{param}``（交接单 §5.2 规则 2）。"""
    return _TEMPLATE_EXPR.sub("{param}", text)


def _colon_params(path: str) -> str:
    """整段 ``:id`` 归一 ``{param}``（与模板串同一占位符，交接单 §5.4）。"""
    parts = path.split("/")
    out: list[str] = []
    for position, segment in enumerate(parts):
        if position and _COLON_SEGMENT.fullmatch(segment):
            out.append("{param}")
        else:
            out.append(segment)
    return "/".join(out)


def _query_keys(query: str) -> tuple[str, ...]:
    """query 只留**键**（保序去重）；值由合成阶段统一填种子（交接单 §5.4）。"""
    keys: list[str] = []
    for key, _value in parse_qsl(query, keep_blank_values=True):
        if not _QUERY_KEY_RE.fullmatch(key):
            continue
        if key not in keys:
            keys.append(key)
    return tuple(keys)


def _relative_base(
    body: bytes, js_url: str, explicit: str | None
) -> str:
    """相对路径的基准目录：默认 JS 文件所在目录，有 ``baseURL`` 常量则用它。

    ``api/x`` 必须相对 **JS 文件所在目录**（交接单 §10.5），不是页面目录。
    """
    candidate = explicit if explicit is not None else ""
    if not candidate:
        match = _BASE_ASSIGN.search(body)
        if match:
            candidate = _unescape(match.group(2).decode("utf-8", errors="replace")).strip()
    if not candidate:
        return urljoin(js_url, ".")
    joined = urljoin(js_url, candidate)
    if not joined.endswith("/"):
        joined += "/"
    return joined


def _join_url(js_url: str, base: str, literal: str) -> str:
    """绝对 URL 原样；根路径对 JS URL 归并；相对路径对基准目录归并。"""
    if _ABSOLUTE_RE.match(literal):
        return literal
    if literal.startswith("/"):
        return urljoin(js_url, literal)
    return urljoin(base, literal)


def extract_endpoints(
    document: JsDocument, *, base: str | None = None
) -> tuple[list[EndpointTemplate], ExtractStats]:
    """从一份 JS 正文抽出接口路径模板（确定性、单遍、按字节偏移去重）。

    ``base`` 显式给相对路径基准（缺省从正文的 ``baseURL``/``API_BASE`` 常量取，
    再缺省为 JS 文件所在目录）。
    """
    body = document.body.encode("utf-8")
    origin = document.origin
    base_url = _relative_base(body, document.primary_url, base)
    stats = ExtractStats(base=base_url)
    templates: list[EndpointTemplate] = []
    index_of: dict[tuple[str, str, tuple[str, ...]], int] = {}

    for offset, end, raw in _scan(body):
        stats.literals += 1
        text = _unescape(raw.decode("utf-8", errors="replace")).strip()
        if len(text) < 2 or len(text) > MAX_LITERAL:
            stats.filtered_length += 1
            continue
        if _is_fragment(body[end : end + 16]):
            stats.fragment_dropped += 1
            continue
        if not _looks_like_path(text):
            stats.filtered_not_path += 1
            continue
        normalized = _normalize_template(text)
        reason = _static_reason(normalized.split("?", 1)[0].split("#", 1)[0])
        if reason is not None:
            stats.filtered_static += 1
            continue
        parsed = urlparse(_join_url(document.primary_url, base_url, normalized))
        joined_origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            stats.filtered_not_path += 1
            continue
        if joined_origin != origin:
            stats.out_of_scope += 1  # 跨域 JS 路径直接丢，不探测（交接单 §8）
            continue
        path_template = _colon_params(parsed.path or "/")
        if len(path_template) > 1:
            path_template = path_template.rstrip("/") or "/"
        query_keys = _query_keys(parsed.query)
        key = (joined_origin, path_template, tuple(sorted(query_keys)))
        anchor = EndpointAnchor(
            offset=offset,
            line=body.count(b"\n", 0, offset) + 1,
            literal=text[:MAX_ANCHOR_LITERAL],
        )
        existing = index_of.get(key)
        if existing is not None:
            head = templates[existing]
            templates[existing] = replace(head, occurrences=head.occurrences + 1)
            stats.duplicates += 1
            continue
        index_of[key] = len(templates)
        templates.append(
            EndpointTemplate(
                js_sha256=document.sha256,
                js_url=document.primary_url,
                origin=joined_origin,
                path_template=path_template,
                query_keys=query_keys,
                anchor=anchor,
            )
        )
    return templates, stats


def dedupe_endpoints(endpoints: Iterable[EndpointTemplate]) -> list[EndpointTemplate]:
    """跨 JS 文件按同一去重键合并（保留首次锚点，累加出现次数）。"""
    merged: list[EndpointTemplate] = []
    index_of: dict[tuple[str, str, tuple[str, ...]], int] = {}
    for endpoint in endpoints:
        existing = index_of.get(endpoint.key)
        if existing is None:
            index_of[endpoint.key] = len(merged)
            merged.append(endpoint)
            continue
        head = merged[existing]
        merged[existing] = replace(head, occurrences=head.occurrences + endpoint.occurrences)
    return merged


__all__ = [
    "MAX_ANCHOR_LITERAL",
    "MAX_LITERAL",
    "EndpointAnchor",
    "EndpointTemplate",
    "ExtractStats",
    "dedupe_endpoints",
    "extract_endpoints",
]
