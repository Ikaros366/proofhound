"""katana JSONL → ``CrawlRecord`` / ``JsDocument``（M24-a 解析层）。

## 为什么从既有产物里捞 JS

JS 接口发现的**原料早就在盘上**：katana ``-jsonl`` 的每条记录都带
``response.body``，被爬到的 ``.js`` 文件正文就在里面（M16-a 实测，见交接单
§1）。故本模块**不重新抓取**任何东西——读一份既有 JSONL，把记录归一成
:class:`CrawlRecord`，把 JS 记录按正文 sha256 去重成 :class:`JsDocument`。
补抓只在正文缺失时由 ``--fetch-missing`` 显式开启（scope 校验在
:func:`proofhound.jsimport.probe.run_jsimport` 里做）。

## 三个产物

1. :attr:`CrawlBundle.records`：全部可用记录（GET ∧ 带整数 ``status_code``）；
2. :attr:`CrawlBundle.js_documents`：JS 正文，**按正文 sha256 去重**——同一份
   JS 被多个 URL 引用时只解析一次，全部 URL 记在 :attr:`JsDocument.urls`；
3. :attr:`CrawlBundle.observed`：2xx 记录 = A 类候选的"观测实例"来源
   （模板匹配见 :mod:`proofhound.jsimport.match`）。

## 容错纪律（与 ``tools/parsers/katana_jsonl.py`` 同一风格）

逐行 ``json.loads``；坏行**计数跳过**，不炸整批。缺 ``request`` / ``endpoint``
/ ``response`` / ``status_code`` 的记录与非 GET 记录分别计数——**不发请求体**
是硬边界（交接单 §4.6），非 GET 记录直接丢弃而不是"试着改发一下"。

## ``Source`` 抽象（为 M24-c 留口）

:class:`CrawlSource` 是"爬行产物来源"的协议，本里程碑只实现
:class:`KatanaJsonlSource`。M24-c 的 Burp XML 包只需另实现一个
``parse() -> ParsedSource``，下游（抽取/匹配/探测）一行不用改。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from typing import Iterable, Protocol, Sequence
from urllib.parse import urlparse

#: 单次导入最多解析的 JS 文件数（交接单 §4.7；超限记 capped，不静默丢）
DEFAULT_MAX_JS_FILES = 50
#: 单个 JS 文件正文的字节上限（交接单 §4.7；超限记 oversized，不解析）
DEFAULT_MAX_JS_BYTES = 5 * 1024 * 1024

#: ``Content-Type`` 里出现即视为 JS（与 ``.js`` 后缀互为补充，任一命中即可）
_JS_CONTENT_TYPE_MARKERS = ("javascript", "ecmascript")


def _sha256_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _content_type(headers) -> str:
    """从 katana 记录的 ``response.headers`` 取 ``Content-Type``（大小写不敏感）。"""
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == "content-type" and isinstance(value, str):
            return value
    return ""


def is_js_url(url: str) -> bool:
    """URL 的 path 以 ``.js`` 结尾（忽略 query/fragment）。"""
    return (urlparse(url).path or "").lower().endswith(".js")


def is_js_content_type(content_type: str) -> bool:
    """``Content-Type`` 含 javascript/ecmascript。"""
    lowered = (content_type or "").lower()
    return any(marker in lowered for marker in _JS_CONTENT_TYPE_MARKERS)


@dataclass(frozen=True)
class CrawlRecord:
    """一条可用的爬行记录（GET ∧ 有状态码；正文可能为空）。"""

    #: 全局序号（跨来源文件累加，1 起）——证据"包内第一条"的排序依据
    order: int
    #: 来源标识（通常是文件路径；写进 ``evidence_ref`` 的行号锚点）
    source: str
    #: 来源文件内的 1 起行号
    lineno: int
    url: str
    method: str
    status: int | None
    content_type: str
    body: str
    body_sha256: str
    error: str | None = None

    @property
    def evidence_ref(self) -> str:
        """证据锚点：``<来源>#L<行号>``（与仓库其余解析器同一形态）。"""
        return f"{self.source}#L{self.lineno}"

    @property
    def origin(self) -> str:
        parsed = urlparse(self.url)
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    @property
    def path(self) -> str:
        return urlparse(self.url).path or "/"

    @property
    def is_ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def as_dict(self) -> dict:
        """落 ``crawl.jsonl`` 的形态（**不含 Cookie / 请求头 / 正文**）。"""
        return {
            "order": self.order,
            "source": self.source,
            "lineno": self.lineno,
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "content_type": self.content_type,
            "body_sha256": self.body_sha256,
            "bytes": len(self.body.encode("utf-8")),
            "error": self.error,
        }


@dataclass(frozen=True)
class JsDocument:
    """一份去重后的 JS 正文（同正文多 URL 只解析一次）。"""

    sha256: str
    body: str
    urls: tuple[str, ...]
    order: int
    content_type: str

    @property
    def name(self) -> str:
        """证据文件名：``<sha256 前 8 位>.js``。"""
        return f"{self.sha256[:8]}.js"

    @property
    def size(self) -> int:
        return len(self.body.encode("utf-8"))

    @property
    def primary_url(self) -> str:
        return self.urls[0]

    @property
    def origin(self) -> str:
        parsed = urlparse(self.primary_url)
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    def as_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "file": self.name,
            "urls": list(self.urls),
            "bytes": self.size,
            "first_order": self.order,
            "content_type": self.content_type,
        }


@dataclass
class ParsedSource:
    """一个来源的解析结果（计数进 summary 与审计）。"""

    name: str
    records: list[CrawlRecord] = field(default_factory=list)
    skipped_lines: int = 0
    skipped_records: int = 0
    non_get_records: int = 0


class CrawlSource(Protocol):
    """爬行产物来源（M24-a 只有 katana JSONL；M24-c 另实现 Burp 包）。"""

    @property
    def name(self) -> str:
        """来源标识（进审计与证据锚点）。"""

    def parse(self) -> ParsedSource:
        """解析成记录集合（坏行只计数，不抛出）。"""


@dataclass
class CrawlBundle:
    """一份或多份来源合并后的爬行产物。"""

    records: list[CrawlRecord] = field(default_factory=list)
    js_documents: list[JsDocument] = field(default_factory=list)
    skipped_lines: int = 0
    skipped_records: int = 0
    non_get_records: int = 0
    #: 是 JS 但正文缺失的 URL（``--fetch-missing`` 的补抓清单）
    js_body_missing: list[str] = field(default_factory=list)
    #: 超过单文件字节上限而**未解析**的 JS URL
    oversized_js: list[str] = field(default_factory=list)
    #: 被 JS 文件数上限挡掉（未解析）的不同正文数
    capped_js: int = 0
    #: 正文相同、URL 不同的重复 JS 记录数（去重生效的证据）
    duplicate_js: int = 0

    @property
    def observed(self) -> list[CrawlRecord]:
        """本次爬行真实请求过且 **2xx** 的记录（A 类候选的实例来源）。"""
        return [record for record in self.records if record.is_ok]

    @property
    def js_urls(self) -> list[str]:
        """全部 JS 记录的 URL（去重后文档的 + 正文缺失的 + 超限的）。"""
        urls: list[str] = []
        for document in self.js_documents:
            urls.extend(document.urls)
        urls.extend(self.js_body_missing)
        urls.extend(self.oversized_js)
        return urls

    def as_dict(self) -> dict:
        """落 ``summary.json`` 的爬行段（**不含时间戳**，保证逐字节可复现）。"""
        return {
            "records": len(self.records),
            "skipped_lines": self.skipped_lines,
            "skipped_records": self.skipped_records,
            "non_get_records": self.non_get_records,
            "js_documents": len(self.js_documents),
            "js_body_missing": list(self.js_body_missing),
            "oversized_js": list(self.oversized_js),
            "capped_js": self.capped_js,
            "duplicate_js": self.duplicate_js,
        }


def parse_katana_text(text: str, *, name: str) -> ParsedSource:
    """解析一段 katana JSONL 文本（独立成函数，单测不必落盘）。"""
    parsed = ParsedSource(name=name)
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue  # 空行（多轮 katana 输出拼接时会出现）不是坏行
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            parsed.skipped_lines += 1
            continue
        if not isinstance(data, dict):
            parsed.skipped_lines += 1
            continue
        request = data.get("request")
        response = data.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            # katana 的失败记录只有 {"request":…, "error":…}，无 response 段
            parsed.skipped_records += 1
            continue
        endpoint = request.get("endpoint")
        status = response.get("status_code")
        if not isinstance(endpoint, str) or not endpoint or not isinstance(status, int):
            parsed.skipped_records += 1
            continue
        method = request.get("method")
        method_text = method if isinstance(method, str) else ""
        if method_text.upper() != "GET":
            parsed.non_get_records += 1
            continue
        body = response.get("body")
        body_text = body if isinstance(body, str) else ""
        parsed.records.append(
            CrawlRecord(
                order=0,
                source=name,
                lineno=lineno,
                url=endpoint,
                method="GET",
                status=status,
                content_type=_content_type(response.get("headers")),
                body=body_text,
                body_sha256=_sha256_text(body_text),
                error=None,
            )
        )
    return parsed


class KatanaJsonlSource:
    """katana ``-jsonl`` 输出文件（``Source`` 的 M24-a 唯一实现）。"""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @property
    def name(self) -> str:
        return str(self.path)

    def parse(self) -> ParsedSource:
        text = self.path.read_bytes().decode("utf-8", errors="replace")
        return parse_katana_text(text, name=self.name)


def load_crawl(
    sources: Iterable[CrawlSource],
    *,
    max_js_files: int = DEFAULT_MAX_JS_FILES,
    max_js_bytes: int = DEFAULT_MAX_JS_BYTES,
) -> CrawlBundle:
    """合并解析多个来源，并按正文 sha256 去重 JS、施加两道上限。"""
    bundle = CrawlBundle()
    order = 0
    #: 去重键（正文 sha256）→ 文档下标；保持"首见"顺序
    index_of: dict[str, int] = {}
    for source in sources:
        parsed = source.parse()
        bundle.skipped_lines += parsed.skipped_lines
        bundle.skipped_records += parsed.skipped_records
        bundle.non_get_records += parsed.non_get_records
        for record in parsed.records:
            order += 1
            record = replace(record, order=order)
            bundle.records.append(record)
            if not (is_js_url(record.url) or is_js_content_type(record.content_type)):
                continue
            if not record.body.strip():
                bundle.js_body_missing.append(record.url)
                continue
            size = len(record.body.encode("utf-8"))
            if size > max_js_bytes:
                bundle.oversized_js.append(record.url)
                continue
            existing = index_of.get(record.body_sha256)
            if existing is not None:
                document = bundle.js_documents[existing]
                bundle.js_documents[existing] = replace(
                    document, urls=document.urls + (record.url,)
                )
                bundle.duplicate_js += 1
                continue
            if len(bundle.js_documents) >= max_js_files:
                bundle.capped_js += 1
                continue
            index_of[record.body_sha256] = len(bundle.js_documents)
            bundle.js_documents.append(
                JsDocument(
                    sha256=record.body_sha256,
                    body=record.body,
                    urls=(record.url,),
                    order=record.order,
                    content_type=record.content_type,
                )
            )
    return bundle


def load_katana_jsonl(
    paths: Sequence[str | Path],
    *,
    max_js_files: int = DEFAULT_MAX_JS_FILES,
    max_js_bytes: int = DEFAULT_MAX_JS_BYTES,
) -> CrawlBundle:
    """便捷入口：``paths`` 里的每个文件按 katana JSONL 解析后合并。"""
    return load_crawl(
        [KatanaJsonlSource(path) for path in paths],
        max_js_files=max_js_files,
        max_js_bytes=max_js_bytes,
    )


__all__ = [
    "CrawlBundle",
    "CrawlRecord",
    "CrawlSource",
    "DEFAULT_MAX_JS_BYTES",
    "DEFAULT_MAX_JS_FILES",
    "JsDocument",
    "KatanaJsonlSource",
    "ParsedSource",
    "is_js_content_type",
    "is_js_url",
    "load_crawl",
    "load_katana_jsonl",
    "parse_katana_text",
]
