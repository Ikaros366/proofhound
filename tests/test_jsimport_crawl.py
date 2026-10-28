"""M24-a 解析层：katana JSONL → ``CrawlRecord`` / ``JsDocument``。

golden fixture ``tests/fixtures/katana_js_spa_1_7.jsonl`` 的前三条是 M16-a 实测
产物（``evidence/demo_katana_js/20260929T095428Z/…``）的**逐字拷贝**，其余是补造
的边界形态（POST / 无 response / 正文缺失 / 同正文不同 URL / 坏行 / 空行）。

锁四件事：

1. **坏行/缺项只计数，不炸整批**（交接单 §5.1）；
2. **JS 判定双通道**：``.js`` 后缀 **∨** Content-Type 含 javascript（缺一都会漏）；
3. **同正文按 sha256 去重**，但**全部 URL 保留**（证据里要能追到来源）；
4. **两道上限**（JS 文件数 / 单文件字节）显式记 capped / oversized，
   **不静默丢**（交接单 §8）。
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from proofhound.jsimport.crawl import (
    DEFAULT_MAX_JS_FILES,
    JsDocument,
    ParsedSource,
    is_js_content_type,
    is_js_url,
    load_crawl,
    load_katana_jsonl,
    parse_katana_text,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "katana_js_spa_1_7.jsonl"
BASE = "http://127.0.0.1:48503"


class _Source:
    """内联字符串来源（避免为每种边界形态都落盘）。"""

    def __init__(self, text: str) -> None:
        self._text = text

    @property
    def name(self) -> str:
        return "inline"

    def parse(self) -> ParsedSource:
        return parse_katana_text(self._text, name=self.name)


def _record(
    endpoint: str,
    *,
    method: str = "GET",
    status: int = 200,
    body: str = "",
    content_type: str = "text/html; charset=utf-8",
) -> str:
    return json.dumps(
        {
            "timestamp": "2026-10-28T00:00:00.000000Z",
            "request": {"method": method, "endpoint": endpoint, "raw": "GET / HTTP/1.1\r\n\r\n"},
            "response": {
                "status_code": status,
                "headers": {"Content-Type": content_type},
                "body": body,
                "content_length": len(body.encode("utf-8")),
                "raw": f"HTTP/1.1 {status} X\r\n\r\n{body}",
            },
        },
        ensure_ascii=False,
    )


def _bundle(text: str, **kwargs):
    return load_crawl([_Source(text)], **kwargs)


# --------------------------------------------------------------- golden fixture


def test_golden_fixture_counts_every_line_class():
    """坏行 / 结构缺项 / 非 GET 三类各自计数——不合并成"跳过 N 行"。"""
    bundle = load_katana_jsonl([FIXTURE])
    assert len(bundle.records) == 5
    assert bundle.skipped_lines == 1  # JSON 截断
    assert bundle.skipped_records == 1  # 只有 request+error，没有 response
    assert bundle.non_get_records == 1  # POST 记录
    assert not bundle.oversized_js
    assert not bundle.capped_js


def test_golden_fixture_dedupes_js_by_body_sha_but_keeps_all_urls():
    """同一份 app.js 被两个 URL 引用 ⇒ 只解析一次，两个 URL 都在证据里。"""
    bundle = load_katana_jsonl([FIXTURE])
    assert len(bundle.js_documents) == 1
    assert bundle.duplicate_js == 1
    document = bundle.js_documents[0]
    assert document.urls == (f"{BASE}/static/app.js", f"{BASE}/static/app.js?v=2")
    assert document.name == f"{document.sha256[:8]}.js"


def test_golden_fixture_records_js_body_missing_explicitly():
    """正文缺失记 ``js_body_missing``——不静默当空文件（交接单 §10.2）。"""
    bundle = load_katana_jsonl([FIXTURE])
    assert bundle.js_body_missing == [f"{BASE}/static/empty.js"]


def test_golden_fixture_record_shape_and_anchor():
    """记录字段与证据锚点：``<来源>#L<行号>``，body sha256 可复核。"""
    bundle = load_katana_jsonl([FIXTURE])
    first = bundle.records[0]
    assert first.order == 1
    assert first.url == f"{BASE}/"
    assert first.path == "/"
    assert first.origin == BASE
    assert first.evidence_ref == f"{FIXTURE}#L1"
    assert first.body_sha256 == sha256(first.body.encode("utf-8")).hexdigest()
    assert first.is_ok
    assert [record.order for record in bundle.records] == [1, 2, 3, 4, 5]
    assert bundle.observed[0].url == f"{BASE}/"


def test_golden_fixture_app_js_is_the_real_m16a_body():
    """JS 正文逐字来自 M16-a 产物（含被 katana 漏抽的模板串/普通字面量）。"""
    bundle = load_katana_jsonl([FIXTURE])
    body = bundle.js_documents[0].body
    assert 'fetch("/api/orders?order_id=42&user=1")' in body
    assert "evil.example.com" in body  # 外域绝对 URL 只在正文里，不在 request.endpoint


# --------------------------------------------------------------- JS 判定双通道


def test_js_detected_by_url_suffix_and_by_content_type():
    assert is_js_url(f"{BASE}/static/app.js?v=1")
    assert not is_js_url(f"{BASE}/static/app.json")
    assert is_js_content_type("application/javascript; charset=utf-8")
    assert is_js_content_type("text/ecmascript")
    assert not is_js_content_type("text/html")

    text = "\n".join(
        [
            _record(f"{BASE}/bundle", body="fetch('/api/x')", content_type="application/javascript"),
            _record(f"{BASE}/app.js", body="fetch('/api/y')", content_type="text/plain"),
            _record(f"{BASE}/page", body="<html></html>", content_type="text/html"),
        ]
    )
    bundle = _bundle(text)
    assert len(bundle.js_documents) == 2  # 后缀通道 + Content-Type 通道各命中一条
    assert [doc.primary_url for doc in bundle.js_documents] == [
        f"{BASE}/bundle",
        f"{BASE}/app.js",
    ]


# --------------------------------------------------------------- 上限与容错


def test_max_js_files_cap_is_counted_not_silent():
    text = "\n".join(
        _record(f"{BASE}/a{i}.js", body=f"fetch('/api/v{i}')") for i in range(3)
    )
    bundle = _bundle(text, max_js_files=2)
    assert len(bundle.js_documents) == 2
    assert bundle.capped_js == 1


def test_oversized_js_is_recorded_not_parsed():
    text = _record(f"{BASE}/big.js", body="x" * 600)
    bundle = _bundle(text, max_js_bytes=500)
    assert bundle.js_documents == []
    assert bundle.oversized_js == [f"{BASE}/big.js"]


def test_blank_lines_are_not_bad_lines():
    text = "\n".join(["", _record(f"{BASE}/a.js", body="fetch('/api/a')"), "", ""])
    bundle = _bundle(text)
    assert bundle.skipped_lines == 0
    assert len(bundle.records) == 1


def test_blank_body_js_record_is_missing_not_empty_document():
    bundle = _bundle(_record(f"{BASE}/a.js", body="   \n"))
    assert bundle.js_documents == []
    assert bundle.js_body_missing == [f"{BASE}/a.js"]


def test_default_max_js_files_constant_is_the_documented_cap():
    assert DEFAULT_MAX_JS_FILES == 50


def test_js_document_size_is_utf8_bytes_not_chars():
    document = JsDocument(
        sha256="0" * 64,
        body="// 注释\n" + "x",
        urls=(f"{BASE}/a.js",),
        order=1,
        content_type="",
    )
    assert document.size == len(document.body.encode("utf-8"))
    assert document.size > len(document.body)
