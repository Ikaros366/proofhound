"""M24-a 抽取层：JS 正文 → 接口路径模板 + 锚点。

锁的是交接单 §5.2 的八条规则与 §10 的坑：

- **模板串**（``${id}``）与 **:id 冒号参数**都要归一 ``{param}``；
- **转义** ``\\/`` 与 ``\\u002f`` 必须还原；
- **拼接前缀**（``"/api/" + x``）必须丢弃并计数——拿 ``/api/`` 去探是纯噪声；
- **相对路径**相对 **JS 文件所在目录**（不是页面目录），``baseURL`` 常量参与归并；
- **跨域**直接丢；
- **锚点**用**字节偏移**（单行 minified JS 的行号恒为 1，行号不是有效锚点）。
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from proofhound.jsimport.crawl import JsDocument, load_katana_jsonl
from proofhound.jsimport.extract import (
    EndpointTemplate,
    dedupe_endpoints,
    extract_endpoints,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "katana_js_spa_1_7.jsonl"


def _doc(body: str, url: str = "http://h.example/static/app.js") -> JsDocument:
    return JsDocument(
        sha256=sha256(body.encode("utf-8")).hexdigest(),
        body=body,
        urls=(url,),
        order=1,
        content_type="application/javascript",
    )


def _templates(body: str, url: str = "http://h.example/static/app.js"):
    return extract_endpoints(_doc(body, url))


# --------------------------------------------------------------- 字面量形态


def test_quoted_literals_dedupe_across_quote_styles():
    body = "fetch(\"/api/a\"); fetch('/api/a'); const t = `/api/a`;"
    templates, stats = _templates(body)
    assert [item.path_template for item in templates] == ["/api/a"]
    assert templates[0].occurrences == 3
    assert stats.duplicates == 2


def test_template_string_becomes_param():
    templates, _ = _templates("fetch(`/api/notes/${id}`);")
    assert [item.path_template for item in templates] == ["/api/notes/{param}"]


def test_template_string_query_values_become_keys_only():
    templates, _ = _templates("fetch(`/api/x?id=${id}&mode=list`);")
    template = templates[0]
    assert template.path_template == "/api/x"
    assert template.query_keys == ("id", "mode")


def test_colon_path_param_becomes_param():
    templates, _ = _templates('fetch("/api/users/:id/profile");')
    assert templates[0].path_template == "/api/users/{param}/profile"


def test_escaped_slashes_are_unescaped():
    body = 'const a = "\\/api\\/x"; const b = "\\u002fapi\\u002fesc";'
    templates, _ = _templates(body)
    assert {item.path_template for item in templates} == {"/api/x", "/api/esc"}


def test_concat_prefix_is_dropped_and_counted():
    """``"/api/" + id`` 只留前缀 ⇒ 丢弃（否则会拿 ``/api/`` 去探）。"""
    templates, stats = _templates('const url = "/api/" + id;')
    assert templates == []
    assert stats.fragment_dropped == 1


def test_concat_with_literal_string_is_not_a_fragment():
    """``"/api/x" + "/y"`` 是字符串拼接，不是"前缀片段"——两个都是完整字面量。

    （刻意**不**重建拼接结果：那需要表达式求值；``+ 变量`` 才是被丢弃的前缀片段。）
    """
    found, stats = _templates('const url = "/api/x" + "/y";')
    assert stats.fragment_dropped == 0
    assert [item.path_template for item in found] == ["/api/x", "/y"]


def test_static_and_scheme_literals_are_filtered():
    body = (
        '"/static/app.css" "/assets/logo.png" "/fonts/x.woff2" '
        '"javascript:void(0)" "#/route" "data:text/html,x" "/img/a.svg"'
    )
    templates, stats = _templates(body)
    assert templates == []
    assert stats.filtered_static == 4  # 四个静态资源路径
    assert stats.filtered_not_path == 3  # javascript: / # / data:


def test_plain_words_are_not_paths():
    found, stats = _templates('const method = "GET"; const n = "hello world";')
    assert found == []
    assert stats.filtered_not_path == 2


def test_root_relative_literal_uses_origin():
    templates, _ = _templates('fetch("/api/x");', url="http://h.example/deep/dir/app.js")
    assert templates[0].origin == "http://h.example"
    assert templates[0].path_template == "/api/x"


# --------------------------------------------------------------- 相对路径


def test_relative_literal_resolves_against_js_directory():
    """``api/x`` 相对 **JS 文件所在目录**，不是页面目录（交接单 §10.5）。"""
    templates, _ = _templates('fetch("api/users/1");', url="http://h.example/static/js/app.js")
    assert templates[0].path_template == "/static/js/api/users/1"
    assert templates[0].origin == "http://h.example"


def test_base_url_constant_prefixes_relative_literals():
    """``baseURL`` 常量参与 ``urljoin``：相对字面量不再是相对 JS 目录。"""
    body = 'const baseURL = "/backend"; fetch("api/users/1");'
    templates, stats = _templates(body, url="http://h.example/static/app.js")
    assert [item.path_template for item in templates] == [
        "/backend",  # 常量本身也是路径形状的字面量（候选过滤会把它收敛成清单）
        "/backend/api/users/1",
    ]
    assert stats.base == "http://h.example/backend/"


def test_explicit_base_overrides_body_constant():
    body = 'const baseURL = "/backend"; fetch("api/users/1");'
    templates, _ = extract_endpoints(_doc(body), base="/v1")
    assert [item.path_template for item in templates] == ["/backend", "/v1/api/users/1"]


# --------------------------------------------------------------- 跨域


def test_cross_origin_literals_are_dropped():
    body = 'fetch("https://evil.example.com/api/steal?id=7"); fetch("http://h.example/api/ok");'
    templates, stats = _templates(body)
    assert [item.path_template for item in templates] == ["/api/ok"]
    assert stats.out_of_scope == 1


def test_protocol_relative_literal_is_not_a_path():
    templates, stats = _templates('fetch("//evil.example.com/api/x");')
    assert templates == []
    assert stats.filtered_not_path == 1


# --------------------------------------------------------------- 归一化与锚点


def test_query_keys_keep_first_seen_order_and_dedupe():
    templates, _ = _templates('fetch("/api/x?b=2&a=1&b=3");')
    assert templates[0].query_keys == ("b", "a")


def test_duplicate_key_uses_sorted_query_keys():
    """``?b=1&a=2`` 与 ``?a=1&b=2`` 是同一去重键（键集相同 ⇒ 同一接口）。"""
    templates, stats = _templates('fetch("/api/x?b=1&a=2"); fetch("/api/x?a=1&b=2");')
    assert len(templates) == 1
    assert stats.duplicates == 1


def test_anchor_offset_points_at_literal_and_line_matches():
    body = 'const a = 1;\nfetch("/api/x");\n'
    templates, _ = _templates(body)
    anchor = templates[0].anchor
    assert body.encode("utf-8")[anchor.offset : anchor.offset + len("/api/x")] == b"/api/x"
    assert anchor.line == 2
    assert anchor.literal == "/api/x"


def test_minified_single_line_anchor_uses_offset():
    """单行 minified JS：line 恒为 1，**offset 才是有效锚点**（交接单 §10.3）。"""
    body = "var a=1;var b=2;" + 'fetch("/api/deep/thing");'
    templates, _ = _templates(body)
    anchor = templates[0].anchor
    assert anchor.line == 1
    assert anchor.offset == len(b"var a=1;var b=2;fetch(") + 1


def test_anchor_literal_is_truncated_to_200():
    long_path = "/api/" + "a" * 250
    templates, _ = _templates(f'fetch("{long_path}");')
    assert len(templates[0].anchor.literal) == 200


def test_occurrences_merge_across_documents():
    first, _ = _templates('fetch("/api/x");', url="http://h.example/a.js")
    second, _ = _templates('fetch("/api/x");', url="http://h.example/b.js")
    merged = dedupe_endpoints(first + second)
    assert len(merged) == 1
    assert merged[0].occurrences == 2


# --------------------------------------------------------------- 真实产物


def test_golden_app_js_extracts_fourteen_templates_and_drops_external_urls():
    bundle = load_katana_jsonl([FIXTURE])
    templates, stats = extract_endpoints(bundle.js_documents[0])
    assert len(templates) == 14
    assert stats.out_of_scope == 4  # evil.example.com ×3 + cdn.evil-other.example.org ×1
    assert stats.filtered_not_path == 1  # $.ajax 的 method: "GET"
    assert all(item.origin == "http://127.0.0.1:48503" for item in templates)
    assert "/api/orders" in {item.path_template for item in templates}


def test_golden_app_js_templates_are_typed():
    bundle = load_katana_jsonl([FIXTURE])
    templates, _ = extract_endpoints(bundle.js_documents[0])
    by_path = {item.path_template: item for item in templates}
    assert by_path["/api/v2/thing"].query_keys == ("thing_id", "verbose")
    assert by_path["/api/item/detail"].query_keys == ()
    assert isinstance(by_path["/api/user"], EndpointTemplate)
    assert by_path["/api/user"].js_sha256 == bundle.js_documents[0].sha256
