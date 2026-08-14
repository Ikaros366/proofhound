"""katana 解析器 M8a 扩展测试：POST 表单页 → form_page Signal。

覆盖：显式 POST（大小写不敏感）/ method 缺省 + action + 密码/文本字段
（规则 B）、显式 get 不产、无 name 字段过滤、相对/跨域 action（同源防线
fail-closed）、同页多表单字段并集、同 URL 双 kind 共存（(kind, asset)
去重）、坏行计数不受影响。
"""

import json

from proofhound.tools.parsers import parse_katana_jsonl


def _line(request: dict, response: dict | None = None) -> str:
    record = {"timestamp": "2026-08-14T00:00:00Z", "request": request}
    if response is not None:
        record["response"] = response
    return json.dumps(record)


def _page(url: str, body: str, status: int = 200) -> str:
    return _line(
        {"method": "GET", "endpoint": url},
        {"status_code": status, "body": body},
    )


def test_post_form_page_signal_fields_exact():
    """显式 POST 表单页：asset=页面裸 URL，字段含 select/textarea/submit，
    button/reset/file/image 不收，无 name 字段过滤。"""
    body = (
        '<form action="/do" method="post">'
        '<input type="text" name="username">'
        '<input type="password" name="password">'
        '<select name="cat"><option>1</option></select>'
        '<textarea name="q"></textarea>'
        '<input type="submit" name="Login" value="Login">'
        '<input type="button" name="btn">'
        '<input type="reset" name="rst">'
        '<input type="file" name="up">'
        '<input type="image" name="img">'
        '<input type="text">'  # 无 name → 过滤
        "</form>"
    )
    signals, skipped = parse_katana_jsonl(
        _page("http://h.tld/login", body), evidence_path="k.log", skill="recon-crawl"
    )
    assert skipped == 0
    assert len(signals) == 1
    signal = signals[0]
    assert signal.kind == "form_page"
    assert signal.asset == "http://h.tld/login"  # 页面 URL 本身，不拼参数
    assert signal.form_fields == ["username", "password", "cat", "q", "Login"]
    assert signal.evidence_ref == "k.log#L1"
    assert signal.status_code == 200


def test_method_case_insensitive():
    """POST/Post/Post 大小写混合 method 均识别。"""
    for method in ("post", "POST", "Post", "pOsT"):
        body = f'<form method="{method}" action="/d"><input name="id"></form>'
        signals, _ = parse_katana_jsonl(
            _page("http://h.tld/p", body), evidence_path="k.log", skill="s"
        )
        assert [s.kind for s in signals] == ["form_page"], method
        assert signals[0].form_fields == ["id"]


def test_rule_b_default_method_with_text_field():
    """规则 B：method 缺省 + 非空 action + 文本字段（type 缺省按 text）。
    分支 B（GET 合成）与 form_page 双产：method 缺省表单两种解读都保留。"""
    body = '<form action="/login.php"><input name="username"></form>'
    signals, _ = parse_katana_jsonl(
        _page("http://h.tld/auth/page", body), evidence_path="k.log", skill="s"
    )
    assert [(s.kind, s.asset) for s in signals] == [
        ("param-endpoint", "http://h.tld/login.php?username=1"),  # 分支 B 不变
        ("form_page", "http://h.tld/auth/page"),  # asset 是页面而非 action
    ]
    assert signals[1].form_fields == ["username"]


def test_rule_b_password_field():
    """规则 B：缺省 method + action + 密码字段 → 产 form_page。"""
    body = '<form action="/auth"><input type="password" name="pw"></form>'
    signals, _ = parse_katana_jsonl(
        _page("http://h.tld/p", body), evidence_path="k.log", skill="s"
    )
    assert [s.kind for s in signals] == ["param-endpoint", "form_page"]
    assert signals[1].form_fields == ["pw"]


def test_rule_b_requires_action_and_text_password():
    """规则 B 边界：缺省 method 无 action → 不产（仍走分支 B 合成）；
    缺省 method + action 但仅 hidden 字段（非密码/文本）→ 不产。"""
    # 无 action：不产 form_page，分支 B 照旧合成 GET URL
    signals, _ = parse_katana_jsonl(
        _page("http://h.tld/p", "<form><input name='id'></form>"),
        evidence_path="k.log",
        skill="s",
    )
    assert [(s.kind, s.asset) for s in signals] == [
        ("param-endpoint", "http://h.tld/p?id=1")
    ]
    # 仅 hidden 字段：无密码/文本字段，规则 B 不命中；分支 B 照常合成
    body = '<form action="/s"><input type="hidden" name="token" value="x"></form>'
    signals, _ = parse_katana_jsonl(
        _page("http://h.tld/p", body), evidence_path="k.log", skill="s"
    )
    assert [(s.kind, s.asset) for s in signals] == [
        ("param-endpoint", "http://h.tld/s?token=x")
    ]


def test_explicit_get_form_never_form_page():
    """显式 method=get 的表单不产 form_page（只走分支 B 合成）。"""
    body = '<form method="get" action="/s"><input type="text" name="q"></form>'
    signals, _ = parse_katana_jsonl(
        _page("http://h.tld/p", body), evidence_path="k.log", skill="s"
    )
    assert [(s.kind, s.asset) for s in signals] == [
        ("param-endpoint", "http://h.tld/s?q=1")
    ]


def test_relative_action_same_origin():
    """相对 action 同源 → 产 form_page（asset 仍是页面 URL）；空 action /
    裸 fragment action = 页面自身，同源。"""
    for action in ("/do", "submit.php", "", "#"):
        body = f'<form method="post" action="{action}"><input name="id"></form>'
        signals, _ = parse_katana_jsonl(
            _page("http://h.tld:8080/app/p", body), evidence_path="k.log", skill="s"
        )
        assert [s.kind for s in signals] == ["form_page"], action
        assert signals[0].asset == "http://h.tld:8080/app/p"


def test_cross_origin_action_skipped_fail_closed():
    """同源防线：action 跨域（异 host/异端口）→ 不产 form_page（fail-closed，
    forms 模式 sqlmap 实际 POST 目标是 action，须处于 -u 的 scope 覆盖面内）。"""
    for action in ("http://evil.tld/do", "//evil.tld/do", "http://h.tld:9090/do"):
        body = f'<form method="post" action="{action}"><input name="id"></form>'
        signals, skipped = parse_katana_jsonl(
            _page("http://h.tld:8080/p", body), evidence_path="k.log", skill="s"
        )
        assert signals == [], action
        assert skipped == 0


def test_all_unnamed_fields_no_signal():
    """POST 表单全是无 name 字段 → 无可测试字段，不产信号（不计坏行）。"""
    body = '<form action="/do" method="post"><input type="text"></form>'
    signals, skipped = parse_katana_jsonl(
        _page("http://h.tld/p", body), evidence_path="k.log", skill="s"
    )
    assert signals == []
    assert skipped == 0


def test_multiple_post_forms_union_fields():
    """同页多个合格 POST 表单：字段名并集进一条信号（保序去重）。"""
    body = (
        '<form method="post" action="/a"><input name="id"><input name="x"></form>'
        '<form method="POST" action="/b"><input name="page"><input name="id"></form>'
    )
    signals, _ = parse_katana_jsonl(
        _page("http://h.tld/p", body), evidence_path="k.log", skill="s"
    )
    assert [s.kind for s in signals] == ["form_page"]
    assert signals[0].form_fields == ["id", "x", "page"]


def test_dual_kind_coexist_same_url():
    """带 query 的 GET 端点页面内含 POST 表单：param-endpoint 与 form_page
    两种 kind 都保留（去重键为 (kind, asset)）；同 kind 跨行去重。"""
    lines = [
        _page(
            "http://h.tld/p?x=1",
            '<form method="post" action="#"><input name="id"></form>',
        ),
        _page(  # 同 URL 再次出现：两 kind 均按首见锚点去重
            "http://h.tld/p?x=1",
            '<form method="post" action="#"><input name="id"></form>',
        ),
    ]
    signals, skipped = parse_katana_jsonl(
        "\n".join(lines), evidence_path="k.log", skill="s"
    )
    assert skipped == 0
    assert [(s.kind, s.asset, s.evidence_ref) for s in signals] == [
        ("param-endpoint", "http://h.tld/p?x=1", "k.log#L1"),
        ("form_page", "http://h.tld/p?x=1", "k.log#L1"),
    ]
    assert signals[1].form_fields == ["id"]


def test_bad_lines_unaffected_by_form_detection():
    """坏行计数不受影响：坏 JSON 计坏行，POST 表单页正常产信号。"""
    text = "\n".join(
        [
            "{bad json",
            _page(
                "http://h.tld/p",
                '<form method="post" action="/d"><input name="id"></form>',
            ),
        ]
    )
    signals, skipped = parse_katana_jsonl(text, evidence_path="k.log", skill="s")
    assert skipped == 1
    assert [s.kind for s in signals] == ["form_page"]
