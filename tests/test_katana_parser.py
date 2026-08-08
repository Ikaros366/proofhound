"""katana JSONL 解析器测试（M3d）：fixture 快照 + 分支 B 表单合成 + 坏行容错。"""

import json
from pathlib import Path

from proofhound.tools.parsers import parse_katana_jsonl

FIXTURE = Path(__file__).parent / "fixtures" / "katana_dvwa_1_7.jsonl"


def _line(request: dict, response: dict | None = None) -> str:
    record = {"timestamp": "2026-08-08T00:00:00Z", "request": request}
    if response is not None:
        record["response"] = response
    return json.dumps(record)


def test_fixture_snapshot():
    """DVWA 真实输出（脱敏）快照：8 行 → 5 条 param-endpoint Signal。"""
    text = FIXTURE.read_text(encoding="utf-8")
    signals, skipped = parse_katana_jsonl(
        text, evidence_path="katana.log", skill="recon-crawl"
    )
    assert skipped == 0
    assert [(s.asset, s.evidence_ref) for s in signals] == [
        ("http://127.0.0.1:8080/vulnerabilities/xss_r/?name=1", "katana.log#L2"),
        (
            "http://127.0.0.1:8080/vulnerabilities/fi/?page=include.php",
            "katana.log#L3",
        ),
        (
            "http://127.0.0.1:8080/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
            "katana.log#L5",
        ),
        (
            "http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit",
            "katana.log#L6",
        ),
        (
            "http://127.0.0.1:8080/vulnerabilities/brute/?username=1&password=1&Login=Login",
            "katana.log#L7",
        ),
    ]
    assert all(s.kind == "param-endpoint" for s in signals)
    assert all(s.source_tool == "katana" for s in signals)
    assert signals[3].status_code == 200  # sqli 页带响应状态码


def test_bad_lines_counted_fail_closed():
    """坏行计数不抛：坏 JSON / 非 dict / 缺 request / 缺 endpoint。"""
    text = "\n".join(
        [
            "{bad json",
            '["not a dict"]',
            json.dumps({"response": {"status_code": 200}}),  # 无 request 段
            _line({"method": "GET"}),  # 无 endpoint
            _line(
                {"method": "GET", "endpoint": "http://h.tld/a?x=1"},
                {"status_code": 200},
            ),
        ]
    )
    signals, skipped = parse_katana_jsonl(
        text, evidence_path="k.log", skill="recon-crawl"
    )
    assert skipped == 4
    assert [s.asset for s in signals] == ["http://h.tld/a?x=1"]


def test_non_get_and_no_query_dropped():
    """POST 端点、无 query 端点、POST 表单一律不产 Signal（不计坏行）。"""
    text = "\n".join(
        [
            _line(
                {"method": "POST", "endpoint": "http://h.tld/login?a=1"},
                {"status_code": 200},
            ),
            _line(
                {"method": "GET", "endpoint": "http://h.tld/plain"},
                {"status_code": 200},
            ),
            _line(
                {"method": "GET", "endpoint": "http://h.tld/postform"},
                {
                    "status_code": 200,
                    "body": '<form action="/do" method="post">'
                    '<input type="text" name="id"></form>',
                },
            ),
        ]
    )
    signals, skipped = parse_katana_jsonl(
        text, evidence_path="k.log", skill="recon-crawl"
    )
    assert signals == []
    assert skipped == 0


def test_form_synthesis_semantics():
    """分支 B：action 相对解析、fragment 剥离、method 缺省按 GET、
    button/reset 不收、跨行去重（首见锚点）。"""
    body = (
        '<form action="search.php#frag">'
        '<input type="text" name="q">'
        '<input type="hidden" name="page" value="2">'
        '<input type="button" name="ignoreme">'
        '<input type="reset" name="alsono">'
        '<input type="submit" value="Go">'
        "</form>"
        "<form method='GET' action=''><input name='id'></form>"
    )
    lines = [
        _line(
            {"method": "GET", "endpoint": "http://h.tld/app/index.php"},
            {"status_code": 200, "body": body},
        ),
        _line(  # 同表单另一页：合成 URL 与前重复 → 去重
            {"method": "GET", "endpoint": "http://h.tld/app/other.php"},
            {"status_code": 200, "body": "<form><input name='id'></form>"},
        ),
    ]
    signals, skipped = parse_katana_jsonl(
        "\n".join(lines), evidence_path="k.log", skill="recon-crawl"
    )
    assert skipped == 0
    assert [(s.asset, s.evidence_ref) for s in signals] == [
        ("http://h.tld/app/search.php?q=1&page=2", "k.log#L1"),  # fragment 剥离
        ("http://h.tld/app/index.php?id=1", "k.log#L1"),  # 空 action → 页面自身
        ("http://h.tld/app/other.php?id=1", "k.log#L2"),
    ]
