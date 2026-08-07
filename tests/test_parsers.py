"""httpx 输出解析器单元测试（M2b）。"""

from proofhound.tools.parsers import PARSER_REGISTRY, parse_httpx_jsonl

SAMPLE = """\
{"url":"http://127.0.0.1:8000","host":"127.0.0.1","port":8000,"status_code":200,"title":"Index","tech":["nginx"]}
{"url":"http://127.0.0.1:8000/admin","status_code":403,"title":"Forbidden"}
this is not json
{"status_code":500}
{"url":"http://127.0.0.1:8000/api","status_code":401}
"""


def test_parse_httpx_jsonl():
    signals, skipped = parse_httpx_jsonl(
        SAMPLE, evidence_path="evidence/abc.stdout.log", skill="web-scan"
    )
    assert skipped == 2  # 坏行 + 缺 url/host 行
    assert len(signals) == 3

    first = signals[0]
    assert first.asset == "http://127.0.0.1:8000"
    assert first.status_code == 200
    assert first.title == "Index"
    assert first.tech == ["nginx"]
    assert first.evidence_ref == "evidence/abc.stdout.log#L1"
    assert first.skill == "web-scan"
    assert first.source_tool == "httpx"
    assert first.kind == "web-probe"

    assert signals[1].evidence_ref.endswith("#L2")
    assert signals[2].status_code == 401
    assert signals[2].tech == []


def test_parse_empty():
    signals, skipped = parse_httpx_jsonl("", evidence_path="x", skill="web-scan")
    assert signals == []
    assert skipped == 0


def test_registry_wiring():
    assert PARSER_REGISTRY["httpx_json"] is parse_httpx_jsonl
