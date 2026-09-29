"""M16-b：dirsearch JSON 报告解析器（零新增 Signal kind）。

锁定四类契约：

1. **判据字段 vs 证据字段分离**——`results[].url`/`status` 决定候选；
   `contentLength`/`contentType`/`elapsed`/`redirect` 只进 ``note``，不参与判定；
2. **产既有 ``web-probe`` kind**，从而走 M3a 起就有的 ``web-exposure`` 映射；
3. **fail-closed 容错**：坏 JSON / 结构不符 / 非 http(s) URL 一律丢弃计数，
   绝不猜、绝不造候选；
4. wrapper 的音量形态：stdout = dirsearch 自己的结果行 + ``cat`` 出来的 JSON 报告，
   解析器只认后者。
"""

from __future__ import annotations

import json

import pytest

from proofhound.core.orchestrator import _triage_candidates
from proofhound.tools.parsers import PARSER_REGISTRY, parse_dirsearch_json

EV = "/ev/dirsearch_stdout.txt"

#: 真实形态：dirsearch 结果行（噪声）+ wrapper cat 出的 JSON 报告
REAL_SHAPE = "\n".join([
    "[13:21:03] 200 -    27B - http://127.0.0.1:44899/admin",
    "[13:21:03] 200 -    27B - http://127.0.0.1:44899/api",
    "{",
    '    "info": {',
    '        "args": "/opt/tools/dirsearch/lib/bin/dirsearch -u http://127.0.0.1:44899",',
    '        "time": "2026-09-29 13:21:02"',
    "    },",
    '    "results": [',
    "        {",
    '            "contentLength": 27,',
    '            "contentType": "text/html",',
    '            "elapsed": 0.008,',
    '            "redirect": "",',
    '            "status": 200,',
    '            "url": "http://127.0.0.1:44899/admin"',
    "        },",
    "        {",
    '            "contentLength": 31,',
    '            "contentType": "application/json",',
    '            "elapsed": 0.012,',
    '            "redirect": "",',
    '            "status": 403,',
    '            "url": "http://127.0.0.1:44899/api"',
    "        }",
    "    ]",
    "}",
    "",
])


def _parse(text: str):
    return parse_dirsearch_json(text, evidence_path=EV, skill="web-dirsearch")


def test_registered_in_parser_registry():
    assert PARSER_REGISTRY["dirsearch_json"] is parse_dirsearch_json


def test_parses_real_stdout_shape_into_web_probe_signals():
    signals, skipped = _parse(REAL_SHAPE)
    assert skipped == 0
    assert [s.asset for s in signals] == [
        "http://127.0.0.1:44899/admin",
        "http://127.0.0.1:44899/api",
    ]
    assert [s.status_code for s in signals] == [200, 403]
    # **零新增 Signal kind**：落既有 web-probe
    assert all(s.kind == "web-probe" for s in signals)
    assert all(s.source_tool == "dirsearch" for s in signals)
    assert all(s.skill == "web-dirsearch" for s in signals)
    # 证据锚点指向 JSON 报告块首行（第 3 行）
    assert all(s.evidence_ref == f"{EV}#L3" for s in signals)


def test_evidence_and_judgement_fields_are_separated():
    """判据字段决定候选；证据字段只在 note，**不进判定**。"""
    signals, _ = _parse(REAL_SHAPE)
    admin = signals[0]
    # 判据
    assert admin.asset.endswith("/admin")
    assert admin.status_code == 200
    # 证据（只在 note）
    assert admin.note is not None
    assert "contentLength=27" in admin.note
    assert "contentType=text/html" in admin.note
    assert "elapsed=0.008" in admin.note


def test_maps_to_web_exposure_through_existing_channel():
    """走 M3a 起就有的 web-probe → web-exposure 映射（零 triage 改动）。"""
    signals, _ = _parse(REAL_SHAPE)
    candidates = [c for s in signals for c in _triage_candidates(s)]
    assert len(candidates) == 2
    assert {c.vuln_type for c in candidates} == {"web-exposure"}
    assert {c.source for c in candidates} == {"web_probe"}
    assert {c.evidence_kind for c in candidates} == {"status-code"}


def test_status_outside_exposed_set_stays_signal_without_candidate():
    """非暴露状态码仍是 Signal（可审计的事实），但不产候选。"""
    text = json.dumps({"info": {}, "results": [
        {"url": "http://h/boom", "status": 500},
    ]})
    signals, skipped = _parse(text)
    assert skipped == 0 and len(signals) == 1
    assert signals[0].status_code == 500
    assert _triage_candidates(signals[0]) == []


def test_missing_status_yields_signal_without_candidate():
    """缺 status 不算坏条目（Signal 允许 None），但自然不产候选。"""
    text = json.dumps({"info": {}, "results": [{"url": "http://h/a"}]})
    signals, skipped = _parse(text)
    assert skipped == 0 and len(signals) == 1
    assert signals[0].status_code is None
    assert _triage_candidates(signals[0]) == []


def test_duplicate_urls_deduped_first_anchor_wins():
    text = json.dumps({"info": {}, "results": [
        {"url": "http://h/a", "status": 200},
        {"url": "http://h/a", "status": 200},
        {"url": "http://h/b", "status": 200},
    ]})
    signals, _ = _parse(text)
    assert [s.asset for s in signals] == ["http://h/a", "http://h/b"]


@pytest.mark.parametrize(
    "label, text",
    [
        ("empty", ""),
        ("plain text only", "[13:00:00] 200 - 1B - http://h/a\nTask Completed\n"),
        ("truncated json", '{"info": {}, "results": [{"url": "http://h/a"'),
        ("results not a list", '{"info": {}, "results": "nope"}'),
        ("top-level list", '[{"url": "http://h/a"}]'),
    ],
)
def test_bad_input_is_fail_closed(label, text):
    signals, skipped = _parse(text)
    assert signals == [], label
    assert skipped >= 1, label


@pytest.mark.parametrize(
    "entry",
    [
        {"status": 200},                        # 缺 url
        {"url": 5, "status": 200},              # url 非字符串
        {"url": "   ", "status": 200},          # url 空白
        {"url": "/admin", "status": 200},       # 相对 URL
        {"url": "file:///etc/passwd", "status": 200},
        {"url": "ftp://h/x", "status": 200},
        {"url": "javascript:alert(1)", "status": 200},
    ],
)
def test_bad_entries_skipped_never_become_signals(entry):
    """畸形/非 http(s) 条目一律跳过——尤其 file:// 不得进发现链路。"""
    text = json.dumps({"info": {}, "results": [entry]})
    signals, skipped = _parse(text)
    assert signals == []
    assert skipped == 1


def test_non_dict_entries_counted_as_skipped_but_good_ones_survive():
    text = json.dumps({"info": {}, "results": [
        123, "x", None, {"url": "http://h/ok", "status": 200},
    ]})
    signals, skipped = _parse(text)
    assert [s.asset for s in signals] == ["http://h/ok"]
    assert skipped == 3


def test_http_and_https_both_accepted():
    text = json.dumps({"info": {}, "results": [
        {"url": "http://h/a", "status": 200},
        {"url": "https://h/b", "status": 200},
    ]})
    signals, _ = _parse(text)
    assert [s.asset for s in signals] == ["http://h/a", "https://h/b"]


def test_json_block_after_noise_is_found_and_anchored_correctly():
    """JSON 报告块的行号锚点必须是**块首行**（不是文件首行）。"""
    noise = "\n".join(f"[13:0{i}:00] 404 - 1B - http://h/x{i}" for i in range(5))
    text = noise + "\n" + json.dumps({"info": {}, "results": [
        {"url": "http://h/hit", "status": 200}]})
    signals, _ = _parse(text)
    assert len(signals) == 1
    assert signals[0].evidence_ref == f"{EV}#L6"
