"""M16-a：katana JS 端点发现的构造器 / 解析器 / scope 兜底测试。

本文件只覆盖**发现侧**：argv 形态、jsluice 输出的解析容错、以及"JS 里含
外域绝对 URL 时外域不产生候选"这条安全回归。判定面（GATE_MATRIX /
triage 提示表 / Verifier 输入边界）不在本轮，故此处无相关断言。
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope, check_scope
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings.finding import FindingStore
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.build import build_command
from proofhound.tools.parsers import parse_katana_jsonl

SEED = "http://127.0.0.1:8080"
EXTERNAL = "http://evil.example.com"


# ---------------------------------------------------------------- 构造器

def test_katana_js_crawl_flag_always_on():
    """-jc 是恒在项（M16-a）：不开等于整块 JS 发现面看不见。"""
    argv = build_command("katana", {"target": SEED})
    assert "-jc" in argv
    # 参数覆盖不了它：jsluice 开关只影响 -jsl
    argv_on = build_command("katana", {"target": SEED, "jsluice": True})
    assert "-jc" in argv_on


def test_katana_jsluice_flag_defaults_off_and_is_opt_in():
    """-jsl 缺省关（实测与 -jc 提取集合等价而峰值内存近乎翻倍）。"""
    assert "-jsl" not in build_command("katana", {"target": SEED})
    assert "-jsl" in build_command("katana", {"target": SEED, "jsluice": True})


def test_katana_known_files_flag_never_emitted():
    """-kf 刻意不暴露：官方要求 depth >= 3 才生效，而 depth 缺省 2。"""
    for extra in ({}, {"jsluice": True}, {"depth": 5, "jsluice": True}):
        argv = build_command("katana", {"target": SEED, **extra})
        assert "-kf" not in argv
        assert "-known-files" not in argv


# ---------------------------------------------------------------- 解析容错

def _record(endpoint, *, method="GET", status=200, body=None, drop=()):
    request = {"method": method, "endpoint": endpoint}
    response = {"status_code": status}
    if body is not None:
        response["body"] = body
    rec = {"timestamp": "2026-09-29T00:00:00Z", "request": request, "response": response}
    for key in drop:
        rec.pop(key, None)
    return json.dumps(rec)


def test_jsluice_expression_placeholder_is_parsed_not_rejected():
    """jsluice 会把拼接串的未知部分写成 EXPR 占位符——解析器照常收下。

    占位符值本身过不了下游键名启发式（键名仍可命中），关键是**不能炸**：
    字段缺失/取值异常一律 fail-closed 丢弃该行，而不是抛异常中断整批。
    """
    text = "\n".join(
        [
            _record(f"{SEED}/api/order?order_id=EXPR&user=EXPR"),
            _record(f"{SEED}/api/user?id=EXPR"),
        ]
    )
    signals, skipped = parse_katana_jsonl(
        text, evidence_path="k.log", skill="recon-crawl"
    )
    assert skipped == 0
    assert [s.kind for s in signals] == ["param-endpoint", "param-endpoint"]
    assert signals[0].asset == f"{SEED}/api/order?order_id=EXPR&user=EXPR"
    assert signals[0].evidence_ref == "k.log#L1"


def test_jsluice_records_missing_fields_tolerated():
    """JS 记录缺 response / 缺 status_code / 缺 method 均不炸（容错计数）。"""
    text = "\n".join(
        [
            _record(f"{SEED}/a?id=1"),                      # 正常
            _record(f"{SEED}/b?id=1", drop=("response",)),   # 无 response 段
            _record(f"{SEED}/c?id=1", status=None),          # status_code=None
            json.dumps({"request": {"endpoint": f"{SEED}/d?id=1"}}),  # 无 method
            "{ 坏 json",
        ]
    )
    signals, skipped = parse_katana_jsonl(
        text, evidence_path="k.log", skill="recon-crawl"
    )
    # 无 method 不算 GET ⇒ 不产候选；坏 json 计 1 行
    assert skipped == 1
    kinds = [(s.asset, s.kind) for s in signals]
    assert (f"{SEED}/a?id=1", "param-endpoint") in kinds
    assert all("/d?" not in asset for asset, _ in kinds)


def test_js_extracted_endpoints_become_param_endpoint_signals():
    """M16-a 主验收：katana 把 JS 里写死的接口路径当普通爬行记录输出 ⇒
    零新增解析器即可落成 param-endpoint Signal（asset/evidence_ref 完整）。"""
    text = "\n".join(
        [
            _record(f"{SEED}/static/app.js", status=200),
            _record(f"{SEED}/api/user?id=1&page=2"),
            _record(f"{SEED}/api/admin/users?role=admin"),
        ]
    )
    signals, skipped = parse_katana_jsonl(
        text, evidence_path="js.log", skill="recon-crawl"
    )
    assert skipped == 0
    # .js 自身无 query ⇒ 不产候选；两条 JS 接口各产一条
    assert [s.asset for s in signals] == [
        f"{SEED}/api/user?id=1&page=2",
        f"{SEED}/api/admin/users?role=admin",
    ]
    assert all(s.kind == "param-endpoint" for s in signals)
    assert all(s.source_tool == "katana" for s in signals)
    assert signals[1].evidence_ref == "js.log#L3"


# ---------------------------------------------------------------- scope 兜底

def test_parser_does_not_rewrite_external_endpoint_into_scope():
    """解析器不做「外域→种子域」改写：外域 URL 原样保留，越界判定交 check_scope。

    若解析器悄悄改写，越界资产会被洗成范围内资产混进 triage——那才是真漏洞。
    """
    text = _record(f"{EXTERNAL}/api/steal?id=1")
    signals, _ = parse_katana_jsonl(text, evidence_path="k.log", skill="recon-crawl")
    assert [s.asset for s in signals] == [f"{EXTERNAL}/api/steal?id=1"]


def test_scope_boundary_rejects_external_endpoint():
    """第二层：外域绝对 URL 过 check_scope 必须被拒（JS 提取最危险的越界路径）。"""
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080])
    decision = check_scope(scope, [f"{EXTERNAL}/api/steal?id=1"])
    assert decision.allowed is False
    assert decision.violations


@pytest.fixture
def env(tmp_path, make_skill_dir):
    """编排器（runner 挂 scope=127.0.0.0/8）+ 证据目录。"""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    audit = AuditLog(evidence_dir / "audit.jsonl")
    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=SimpleNamespace(scope=Scope(networks=["127.0.0.0/8"])),
        llm=None,
        audit=audit,
        evidence_dir=evidence_dir,
    )
    return orch, audit, evidence_dir


def _write_signals(evidence_dir, rows):
    with (evidence_dir / "crawl.signals.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _signal_row(asset, ref, kind="param-endpoint"):
    return {
        "asset": asset,
        "status_code": 200,
        "title": None,
        "tech": [],
        "kind": kind,
        "source_tool": "katana",
        "skill": "recon-crawl",
        "evidence_ref": ref,
    }


def test_js_external_endpoint_produces_no_candidate(env):
    """端到端 scope 兜底：JS 记录里混入的外域接口不产生任何候选。

    这是本轮最重要的一条安全回归——「JS 提取把范围带出去」。
    """
    orch, audit, evidence_dir = env
    _write_signals(
        evidence_dir,
        [
            # 外域 JS 里写死的相对路径接口（被解析成外域绝对 URL）。
            # 两条都用**能命中提示表**的键，确保它们真的走到 check_scope
            # 那一层（零候选的信号会先在候选映射处被丢弃，验证不到 scope）。
            _signal_row(f"{EXTERNAL}/evil/api/users?id=1", "crawl.log#L1"),
            _signal_row(f"{EXTERNAL}/evil/api/dump?file=users.csv", "crawl.log#L2"),
            # 范围内的正常接口（对照：必须建出来）
            _signal_row(f"{SEED}/api/user?id=1", "crawl.log#L3"),
        ],
    )
    orch.run_triage_phase()

    store = FindingStore(evidence_dir / "findings.jsonl")
    findings = store.load_all()
    assets = {f.asset for f in findings}
    assert assets, "范围内的对照接口应当建出候选"
    assert all(EXTERNAL not in asset for asset in assets), assets

    oos = [e for e in audit.read_all() if e["event"] == "triage_out_of_scope"]
    assert {e["asset"] for e in oos} == {
        f"{EXTERNAL}/evil/api/users?id=1",
        f"{EXTERNAL}/evil/api/dump?file=users.csv",
    }
    assert all(e["violations"] for e in oos)
