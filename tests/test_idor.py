"""M8c verify-idor 测试：idor.py 纯函数（相似度/键重叠/判定阈值）、双会话
脱敏、证据门 idor 白名单、triage idor 分支、_verify_idor 全链（罐头
idor_fetch 注入，零真实网络）、runner 三 verify skill 接线。

覆盖验收点：阈值边界（0.89 vs 0.91 / 0.79 vs 0.80）、非 2xx 分类、空正文、
JSON 嵌套键；两会话秘密值全形态脱敏（证据文件无任一原文）；
dual-session-confirmed 在 idor 白名单、不染指 sqli/xss 白名单；
hint 命中（invoice 单产 idor / id 同产 sqli+idor 设计行为）/零命中/独立
上限/独立 triage_capped；违反成立 → Confirmed（四段式齐、代码算分覆盖
种子 severity）；判定不成立 → REJECTED；缺第二会话/网络错误/基准不成立
→ blocked（覆盖不全不驳回）；Verifier reject → REJECTED。
"""

from __future__ import annotations

import json
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings import (
    Finding,
    FindingState,
    FindingStore,
    compute_dedup_key,
)
from proofhound.llm.router import ModelRouter, Tier
from proofhound.skills.registry import SkillRegistry
from proofhound.verify.cvss import base_score, severity_for_score
from proofhound.verify.gate import check as gate_check
from proofhound.verify.idor import (
    IdorResponse,
    body_similarity,
    fetch,
    has_substance,
    json_key_overlap,
    json_key_paths,
    judge,
    status_class,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE = "http://127.0.0.1:8080"
IDOR_ASSET = f"{BASE}/invoice?id=1001"
A_TOKEN = "aaaaaaaabbbbbbbb"  # 16 字符（≥ MIN_SECRET_LEN，裸值也脱敏）
B_TOKEN = "ccccccccdddddddd"
DUAL_SESSION = SessionConfig(
    cookies={"phsess": A_TOKEN},
    reference=SessionConfig(cookies={"phsess": B_TOKEN}),
)
# 水平越权（IDOR）典型向量：低权限身份读他人私有对象（C:H，不证完整拖取）
CVSS_IDOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"


def _padded_body(token: str, size: int = 400, owner: str | None = None) -> str:
    """定长正文：固定头部 + x 填充 + **等长尾部标记区**。

    相似度契约（M11b 实测修正）：两身份的尾部标记必须**等长**，否则会整体错位、
    把 x 填充与注释文本错误对齐，相似度跌破 0.9 阈值（实测 0.8725）。故 token
    注释定长（与 token 值本身无关，纯标记），再加一个 3 字符的 ``data-s`` 差异。

    ``owner`` 为**可归属字段** ``owner=<值>``，供确定性归属提取
    （``verify/idor_control.py``）——它要求"归属字段名 + 值与 reference 身份
    一致"两族同时命中；散文"（属主 B）"不构成证据（刻意的宁漏勿滥）。
    """
    head = "<html><body><h1>发票 #1001</h1><p>金额 ¥8,800.00（属主 B）</p>"
    owner_part = f"<span>owner={owner}</span>" if owner else ""
    # token 注释**定长**（16 个 x 与任何 token 值同长），使两身份尾部等长
    tail = (
        f"{owner_part}<i data-s=\"{token[:3]}\"></i><!-- token:xxxxxxxxxxxxxxxx -->"
        "</body></html>"
    )
    return head + "x" * max(size - len(head) - len(tail), 0) + tail


def _victim_identity() -> str:
    """reference 会话的身份标识（= 归属提取的期望值来源）。"""
    reference = DUAL_SESSION.reference
    return reference.cookies["phsess"] if reference else ""


# ---- idor.py 纯函数：相似度 / 键重叠 / 状态分类 / 实质数据 / 判定 ----


def test_body_similarity_identical_and_disjoint():
    assert body_similarity("abcdef", "abcdef") == 1.0
    assert body_similarity("aaaa", "bbbb") == 0.0


def test_body_similarity_threshold_boundary():
    """阈值边界：0.89 不违反、0.91 违反（确定性构造）。"""
    base = "a" * 100
    below = "a" * 89 + "b" * 11  # ratio = 2*89/200 = 0.89
    above = "a" * 91 + "b" * 9  # ratio = 2*91/200 = 0.91
    assert body_similarity(base, below) == pytest.approx(0.89)
    assert body_similarity(base, above) == pytest.approx(0.91)


def test_body_similarity_empty_side_is_zero():
    assert body_similarity("", "x" * 100) == 0.0
    assert body_similarity("", "") == 0.0


def test_json_key_paths_nested():
    obj = {"a": 1, "b": {"c": 2, "d": {"e": 3}}, "f": [{"g": 4}]}
    assert json_key_paths(obj) == {"a", "b", "b.c", "b.d", "b.d.e", "f", "f[].g"}


def test_json_key_overlap_jaccard():
    a = json.dumps({"id": 1001, "amount": 8800, "owner": {"name": "b"}})
    b = json.dumps({"id": 1001, "amount": 8800, "owner": {"name": "b", "tel": "x"}})
    # 键集 {id,amount,owner,owner.name} vs 多 owner.tel：Jaccard = 4/5
    assert json_key_overlap(a, b) == pytest.approx(0.8)


def test_json_key_overlap_non_json_returns_none():
    assert json_key_overlap("<html>", "{}") is None
    assert json_key_overlap("{}", "<html>") is None
    assert json_key_overlap("{}", "{}") is None  # 空并集


def test_status_class_classification():
    assert status_class(200) == "ok"
    assert status_class(204) == "ok"
    assert status_class(302) == "redirect"
    assert status_class(403) == "client_error"
    assert status_class(404) == "client_error"
    assert status_class(500) == "server_error"
    assert status_class(None) == "none"


def test_has_substance_rules():
    assert has_substance(IdorResponse(url="u", status=200, body="x" * 64))
    assert not has_substance(IdorResponse(url="u", status=403, body="x" * 64))
    assert not has_substance(IdorResponse(url="u", status=200, body="ok"))
    assert not has_substance(IdorResponse(url="u", status=200, body="{}"))
    assert not has_substance(IdorResponse(url="u", status=200, body="  [ ] ".replace(" ", "")))


def _resp(status, body):
    return IdorResponse(url=IDOR_ASSET, status=status, body=body)


def test_judge_violation_by_similarity():
    b = _resp(200, _padded_body(B_TOKEN))
    a = _resp(200, _padded_body(A_TOKEN))
    j = judge(b, a)
    assert j.violation is True
    assert j.similarity >= 0.9
    assert j.b_status == 200 and j.a_status == 200
    assert any("属性违反成立" in r for r in j.reasons)


def test_judge_violation_by_json_overlap():
    """正文文本差异大（相似度 < 0.9）但 JSON 键集合重叠 ≥ 0.8 → 违反。"""
    b = _resp(200, json.dumps({"invoice": 1001, "amount": 8800, "owner": "b"}) + " " * 40)
    a = _resp(200, json.dumps({"invoice": 1001, "amount": 8800, "owner": "b" + "y" * 300}))
    j = judge(b, a)
    assert j.similarity < 0.9
    assert j.json_overlap == pytest.approx(1.0)
    assert j.violation is True


def test_judge_no_violation_below_threshold():
    b = _resp(200, "a" * 100)
    a = _resp(200, "a" * 89 + "b" * 11)  # 0.89 < 0.9
    j = judge(b, a)
    assert j.violation is False


def test_judge_no_violation_a_forbidden():
    j = judge(_resp(200, _padded_body(B_TOKEN)), _resp(403, "Forbidden"))
    assert j.violation is False
    assert j.a_status == 403


def test_judge_no_violation_a_redirect_to_login():
    j = judge(_resp(200, _padded_body(B_TOKEN)), _resp(302, ""))
    assert j.violation is False


def test_judge_no_violation_baseline_not_substantive():
    j = judge(_resp(404, "not found"), _resp(200, _padded_body(A_TOKEN)))
    assert j.violation is False
    assert any("B 基准不成立" in r for r in j.reasons)


# ---- idor.py fetch：本地 fixture 服务（零外部网络） ----


class _IdorHandler(BaseHTTPRequestHandler):
    seen_cookies: list[str | None] = []
    seen_auth: list[str | None] = []

    def do_GET(self):
        type(self).seen_cookies.append(self.headers.get("Cookie"))
        type(self).seen_auth.append(self.headers.get("Authorization"))
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, body = {
            "/ok": (200, "<html><body>invoice page substantial body content</body></html>"),
            "/json": (200, json.dumps({"invoice": 1001, "amount": 8800}) + " " * 40),
            "/forbidden": (403, "Forbidden"),
            "/empty": (200, "ok"),
        }.get(self.path.split("?")[0], (404, "not found"))
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def idor_server():
    _IdorHandler.seen_cookies = []
    _IdorHandler.seen_auth = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _IdorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join(timeout=5)


def test_fetch_ok_and_session_injection(idor_server):
    session = SessionConfig(
        cookies={"phsess": A_TOKEN}, headers={"Authorization": "Bearer tok-x-1"}
    )
    resp = fetch(f"{idor_server}/ok", session)
    assert resp.error is None
    assert resp.status == 200
    assert "invoice page" in resp.body
    assert _IdorHandler.seen_cookies[-1] == f"phsess={A_TOKEN}"
    assert _IdorHandler.seen_auth[-1] == "Bearer tok-x-1"


def test_fetch_403_is_response_not_error(idor_server):
    resp = fetch(f"{idor_server}/forbidden", SessionConfig())
    assert resp.error is None
    assert resp.status == 403


def test_fetch_redirect_not_followed(idor_server):
    resp = fetch(f"{idor_server}/redirect", SessionConfig())
    assert resp.error is None
    assert resp.status == 302  # 重定向以状态码暴露（不跟随）


def test_fetch_network_error_form():
    resp = fetch("http://127.0.0.1:9/ok", SessionConfig())  # 端口 9 不监听
    assert resp.status is None
    assert resp.error is not None


# ---- 证据门：idor 白名单（与 sqli/xss 互不染指） ----


def _gate_finding(vuln_type, method):
    return Finding(
        id="F-2026-0001",
        state=FindingState.REPRODUCED,
        vuln_type=vuln_type,
        asset=IDOR_ASSET,
        param="id",
        evidence_kinds=["crawl-endpoint", "behavioral"],
        verification={"method": method, "evidence_refs": ["evidence/x.log#L1"]},
        dedup_key="sha256:deadbeef",
        created_at="2026-08-15T00:00:00.000+00:00",
        updated_at="2026-08-15T00:00:00.000+00:00",
    )


def test_gate_idor_dual_session_confirmed_passes():
    assert gate_check(_gate_finding("idor", "dual-session-confirmed")).passed


def test_gate_idor_rejects_browser_method():
    result = gate_check(_gate_finding("idor", "browser-confirmed"))
    assert not result.passed
    assert any("白名单" in item for item in result.missing)


def test_gate_xss_rejects_dual_session_method():
    """dual-session-confirmed 只进 idor 白名单，不染指 xss。"""
    assert not gate_check(_gate_finding("xss", "dual-session-confirmed")).passed


def test_gate_sqli_rejects_dual_session_method():
    assert not gate_check(_gate_finding("sqli", "dual-session-confirmed")).passed


# ---- triage：idor 分支 ----


class FakeLLM:
    def complete(self, messages):
        raise AssertionError("triage 不得调用 LLM")


def _param_row(asset, evidence_ref):
    return {
        "asset": asset,
        "status_code": 200,
        "title": None,
        "tech": [],
        "kind": "param-endpoint",
        "source_tool": "katana",
        "skill": "recon-crawl",
        "evidence_ref": evidence_ref,
    }


@pytest.fixture
def triage_env(tmp_path, make_skill_dir):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    raw = evidence_dir / "crawl.stdout.log"
    raw.write_text(
        "\n".join(f"line{i}" for i in range(1, 80)) + "\n", encoding="utf-8"
    )
    audit = AuditLog(evidence_dir / "audit.jsonl")
    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=SimpleNamespace(scope=Scope(networks=["127.0.0.0/8"])),
        llm=FakeLLM(),
        audit=audit,
        evidence_dir=evidence_dir,
    )
    return orch, audit, evidence_dir, raw


def _write_signals(evidence_dir, rows):
    signals_path = evidence_dir / "crawl.signals.jsonl"
    with signals_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _triage_summary(audit):
    return [e for e in audit.read_all() if e["event"] == "triage_completed"][0]


def test_invoice_hint_creates_idor_only(triage_env):
    """invoice 仅在 idor 表（不在 sqli/xss 表）→ 单产一条 idor 候选。"""
    orch, audit, evidence_dir, raw = triage_env
    _write_signals(evidence_dir, [_param_row(f"{BASE}/invoice?invoice=1", f"{raw}#L1")])
    findings = orch.run_triage_phase()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vuln_type == "idor"
    assert finding.param == "invoice"
    assert finding.severity == "medium"
    assert finding.evidence_kinds == ["crawl-endpoint"]
    summary = _triage_summary(audit)
    assert summary["created_by_type"] == {"idor": 1}
    assert summary["created_by_source"] == {"get_param": 1}


def test_id_hint_coproduces_sqli_and_idor(triage_env):
    """id 同中 sqli/idor 两表 → 同产两类候选（设计行为，dedup 互不合并）。"""
    orch, audit, evidence_dir, raw = triage_env
    _write_signals(evidence_dir, [_param_row(IDOR_ASSET, f"{raw}#L1")])
    findings = orch.run_triage_phase()

    by_type = {f.vuln_type: f for f in findings}
    assert set(by_type) == {"sqli", "idor"}
    assert by_type["sqli"].param == by_type["idor"].param == "id"
    assert by_type["sqli"].dedup_key != by_type["idor"].dedup_key
    assert _triage_summary(audit)["created_by_type"] == {"sqli": 1, "idor": 1}


def test_idor_zero_hint_kept_signal(triage_env):
    orch, audit, evidence_dir, raw = triage_env
    _write_signals(evidence_dir, [_param_row(f"{BASE}/x?foo=1", f"{raw}#L1")])
    assert orch.run_triage_phase() == []
    assert _triage_summary(audit)["kept_signal"] == 1


def test_idor_independent_cap_and_capped_audit(triage_env):
    """idor 独立上限 10（与 sqli 20 互不挤占）；独立 triage_capped 事件。"""
    orch, audit, evidence_dir, raw = triage_env
    rows = [_param_row(f"{BASE}/o{n}?id={n}", f"{raw}#L1") for n in range(1, 26)]
    _write_signals(evidence_dir, rows)
    orch.run_triage_phase()

    store = FindingStore(evidence_dir / "findings.jsonl")
    findings = store.load_all()
    assert sum(1 for f in findings if f.vuln_type == "sqli") == 20  # sqli 满
    assert sum(1 for f in findings if f.vuln_type == "idor") == 10  # idor 独立上限
    capped = [e for e in audit.read_all() if e["event"] == "triage_capped"]
    by_type = {e["vuln_type"]: e for e in capped}
    assert by_type["sqli"]["dropped"] == 5
    assert by_type["idor"]["limit"] == 10
    assert by_type["idor"]["dropped"] == 15


# ---- verify 全链：罐头 idor_fetch 注入 + MockRouter ----


class MockRouter(ModelRouter):
    """罐头 T2 路由（继承 ModelRouter 过 ensure_router 的 isinstance 闸）。"""

    def __init__(self, reply: str):
        self.reply = reply  # 不调 super().__init__：不建 HTTP 客户端
        self.configs = {Tier.T2: SimpleNamespace(model="kimi-k3-test")}

    def complete(self, tier, messages):
        return self.reply


def _confirm_reply():
    return (
        '{"verdict": "confirm", "reason": "双会话属性违反证据链完整", '
        f'"cvss_vector": "{CVSS_IDOR}", "cvss_rationale": "水平越权读他人私有对象按证据定指标"}}'
    )


def _canned_fetch(*, a_status=200, a_body=None, b_status=200, b_body=None,
                  a_error=None, b_error=None, c_status=403,
                  c_body=None, c_error=None, owner="__default__",
                  b_body_override=None):
    """按会话分角色的罐头 fetch（B=reference/victim，A=主会话，C=未认证对照）。

    M11b：新增第三个角色——**空会话**（scope 未配 session_third 时编排层用
    ``SessionConfig()``，即完全不发凭据）。默认给 403 + 明显不同的正文，模拟
    "未认证被拒"，使对照判 ``protected``（属性违反解释成立）。
    """
    calls = []

    def _fake(url, session):
        phsess = session.cookies.get("phsess")
        # M11b：对照角色 = 无任何 cookie（匿名探测）
        if not session.cookies and not session.headers:
            role = "control"
        else:
            role = "b" if phsess == B_TOKEN else "a"
        calls.append(role)

        if role == "b":
            if b_error is not None:
                return IdorResponse(url=url, error=b_error)
            if b_body_override is not None:
                # 逐字替换（供"正文里塞哨兵串以验证不泄漏"这类用例）
                body = b_body_override
            else:
                # owner 开关：默认注入 reference 身份（matched）；传 None 则不写
                # 归属字段（absent）；传其他值则归属指向他人（mismatched）
                owner_value = (
                    _victim_identity() if owner == "__default__" else owner
                )
                # 统一走定长助手：显式正文也按同一契约生成（仅尾部标记不同），
                # 否则相似度会跌破 0.9 阈值、测不到 Verifier 那条路径
                body = _padded_body(B_TOKEN, owner=owner_value)
            return IdorResponse(url=url, status=b_status, body=body)
        if role == "control":
            if c_error is not None:
                return IdorResponse(url=url, error=c_error)
            return IdorResponse(
                url=url, status=c_status,
                body=(
                    c_body
                    if c_body is not None
                    else "<html><body>请先登录后再查看该内容。</body></html>"
                ),
            )
        if a_error is not None:
            return IdorResponse(url=url, error=a_error)
        return IdorResponse(
            url=url, status=a_status,
            body=a_body if a_body is not None else _padded_body(A_TOKEN),
        )

    _fake.calls = calls
    return _fake


@pytest.fixture
def verify_env(tmp_path, make_skill_dir):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    audit = AuditLog(evidence_dir / "audit.jsonl")
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080], session=DUAL_SESSION)
    registry = SkillRegistry(make_skill_dir(name="verify-idor", tools=())).discover()
    store = FindingStore(evidence_dir / "findings.jsonl")
    return SimpleNamespace(
        evidence_dir=evidence_dir, audit=audit, scope=scope,
        registry=registry, store=store,
    )


def _seed_idor(store: FindingStore, audit: AuditLog) -> Finding:
    finding = Finding(
        id=store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type="idor",
        severity="medium",
        asset=IDOR_ASSET,
        param="id",
        confidence="low",
        evidence_kinds=["crawl-endpoint"],
        dedup_key=compute_dedup_key(IDOR_ASSET, "idor", "id"),
        source_signal_refs=[],
        created_at="2026-08-15T00:00:00.000+00:00",
        updated_at="2026-08-15T00:00:00.000+00:00",
        audit=audit,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="测试种子")
    store.append(finding)
    return finding


def _make_orch(env, fake_fetch, reply, *, session=DUAL_SESSION):
    env.scope.session = session
    runner = SimpleNamespace(scope=env.scope)
    orch = Orchestrator(
        env.registry, runner, MockRouter(reply), env.audit,
        evidence_dir=env.evidence_dir, idor_fetch=fake_fetch,
    )
    return orch


def _events(audit, name):
    return [e for e in audit.read_all() if e["event"] == name]


def test_verify_idor_full_chain_confirmed(verify_env):
    """双会话属性违反成立 → 证据门 → Verifier confirm → Confirmed（四段式齐全）。"""
    env = verify_env
    seed = _seed_idor(env.store, env.audit)
    fake_fetch = _canned_fetch()
    orch = _make_orch(env, fake_fetch, _confirm_reply())

    processed = orch.run_verify_phase(skill_name="verify-idor")

    assert [f.id for f in processed] == [seed.id]
    finding = env.store.load_all()[0]  # run_verify_phase 回放出新实例
    assert finding.state is FindingState.CONFIRMED
    verification = finding.verification
    assert verification.method == "dual-session-confirmed"
    assert "behavioral" in finding.evidence_kinds
    # 四段式齐全
    assert verification.claim and "身份 A" in verification.claim
    assert verification.expected and "403" in verification.expected
    assert verification.actual and "属性违反" in verification.actual
    assert verification.baseline_diff and "相似度" in verification.baseline_diff
    # 代码算分覆盖 triage 种子 severity（M6b 机制）
    assert finding.cvss_vector == CVSS_IDOR
    assert finding.cvss_score == base_score(CVSS_IDOR)
    assert finding.severity == severity_for_score(finding.cvss_score)
    # M11b：五条证据全部落盘——B 基准 / A 对比 / 判定 JSON /
    # C 未认证对照响应 / 对照与归属结论 JSON
    assert len(verification.evidence_refs) == 5
    paths = [Path(p) for p in verification.evidence_refs]
    b_path, a_path, j_path, c_path, s_path = paths
    assert b_path.name == f"idor_{finding.id}_b_response.txt"
    assert a_path.name == f"idor_{finding.id}_a_response.txt"
    assert j_path.name == f"idor_{finding.id}_judgment.json"
    assert c_path.name == f"idor_{finding.id}_c_response.txt"
    assert s_path.name == f"idor_{finding.id}_control.json"
    for path in paths:
        assert path.is_file() and path.stat().st_size > 0
    # 对照结论结构化落盘：protected + matched（M11b 判据）
    control_doc = json.loads(s_path.read_text(encoding="utf-8"))
    assert control_doc["unauthenticated_control"]["verdict"] == "protected"
    assert control_doc["object_ownership"]["verdict"] == "matched"
    # 两份响应指纹都记录（便于离线复核"是否逐字节相同"）
    assert len(control_doc["baseline_body_sha256"]) == 64
    assert len(control_doc["control_body_sha256"]) == 64
    # 判定 JSON 结构化记录（双状态码 + 相似度数值 + 阈值）
    judgment = json.loads(j_path.read_text(encoding="utf-8"))
    assert judgment["violation"] is True
    assert judgment["b_status"] == 200 and judgment["a_status"] == 200
    assert judgment["similarity"] >= 0.9
    assert judgment["thresholds"]["similarity"] == 0.9
    assert judgment["thresholds"]["json_overlap"] == 0.8
    # M11b：三次请求按次审计，角色成对（新增未认证对照）
    attempts = _events(env.audit, "idor_probe_attempt")
    assert [e["role"] for e in attempts] == [
        "reference",
        "attacker",
        "unauthenticated_control",
    ]
    assert all(e["status"] in (200, 403) and e["error"] is False for e in attempts)
    assert fake_fetch.calls == ["b", "a", "control"]
    # 对照与归属的确定性结论进审计
    judged = _events(env.audit, "idor_control_judged")
    assert judged[0]["control_verdict"] == "protected"
    assert judged[0]["ownership_verdict"] == "matched" 
    # 审计链完整：Verifier 带向量 + verify_completed 计数
    verdicts = _events(env.audit, "verifier_verdict")
    assert verdicts[0]["verdict"] == "confirm"
    assert verdicts[0]["cvss_vector"] == CVSS_IDOR
    assert _events(env.audit, "verify_completed")[0]["confirmed"] == 1
    # 证据包 manifest 收编三条证据
    manifest = json.loads(
        (env.evidence_dir / "findings" / finding.id / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    packed = {item["source_ref"] for item in manifest["items"]}
    assert {str(b_path), str(a_path), str(j_path), str(c_path), str(s_path)} <= packed


def test_verify_idor_evidence_redacts_both_sessions(verify_env):
    """脱敏是两个会话都要：证据文件与 Finding 字段无任一会话原文。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    orch = _make_orch(env, _canned_fetch(), _confirm_reply())
    orch.run_verify_phase(skill_name="verify-idor")

    finding = env.store.load_all()[0]
    for path in env.evidence_dir.rglob("*"):
        if not path.is_file():
            continue
        content = path.read_bytes()
        for token in (A_TOKEN, B_TOKEN):
            assert token.encode() not in content, f"{path} 含会话原文 {token}"
    for step in finding.verification.reproduction_steps:
        assert A_TOKEN not in step and B_TOKEN not in step
    # 两身份 Cookie 只记脱敏标记（前两步各一个 marker）
    assert "sha256:" in finding.verification.reproduction_steps[0]
    assert "sha256:" in finding.verification.reproduction_steps[1]
    assert (
        finding.verification.reproduction_steps[0]
        != finding.verification.reproduction_steps[1]
    )


def test_verify_idor_a_forbidden_rejected(verify_env):
    """对照组：A 被 403 → 属性判定不成立 → REJECTED（Verifier 零调用）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    orch = _make_orch(
        env, _canned_fetch(a_status=403, a_body=""), _confirm_reply()
    )
    orch.run_verify_phase(skill_name="verify-idor")

    finding = env.store.load_all()[0]
    assert finding.state is FindingState.REJECTED
    assert "判定不成立" in finding.rejection_reason
    transitions = [
        e for e in _events(env.audit, "finding_state") if e["to"] == "rejected"
    ]
    assert transitions[0]["actor"] == "verify-idor"
    assert not _events(env.audit, "verifier_verdict")  # 未确认不进终审
    assert _events(env.audit, "verify_completed")[0]["rejected"] == 1
    # 判定 JSON 同样落盘（驳回也有完整判定依据）
    j_path = env.evidence_dir / f"idor_{finding.id}_judgment.json"
    assert json.loads(j_path.read_text(encoding="utf-8"))["violation"] is False


def test_verify_idor_missing_reference_blocked(verify_env):
    """缺第二身份会话 → verify_blocked（fail-closed，停留 Hypothesis）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    orch = _make_orch(
        env, _canned_fetch(), _confirm_reply(),
        session=SessionConfig(cookies={"phsess": A_TOKEN}),  # 无 reference
    )
    orch.run_verify_phase(skill_name="verify-idor")

    finding = env.store.load_all()[0]
    assert finding.state is FindingState.HYPOTHESIS
    blocked = _events(env.audit, "verify_blocked")
    assert any("第二身份会话" in e["reason"] for e in blocked)
    assert _events(env.audit, "verify_completed")[0]["blocked"] == 1


def test_verify_idor_fetch_error_blocked(verify_env):
    """B 基准请求网络错误 → blocked（覆盖不全不驳回）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    orch = _make_orch(
        env, _canned_fetch(b_error="URLError: <urlopen error boom>"), _confirm_reply()
    )
    orch.run_verify_phase(skill_name="verify-idor")

    finding = env.store.load_all()[0]
    assert finding.state is FindingState.HYPOTHESIS
    assert any(
        "基准请求失败" in e["reason"] for e in _events(env.audit, "verify_blocked")
    )
    attempts = _events(env.audit, "idor_probe_attempt")
    assert len(attempts) == 1 and attempts[0]["error"] is True


def test_verify_idor_baseline_not_substantive_blocked(verify_env):
    """B 基准非 2xx（属主自己也访问不到）→ blocked 而非 rejected。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    orch = _make_orch(env, _canned_fetch(b_status=404), _confirm_reply())
    orch.run_verify_phase(skill_name="verify-idor")

    finding = env.store.load_all()[0]
    assert finding.state is FindingState.HYPOTHESIS  # 覆盖不全不驳回
    assert any(
        "基准不成立" in e["reason"] for e in _events(env.audit, "verify_blocked")
    )
    assert not _events(env.audit, "verifier_verdict")


def test_verify_idor_verifier_reject_rejected(verify_env):
    """违反成立但 Verifier reject → REJECTED（actor=verifier）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    orch = _make_orch(
        env, _canned_fetch(),
        '{"verdict": "reject", "reason": "对象归属不明，证据不足以证私有性"}',
    )
    orch.run_verify_phase(skill_name="verify-idor")

    finding = env.store.load_all()[0]
    assert finding.state is FindingState.REJECTED
    transitions = [
        e for e in _events(env.audit, "finding_state") if e["to"] == "rejected"
    ]
    assert transitions[0]["actor"] == "verifier"


# ---- 多 verify skill 接线（runner 层，TestClient 半集成） ----


class FakePhasesVerifyIdor:
    """暴露三 verify skill 的假阶段执行器（M8c 多 verify skill 接口）。"""

    scan_skills = [("web-scan", "L1")]
    verify_skill = "verify-sqli"
    verify_risk_level = "L2"
    verify_skills = [("verify-sqli", "L2"), ("verify-xss", "L2"), ("verify-idor", "L2")]

    def __init__(self, runtime):
        self.dir = runtime.engagement.dir
        self.target = runtime.engagement.target
        self.audit = runtime.audit
        self.verified: list[str] = []

    def scan_with_skill(self, skill_name, targets):
        pass

    def triage(self):
        store = FindingStore(self.dir / "findings.jsonl")
        created = []
        for vuln_type, asset, param in (
            ("sqli", f"{self.target}/vulnerabilities/sqli/?id=1", "id"),
            ("xss", f"{self.target}/vulnerabilities/xss_r/?name=1", "name"),
            ("idor", f"{self.target}/invoice?id=1001", "id"),
        ):
            finding = Finding(
                id=store.next_id(),
                state=FindingState.SIGNAL,
                vuln_type=vuln_type,
                severity="medium",
                asset=asset,
                param=param,
                confidence="low",
                evidence_kinds=["crawl-endpoint"],
                dedup_key=compute_dedup_key(asset, vuln_type, param),
                created_at="2026-08-15T00:00:00.000+00:00",
                updated_at="2026-08-15T00:00:00.000+00:00",
                audit=self.audit,
            )
            finding.transition(
                FindingState.HYPOTHESIS, actor="triage", reason="fake triage"
            )
            store.append(finding)
            created.append(finding)
        return created

    def verify_covered_vuln_types(self, skill_name=None):
        return {
            "verify-sqli": frozenset({"sqli"}),
            "verify-xss": frozenset({"xss"}),
            "verify-idor": frozenset({"idor"}),
        }[skill_name or "verify-sqli"]

    def verify_with_skill(self, skill_name):
        self.verified.append(skill_name)
        return []

    def verify(self):
        raise AssertionError("多 skill 接口下不得走旧式 verify()")


@pytest.fixture
def api_workspace(tmp_path):
    (tmp_path / "scope.yaml").write_text("networks: [127.0.0.0/8]\n", encoding="utf-8")
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    shutil.copyfile(
        REPO_ROOT / "templates" / "default_template.docx",
        templates_dir / "default_template.docx",
    )
    return tmp_path


def _wait_pending_conf(client, eng_id, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state in ("done", "failed"):
            return None
        confs = client.get(f"/api/engagements/{eng_id}/confirmations").json()[
            "confirmations"
        ]
        if confs:
            return confs[0]
        time.sleep(0.05)
    raise AssertionError("等待待确认动作超时")


def test_runner_multi_verify_skills_gating_with_idor(api_workspace):
    """runner 逐 verify skill 过闸：idor 归 verify-idor（第三槽位），
    三 phase 均按 skill 执行（确认/审计粒度到 skill）。"""
    instances = []

    def _factory(runtime):
        phases = FakePhasesVerifyIdor(runtime)
        instances.append(phases)
        return phases

    app = create_app(api_workspace, phases_factory=_factory, confirm_timeout=30.0)
    with TestClient(app) as client:
        resp = client.post(
            "/api/engagements",
            json={
                "target": "http://127.0.0.1:8080",
                "scope_paths": ["scope.yaml"],
                "autonomy_mode": "semi_auto",
            },
        )
        assert resp.status_code == 201, resp.text
        eng_id = resp.json()["id"]
        assert client.post(f"/api/engagements/{eng_id}/run").status_code == 202

        seen_actions = []
        while True:
            conf = _wait_pending_conf(client, eng_id)
            if conf is None:
                break
            seen_actions.append(conf["action"])
            assert client.post(
                f"/api/confirmations/{conf['cid']}/approve",
                json={"operator": "tester"},
            ).status_code == 200

        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if client.get(f"/api/engagements/{eng_id}").json()["state"] == "done":
                break
            time.sleep(0.05)

        phases = instances[0]
        assert phases.verified == ["verify-sqli", "verify-xss", "verify-idor"]
        assert seen_actions == ["verify-sqli", "verify-xss", "verify-idor"]

# =====================================================================
# M11b：未认证对照 + 确定性归属 的编排层测试
# =====================================================================
#
# 判据是**确定性代码**，故这三条形态在编排层直接定终态（零额外 LLM）：
# public → rejected、blocked → blocked（不驳回）、归属非 matched → rejected。
# 本组测试把它们逐一钉死，并验证结论确实进了送审摘要（红线 3：只有结论+锚点）。


def _control_doc(env, finding_id):
    return json.loads(
        (env.evidence_dir / f"idor_{finding_id}_control.json").read_text(
            encoding="utf-8"
        )
    )


def test_verify_idor_public_resource_rejected_without_llm(verify_env):
    """未认证就能拿到与 B 基准**完全相同**的内容 → 公开资源，确定性驳回。

    这是 M10a 那个 4 臂方差的正面解法：不再交给 Verifier 自由裁量，而是由
    确定性对照判定驳回（零额外 LLM 调用）。
    """
    env = verify_env
    seed = _seed_idor(env.store, env.audit)
    # 对照正文 == B 基准正文（含 owner 字段）：未认证即可拿到 → 公开资源
    same_body = _padded_body(B_TOKEN, owner=_victim_identity())
    orch = _make_orch(env, _canned_fetch(c_status=200, c_body=same_body), _confirm_reply())

    orch.run_verify_phase(skill_name="verify-idor")

    finding = env.store.load_all()[0]
    assert finding.state is FindingState.REJECTED
    transitions = [e for e in _events(env.audit, "finding_state") if e["to"] == "rejected"]
    assert transitions[0]["actor"] == "verify-idor"  # 确定性驳回，非 Verifier
    assert "公开" in transitions[0]["reason"]
    judged = _events(env.audit, "idor_control_judged")[0]
    assert judged["control_verdict"] == "public"
    assert judged["same_bytes"] is True
    # 零 LLM：不给 Verifier 任何机会（这正是消除方差的机制）
    assert _events(env.audit, "verifier_verdict") == []
    assert _events(env.audit, "idor_control_judged")[0]["finding_id"] == seed.id


def test_verify_idor_public_resource_rejected_by_similarity(verify_env):
    """逐字节不同但高度相似 → 仍判公开并驳回（阈值判据同样生效）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    base_b = _padded_body(B_TOKEN, owner=_victim_identity())
    near = _padded_body(B_TOKEN, owner=_victim_identity()).replace(
        "金额 ¥8,800.00", "金额 ¥8,800.01"
    )
    orch = _make_orch(
        env, _canned_fetch(c_status=200, c_body=near), _confirm_reply()
    )
    orch.run_verify_phase(skill_name="verify-idor")
    finding = env.store.load_all()[0]
    assert finding.state is FindingState.REJECTED
    judged = _events(env.audit, "idor_control_judged")[0]
    assert judged["control_verdict"] == "public"
    assert judged["same_bytes"] is False
    assert base_b != near  # 确认这两份正文不同，测的是阈值判据


def test_verify_idor_control_blocked_on_network_error(verify_env):
    """未认证对照请求失败 → **blocked**（覆盖不全，不驳回也不确认）。"""
    env = verify_env
    seed = _seed_idor(env.store, env.audit)
    orch = _make_orch(
        env, _canned_fetch(c_error="URLError: timed out"), _confirm_reply()
    )
    out = orch.run_verify_phase(skill_name="verify-idor")
    assert [f.state.value for f in out] == ["hypothesis"]  # 停留 Hypothesis
    blocked = _events(env.audit, "verify_blocked")
    assert blocked and "未认证对照无法判定" in blocked[0]["reason"]
    assert _events(env.audit, "verifier_verdict") == []


def test_verify_idor_control_blocked_when_inconclusive(verify_env):
    """未认证 2xx 但内容既不逐字节相同、相似度也低于阈值 → blocked（不猜）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    other = "".join(f"<p>other-{i}</p>" for i in range(30))
    orch = _make_orch(
        env, _canned_fetch(c_status=200, c_body=other), _confirm_reply()
    )
    orch.run_verify_phase(skill_name="verify-idor")
    assert env.store.load_all()[0].state is FindingState.HYPOTHESIS
    assert _events(env.audit, "verify_blocked")


def test_verify_idor_ownership_absent_rejected(verify_env):
    """对照 protected 但 B 基准里**没有**可归属 reference 的字段 → 驳回。

    这正是 M11a 裁决第 2 条：单靠"reference 可访问 + 攻击者拿到等价响应"
    不足以构成属性违反，必须有归属证据。
    """
    env = verify_env
    _seed_idor(env.store, env.audit)
    orch = _make_orch(env, _canned_fetch(owner=None), _confirm_reply())
    orch.run_verify_phase(skill_name="verify-idor")
    finding = env.store.load_all()[0]
    assert finding.state is FindingState.REJECTED
    transitions = [e for e in _events(env.audit, "finding_state") if e["to"] == "rejected"]
    assert transitions[0]["actor"] == "verify-idor"
    assert "归属" in transitions[0]["reason"]
    judged = _events(env.audit, "idor_control_judged")[0]
    assert judged["control_verdict"] == "protected"
    assert judged["ownership_verdict"] == "absent"
    assert _events(env.audit, "verifier_verdict") == []


def test_verify_idor_ownership_mismatched_rejected(verify_env):
    """归属字段指向**别人** → mismatched → 驳回（并记下命中字段与值）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    orch = _make_orch(
        env, _canned_fetch(owner="somebody-else"), _confirm_reply()
    )
    orch.run_verify_phase(skill_name="verify-idor")
    finding = env.store.load_all()[0]
    assert finding.state is FindingState.REJECTED
    judged = _events(env.audit, "idor_control_judged")[0]
    assert judged["ownership_verdict"] == "mismatched"
    transitions = [e for e in _events(env.audit, "finding_state") if e["to"] == "rejected"]
    assert "somebody-else" in transitions[0]["reason"]


def test_verify_idor_protected_and_matched_reaches_verifier(verify_env):
    """protected + matched → 才放行进 Verifier（正向路径，确认成立）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    orch = _make_orch(env, _canned_fetch(), _confirm_reply())
    orch.run_verify_phase(skill_name="verify-idor")
    assert env.store.load_all()[0].state is FindingState.CONFIRMED
    assert len(_events(env.audit, "verifier_verdict")) == 1


def test_verify_idor_control_doc_records_both_fingerprints(verify_env):
    """结论文件落盘：三态结论 + 两份响应指纹（供离线复核"是否逐字节相同"）。"""
    env = verify_env
    seed = _seed_idor(env.store, env.audit)
    orch = _make_orch(env, _canned_fetch(), _confirm_reply())
    orch.run_verify_phase(skill_name="verify-idor")
    doc = _control_doc(env, seed.id)
    assert doc["finding_id"] == seed.id
    assert doc["unauthenticated_control"]["verdict"] == "protected"
    assert doc["object_ownership"]["verdict"] == "matched"
    assert doc["object_ownership"]["line_anchor"] is not None
    assert len(doc["baseline_body_sha256"]) == 64
    assert len(doc["control_body_sha256"]) == 64
    assert doc["baseline_body_sha256"] != doc["control_body_sha256"]


def test_verify_idor_control_doc_has_no_raw_body(verify_env):
    """红线 3：结论文件与送审摘要都**不得**含响应体原文。"""
    env = verify_env
    seed = _seed_idor(env.store, env.audit)
    marker = "SECRET-BODY-MARKER-12345"
    body = _padded_body(B_TOKEN, owner=_victim_identity()).replace(
        "（属主 B）", f"（属主 B{marker}）"
    )
    orch = _make_orch(env, _canned_fetch(b_body_override=body), _confirm_reply())
    orch.run_verify_phase(skill_name="verify-idor")
    raw = (env.evidence_dir / f"idor_{seed.id}_control.json").read_text(encoding="utf-8")
    assert marker not in raw
    assert "<html>" not in raw


def test_verify_idor_verifier_receives_deterministic_summary(verify_env):
    """确定性结论块必须进入 Verifier 的送审载荷（且仍无响应体原文）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    captured: list[dict] = []

    class _CapturingRouter(MockRouter):
        def complete(self, tier, messages):
            captured.append(json.loads(messages[-1]["content"]))
            return self.reply

    orch = _make_orch(env, _canned_fetch(), _confirm_reply())
    orch.router = _CapturingRouter(_confirm_reply())
    orch.planner.router = orch.router  # Verifier 复用 planner 的 router
    orch.run_verify_phase(skill_name="verify-idor")

    assert captured, "Verifier 未被调用"
    payload = captured[-1]
    assert "deterministic_summary" in payload
    summary = payload["deterministic_summary"]
    assert summary["unauthenticated_control"]["verdict"] == "protected"
    assert summary["object_ownership"]["verdict"] == "matched"
    assert "<html>" not in json.dumps(summary, ensure_ascii=False)


def test_verify_idor_third_session_used_when_configured(verify_env):
    """scope 配了 session_third 时，对照请求带**第三身份**凭据（而非匿名）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    third = SessionConfig(cookies={"phsess": "eeeeeeeeffffffff"})
    env.scope.session_third = third
    seen: list[dict] = []

    base_fetch = _canned_fetch()

    def _spy(url, session):
        seen.append(dict(session.cookies))
        return base_fetch(url, session)

    orch = _make_orch(env, _spy, _confirm_reply())
    orch.run_verify_phase(skill_name="verify-idor")

    # 三个请求依次是 B / A / 对照；对照必须带**第三身份**凭据
    assert len(seen) == 3
    assert seen[2] == {"phsess": "eeeeeeeeffffffff"}
    assert seen[0] == {"phsess": B_TOKEN} and seen[1] == {"phsess": A_TOKEN}


def test_verify_idor_anonymous_control_when_no_third_session(verify_env):
    """未配 session_third 时，对照请求**完全不发凭据**（匿名）。"""
    env = verify_env
    _seed_idor(env.store, env.audit)
    seen: list[dict] = []
    base_fetch = _canned_fetch()

    def _spy(url, session):
        seen.append(dict(session.cookies))
        return base_fetch(url, session)

    orch = _make_orch(env, _spy, _confirm_reply())
    orch.run_verify_phase(skill_name="verify-idor")
    assert len(seen) == 3
    assert seen[2] == {}  # 匿名
