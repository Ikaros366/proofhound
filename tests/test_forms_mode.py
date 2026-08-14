"""M8a forms 模式测试：sqlmap --forms argv 构造、scope 拒绝、triage form_page
展开、verify 全链（FakeRunner 预制输出，零真实执行）。

覆盖验收点：--forms 在 / --data 与 -p 不在、forms+param 互斥 fail-closed、
越界目标拒绝（构造器→check_scope 与 triage 两层）、字段名/页面路径两级
启发式、forms 与 get_param 共享 20 上限（triage_capped）、created_by_source
摘要、--forms 全链 Confirmed（method 仍 sqlmap-confirmed、行为证据标签）。
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope, check_scope
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
from proofhound.tools.build import build_command
from proofhound.tools.sandbox import RunResult

FIXTURES = Path(__file__).parent / "fixtures"
BASE = "http://127.0.0.1:8080"
FORMS_PAGE = f"{BASE}/vulnerabilities/sqli/"  # POST 表单页（裸 URL，无 query）
PHPSESSID = "df6a4b9c0e1f2a3b4c5d6e7f890abcde"
SESSION = SessionConfig(cookies={"PHPSESSID": PHPSESSID, "security": "medium"})
CVSS_98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


# ---- build.py：forms 模式 argv ----


def test_forms_argv_golden():
    argv = build_command(
        "sqlmap", {"url": FORMS_PAGE, "forms": True, "with_session": True},
        session=SESSION,
    )
    assert argv[:2] == ["sqlmap", "-u"]
    assert argv[2] == FORMS_PAGE
    assert "--forms" in argv
    assert "--data" not in argv  # 永不手拼请求体
    assert "-p" not in argv  # forms 模式不指定测试参数
    assert "--cookie" in argv
    assert argv[argv.index("--cookie") + 1] == SESSION.cookie_header()
    assert "--batch" in argv and "--flush-session" in argv
    assert "--disable-coloring" in argv


def test_forms_default_off_unchanged():
    """forms 缺省 False：argv 与旧 golden 一致（不产 --forms）。"""
    argv = build_command("sqlmap", {"url": f"{BASE}/x?id=1", "param": "id"})
    assert "--forms" not in argv
    assert "-p" in argv


def test_forms_param_mutually_exclusive_fail_closed():
    with pytest.raises(ValueError, match="互斥"):
        build_command("sqlmap", {"url": FORMS_PAGE, "forms": True, "param": "id"})


def test_forms_out_of_scope_rejected():
    """forms 模式越界目标：构造的 argv 过 check_scope 被拒（沙箱层强校验同源）。"""
    argv = build_command("sqlmap", {"url": "http://10.9.9.9:8080/p", "forms": True})
    decision = check_scope(Scope(networks=["127.0.0.0/8"]), argv[1:])
    assert not decision.allowed
    assert decision.violations


# ---- triage：form_page 展开 ----


class FakeLLM:
    def __init__(self):
        self.calls = 0

    def complete(self, messages):
        self.calls += 1
        raise AssertionError("triage 不得调用 LLM")


def _form_row(asset, fields, evidence_ref):
    return {
        "asset": asset,
        "status_code": 200,
        "title": None,
        "tech": [],
        "kind": "form_page",
        "source_tool": "katana",
        "skill": "recon-crawl",
        "evidence_ref": evidence_ref,
        "form_fields": fields,
    }


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


def _summary(audit):
    return [e for e in audit.read_all() if e["event"] == "triage_completed"][0]


def test_form_field_hint_creates_forms_candidate(triage_env):
    """字段名命中提示表 → forms 模式 sqli 候选（crawl-form + param 分量）。"""
    orch, audit, evidence_dir, raw = triage_env
    _write_signals(
        evidence_dir,
        [_form_row(FORMS_PAGE, ["id", "Submit"], f"{raw}#L6")],
    )
    findings = orch.run_triage_phase()

    assert len(findings) == 1  # id 命中；Submit 非启发式键不建
    finding = findings[0]
    assert finding.vuln_type == "sqli"
    assert finding.param == "id"
    assert finding.severity == "medium"
    assert finding.evidence_kinds == ["crawl-form"]  # forms 验证模式标记
    assert finding.asset == FORMS_PAGE
    summary = _summary(audit)
    assert summary["created"] == 1
    assert summary["created_by_source"] == {"form_page": 1}


def test_form_path_hint_fallback(triage_env):
    """字段名零命中 → 页面路径提示回退（param=None）；路径也不命中保持 Signal。"""
    orch, audit, evidence_dir, raw = triage_env
    _write_signals(
        evidence_dir,
        [
            _form_row(f"{BASE}/login.php", ["usrename", "pw"], f"{raw}#L1"),
            _form_row(f"{BASE}/guestbook", ["txtname", "msg"], f"{raw}#L2"),
        ],
    )
    findings = orch.run_triage_phase()

    assert len(findings) == 1  # login.php 路径命中；guestbook 路径不命中
    assert findings[0].asset == f"{BASE}/login.php"
    assert findings[0].param is None
    assert findings[0].evidence_kinds == ["crawl-form"]
    summary = _summary(audit)
    assert summary["created"] == 1
    assert summary["kept_signal"] == 1


def test_forms_dedup_param_dimension(triage_env):
    """同页不同命中字段不合并（dedup 带 param 分量）；同指纹重跑合并证据。"""
    orch, audit, evidence_dir, raw = triage_env
    _write_signals(
        evidence_dir,
        [_form_row(f"{BASE}/p", ["id", "page", "foo"], f"{raw}#L1")],
    )
    orch.run_triage_phase()
    store = FindingStore(evidence_dir / "findings.jsonl")
    findings = store.load_all()
    assert len(findings) == 2
    assert {f.param for f in findings} == {"id", "page"}

    orch.run_triage_phase()  # 重跑幂等：证据已归并，不重复建
    assert len(store.load_all()) == 2
    summaries = [e for e in audit.read_all() if e["event"] == "triage_completed"]
    assert summaries[1]["created"] == 0
    assert summaries[1]["merged"] == 0


def test_forms_share_sqli_cap_with_get_param(triage_env):
    """forms 与 get_param 候选共享每 engagement 20 条上限（同一计数器）。"""
    orch, audit, evidence_dir, raw = triage_env
    rows = [_param_row(f"{BASE}/g{n}?id={n}", f"{raw}#L1") for n in range(1, 13)]
    rows += [
        _form_row(f"{BASE}/f{n}", ["id"], f"{raw}#L2") for n in range(1, 14)
    ]
    _write_signals(evidence_dir, rows)
    orch.run_triage_phase()

    store = FindingStore(evidence_dir / "findings.jsonl")
    # sqli 12 get_param + 8 form_page = 20 满；M8c：get_param 的 id 键另产
    # idor 候选（独立上限 10，与 sqli 共享计数器无涉）
    findings = store.load_all()
    assert sum(1 for f in findings if f.vuln_type == "sqli") == 20
    assert sum(1 for f in findings if f.vuln_type == "idor") == 10
    capped = [e for e in audit.read_all() if e["event"] == "triage_capped"]
    assert len(capped) == 2  # sqli 与 idor 各自独立记一条
    by_type = {e["vuln_type"]: e for e in capped}
    assert by_type["sqli"]["dropped"] == 5
    assert by_type["idor"]["dropped"] == 2  # 12 条 get_param 的 idor 候选建 10 丢 2
    summary = _summary(audit)
    assert summary["created_by_source"] == {"get_param": 22, "form_page": 8}


def test_forms_out_of_scope_dropped(triage_env):
    """triage 层 scope 校验：form_page 越界 asset 丢弃并记审计。"""
    orch, audit, evidence_dir, raw = triage_env
    _write_signals(
        evidence_dir, [_form_row("http://10.9.9.9:8080/p", ["id"], f"{raw}#L1")]
    )
    assert orch.run_triage_phase() == []
    oos = [e for e in audit.read_all() if e["event"] == "triage_out_of_scope"]
    assert len(oos) == 1
    assert oos[0]["asset"] == "http://10.9.9.9:8080/p"


# ---- verify：--forms 全链（FakeRunner + MockRouter） ----


class FakeRunner:
    """按工具名弹出预制输出；写真实 stdout/stderr 证据文件，零执行。"""

    def __init__(self, scope: Scope, evidence_dir: Path, script: dict[str, list]):
        self.scope = scope
        self.evidence_dir = evidence_dir
        self.script = {tool: list(responses) for tool, responses in script.items()}
        self.calls: list[tuple[str, list[str]]] = []
        self.egress_proxy_url = None
        self._seq = 0

    def run(self, tool, args, timeout=300, image=None):
        self.calls.append((tool, args))
        responses = self.script.get(tool) or []
        if not responses:
            raise AssertionError(f"FakeRunner 未预制 {tool} 的输出")
        stdout_text, exit_code = responses.pop(0)
        self._seq += 1
        stdout_path = self.evidence_dir / f"fake{self._seq}.stdout.log"
        stderr_path = self.evidence_dir / f"fake{self._seq}.stderr.log"
        stdout_path.write_text(stdout_text, encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        return RunResult(
            rejected=False,
            command=[tool, *args],
            exit_code=exit_code,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )


class MockRouter(ModelRouter):
    """罐头 T2 路由（继承 ModelRouter 过 ensure_router 的 isinstance 闸）。"""

    def __init__(self, reply: str):
        self.reply = reply  # 不调 super().__init__：不建 HTTP 客户端
        self.calls: list[tuple] = []
        self.configs = {Tier.T2: SimpleNamespace(model="kimi-k3-test")}

    def complete(self, tier, messages):
        self.calls.append((tier, messages))
        return self.reply


@pytest.fixture
def verify_env(tmp_path, make_skill_dir):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    audit = AuditLog(evidence_dir / "audit.jsonl")
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080], session=SESSION)
    registry = SkillRegistry(
        make_skill_dir(name="verify-sqli", tools=("httpx", "sqlmap"))
    ).discover()
    store = FindingStore(evidence_dir / "findings.jsonl")
    return SimpleNamespace(
        evidence_dir=evidence_dir, audit=audit, scope=scope,
        registry=registry, store=store,
    )


def _seed_forms(store: FindingStore, audit: AuditLog) -> Finding:
    finding = Finding(
        id=store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type="sqli",
        severity="medium",
        asset=FORMS_PAGE,
        param="id",
        confidence="low",
        evidence_kinds=["crawl-form"],  # forms 验证模式标记
        dedup_key=compute_dedup_key(FORMS_PAGE, "sqli", "id"),
        source_signal_refs=[],
        created_at="2026-08-14T00:00:00.000+00:00",
        updated_at="2026-08-14T00:00:00.000+00:00",
        audit=audit,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="测试种子")
    store.append(finding)
    return finding


def test_verify_forms_mode_full_chain(verify_env):
    """crawl-form Hypothesis → baseline → sqlmap --forms → 证据门 →
    Verifier confirm → Confirmed；argv 断言 --forms 在、-p/--data 不在。"""
    seed = _seed_forms(verify_env.store, verify_env.audit)
    httpx_line = (
        json.dumps({"url": FORMS_PAGE, "status_code": 200, "title": "DVWA"}) + "\n"
    )
    forms_stdout = (FIXTURES / "sqlmap_confirmed_forms_1_10.txt").read_text(
        encoding="utf-8"
    )
    reply = (
        '{"verdict": "confirm", "reason": "POST 表单证据链完整", '
        f'"cvss_vector": "{CVSS_98}", "cvss_rationale": "sqlmap 确认注入"}}'
    )
    runner = FakeRunner(
        verify_env.scope,
        verify_env.evidence_dir,
        {"httpx": [(httpx_line, 0)], "sqlmap": [(forms_stdout, 0)]},
    )
    router = MockRouter(reply)
    orch = Orchestrator(
        verify_env.registry, runner, router, verify_env.audit,
        evidence_dir=verify_env.evidence_dir,
    )

    processed = orch.run_verify_phase(skill_name="verify-sqli")

    assert [f.id for f in processed] == [seed.id]
    assert [tool for tool, _ in runner.calls] == ["httpx", "sqlmap"]
    sqlmap_args = runner.calls[1][1]
    assert "--forms" in sqlmap_args
    assert "-p" not in sqlmap_args
    assert "--data" not in sqlmap_args
    assert "--cookie" in sqlmap_args
    assert PHPSESSID in sqlmap_args[sqlmap_args.index("--cookie") + 1]

    finding = verify_env.store.load_all()[0]
    assert finding.state is FindingState.CONFIRMED
    verification = finding.verification
    assert verification.method == "sqlmap-confirmed"  # 证据门白名单不变
    assert "behavioral" in finding.evidence_kinds
    assert "crawl-form" in finding.evidence_kinds
    assert "（POST）" in verification.baseline_diff  # param_kind 来自 stdout
    assert "--forms" in verification.reproduction_steps[1]
    assert finding.cvss_vector == CVSS_98
    assert finding.cvss_score == 9.8
    assert finding.severity == "critical"  # 算分覆盖种子 medium
    completed = [
        e for e in verify_env.audit.read_all() if e["event"] == "verify_completed"
    ]
    assert completed and completed[0]["confirmed"] == 1


def test_verify_get_mode_unaffected(verify_env):
    """对照组：crawl-endpoint（GET）候选仍走 -p 模式，不产 --forms。"""
    asset = f"{BASE}/vulnerabilities/sqli/?id=1&Submit=Submit"
    finding = Finding(
        id=verify_env.store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type="sqli",
        severity="medium",
        asset=asset,
        param="id",
        confidence="low",
        evidence_kinds=["crawl-endpoint"],
        dedup_key=compute_dedup_key(asset, "sqli", "id"),
        source_signal_refs=[],
        created_at="2026-08-14T00:00:00.000+00:00",
        updated_at="2026-08-14T00:00:00.000+00:00",
        audit=verify_env.audit,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="测试种子")
    verify_env.store.append(finding)

    httpx_line = json.dumps({"url": asset, "status_code": 200}) + "\n"
    negative = (FIXTURES / "sqlmap_negative_1_10.txt").read_text(encoding="utf-8")
    runner = FakeRunner(
        verify_env.scope,
        verify_env.evidence_dir,
        {"httpx": [(httpx_line, 0)], "sqlmap": [(negative, 0)]},
    )
    orch = Orchestrator(
        verify_env.registry, runner, MockRouter("{}"), verify_env.audit,
        evidence_dir=verify_env.evidence_dir,
    )
    orch.run_verify_phase(skill_name="verify-sqli")

    sqlmap_args = runner.calls[1][1]
    assert "--forms" not in sqlmap_args
    assert "-p" in sqlmap_args
