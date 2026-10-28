"""M22-b：verify-ssti —— 差分求值判定器（纯函数）+ 编排层三态。

## 这份文件钉住什么

1. **纯函数层**（`proofhound/verify/ssti.py`）：乘积匹配的数字边界、三个语法族、
   8 次探针预算的算术、以及 `judge` 的**三态与优先级**——每一条否定条件都有用例
   （基线脏 / 只中一个 / 畸形对照也出数 / 探针出错 / 缺对照）。
2. **编排层**（`Orchestrator._verify_ssti`）：confirmed 走证据门 + Verifier + 四段式；
   rejected 是**真阴性**（回显不求值的形对照必须被驳回）；blocked 是**覆盖不全**
   （宁可不判，绝不驳回）。

## 与 `tests/test_bench_fixture.py` 的分工

那边钉的是**基准靶场**里 F 族真的会求值（真 jinja2）；这边钉的是**判定器**对
观测的正确解读——两边都用「真引擎」以外的替身会同时失去意义，故刻意分开：
靶场用真引擎，判定器用**可控的罐头观测**（要构造"只中一个""畸形也出数"这类
真引擎不会产生的形态，只能用罐头）。
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlparse

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings.dedup import compute_dedup_key
from proofhound.findings.finding import (
    Finding,
    FindingState,
    FindingStore,
    Verification,
)
from proofhound.llm.router import ModelRouter, Tier
from proofhound.skills.registry import SkillRegistry
from proofhound.verify import ssti
from proofhound.verify.gate import GATE_MATRIX
from proofhound.verify.gate import check as gate_check

ASSET = "http://127.0.0.1:8080/render?template=1"
PARAM = "template"
CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

CONFIRM_REPLY = json.dumps(
    {
        "verdict": "confirm",
        "reason": "两个不同乘积都被算出，基线干净、畸形对照未出数",
        "cvss_vector": CVSS,
        "cvss_rationale": "模板注入可致服务端任意代码执行，按证据定指标",
    },
    ensure_ascii=False,
)
REJECT_REPLY = json.dumps(
    {"verdict": "reject", "reason": "差分求值不成立"}, ensure_ascii=False
)


class MockRouter(ModelRouter):
    """罐头 T2 路由（继承 ModelRouter 过 `ensure_router` 的 isinstance 闸）。"""

    def __init__(self, reply: str = CONFIRM_REPLY) -> None:
        self.reply = reply
        self.calls = 0
        self.configs = {Tier.T2: SimpleNamespace(model="canned-verifier")}

    def complete(self, tier, messages):
        self.calls += 1
        return self.reply


class _Runner:
    """最小 runner：只提供 scope（verify 阶段不执行任何工具）。"""

    def __init__(self, scope: Scope) -> None:
        self.scope = scope


# =====================================================================
# 一、纯函数：乘积匹配与探针预算
# =====================================================================


def test_product_matching_respects_digit_boundaries():
    """数字边界匹配：`136481` 里的 `36481` **不得**算命中（否则处处假阳性）。"""
    assert ssti.match_products("结果 36481 与 36672") == {"36481", "36672"}
    assert ssti.match_products("136481") == frozenset()
    assert ssti.match_products("364819") == frozenset()
    assert ssti.match_products("x36481y") == {"36481"}, "非数字边界应当命中"
    assert ssti.match_products("") == frozenset()
    assert ssti.match_products("{{191*191}}") == frozenset(), "表达式本身不含乘积"


def test_syntax_families_cover_three_engine_families_uniquely():
    labels = [f.label for f in ssti.SYNTAX_FAMILIES]
    assert labels == ["double-brace", "dollar-brace", "erb-tag"]
    assert len(set(labels)) == len(labels)
    # 每个族两条表达式 + 一条畸形对照，且畸形对照**确实少一个右括号**
    for family in ssti.SYNTAX_FAMILIES:
        assert family.expr_a != family.expr_b
        assert family.malformed.endswith("}") is False or family.malformed.count("}") < (
            family.expr_a.count("}")
        )
        assert family.engines


def test_probe_budget_matches_worst_case_arithmetic():
    """8 = 1 基线 + 3 语法 × 2 探针 + 1 畸形对照（命中即停只会更少）。"""
    assert ssti.PROBE_BUDGET == 1 + 2 * len(ssti.SYNTAX_FAMILIES) + 1
    assert ssti.PROBE_BUDGET == 8


def test_build_probe_url_replaces_only_target_param():
    url = ssti.build_probe_url("http://h/x?a=1&template=2&b=3", "template", "{{1*1}}")
    pairs = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    assert pairs["a"] == "1" and pairs["b"] == "3"
    assert pairs["template"] == "{{1*1}}", "浏览器/目标侧解码后必须还原表达式"
    assert " " not in url


# =====================================================================
# 二、纯函数：judge 的三态与优先级
# =====================================================================


def _probe(label, kind, syntax, *, products=(), status=200, error=None, url=None):
    return ssti.Probe(
        label=label,
        kind=kind,
        syntax=syntax,
        url=url or f"http://h/?{PARAM}={label}",
        status=status,
        error=error,
        products=frozenset(products),
    )


def _baseline(*, products=(), status=200, error=None):
    return _probe("baseline", ssti.KIND_BASELINE, None, products=products,
                  status=status, error=error, url=ASSET)


def _family_probes(family, *, a_products, b_products, control_products=(),
                   control_error=None, control_missing=False):
    out = [
        _probe(f"{family.label}-expr-a", ssti.KIND_EXPRESSION, family.label,
               products=a_products),
        _probe(f"{family.label}-expr-b", ssti.KIND_EXPRESSION, family.label,
               products=b_products),
    ]
    if not control_missing:
        out.append(
            _probe(f"{family.label}-malformed", ssti.KIND_CONTROL, family.label,
                   products=control_products, error=control_error)
        )
    return out


def test_judge_confirms_two_products_with_clean_control():
    family = ssti.SYNTAX_FAMILIES[0]
    probes = [
        _baseline(),
        *_family_probes(
            family, a_products={"36481"}, b_products={"36672"}
        ),
    ]
    judgment = ssti.judge(probes)
    assert judgment.verdict == "confirmed"
    assert judgment.syntax == family.label
    assert judgment.products == ("36481", "36672")
    assert any("两个不同乘积" in reason for reason in judgment.reasons)


@pytest.mark.parametrize("index", [1, 2])
def test_judge_confirms_on_either_of_the_other_syntax_families(index):
    """`${}` 与 `<%= %>` 两族同样能确认（语法族不是装饰）。"""
    family = ssti.SYNTAX_FAMILIES[index]
    probes = [
        _baseline(),
        *_family_probes(family, a_products={"36481"}, b_products={"36672"}),
    ]
    assert ssti.judge(probes).verdict == "confirmed"


def test_judge_rejects_when_everything_is_clean():
    probes = [_baseline()]
    for family in ssti.SYNTAX_FAMILIES:
        probes.extend(
            _family_probes(family, a_products=set(), b_products=set())
        )
    judgment = ssti.judge(probes)
    assert judgment.verdict == "rejected"
    assert "真阴性" in "".join(judgment.reasons)


def test_judge_blocks_when_only_one_product_appears():
    family = ssti.SYNTAX_FAMILIES[0]
    probes = [
        _baseline(),
        *_family_probes(family, a_products={"36481"}, b_products=set()),
    ]
    judgment = ssti.judge(probes)
    assert judgment.verdict == "blocked"
    assert "只命中一个乘积" in "".join(judgment.reasons)


def test_judge_blocks_when_baseline_contains_product():
    family = ssti.SYNTAX_FAMILIES[0]
    probes = [
        _baseline(products={"36481"}),
        *_family_probes(family, a_products={"36481"}, b_products={"36672"}),
    ]
    judgment = ssti.judge(probes)
    assert judgment.verdict == "blocked"
    assert "反事实不可测" in "".join(judgment.reasons)


def test_judge_blocks_when_baseline_request_fails():
    judgment = ssti.judge([_baseline(error="URLError: down")])
    assert judgment.verdict == "blocked"
    assert "基线请求失败" in "".join(judgment.reasons)


def test_judge_blocks_when_malformed_control_also_evaluates():
    """畸形对照也出数 ⇒ 疑似「strip 非数字后强算」，**判不了**（不确认也不驳回）。"""
    family = ssti.SYNTAX_FAMILIES[0]
    probes = [
        _baseline(),
        *_family_probes(
            family,
            a_products={"36481"},
            b_products={"36672"},
            control_products={"36481"},
        ),
    ]
    judgment = ssti.judge(probes)
    assert judgment.verdict == "blocked"
    assert "畸形模板对照" in "".join(judgment.reasons)


def test_judge_blocks_when_control_is_missing_after_hit():
    """命中却没有补畸形对照 ⇒ 覆盖不全（绝不因为"看起来命中"就确认）。"""
    family = ssti.SYNTAX_FAMILIES[0]
    probes = [
        _baseline(),
        *_family_probes(
            family, a_products={"36481"}, b_products={"36672"}, control_missing=True
        ),
    ]
    judgment = ssti.judge(probes)
    assert judgment.verdict == "blocked"
    assert "缺畸形模板对照" in "".join(judgment.reasons)


def test_judge_blocks_when_control_request_fails():
    family = ssti.SYNTAX_FAMILIES[0]
    probes = [
        _baseline(),
        *_family_probes(
            family,
            a_products={"36481"},
            b_products={"36672"},
            control_error="TimeoutError: slow",
        ),
    ]
    judgment = ssti.judge(probes)
    assert judgment.verdict == "blocked"
    assert "畸形模板对照请求失败" in "".join(judgment.reasons)


def test_judge_blocks_when_probe_errors_and_nothing_hits():
    probes = [_baseline()]
    broken = ssti.SYNTAX_FAMILIES[0]
    probes.extend(
        _family_probes(broken, a_products=set(), b_products=set())
    )
    probes[1] = _probe(
        "double-brace-expr-a", ssti.KIND_EXPRESSION, broken.label,
        error="TimeoutError: read timed out",
    )
    judgment = ssti.judge(probes)
    assert judgment.verdict == "blocked"
    assert "覆盖不全" in "".join(judgment.reasons)


def test_judge_prefers_full_hit_over_partial_in_earlier_family():
    """先扫**全中**再谈"只中一个"：不能因为先探的语法只中一个就否掉后一个的全中。"""
    first, second = ssti.SYNTAX_FAMILIES[0], ssti.SYNTAX_FAMILIES[1]
    probes = [
        _baseline(),
        *_family_probes(first, a_products={"36481"}, b_products=set(),
                        control_missing=True),
        *_family_probes(second, a_products={"36481"}, b_products={"36672"}),
    ]
    judgment = ssti.judge(probes)
    assert judgment.verdict == "confirmed"
    assert judgment.syntax == second.label


def test_judge_blocks_on_empty_probe_list():
    assert ssti.judge([]).verdict == "blocked"
    # 首条不是基线 ⇒ 顺序约定被破坏，fail-closed
    wrong = [
        _probe("x", ssti.KIND_EXPRESSION, "double-brace", products={"36481"})
    ]
    assert ssti.judge(wrong).verdict == "blocked"


# =====================================================================
# 三、纯函数：给 Verifier 的结构化摘要（红线 3）
# =====================================================================


def test_summary_for_verifier_carries_no_response_body():
    """红线 3：摘要里只能有枚举/计数/状态码——**响应体一行都不进**。"""
    sentinel = "SECRET_BODY_MARKER_42"
    family = ssti.SYNTAX_FAMILIES[0]
    probes = [
        ssti.Probe(
            label="baseline",
            kind=ssti.KIND_BASELINE,
            syntax=None,
            url=ASSET,
            status=200,
            error=None,
            products=frozenset(),
        ),
        *_family_probes(family, a_products={"36481"}, b_products={"36672"}),
    ]
    judgment = ssti.judge(probes)
    summary = ssti.summary_for_verifier(
        judgment, probes, url=ASSET, param=PARAM
    )
    text = json.dumps(summary, ensure_ascii=False)
    assert sentinel not in text
    assert summary["verdict"] == "confirmed"
    assert summary["baseline_clean"] is True
    assert summary["malformed_checked"] is True
    assert summary["malformed_clean"] is True
    assert summary["probe_count"] == len(probes)
    assert summary["probe_budget"] == ssti.PROBE_BUDGET
    assert summary["param"] == PARAM


def test_summary_for_verifier_marks_blocked_control_explicitly():
    family = ssti.SYNTAX_FAMILIES[0]
    probes = [
        _baseline(),
        *_family_probes(
            family,
            a_products={"36481"},
            b_products={"36672"},
            control_products={"36481"},
        ),
    ]
    summary = ssti.summary_for_verifier(
        ssti.judge(probes), probes, url=ASSET, param=PARAM
    )
    assert summary["verdict"] == "blocked"
    assert summary["malformed_clean"] is False
    assert summary["malformed_checked"] is True


# =====================================================================
# 四、编排层：三态 + 证据门 + 四段式
# =====================================================================


def _param_value(url: str) -> str:
    for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if key == PARAM:
            return value
    return ""


def _make_victim(mode: str):
    """可控的罐头取数：模拟真实目标的四种形态。

    - ``jinja``：只对 ``{{ }}`` 求值（真实的真引擎形态）；
    - ``erb``：只对 ``<%= %>`` 求值（第三语法族，用于钉 8 次预算）；
    - ``echo``：**只回显不求值**（形对照，必须 rejected）；
    - ``naive``：strip 掉非数字/非 ``*`` 后**强算**（畸形对照也出数，必须 blocked）。
    """

    def victim(url: str, session) -> ssti.ProbeResponse:
        value = _param_value(url)
        if mode == "echo":
            body = f"<div>{value}</div>"
        elif mode == "naive":
            cleaned = "".join(ch for ch in value if ch.isdigit() or ch == "*")
            try:
                left, _, right = cleaned.partition("*")
                product = str(int(left) * int(right))
            except (ValueError, TypeError):
                product = ""
            body = f"<div>结果 {product}</div>" if product else "<div>无法计算</div>"
        else:
            pairs = {"{{191*191}}": "36481", "{{191*192}}": "36672"}
            if mode == "erb":
                pairs = {"<%= 191*191 %>": "36481", "<%= 191*192 %>": "36672"}
            rendered = pairs.get(value)
            body = (
                f"<div>渲染结果 {rendered}</div>"
                if rendered
                else f"<div>模板错误：{value}</div>"
            )
        return ssti.ProbeResponse(url=url, status=200, body=body)

    return victim


@pytest.fixture
def env(tmp_path, make_skill_dir):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    audit = AuditLog(evidence_dir / "audit.jsonl")
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080])
    return SimpleNamespace(
        evidence_dir=evidence_dir,
        audit=audit,
        registry=SkillRegistry(make_skill_dir(name="verify-ssti", tools=())).discover(),
        store=FindingStore(evidence_dir / "findings.jsonl"),
        scope=scope,
        router=MockRouter(),
    )


def _finding(env, *, asset=ASSET, param=PARAM, evidence_kinds=("crawl-endpoint",)):
    finding = Finding(
        id=env.store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type="ssti",
        severity="critical",
        asset=asset,
        param=param,
        confidence="low",
        evidence_kinds=list(evidence_kinds),
        dedup_key=compute_dedup_key(asset, "ssti", param),
        source_signal_refs=[],
        created_at="2026-10-28T00:00:00.000+00:00",
        updated_at="2026-10-28T00:00:00.000+00:00",
        audit=env.audit,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="测试种子")
    env.store.append(finding)
    return finding


def _orch(env, victim, *, router=None):
    return Orchestrator(
        env.registry,
        _Runner(env.scope),
        router or env.router,
        env.audit,
        evidence_dir=env.evidence_dir,
        ssti_fetch=victim,
    )


def _events(env, name: str) -> list[dict]:
    return [e for e in env.audit.read_all() if e.get("event") == name]


def test_handler_registered_and_covers_only_ssti():
    handlers = Orchestrator._verify_handlers(Orchestrator.__new__(Orchestrator))
    assert "verify-ssti" in handlers
    covered, fn = handlers["verify-ssti"]
    assert covered == frozenset({"ssti"})
    assert callable(fn)


def test_gate_requires_named_template_evaluation_kind(env):
    """证据门：ssti 只认具名标签 `template-evaluation`（笼统 behavioral 不算）。"""
    requirement = GATE_MATRIX["ssti"]
    assert requirement.methods == frozenset({ssti.SSTI_CONFIRMED_METHOD})
    assert requirement.behavioral_kinds == frozenset(
        {ssti.SSTI_EVALUATION_EVIDENCE_KIND}
    )

    finding = _finding(env)
    assert not gate_check(finding).passed, "无 verification 必须 fail-closed"

    finding.verification = Verification(
        method=ssti.SSTI_CONFIRMED_METHOD, evidence_refs=["x.json"]
    )
    assert not gate_check(finding).passed, "缺具名证据标签不得过门"
    finding.evidence_kinds.append("behavioral")
    assert not gate_check(finding).passed, "笼统 behavioral 不是本类型的证据"
    finding.evidence_kinds.append(ssti.SSTI_EVALUATION_EVIDENCE_KIND)
    assert gate_check(finding).passed


def test_confirmed_path_records_four_part_evidence(env):
    finding = _finding(env)
    orch = _orch(env, _make_victim("jinja"))
    outcome = orch._verify_ssti(finding, env.registry.get("verify-ssti"), env.store)

    assert outcome == "confirmed", outcome
    stored = env.store.load_all()[0]
    assert stored.state is FindingState.CONFIRMED
    assert stored.verification is not None
    assert stored.verification.method == ssti.SSTI_CONFIRMED_METHOD
    assert ssti.SSTI_EVALUATION_EVIDENCE_KIND in stored.evidence_kinds
    # 四段式齐备（M8d 起所有确认链路都要有）
    assert stored.verification.claim
    assert stored.verification.expected
    assert stored.verification.actual
    assert stored.verification.reproduction_steps
    # CVSS 由代码算分（不是模型给的数字）
    assert stored.cvss_vector == CVSS
    assert stored.cvss_score is not None and stored.cvss_score > 0
    # 探针按次审计 + 判定审计
    attempts = _events(env, "ssti_probe_attempt")
    assert len(attempts) == 4, "confirmed 只需 1 基线 + 2 表达式 + 1 畸形对照"
    assert {a["kind"] for a in attempts} == {"baseline", "expression", "control"}
    judged = _events(env, "ssti_judged")
    assert judged and judged[0]["verdict"] == "confirmed"
    assert judged[0]["budget"] == ssti.PROBE_BUDGET
    # 证据引用指向真文件
    assert len(stored.verification.evidence_refs) == 5  # 4 探针 + 判定 JSON
    for ref in stored.verification.evidence_refs:
        assert (env.evidence_dir / ref.split("/")[-1]).exists(), ref


def test_rejected_path_when_target_only_echoes(env):
    """形对照：参数被回显但**不求值** ⇒ 真阴性，必须 REJECTED（不误报）。"""
    finding = _finding(env)
    orch = _orch(env, _make_victim("echo"))
    outcome = orch._verify_ssti(finding, env.registry.get("verify-ssti"), env.store)

    assert outcome == "rejected", outcome
    stored = env.store.load_all()[0]
    assert stored.state is FindingState.REJECTED
    assert "差分求值不成立" in (stored.rejection_reason or "")
    attempts = _events(env, "ssti_probe_attempt")
    assert len(attempts) == 7, "未命中时不补畸形对照：1 基线 + 3 语法 × 2"
    assert all(a["products"] == [] for a in attempts)
    assert env.router.calls == 0, "真阴性不得调用 Verifier"


def test_blocked_path_when_naive_calculator_also_evaluates_malformed(env):
    """「strip 非数字后强算」的端点：表达式全中、畸形对照也出数 ⇒ **判不了**。"""
    finding = _finding(env)
    orch = _orch(env, _make_victim("naive"))
    outcome = orch._verify_ssti(finding, env.registry.get("verify-ssti"), env.store)

    assert outcome == "blocked", outcome
    stored = env.store.load_all()[0]
    assert stored.state is FindingState.HYPOTHESIS, "blocked 必须停在 Hypothesis"
    blocked = _events(env, "verify_blocked")
    assert blocked and "畸形模板对照" in blocked[0]["reason"]
    assert env.router.calls == 0


def test_blocked_path_when_scope_rejects_asset(env):
    env.scope = Scope(networks=["10.0.0.0/8"], ports=[8080])
    finding = _finding(env)
    orch = _orch(env, _make_victim("jinja"))
    assert orch._verify_ssti(finding, env.registry.get("verify-ssti"), env.store) == "blocked"
    assert _events(env, "verify_scope_rejected"), "越界必须留审计"


def test_blocked_when_candidate_has_no_param(env):
    finding = _finding(env, asset="http://127.0.0.1:8080/render", param=None)
    orch = _orch(env, _make_victim("jinja"))
    assert orch._verify_ssti(finding, env.registry.get("verify-ssti"), env.store) == "blocked"
    blocked = _events(env, "verify_blocked")
    assert blocked and "缺 param" in blocked[0]["reason"]


def test_blocked_for_post_form_candidate(env):
    """POST 表单型候选的 SSTI 验证未实现 ⇒ blocked（不凭空造 URL）。"""
    finding = _finding(env, evidence_kinds=("crawl-form",))
    orch = _orch(env, _make_victim("jinja"))
    assert orch._verify_ssti(finding, env.registry.get("verify-ssti"), env.store) == "blocked"
    blocked = _events(env, "verify_blocked")
    assert blocked and "POST 表单" in blocked[0]["reason"]


def test_probe_budget_is_never_exceeded_on_third_syntax(env):
    """第三语法族命中时**恰好**用满 8 次（1 + 2 + 2 + 2 + 1），一次不多。"""
    finding = _finding(env)
    orch = _orch(env, _make_victim("erb"))
    outcome = orch._verify_ssti(finding, env.registry.get("verify-ssti"), env.store)

    assert outcome == "confirmed", outcome
    attempts = _events(env, "ssti_probe_attempt")
    assert len(attempts) == ssti.PROBE_BUDGET == 8
    labels = [a["label"] for a in attempts]
    assert labels[0] == "baseline"
    assert labels[-1] == "erb-tag-malformed"
    synthetic = [a for a in attempts if a["syntax"] == "double-brace"]
    assert len(synthetic) == 2, "第一族的两条表达式探针仍要发出（顺序探测）"


def test_verifier_reject_on_confirmed_facts_leaves_reproduced(env):
    """证据靠得住、但 Verifier 判 reject ⇒ 终态 REJECTED（终审仍是否决权）。"""
    env.router = MockRouter(REJECT_REPLY)
    finding = _finding(env)
    orch = _orch(env, _make_victim("jinja"))
    outcome = orch._verify_ssti(finding, env.registry.get("verify-ssti"), env.store)
    assert outcome == "rejected", outcome
    assert env.store.load_all()[0].state is FindingState.REJECTED
    assert env.router.calls == 1
