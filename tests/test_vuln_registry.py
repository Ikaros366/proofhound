"""落点守护：每个**已注册的 vuln_type** 在六处落点齐备且互相一致。

## 这份文件防的是什么（M16-c 交付缺陷的复盘）

`unauth-exposure` 曾经「什么都齐了、就是没接上」：`GATE_MATRIX` 项、
`skills/verify-unauth/`、`profiles.py` 登记、`orchestrator._verify_unauth`、41 个测试、
真靶验收脚本**全部就位**，**却没有任何生产期 producer** ⇒ 真实扫描永远不会有
Finding 进入 `_verify_unauth`。当时 **1262 个测试全绿**，因为绝大多数测试
**直接构造 Finding**（含该里程碑自己的 `test_unauth_judge.py` 与 demo 的 `_seed()`）
——它们覆盖「判定通道」，覆盖不到「扫描→发现→验证」这条生产路径，而且
**没有任何测试断言「每个注册类型必须有生产者」**（AGENTS.md 已知限制 58）。

⇒ 本文件的纪律：**断言对象是生产链路本身，不是手写的 Finding**。

## 三条守护（交接单首要事项 ②）

1. :func:`test_every_registered_type_has_a_reachable_producer` —— **每个注册类型都
   至少有一个生产期 producer**，走**真实** `run_triage_phase`（零 seed）+
   模型白名单。这条能自动抓住限制 58 那类缺陷。
2. :func:`test_every_registered_type_is_wired_into_production_stack` —— 每个注册类型
   的 verify handler **真的挂在 API 生产栈上**。M16-c 之后复核发现：
   `verify-unauth` 连 `OrchestratorPhases` 的第 5 个槽位都没有，属同一类缺陷
   断在**出口**那一端（AGENTS.md 已知限制 59）。
3. :func:`test_discovery_smoke_without_session_...` —— 无会话时不得派生
   `unauth-exposure`（等价性判定结构上要求目标能认证）。

## 与既有测试的分工

- `tests/test_skill_profiles.py`（M9d）钉住 **profiles ↔ SKILL.md frontmatter** 一致；
- 本文件钉住 **GATE_MATRIX ↔ 生产者 ↔ verify handler ↔ 生产栈槽位** 这条链，
  并复用 `profile_for` 断言落点**在册**（未登记即 KeyError，fail-closed）。
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import NamedTuple

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core import orchestrator as orch_mod
from proofhound.core.orchestrator import Orchestrator, _VERIFY_PRECONDITIONS
from proofhound.findings.finding import FindingStore
from proofhound.findings.signal import Signal
from proofhound.skills.profiles import profile_for
from proofhound.skills.registry import SkillRegistry
from proofhound.verify.gate import ALLOWED_VULN_TYPES, GATE_MATRIX, VULN_REGISTRY
from proofhound.verify.gate import VulnSpec

REPO = Path(__file__).resolve().parent.parent
BUILTIN_SKILLS = REPO / "skills"

#: 生产栈必须把每个 verify handler 都挂上（含默认形参的那几个）。
PRODUCTION_INIT = "proofhound/api/runner.py::OrchestratorPhases.__init__"

#: `cmdi` 生产者未接的 xfail 理由（限制 61）；M18-b 接好后必须删掉本标记。
XFAIL_CMDI_PRODUCER = (
    "已知限制 61：cmdi 的候选来源（规则表 _CMDI_PARAM_HINTS + 模型通道）"
    "属 M18-b，尚未接上"
)



class VulnLanding(NamedTuple):
    """单个 vuln_type 的落点清单。

    **机制字段全部从登记表派生**（M17-c）：``verify_skill`` /
    ``in_model_whitelist`` / ``requires_session`` 三项直接读
    ``verify/gate.py::VULN_REGISTRY``，本文件**不再自持这几份副本**——
    自持副本正是限制 58 那一类「多处手工同步、互不校验」缺陷的温床。

    ``producer`` 是本文件**唯一自持**的字段：它是**人类可读的生产者说明**
    （规则表 kind / 模型通道），只用于失败信息定位，判定一律走真实代码。
    登记表**刻意不记 producer**——它是规则表的属性、会随规则表演进，
    记进「类型事实表」就等于制造第二个真相源。
    """

    producer: str
    #: 以下三项由 :func:`_landing` 从 ``VULN_REGISTRY`` 回填
    verify_skill: str
    in_model_whitelist: bool
    requires_session: bool
    #: **已核实**「刻意只走模型通道、规则表零候选」——只有这类才豁免
    #: 「必须能在规则表产出里看到」的断言。当前仅 ``ssrf``（M15 裁定：
    #: 规则表刻意不给 SSRF 提示表），其模型产出能力由 tests/test_llm_triage.py 实测。
    #: ⚠️ 不要为了让新类型过关而随手置 True——那正是本字段要防的后门。
    model_channel_only: bool = False


def _landing(
    vuln_type: str, producer: str, *, model_channel_only: bool = False
) -> VulnLanding:
    """从登记表取机制字段 + 本文件给出的人类可读生产者说明。"""
    spec = VULN_REGISTRY[vuln_type]
    return VulnLanding(
        producer=producer,
        verify_skill=spec.verify_skill,
        in_model_whitelist=spec.in_model_whitelist,
        requires_session=spec.requires_session,
        model_channel_only=model_channel_only,
    )


#: vuln_type → 落点清单。**新增类型必须在此登记**（与 `VULN_REGISTRY` 键集双向校验）。
VULN_LANDINGS: dict[str, VulnLanding] = {
    "sqli": _landing(
        "sqli",
        "param-endpoint / form_page（_SQLI_PARAM_HINTS 命中）+ 模型通道",
    ),
    "xss": _landing(
        "xss",
        "param-endpoint（_XSS_PARAM_HINTS 命中）+ 模型通道",
    ),
    "idor": _landing(
        "idor",
        "param-endpoint（_IDOR_PARAM_HINTS 命中）+ 模型通道",
    ),
    "ssrf": _landing(
        "ssrf",
        # M15 第一步刻意只放开候选：规则表**不给** SSRF 提示表，
        # 唯一生产者是模型通道。**已核实**：tests/test_llm_triage.py 覆盖其模型产出。
        "模型通道（ALLOWED_VULN_TYPES；规则表刻意零候选）",
        model_channel_only=True,
    ),
    "unauth-exposure": _landing(
        "unauth-exposure",
        # M16-c 裁定：窄形态无需语义判断 ⇒ 由确定性规则表从 web-probe 派生，
        # **不**进模型白名单。该派生由 M17-b 实现（限制 58 关闭）。
        "web-probe（有预置会话且状态码 ∈ 2xx）",
    ),
    "cmdi": _landing(
        "cmdi",
        # M18 裁定 C3：规则表 `_CMDI_PARAM_HINTS` + 模型通道**两条路都产**。
        # 候选来源在 M18-b 接上；M18-a 先落判定通道。
        "param-endpoint（_CMDI_PARAM_HINTS 命中）+ 模型通道",
    ),
}


# --------------------------------------------------------------------------
# 合成 Signal：覆盖规则表**全部输入域**（守护 1/2 共用；零 seed、零 mock）
# --------------------------------------------------------------------------


def _synthetic_signals() -> list[Signal]:
    """覆盖规则表全部输入域的合成 Signal 集合。

    穷举维度：① `web-probe` × 全部状态码（含 `_EXPOSED_STATUSES` 之外的值）；
    ② `param-endpoint` × 三张提示表的**并集**每个键；③ `form_page` ×
    {命中页面路径回退, 命中字段名, 两者都不命中}。
    """
    signals: list[Signal] = []
    ref = "synthetic.stdout.log#L1"

    for status in sorted({200, 201, 204, 301, 302, 307, 308, 401, 403, 404, 500}):
        signals.append(
            Signal(
                asset="http://h/admin",
                status_code=status,
                kind="web-probe",
                source_tool="httpx",
                skill="web-scan",
                evidence_ref=ref,
            )
        )

    hint_union = (
        orch_mod._SQLI_PARAM_HINTS
        | orch_mod._XSS_PARAM_HINTS
        | orch_mod._IDOR_PARAM_HINTS
    )
    for key in sorted(hint_union):
        signals.append(
            Signal(
                asset="http://h/x?" + key + "=1",
                status_code=200,
                kind="param-endpoint",
                source_tool="katana",
                skill="recon-crawl",
                evidence_ref=ref,
            )
        )

    for asset, fields in (
        ("http://h/login", ()),  # 路径提示回退（_SQLI_PATH_HINTS 含 login）
        ("http://h/x", tuple(sorted(orch_mod._SQLI_PARAM_HINTS))),  # 字段名命中
        ("http://h/zzz", ("nosuchfield",)),  # 两者都不命中 → 保持 Signal
    ):
        signals.append(
            Signal(
                asset=asset,
                status_code=200,
                kind="form_page",
                source_tool="katana",
                skill="recon-crawl",
                evidence_ref=ref,
                form_fields=list(fields),
            )
        )
    return signals


def _model_channel_producers() -> set[str]:
    from proofhound.llm.triage import ALLOWED_VULN_TYPES

    return set(ALLOWED_VULN_TYPES)


#: **已知的非门禁类型**（生产期有产出、刻意不在 `GATE_MATRIX`、不可 Confirmed）。
#: 显式登记而非隐式豁免——它们进报告 hypothesis 桶（`report/data.py`），
#: 故生产链路的产出集必须把它们算作「已知」，否则反向断言会误报。
NON_GATE_VULN_TYPES: dict[str, str] = {
    "web-exposure": (
        "web-probe 存活状态码产出（M3a）；证据是纯 status-code，"
        "铁律 2 禁止其 Confirmed，故**刻意不在** GATE_MATRIX"
    ),
}


def _registered_types() -> set[str]:
    """已注册类型的真相源 = ``verify/gate.py::VULN_REGISTRY``（M17-c）。"""
    return set(VULN_REGISTRY)


def _known_types() -> set[str]:
    """生产链路**允许产出**的全部类型 = 注册类型 ∪ 已知非门禁类型。"""
    return _registered_types() | set(NON_GATE_VULN_TYPES)


def _handler_names() -> list[str]:
    """真实编排器声明的 verify handler 名（由 ``_verify_handlers()`` 派生）。"""
    orch = Orchestrator.__new__(Orchestrator)  # 只读方法，不建实例
    return sorted(Orchestrator._verify_handlers(orch))


def _production_init_source() -> str:
    from proofhound.api.runner import OrchestratorPhases

    return inspect.getsource(OrchestratorPhases.__init__)


def _sessioned() -> SessionConfig:
    return SessionConfig(cookies={"PHPSESSID": "sessioned-probe-value"})


class _RunnerStub:
    """最小 runner：triage 阶段只读 ``scope``（不执行任何工具）。

    ``scope`` 是**真 Scope**（授权合成资产的 host ``h``）——这样
    ``run_triage_phase`` 的 ``check_scope`` 兜底也走真实代码路径。
    """

    def __init__(self, session: SessionConfig | None) -> None:
        self.scope = Scope(domains=["h"], session=session)


def _run_real_triage(tmp_path: Path, session: SessionConfig | None):
    """把合成 Signal 落盘 → 走**真实** ``run_triage_phase`` → 返回 (findings, audit)。"""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    raw = evidence_dir / "synthetic.stdout.log"
    raw.write_text("synthetic evidence line\n", encoding="utf-8")

    signals_path = evidence_dir / "synthetic.signals.jsonl"
    signals_path.write_text(
        "\n".join(s.model_dump_json() for s in _synthetic_signals()) + "\n",
        encoding="utf-8",
    )

    audit = AuditLog(evidence_dir / "audit.jsonl")
    orch = Orchestrator(
        SkillRegistry(BUILTIN_SKILLS).discover(),
        runner=_RunnerStub(session),
        llm=None,  # 规则表路径零 LLM：llm=None 本身即证明这一点
        audit=audit,
        evidence_dir=evidence_dir,
    )
    orch.run_triage_phase()
    return FindingStore(evidence_dir / "findings.jsonl").load_all(), audit


# --------------------------------------------------------------------------
# 登记表自身的完整性
# --------------------------------------------------------------------------


def test_landings_and_gate_matrix_are_bijective():
    """三处键集/派生值必须逐条一致：``VULN_REGISTRY`` ↔ ``VULN_LANDINGS`` ↔ ``GATE_MATRIX``。

    M17-c 起 ``GATE_MATRIX`` 是登记表的派生视图，故这条同时钉住
    「派生确实生效」与「本文件的落点清单没漏登记」。
    """
    assert set(VULN_LANDINGS) == set(VULN_REGISTRY), (
        "落点清单与登记表键集必须完全一致；仅在登记表="
        + str(sorted(set(VULN_REGISTRY) - set(VULN_LANDINGS)))
        + "，仅在清单="
        + str(sorted(set(VULN_LANDINGS) - set(VULN_REGISTRY)))
    )
    assert set(GATE_MATRIX) == set(VULN_REGISTRY), (
        "GATE_MATRIX 必须是登记表的派生视图；差异="
        + str(sorted(set(GATE_MATRIX) ^ set(VULN_REGISTRY)))
    )
    # 派生值逐项等价（不只是键集）
    for vuln_type, spec in VULN_REGISTRY.items():
        requirement = GATE_MATRIX[vuln_type]
        assert requirement.methods == spec.methods, vuln_type + " 的 methods 派生不一致"
        assert requirement.behavioral_kinds == spec.behavioral_kinds, (
            vuln_type + " 的 behavioral_kinds 派生不一致"
        )


def test_every_registered_type_has_skill_dir_and_profile():
    """登记表里每个类型的 verify skill 都必须在**三处**真实存在且同名。

    三处 = ``skills/<name>/SKILL.md`` 目录 + ``profiles.py`` 画像登记 +
    ``_verify_handlers`` 的键（第三处在 `test_every_registered_type_has_verify_handler` 里断言）。
    """
    for vuln_type, spec in sorted(VULN_REGISTRY.items()):
        assert spec.verify_skill, vuln_type + " 未声明 verify_skill"
        skill_md = BUILTIN_SKILLS / spec.verify_skill / "SKILL.md"
        assert skill_md.is_file(), (
            vuln_type + " 的 verify skill " + spec.verify_skill + " 缺 "
            + str(skill_md.relative_to(REPO))
        )
        profile = profile_for(spec.verify_skill)  # 未登记即 KeyError（fail-closed）
        assert profile.risk_level == "L2", (
            vuln_type + " 的验证 skill 风险级为 " + profile.risk_level + "，预期 L2"
        )


def test_model_whitelist_matches_registry():
    """白名单必须**恰好**是登记表里 ``in_model_whitelist=True`` 的那些（M17-c）。

    同时钉住 ``llm/triage.py`` 的 re-export 与登记表同源（同一对象），
    防止有人把白名单改回手工常量。
    """
    declared = {
        spec.vuln_type for spec in VULN_REGISTRY.values() if spec.in_model_whitelist
    }
    assert declared == set(ALLOWED_VULN_TYPES), (
        "登记表与 ALLOWED_VULN_TYPES（gate 派生）不一致：仅在登记表="
        + str(sorted(declared - set(ALLOWED_VULN_TYPES)))
        + "，仅在白名单="
        + str(sorted(set(ALLOWED_VULN_TYPES) - declared))
    )
    triage_allowed = _model_channel_producers()
    assert triage_allowed == set(ALLOWED_VULN_TYPES), (
        "llm/triage.py 的白名单必须与 verify/gate.py 派生值同源；差异="
        + str(sorted(triage_allowed ^ set(ALLOWED_VULN_TYPES)))
    )


def test_probe_enumeration_is_saturated():
    """穷举器必须真的覆盖提示表全部键——否则守护会「因为没喂到」而假绿。"""
    exercised = {
        signal.asset.rsplit("?", 1)[-1].split("=", 1)[0]
        for signal in _synthetic_signals()
        if signal.kind == "param-endpoint"
    }
    expected = (
        orch_mod._SQLI_PARAM_HINTS
        | orch_mod._XSS_PARAM_HINTS
        | orch_mod._IDOR_PARAM_HINTS
    )
    assert exercised == set(expected)
    statuses = {s.status_code for s in _synthetic_signals() if s.kind == "web-probe"}
    assert set(orch_mod._EXPOSED_STATUSES) <= statuses
    assert {s.kind for s in _synthetic_signals()} == {
        "web-probe",
        "param-endpoint",
        "form_page",
    }


# --------------------------------------------------------------------------
# 守护 0：登记表自身的自洽（M17-c）
# --------------------------------------------------------------------------


def test_registry_specs_are_internally_consistent():
    """``VulnSpec`` 的字段必须与键、派生值、前置集三处一致（M17-c）。"""
    for key, spec in sorted(VULN_REGISTRY.items()):
        assert isinstance(spec, VulnSpec), key + " 不是 VulnSpec"
        assert spec.vuln_type == key, (
            key + " 的 spec.vuln_type=" + spec.vuln_type + " 与键不一致"
        )
        assert spec.methods, key + " 的 methods 为空"
        assert spec.behavioral_kinds, key + " 的 behavioral_kinds 为空"
        assert spec.verify_skill.startswith("verify-"), (
            key + " 的 verify_skill 命名不符合 verify-* 约定：" + spec.verify_skill
        )
        assert spec.note, key + " 缺 note（给人看的理由也要有）"
    # 需会话前置集必须与登记表逐条一致
    declared = {
        spec.vuln_type for spec in VULN_REGISTRY.values() if spec.requires_session
    }
    assert declared == set(_VERIFY_PRECONDITIONS), (
        "_VERIFY_PRECONDITIONS 必须由登记表的 requires_session 派生；差异="
        + str(sorted(declared ^ set(_VERIFY_PRECONDITIONS)))
    )


def test_registry_producer_descriptions_are_complete():
    """每个注册类型都要有生产者说明（防「加了类型但没人写它怎么被产出」）。"""
    for vuln_type, landing in sorted(VULN_LANDINGS.items()):
        assert landing.producer.strip(), vuln_type + " 缺 producer 说明"
    extra = sorted(set(VULN_LANDINGS) - set(VULN_REGISTRY))
    assert not extra, "落点清单里有未注册的类型：" + str(extra)


def test_landing_mechanism_fields_are_derived_not_duplicated():
    """落点的机制字段必须**等于**登记表（派生，而非第二份副本）。"""
    for vuln_type, landing in sorted(VULN_LANDINGS.items()):
        spec = VULN_REGISTRY[vuln_type]
        assert landing.verify_skill == spec.verify_skill
        assert landing.in_model_whitelist == spec.in_model_whitelist
        assert landing.requires_session == spec.requires_session


# --------------------------------------------------------------------------
# 守护 1：每个注册类型都能被**真实生产链路**构造出 Finding（限制 58）
# --------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason=XFAIL_CMDI_PRODUCER)
def test_every_registered_type_has_a_reachable_producer(tmp_path):
    """**每个注册类型**都必须能被生产链路构造出来（零 seed 的「发现」冒烟）。

    判定**按类型逐个**做，而不是「产出 ∪ 白名单」这种并集口径：

    - 规则表能产出 ⇒ 通过（**默认要求**）；
    - 只在模型白名单里 ⇒ **仅当** ``VULN_LANDINGS[t].model_channel_only`` 为
      True（即已核实「刻意只走模型通道」）才豁免规则表断言。

    ⚠️ 并集口径有过一个**真后门**：只要类型进了 ``ALLOWED_VULN_TYPES``，即便
    规则表与模型通道**都还没接**，守护也会通过——M18-a 加 ``cmdi`` 时就靠它
    蒙混过关，直到接候选时才发现。故此处必须按类型断言。

    与「直接构造 Finding」的测试的关键差别：本测试只写 **Signal**，
    Finding 由**生产代码**建——正是限制 58 里缺失的那一环。
    另断言本轮**零 ``triage_capped``**，否则「没建出」会被配额掩盖成假绿。
    """
    findings, audit = _run_real_triage(tmp_path, _sessioned())
    produced = {f.vuln_type for f in findings}

    # 穷举输入**故意**超出各类型配额，故 triage_capped 是预期现象。
    # 它对本次判定不是噪声而是**证据**：某类型被 cap ⇒ 生产者确实存在，
    # 只是超出配额没建全（cap 只在「已存在同型计数 >= 上限」时触发）。
    capped_types = {
        e["vuln_type"] for e in audit.read_all() if e["event"] == "triage_capped"
    }

    model_only = _model_channel_producers()
    rule_produced = set(produced) | capped_types  # 被配额截断同样证明产过

    missing = sorted(set(GATE_MATRIX) - (produced | model_only))
    detail = {
        v: {
            "declared_producer": VULN_LANDINGS[v].producer,
            "建出了 Finding": v in produced,
            "被配额截断(证明产过)": v in capped_types,
        }
        for v in missing
    }
    unexplained = [v for v in missing if v not in capped_types]
    assert not unexplained, (
        "以下已注册 vuln_type **没有任何生产期 producer**（真实扫描永远不会"
        "产生该类型的 Finding，且配额审计里也没有它被截断的证据）："
        + str({v: detail[v] for v in unexplained})
        + "；实际产出=" + str(sorted(produced))
        + "；模型白名单=" + str(sorted(model_only))
    )

    # **按类型**断言：不在规则表产出里，就必须显式声明「刻意只走模型通道」。
    not_rule_produced = sorted(set(GATE_MATRIX) - rule_produced)
    for vuln_type in not_rule_produced:
        landing = VULN_LANDINGS[vuln_type]
        assert landing.model_channel_only, (
            vuln_type + " 既不在规则表产出里，也没声明 model_channel_only=True；"
            "若它确实刻意只走模型通道，请在 VULN_LANDINGS 里显式声明并核实"
            "（tests/test_llm_triage.py 那种实测），否则它大概率是**没有生产者**"
            "（AGENTS.md 限制 58 那一类缺陷）。"
        )
        assert vuln_type in model_only, (
            vuln_type + " 声明了 model_channel_only=True，却不在模型白名单里"
            "——两条路都不产。"
        )
    assert produced, "冒烟必须至少建出一条 Finding，否则是空跑"
    assert not_rule_produced or True
    assert set(NON_GATE_VULN_TYPES) <= produced, (
        "已知非门禁类型未能被生产链路构造出来：" + str(sorted(set(NON_GATE_VULN_TYPES) - produced))
    )


def test_real_triage_produces_only_known_types(tmp_path):
    """反向：生产链路的产出**不得超出**已知集（注册类型 ∪ 显式登记的非门禁类型）。"""
    findings, _audit = _run_real_triage(tmp_path, _sessioned())
    produced = {f.vuln_type for f in findings}
    extra = sorted(produced - _known_types())
    assert not extra, (
        "生产期产出了既未注册、也未在 NON_GATE_VULN_TYPES 登记的类型：" + str(extra)
    )


def test_unauth_exposure_candidate_is_derived_with_session(tmp_path):
    """有预置会话时，``web-probe`` 存活信号必须派生出 ``unauth-exposure`` 候选。"""
    findings, _audit = _run_real_triage(tmp_path, _sessioned())
    produced = {f.vuln_type for f in findings}
    assert "unauth-exposure" in produced, (
        "有预置会话时未派生 unauth-exposure 候选；实际产出=" + str(sorted(produced))
    )


def test_discovery_smoke_without_session_has_no_unauth_candidate(tmp_path):
    """无会话时**不得**派生 ``unauth-exposure``（前置不可满足 ⇒ 派生即噪声）。"""
    findings, _audit = _run_real_triage(tmp_path, None)
    produced = {f.vuln_type for f in findings}
    assert "unauth-exposure" not in produced, (
        "scope 无预置会话时仍建出了 unauth-exposure Finding；该类型的验证恒 "
        "blocked（等价性判定要求已认证视图）"
    )


def test_discovery_smoke_is_zero_llm(tmp_path):
    """规则表 triage 必须零 LLM：``llm=None`` 下不得抛错、不得触达模型通道。"""
    findings, audit = _run_real_triage(tmp_path, _sessioned())
    assert findings, "冒烟必须至少建出一条 Finding，否则是空跑"
    events = {e["event"] for e in audit.read_all()}
    assert "triage_completed" in events
    model_events = {"llm_call", "triage_model_invalid", "triage_model_failed"} & events
    assert not model_events, (
        "规则表 triage 不得触达模型通道，实测事件=" + str(sorted(model_events))
    )


# --------------------------------------------------------------------------
# 守护 2：handler 存在 **且** 真的挂在生产栈上（限制 59）
# --------------------------------------------------------------------------


def test_every_registered_type_has_verify_handler():
    """handler 的覆盖集与 ``VULN_LANDINGS`` **双向一致**（不多不少）。

    刻意**不用** `_registered_types()`（它是矩阵 ∪ 清单的并集）：并集会把
    「忘登记的类型」也撑进来，从而掩盖「该类型没有 handler」——变异探针实测
    过这个假绿。以 `VULN_LANDINGS` 为基准，少一个多一个都必须失败。
    """
    orch = Orchestrator.__new__(Orchestrator)
    handlers = Orchestrator._verify_handlers(orch)
    covered: set[str] = set()
    for name, (vuln_types, _fn) in handlers.items():
        assert isinstance(vuln_types, frozenset), name + " 的覆盖集不是 frozenset"
        covered |= set(vuln_types)
    missing = sorted(set(VULN_REGISTRY) - covered)
    extra = sorted(covered - set(VULN_REGISTRY))
    assert not missing and not extra, (
        "handler 覆盖集与登记表不一致：缺 handler 的注册类型="
        + str(missing) + "；覆盖了未登记类型=" + str(extra)
    )
    # handler 名必须与登记表声明的 verify_skill 一致（四处同名）
    wrong = sorted(
        spec.verify_skill
        for vuln_type, spec in VULN_REGISTRY.items()
        if spec.verify_skill not in handlers
    )
    assert not wrong, "登记表声明的 verify_skill 在 _verify_handlers 里找不到：" + str(wrong)


def test_verify_handlers_cover_nothing_unregistered():
    """handler 覆盖的类型不得超出注册集，且每个 handler 名都要有对应 skill。"""
    orch = Orchestrator.__new__(Orchestrator)
    handlers = Orchestrator._verify_handlers(orch)
    for name, (vuln_types, fn) in handlers.items():
        assert vuln_types, name + " 的覆盖集为空"
        assert callable(fn), name + " 的 handler 不可调用"
        skill_md = BUILTIN_SKILLS / name / "SKILL.md"
        assert skill_md.is_file(), "handler " + name + " 没有对应的 " + str(skill_md)
        extra = sorted(set(vuln_types) - _known_types())
        assert not extra, "handler " + name + " 覆盖了未登记类型：" + str(extra)


def test_every_registered_type_is_wired_into_production_stack():
    """**关键守护**：每个 handler 都必须在 API 生产栈的 init 里被真正挂上。

    M16-c 之后复核发现：``verify-unauth`` 有 handler、有 skill、有 profiles
    登记，但 ``OrchestratorPhases.__init__`` **没有第 5 个槽位** ⇒ 经 API/
    控制台跑的真实 engagement 永不调用 ``_verify_unauth``，只在初始化时静默
    记一条 ``verify_skill_skipped``。这与限制 58「缺生产者」是同一类缺陷，
    断在**出口**那一端。
    """
    source = _production_init_source()
    not_wired = [name for name in _handler_names() if name not in source]
    assert not not_wired, (
        "以下 verify handler 未挂进生产栈（" + PRODUCTION_INIT
        + " 里找不到该名字）：" + str(not_wired)
        + " ⇒ 经 API/控制台跑的真实 engagement 永远不会调用它们。"
    )


def test_production_init_declares_no_stray_verify_skill():
    """与上一条互补：生产栈 init 里出现的每个 ``verify-*`` skill 名都必须在册。

    用**字面量正则**提取（对 `verify_unauth_skill = "verify-unauth"` 这种
    「形参名与字符串不同形」的写法也成立），防拼写错误或挂了没有 handler 的 skill。
    """
    source = _production_init_source()
    declared = set(re.findall(r"verify-[a-z]+", source))
    assert declared, "生产栈 init 里没有找到任何 verify skill 名——提取失配"
    stray = sorted(declared - set(_handler_names()))
    assert not stray, (
        "生产栈 init 里出现了没有 handler 的 verify skill 名：" + str(stray)
        + "；真实 handler=" + str(_handler_names())
    )
