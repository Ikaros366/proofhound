"""漏洞类型的**单一真相源** :data:`VULN_REGISTRY` 与证据门（M3b，§5.4.2）。

## 为什么有 VULN_REGISTRY（M17-c）

在 M17-c 之前，一个 ``vuln_type`` 的关键事实散在三处**手工维护、互不校验**的地方：

1. ``verify/gate.py::GATE_MATRIX`` —— 确认门 + method 白名单（**兼任**类型清单）
2. ``llm/triage.py::ALLOWED_VULN_TYPES`` —— 模型 triage 白名单
3. ``core/orchestrator.py::_VERIFY_PRECONDITIONS`` —— 验证前置（是否需预置会话）

M16-c / 已知限制 58 那次「六个落点全就位、就是没接上」正是这种散落的代价：
登记表之间**没有任何机制保证一致**，改一处忘一处即静默不一致，而这类不一致恰好
落在安全语义上（能不能确认、能不能被模型产出、能不能被验证）。

M17-c 起：:data:`VULN_REGISTRY` 是唯一真相源，上表三处**全部由它派生**。

**仍在原处、由守护测试钉住**的两件事（它们是"机制"而非"事实"）：

- ``core/orchestrator.py::_verify_handlers`` —— handler **方法对象**（运行时调度；
  登记表只声明 skill **名**）；
- ``skills/profiles.py::SKILL_PROFILES`` —— 风险画像（闸门输入；M9d 起已是单一真相源）。

``tests/test_vuln_registry.py`` 断言登记表、handler、画像表、``skills/`` 目录四者
**双向一致**——文档可以读，但不能与代码矛盾。

## 证据门

每个 ``vuln_type`` 在 :data:`GATE_MATRIX`（由登记表**派生**）中声明：

- ``methods``：``verification.method`` 白名单（确认手段，如 sqlmap 明确判定、
  布尔/时间盲注对照差异）；
- ``behavioral_kinds``：``evidence_kinds`` 中至少命中一个的行为类证据标签。

判定 fail-closed：未知 ``vuln_type`` 直接不通过。本门与 M3a 状态机铁律
（version-cve 型与纯 status-code 证据永远禁止 Confirmed，硬编码在
``Finding.transition``）构成**双层防守**：编排层在 ``transition(CONFIRMED)``
之前必须先过 :func:`check`；铁律在状态机层兜底。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from proofhound.findings.finding import Finding
from proofhound.verify.cmdi import CMDI_CONFIRMED_METHOD
from proofhound.verify.ssrf import SSRF_CONFIRMED_METHOD
from proofhound.verify.unauth_control import (
    UNAUTH_CONFIRMED_METHOD,
    UNAUTH_EQUIVALENCE_EVIDENCE_KIND,
)

#: 行为类证据标签（verify-* skill 在行为验证成功后追加到 evidence_kinds）
BEHAVIORAL_EVIDENCE_KIND = "behavioral"


@dataclass(frozen=True)
class GateRequirement:
    """单漏洞类型的 Confirmed 最低验收标准。"""

    methods: frozenset[str]  # verification.method 白名单
    behavioral_kinds: frozenset[str]  # 至少命中一个的行为类 evidence_kinds 标签


@dataclass(frozen=True)
class VulnSpec:
    """一个已注册漏洞类型的**全部登记事实**（M17-c 单一真相源）。

    **判断逻辑一律不读 ``note``**：它是给人看的理由，不是机制。
    """

    vuln_type: str
    #: 唯一认可确认手段（``verification.method`` 白名单）。**各类型互不染指**：
    #: 任何一个 method 名不得出现在两个类型里——由 tests/test_ssrf.py 与
    #: tests/test_unauth_judge.py 逐条断言互斥。
    methods: frozenset[str]
    #: ``evidence_kinds`` 中至少命中一个的行为类证据标签。
    behavioral_kinds: frozenset[str]
    #: 覆盖本类型的 verify skill 名（必须与 ``skills/<name>/`` 目录、
    #: ``profiles.py`` 登记、``_verify_handlers`` 键**三处同名**）。
    verify_skill: str
    #: 是否进模型 triage 白名单。**刻意与「在不在登记表」分离**：
    #: ``ssrf`` 只在白名单（先放开候选、后补验证器）；``unauth-exposure``
    #: 只在规则表（窄形态无需语义判断，反而刻意不进白名单）。
    in_model_whitelist: bool
    #: 验证前置是否**结构上要求** scope 配了可用的预置会话；是则缺会话时该类型的
    #: 候选一次也不进贵验证档（``_VERIFY_PRECONDITIONS`` 由它派生）。
    requires_session: bool
    note: str = ""


#: **漏洞类型单一真相源**（M17-c）。加一个类型 = 在此登记一条 + 建对应
#: ``skills/verify-*`` 目录 + 在 ``skills/profiles.py`` 登记画像 + 在
#: ``orchestrator._verify_handlers`` 挂 handler；``tests/test_vuln_registry.py``
#: 断言这四处**双向一致**，漏一处即测试失败。
#:
#: **``unauth-exposure`` 与 ``web-exposure`` 是两回事**：``web-exposure`` 仍是纯
#: status-code 证据（铁律 2 禁止其 Confirmed，故**刻意不在**本表、也没有 verify
#: skill——它以 ``tests/test_vuln_registry.py::NON_GATE_VULN_TYPES`` 显式登记为
#: 「已知非门禁类型」）；``unauth-exposure`` 的证据是**匿名/已认证响应等价**
#: （可复现的行为事实），故有自己的项。
VULN_REGISTRY: dict[str, VulnSpec] = {
    "sqli": VulnSpec(
        vuln_type="sqli",
        methods=frozenset({"sqlmap-confirmed", "boolean-diff", "time-blind-diff"}),
        behavioral_kinds=frozenset({BEHAVIORAL_EVIDENCE_KIND}),
        verify_skill="verify-sqli",
        in_model_whitelist=True,
        requires_session=False,
        note="M3b 落自；规则表 param-endpoint/form_page 产候选，模型通道也产",
    ),
    "xss": VulnSpec(
        vuln_type="xss",
        # M8b：XSS 唯一认可确认手段 = 无头浏览器 canary 执行事件（反射不算证据）
        methods=frozenset({"browser-confirmed"}),
        behavioral_kinds=frozenset({BEHAVIORAL_EVIDENCE_KIND}),
        verify_skill="verify-xss",
        in_model_whitelist=True,
        requires_session=False,
        note="M8b：反射不算证据，只有 canary 真执行才算",
    ),
    "idor": VulnSpec(
        vuln_type="idor",
        # M8c：IDOR 唯一认可确认手段 = 双会话属性违反（单会话异常响应不确认）
        methods=frozenset({"dual-session-confirmed"}),
        behavioral_kinds=frozenset({BEHAVIORAL_EVIDENCE_KIND}),
        verify_skill="verify-idor",
        in_model_whitelist=True,
        requires_session=False,
        note="M8c：双会话属性违反；缺 reference 会话时走匿名对照，不因此免检",
    ),
    "ssrf": VulnSpec(
        vuln_type="ssrf",
        # M16：SSRF 唯一认可确认手段 = **回调 listener 收到请求**（带外二值事实）。
        # 目标响应里的 callback URL 反射、状态码、耗时一律不是证据；
        # method 名与其余四类互不染指。
        methods=frozenset({SSRF_CONFIRMED_METHOD}),
        behavioral_kinds=frozenset({BEHAVIORAL_EVIDENCE_KIND}),
        verify_skill="verify-ssrf",
        in_model_whitelist=True,
        # M16 的验证要求「带会话 baseline」，故缺会话时整类不可验证
        requires_session=True,
        note=(
            "M15 只放开模型候选（规则表刻意零候选），M16 补验证器；"
            "确认靠宿主 listener 收到回调"
        ),
    ),
    "unauth-exposure": VulnSpec(
        vuln_type="unauth-exposure",
        # M16-c：唯一认可确认手段 = **匿名/已认证响应等价**（可复现的二值事实）。
        #
        # 证据标签刻意用具名的 `unauth-response-equivalence` 而非笼统的 `behavioral`：
        # 让"这条 Confirmed 靠的是响应字节等价"在证据层可分辨（报告/审计据此区分来源）。
        # 铁律 2 只要求"存在任一非 status-code 标签"，具名标签同样满足它。
        #
        # **刻意不接受** AI 判定器的语义结论作证据（M16-c 裁定：形态 B 若把 AI 结论
        # 当证据就等于打开"AI 说敏感即确认"的降级路径，撞铁律 2 与 README 边界）。
        methods=frozenset({UNAUTH_CONFIRMED_METHOD}),
        behavioral_kinds=frozenset({UNAUTH_EQUIVALENCE_EVIDENCE_KIND}),
        verify_skill="verify-unauth",
        # M16-c 裁定：由**确定性规则表**从 web-probe 派生，窄形态无需语义判断，
        # 故刻意**不进**模型白名单（且进了也是死路——web-probe 信号不进模型通道）。
        in_model_whitelist=False,
        # 等价性判定要拿「已认证视图」当基准，没有它就没有可比对象
        requires_session=True,
        note="M17-b 接上生产者与生产栈槽位（限制 58/59 关闭）",
    ),
    "cmdi": VulnSpec(
        vuln_type="cmdi",
        # M18：唯一认可确认手段 = **回调 listener 收到请求**（带外二值事实）。
        # 与 ssrf 同族但**互不染指**：ssrf 证明"服务端替我们发了请求"，
        # cmdi 证明"我们注入的命令被执行了"——前者是服务端行为，后者是命令
        # 执行，两者的载荷与排除手段都不同（cmdi 多一道 DNS 非命中防伪）。
        methods=frozenset({CMDI_CONFIRMED_METHOD}),
        behavioral_kinds=frozenset({BEHAVIORAL_EVIDENCE_KIND}),
        verify_skill="verify-cmdi",
        # M18 裁定 C3：规则表加 `_CMDI_PARAM_HINTS` 保守表（cmd/exec/ping 这类
        # 参数名恰是关键词表的强项）+ 模型通道补盲区，两条路都产候选。
        in_model_whitelist=True,
        # **不需要预置会话**：判据是"我们注入的命令发起的回调"，与身份无关
        # （对比 ssrf/unauth-exposure 需要会话做 baseline/等价性对照）。
        requires_session=False,
        note="M18：带外回调确认；不做时间盲注/回显型/反弹 shell/读文件",
    ),
}


#: 证据门矩阵（§5.4.2 表的代码化）——**由 :data:`VULN_REGISTRY` 派生**（M17-c）。
#: 键集恒等于登记表键集，故「注册了类型却没有门」在结构上不可能。
GATE_MATRIX: dict[str, GateRequirement] = {
    spec.vuln_type: GateRequirement(
        methods=spec.methods,
        behavioral_kinds=spec.behavioral_kinds,
    )
    for spec in VULN_REGISTRY.values()
}

#: 模型 triage 白名单——**由 :data:`VULN_REGISTRY` 派生**（M17-c）。
#: ``llm/triage.py`` 仍以同名 re-export 供既有 import 点使用。
ALLOWED_VULN_TYPES: frozenset[str] = frozenset(
    spec.vuln_type for spec in VULN_REGISTRY.values() if spec.in_model_whitelist
)


@dataclass(frozen=True)
class GateResult:
    """证据门判定结论：通过与缺项清单（供审计与升级人工）。"""

    passed: bool
    vuln_type: str
    missing: list[str] = field(default_factory=list)


def check(finding: Finding) -> GateResult:
    """检查 Finding 是否满足其 vuln_type 的 Confirmed 最低验收标准。"""
    requirement = GATE_MATRIX.get(finding.vuln_type)
    if requirement is None:
        return GateResult(
            passed=False,
            vuln_type=finding.vuln_type,
            missing=[f"漏洞类型 {finding.vuln_type} 无证据门定义（fail-closed）"],
        )

    missing: list[str] = []
    verification = finding.verification
    if verification is None:
        missing.append("缺 verification（Confirmed 必须携带验证信息）")
    else:
        if verification.method not in requirement.methods:
            missing.append(
                f"验证方法 {verification.method} 不在白名单 "
                f"{sorted(requirement.methods)}"
            )
        if not verification.evidence_refs:
            missing.append("verification.evidence_refs 为空（证据完备率 100%）")
    if not requirement.behavioral_kinds.intersection(finding.evidence_kinds):
        missing.append(
            f"evidence_kinds 缺行为类标签（要求 {sorted(requirement.behavioral_kinds)}"
            f" 至少其一，当前 {sorted(finding.evidence_kinds)}）"
        )
    return GateResult(passed=not missing, vuln_type=finding.vuln_type, missing=missing)
