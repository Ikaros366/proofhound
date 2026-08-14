"""证据门（M3b，§5.4.2）：各漏洞类型 Confirmed 最低验收标准的代码化。

每个 ``vuln_type`` 在 :data:`GATE_MATRIX` 中声明：

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

#: 行为类证据标签（verify-* skill 在行为验证成功后追加到 evidence_kinds）
BEHAVIORAL_EVIDENCE_KIND = "behavioral"


@dataclass(frozen=True)
class GateRequirement:
    """单漏洞类型的 Confirmed 最低验收标准。"""

    methods: frozenset[str]  # verification.method 白名单
    behavioral_kinds: frozenset[str]  # 至少命中一个的行为类 evidence_kinds 标签


# 证据门矩阵（§5.4.2 表的代码化；sqli 落自 M3b，xss 落自 M8b，
# idor 落自 M8c，其余类型随 verify-* skill 扩展）
GATE_MATRIX: dict[str, GateRequirement] = {
    "sqli": GateRequirement(
        methods=frozenset({"sqlmap-confirmed", "boolean-diff", "time-blind-diff"}),
        behavioral_kinds=frozenset({BEHAVIORAL_EVIDENCE_KIND}),
    ),
    # M8b：XSS 唯一认可确认手段 = 无头浏览器 canary 执行事件（反射不算证据）
    "xss": GateRequirement(
        methods=frozenset({"browser-confirmed"}),
        behavioral_kinds=frozenset({BEHAVIORAL_EVIDENCE_KIND}),
    ),
    # M8c：IDOR 唯一认可确认手段 = 双会话属性违反（单会话异常响应不确认）
    "idor": GateRequirement(
        methods=frozenset({"dual-session-confirmed"}),
        behavioral_kinds=frozenset({BEHAVIORAL_EVIDENCE_KIND}),
    ),
}


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
