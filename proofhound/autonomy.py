"""自主模式引擎（M5a，§5.9.2 自治模式）：动作风险等级 → 执行闸门。

- :class:`AutonomyMode` 三档：``supervised``（监督）/ ``semi_auto``（半自动，
  默认）/ ``unattended``（无人值守）；
- :class:`AutonomyGate`：输入动作风险等级（L0 被动 / L1 主动扫描 / L2 利用
  验证，与 skill manifest 的 ``risk_level`` 同源），输出闸门裁定
  ``auto``（直接执行）/ ``confirm``（进确认队列等人工）/ ``forbidden``
  （未知等级，fail-closed）：

  **M9c③：L2 内部再分「只读验证」与「写操作」**。``mutating`` 来自 skill
  manifest 的同名字段（**缺省 true = fail-closed**：未声明即按写操作对待）。

  ============  ======  ========  ==========  ==================
  模式           L0      L1        L2 写操作    L2 只读验证
  ============  ======  ========  ==========  ==================
  supervised    auto    confirm   confirm     confirm
  semi_auto     auto    auto      confirm     **auto**
  unattended    auto    auto      auto        auto
  ============  ======  ========  ==========  ==================

  即：**semi_auto 下，只有声明为只读的验证动作可自动执行**；写操作（状态
  变更）永远保留人工确认。supervised 一律 confirm（细分级只在"要不要问人"
  上做区分，不放宽最严格档）；unattended 本就全自动，细分不改变其裁定。

  > **为什么这一刀安全**：区分的是「是否改变目标状态」，而**不是**放宽任何
  > 硬闸——scope 强校验、token 预算、凭据脱敏、append-only 审计在任何裁定下
  > 一律照旧。且只读声明是 skill 的**显式契约**，未声明一律按写操作处理。

- 模式切换**只允许单向收紧自由进行**：unattended→semi_auto→supervised 随时
  可切；向宽松切换（如 supervised→unattended）必须显式调用
  :meth:`AutonomyGate.switch_mode` 并携带 ``operator``，落审计事件
  ``autonomy_mode_changed{from, to, operator, note}``；

**不可旁路声明**：本模块只回答"是否停下来问人"。在任何模式（含无人值守）
下，scope 强制校验（红线 5）、token 预算硬闸、cookie 凭据脱敏、
append-only 审计追加永远生效——闸门裁定为 ``auto`` 不等于绕过上述硬闸，
它们由 ScopeEnforcer / TokenBudget / 沙箱脱敏各自独立强制，本模块不提供、
也绝不提供关闭它们的开关。
"""

from __future__ import annotations

from enum import Enum

from proofhound.compliance.audit import AuditLog


class AutonomyMode(str, Enum):
    """自治模式三档（§5.9.2），按 engagement 设置、运行中可切换。"""

    SUPERVISED = "supervised"  # 监督：L0 自动，L1/L2 逐条确认
    SEMI_AUTO = "semi_auto"  # 半自动（默认）：L0/L1 自动，L2 确认
    UNATTENDED = "unattended"  # 无人值守：L0/L1/L2 全自动


class GateDecision(str, Enum):
    """闸门裁定：直接执行 / 需人工确认 / 禁止（fail-closed）。"""

    AUTO = "auto"
    CONFIRM = "confirm"
    FORBIDDEN = "forbidden"


#: 动作风险等级排序（L0 被动 / L1 主动扫描 / L2 利用验证），与
#: ``proofhound/skills/manifest.py`` 的 ``risk_level`` 字面量同源
RISK_ORDER: dict[str, int] = {"L0": 0, "L1": 1, "L2": 2}

#: 模式严格程度排序（小 = 更严格）：向更宽松切换需显式确认
_MODE_STRICTNESS: dict[AutonomyMode, int] = {
    AutonomyMode.SUPERVISED: 0,
    AutonomyMode.SEMI_AUTO: 1,
    AutonomyMode.UNATTENDED: 2,
}

#: 闸门矩阵（§5.9.2 + M9c③）：模式 × 风险等级 × 是否改变目标状态 → 裁定。
#: 键 ``mutating`` = 写操作行（缺省），``read_only`` = 只读验证行。
#: 两行只在 semi_auto × L2 上不同——这正是 M9c③ 的全部改动面。
_GATE_MATRIX: dict[AutonomyMode, dict[str, dict[str, GateDecision]]] = {
    AutonomyMode.SUPERVISED: {
        "L0": {"mutating": GateDecision.AUTO, "read_only": GateDecision.AUTO},
        "L1": {"mutating": GateDecision.CONFIRM, "read_only": GateDecision.CONFIRM},
        "L2": {"mutating": GateDecision.CONFIRM, "read_only": GateDecision.CONFIRM},
    },
    AutonomyMode.SEMI_AUTO: {
        "L0": {"mutating": GateDecision.AUTO, "read_only": GateDecision.AUTO},
        "L1": {"mutating": GateDecision.AUTO, "read_only": GateDecision.AUTO},
        # M9c③：只读验证可自动（不改变目标状态，无需人工确认）；
        # 写操作仍须人工确认。
        "L2": {"mutating": GateDecision.CONFIRM, "read_only": GateDecision.AUTO},
    },
    AutonomyMode.UNATTENDED: {
        "L0": {"mutating": GateDecision.AUTO, "read_only": GateDecision.AUTO},
        "L1": {"mutating": GateDecision.AUTO, "read_only": GateDecision.AUTO},
        "L2": {"mutating": GateDecision.AUTO, "read_only": GateDecision.AUTO},
    },
}


class AutonomySwitchError(PermissionError):
    """非法模式切换：向宽松切换缺少显式 operator 确认。"""


class AutonomyGate:
    """自主模式闸门：判定动作是否自动执行，或须进确认队列。

    ``audit`` 可选；提供时模式切换落审计事件 ``autonomy_mode_changed``。
    """

    def __init__(self, mode: AutonomyMode | str, audit: AuditLog | None = None):
        self.mode = AutonomyMode(mode)  # 非法模式名在此即抛 ValueError
        self.audit = audit

    def decide(self, risk_level: str, *, mutating: bool = True) -> GateDecision:
        """对给定风险等级的动作做出闸门裁定。

        - 未知/未声明的风险等级一律 ``forbidden``（fail-closed）——宁可拒做，
          不可放过未分级的动作；
        - ``mutating``（M9c③）：该动作是否**改变目标状态**。**缺省 True**
          （fail-closed：调用方不声明即按写操作对待，故既有调用方零行为变化）。
          只在 semi_auto × L2 上区分：只读验证 → auto，写操作 → confirm。
        """
        by_level = _GATE_MATRIX[self.mode].get(risk_level)
        if by_level is None:
            return GateDecision.FORBIDDEN
        return by_level["mutating" if mutating else "read_only"]

    def is_tightening(self, to: AutonomyMode) -> bool:
        """``to`` 是否比当前模式更严格。"""
        return _MODE_STRICTNESS[to] < _MODE_STRICTNESS[self.mode]

    def switch_mode(
        self,
        to: AutonomyMode | str,
        *,
        operator: str | None = None,
        note: str = "",
    ) -> dict:
        """切换模式，返回切换记录（含 from/to/operator/note）。

        - 向更严格切换：随时允许（operator 可空）；
        - 向更宽松切换：必须携带非空 ``operator``（显式确认），否则抛
          :class:`AutonomySwitchError`；
        - 目标模式与当前相同：幂等返回，不动模式、不记审计；
        - 每次实际切换落审计 ``autonomy_mode_changed{from,to,operator,note}``。
        """
        to = AutonomyMode(to)  # 非法模式名抛 ValueError
        if to is self.mode:
            return {
                "from": self.mode.value,
                "to": to.value,
                "operator": operator,
                "note": note,
                "changed": False,
            }
        if not self.is_tightening(to) and not (operator and operator.strip()):
            raise AutonomySwitchError(
                f"向更宽松模式切换（{self.mode.value} → {to.value}）"
                "需要显式 operator 确认"
            )
        record = {
            "from": self.mode.value,
            "to": to.value,
            "operator": operator,
            "note": note,
            "changed": True,
        }
        if self.audit is not None:
            self.audit.record("autonomy_mode_changed", **record)
        self.mode = to
        return record


def _export(mutating: bool) -> dict[str, dict[str, str]]:
    """按 ``mutating`` 维度导出「模式 → 等级 → 裁定字符串」。"""
    key = "mutating" if mutating else "read_only"
    return {
        mode.value: {level: by_mut[key].value for level, by_mut in row.items()}
        for mode, row in _GATE_MATRIX.items()
    }


def gate_matrix() -> dict[str, dict[str, str]]:
    """导出闸门矩阵（文档/健康检查用）：模式 → 等级 → 裁定字符串。

    **形态与 M9c③ 之前逐字节一致**（取 ``mutating=True`` 行）——`GET /health`
    的 `autonomy_gate` 字段与控制台渲染依赖该扁平形态，故不因新增分级而改形。
    只读验证的裁定见 :func:`gate_matrix_read_only`。
    """
    return _export(mutating=True)


def gate_matrix_read_only() -> dict[str, dict[str, str]]:
    """导出**只读验证**行（M9c③）：模式 → 等级 → 裁定字符串。

    与 :func:`gate_matrix` 仅差 ``semi_auto × L2``（``confirm`` → ``auto``）——
    这正是「只读验证可自动、写操作留人工」的全部差异面。
    """
    return _export(mutating=False)
