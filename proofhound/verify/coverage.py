"""覆盖截图（M20-b）：每种漏洞类型的**固定取证镜头**——不论判定结果都留图。

与 M20「确认后截图」的分工：

============  ==================================  ==================================
截图          何时                                 它证明什么
============  ==================================  ==================================
确认截图       Finding 变 Confirmed **之后**        「这个漏洞成立」（进
              （`_gate_and_review`）               `verification.evidence_refs`）
覆盖截图       候选**一进验证**就截（本模块）        「这条端点被真的测过」，与
                                                   判定结果无关
============  ==================================  ==================================

覆盖截图**绝不能**被当成确认证据：它不进 `evidence_kinds`、不进
`verification.evidence_refs`，只进 ``Finding.coverage_refs``；证据门与
Verifier 的输入边界一字未动。

## 「固定的图」从哪来

:data:`COVERAGE_SHOTS` 是**类型 → 取证镜头**的单一真相源：每个镜头声明
标签、可选的参数取值覆盖、以及用哪个会话（主会话 / 匿名 / reference）。
加漏洞类型时必须同步这张表——``tests/test_coverage_shots.py`` 用
``VULN_REGISTRY`` **双向锁定**（注册了就必须有镜头表，反之亦然）。

## 成本

每个镜头 = 一次真实浏览器导航（约 1~3s）。故有**每类型候选上限**与
**单 phase 总张数上限**，超限记 ``coverage_shot_capped``——这是资源调度，
不是判定（与 triage_capped 同语义：被裁掉的候选仍照常验证）。
"""

from __future__ import annotations

from dataclasses import dataclass

from proofhound.compliance.session import SessionConfig
from proofhound.verify.prefilter import with_query_param

#: 每类型最多留图的候选数（单条候选的全部镜头算一次）。
CAP_PER_TYPE = 5

#: 单次 verify phase 的覆盖截图总张数上限（跨类型）。
CAP_TOTAL = 24

#: 会话角色（镜头用它决定以谁的身份取证）。
SESSION_PRIMARY = "primary"
SESSION_ANONYMOUS = "anonymous"
SESSION_REFERENCE = "reference"


@dataclass(frozen=True)
class CoverageShot:
    """一个取证镜头：**确定性**的 URL/会话变换（零 LLM、零随机）。"""

    #: 镜头标签（进文件名与审计，须在类型内唯一）。
    label: str
    #: 参数取值覆盖；``None`` = 保留 asset 原 query（基线页）。
    param_value: str | None = None
    #: 用哪个会话取证：``primary`` / ``anonymous`` / ``reference``。
    session: str = SESSION_PRIMARY


#: **类型 → 固定镜头**（单一真相源，加类型必须同步；见模块 docstring）。
#:
#: 取值原则：只用**无副作用**的探针——GET、只改 query 取值、不写目标、
#: 不弹框。探针要能让人从图上看懂「这里测过什么」：
#: sqli 用注入标点（页面回显 SQL 报错即是证据）、xss 用一条不弹框的
#: script 探针、idor/unauth 用双身份对照。
COVERAGE_SHOTS: dict[str, tuple[CoverageShot, ...]] = {
    "sqli": (
        CoverageShot("baseline"),
        CoverageShot("probe", param_value="1'"),
    ),
    "xss": (
        CoverageShot("baseline"),
        CoverageShot("probe", param_value="<script>window.__ph_shot=1</script>"),
    ),
    "idor": (
        CoverageShot("attacker"),
        CoverageShot("reference", session=SESSION_REFERENCE),
    ),
    "ssrf": (CoverageShot("baseline"),),
    "unauth-exposure": (
        CoverageShot("anonymous", session=SESSION_ANONYMOUS),
        CoverageShot("authenticated"),
    ),
    "cmdi": (CoverageShot("baseline"),),
}


def plan_for(vuln_type: str) -> tuple[CoverageShot, ...] | None:
    """取某类型的固定镜头表；未登记的类型返回 None（不截图，不猜）。"""
    return COVERAGE_SHOTS.get(vuln_type)


def build_url(asset: str, param: str | None, shot: CoverageShot) -> str:
    """按镜头构造取证 URL（确定性）。

    ``param_value`` 为 None ⇒ 原样返回 asset；否则要求候选有 ``param``，
    缺参数抛 :class:`ValueError`（调用方记 ``coverage_shot_skipped``，
    不凭空构造 URL）。
    """
    if shot.param_value is None:
        return asset
    if not param:
        raise ValueError(f"镜头 {shot.label} 需要参数取值覆盖，但候选没有 param")
    return with_query_param(asset, param, shot.param_value)


def select_session(
    session: SessionConfig | None, role: str
) -> tuple[SessionConfig | None, str | None]:
    """按镜头的会话角色选出本次取证用的会话。

    返回 ``(会话, 跳过原因)``：原因非 None 时调用方记
    ``coverage_shot_skipped``（例如 idor 镜头要 reference 会话，但 scope
    只配了主会话——此时**不**拿主会话顶替，那会伪造出「双身份对照」）。
    未知角色属代码错误，直接抛 :class:`ValueError`（fail-closed）。
    """
    if role == SESSION_PRIMARY:
        return session, None
    if role == SESSION_ANONYMOUS:
        return None, None
    if role == SESSION_REFERENCE:
        reference = getattr(session, "reference", None) if session is not None else None
        if reference is None:
            return None, "缺第二身份会话（reference），无法以第二身份取证"
        return reference, None
    raise ValueError(f"未知会话角色 {role!r}（可选 primary/anonymous/reference）")


__all__ = [
    "CAP_PER_TYPE",
    "CAP_TOTAL",
    "COVERAGE_SHOTS",
    "SESSION_ANONYMOUS",
    "SESSION_PRIMARY",
    "SESSION_REFERENCE",
    "CoverageShot",
    "build_url",
    "plan_for",
    "select_session",
]
