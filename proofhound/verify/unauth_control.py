"""未授权暴露的**确定性前置门**（M16-c，§5.4.2 / design.md §7.15）。

## 这个模块解决的问题

「不需要登录就能拿到信息」（`unauth-exposure`）这个说法里其实混了**两半**：

1. **可复现的一半**——「**同一 URL**，**匿名客户端**拿到的响应 == **已认证客户端**
   拿到的响应」。这是**二值事实**：判据落在响应字节上，纯确定性代码可答，零 LLM；
2. **不可复现的一半**——「这份内容**本来应该**要求登录」。这是**敏感度的语义判断**，
   没有二值观测量（同一段 JSON 在 A 系统是公开目录、在 B 系统是客户 PII）。

本模块只处理**第 1 半**，并把它做成 Confirmed 的**行为证据**。第 2 半交给
`verify/unauth_judge.py`（独立 AI 判定器）只产**结论与行号锚点**，**不产证据**——
这是铁律 2 的硬约束（`findings/finding.py`：`evidence_kinds` 里若没有任何非
`status-code` 标签，迁入 Confirmed 必抛 `IronRuleViolationError`）。

## 与 `idor_control.judge_control` 的关系（**方向相反，刻意不复用同一个结论**）

判据形态**同构**（都是"已认证基准 vs 匿名对照"），但**语义方向相反**：

| 场景 | `judge_control` 的 `public` 态 | 本模块的 `exposed` 态 |
|---|---|---|
| idor（水平越权） | **否定**违反："公开资源，谈不上越权" → 编排层**驳回** | — |
| unauth-exposure | — | **肯定**暴露："匿名即得已认证内容" → 编排层**放行确认** |

⇒ 同一份响应在两个漏洞类型下会得到**结论相反**的裁定。故本模块**独立成文件、
独立命名空间**，且 `tests/test_unauth_control.py` 用同一份输入**显式钉住两者方向相反**，
防后人图省事合并两处逻辑（合并即静默改变其中一个漏洞类型的判定语义）。

## 为什么不让 `unauth-exposure` 复用 `web-exposure` 通道

`web-exposure` 由 `web-probe` + 状态码产出，证据种类是 `status-code`，
而铁律 2 禁止纯 status-code 证据晋级 Confirmed。故 `unauth-exposure` 必须有自己的
**行为类证据标签**（`:data:`UNAUTH_EQUIVALENCE_EVIDENCE_KIND`）与自己的
`GATE_MATRIX` 项与 method——三者都不得与既有四类（sqli/xss/idor/ssrf）**任何一项**重名。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from proofhound.verify.idor import (
    IdorResponse,
    body_similarity,
    status_class,
)
from proofhound.verify.idor_control import (
    PUBLIC_SIMILARITY_THRESHOLD,
    body_sha256,
)

#: `unauth-exposure` 的**行为类证据标签**（写入 `Finding.evidence_kinds`）。
#:
#: 它是新标签而非复用 `BEHAVIORAL_EVIDENCE_KIND`（"behavioral"）：铁律 2 只要求
#: "存在任一非 `status-code` 标签"，故两者都能满足它；但具名标签让**证据来源可分辨**
#: （"这条 Confirmed 靠的是匿名/已认证响应等价"而不是"靠某次 sqlmap"），
#: 报告层与审计都能据此区分。既有四类的证据标签**不受影响**。
UNAUTH_EQUIVALENCE_EVIDENCE_KIND = "unauth-response-equivalence"

#: `verify/unauth_control.py::judge_unauth` 的确认手段名（写进
#: `Finding.verification.method`）。**必须与既有四类的 method 互不染指**
#: （`tests/test_unauth_gate.py` 逐条断言唯一性）。
UNAUTH_CONFIRMED_METHOD = "unauth-equivalence-confirmed"

#: 三态枚举（与 `judge_control` 的 public/protected/blocked 平行但**语义不同**）。
VERDICT_EXPOSED = "exposed"           # 匿名 2xx 且内容与已认证基准等价 → 暴露成立
VERDICT_REQUIRES_AUTH = "requires_auth"  # 匿名被拒（非 2xx）→ 资源本就要求认证，不成立
VERDICT_BLOCKED = "blocked"           # 覆盖不全 → 既不驳回也不确认（fail-closed）


@dataclass
class UnauthJudgment:
    """匿名/已认证等价性判定结果（全部判定依据结构化，供落盘与送审）。"""

    verdict: str  # exposed / requires_auth / blocked
    baseline_status: int | None
    anon_status: int | None
    similarity: float
    byte_identical: bool
    baseline_sha256: str
    anon_sha256: str
    reasons: list[str] = field(default_factory=list)

    def as_summary(self) -> dict:
        """送 Verifier 的确定性结论块（**响应体一行不进 prompt**，红线 3）。

        只含枚举 / 数值 / 布尔 / 哈希 / 行号锚点——与
        ``ssrf.summary_for_verifier`` 与 ``idor_control.control_summary`` 同构。
        """
        return {
            "unauth_verdict": self.verdict,
            "baseline_status": self.baseline_status,
            "anon_status": self.anon_status,
            "similarity_to_authenticated": round(self.similarity, 3),
            "byte_identical": self.byte_identical,
            "baseline_body_sha256": self.baseline_sha256,
            "anon_body_sha256": self.anon_sha256,
            "reasons": list(self.reasons),
        }


def judge_unauth(
    baseline: IdorResponse, anon: IdorResponse
) -> UnauthJudgment:
    """匿名对照的确定性判定（零 LLM；判据落在响应字节与状态码上）。

    ``baseline`` = **带预置会话**（已认证）请求该 URL 的响应；
    ``anon``     = **完全不发凭据**请求**同一 URL** 的响应。

    三态语义：

    - ``exposed``：匿名 **2xx** 且（与已认证基准**逐字节相同** **或** 相似度 ≥
      :data:`PUBLIC_SIMILARITY_THRESHOLD`）→ **匿名拿到了已认证用户的同一份内容**，
      暴露成立（这是本模块唯一产证据的态）。
    - ``requires_auth``：匿名 **非 2xx**（3xx/4xx/5xx）→ 资源**本来就要求认证**，
      不存在"未授权暴露"，编排层**驳回**。
    - ``blocked``：匿名请求**网络错误**，或匿名 2xx 但内容与基准**既不逐字节相同、
      相似度也低于阈值** → **判定不了**（覆盖不全）→ 编排层停 Hypothesis，
      **既不驳回也不确认**（fail-closed；宁可不判，也不猜）。

    为什么 ``blocked`` 不直接放行：内容"不同但不像"同样符合"两个客户端看到不同视图"
    这一**合法且常见**的形态（例如匿名看到精简版、已认证看到完整版）——把它当暴露证据
    是会误报的方向。故本模块**只做"字节级肯定"与"状态码否定"**，不做任何语义肯定。

    **同 URL 自检（fail-closed）**：两侧 ``url`` 必须一致（含 query），否则直接判
    ``blocked``——防止"拿两个不同页面对比"这种判据成立性都不具备的输入。
    """
    reasons: list[str] = []
    b_sha = body_sha256(baseline.body) if baseline.body else ""
    a_sha = body_sha256(anon.body) if anon.body else ""

    # 同 URL 自检：判据成立性的前提，缺它则整个对比无意义（fail-closed）
    if (baseline.url or "").strip() != (anon.url or "").strip():
        reasons.append(
            f"两侧 URL 不一致（基准 {baseline.url!r} vs 匿名 {anon.url!r}）"
            "→ 对比不成立（fail-closed）"
        )
        return UnauthJudgment(
            verdict=VERDICT_BLOCKED,
            baseline_status=baseline.status,
            anon_status=anon.status,
            similarity=0.0,
            byte_identical=False,
            baseline_sha256=b_sha,
            anon_sha256=a_sha,
            reasons=reasons,
        )

    similarity = body_similarity(baseline.body, anon.body)
    byte_identical = bool(anon.body) and b_sha == a_sha
    a_class = status_class(anon.status)

    reasons.append(
        f"已认证基准响应：状态 {baseline.status}；匿名响应：状态 {anon.status}（{a_class}）"
    )
    if byte_identical:
        reasons.append("匿名响应与已认证基准**逐字节相同**（sha256 一致）——铁证")
    else:
        reasons.append(f"匿名响应与已认证基准正文相似度 {similarity:.3f}")

    # ① 匿名请求失败 → 覆盖不全
    if anon.error is not None:
        reasons.append(f"匿名对照请求失败（覆盖不全，不驳回）：{anon.error}")
        return UnauthJudgment(
            verdict=VERDICT_BLOCKED,
            baseline_status=baseline.status,
            anon_status=anon.status,
            similarity=similarity,
            byte_identical=False,
            baseline_sha256=b_sha,
            anon_sha256=a_sha,
            reasons=reasons,
        )

    # ② 匿名被拒 → 资源本就要求认证 → 暴露不成立
    if a_class != "ok":
        reasons.append(
            f"匿名被拒（{a_class}）→ 该资源本就要求认证，未授权暴露**不成立**"
        )
        return UnauthJudgment(
            verdict=VERDICT_REQUIRES_AUTH,
            baseline_status=baseline.status,
            anon_status=anon.status,
            similarity=similarity,
            byte_identical=byte_identical,
            baseline_sha256=b_sha,
            anon_sha256=a_sha,
            reasons=reasons,
        )

    # ③ 匿名 2xx 且内容等价 → 暴露成立（唯一产证据的态）
    if byte_identical or similarity >= PUBLIC_SIMILARITY_THRESHOLD:
        reasons.append(
            "匿名即可获得与已认证视图等价的内容 → **未授权暴露成立**"
            "（判据是响应字节等价，不是内容语义）"
        )
        return UnauthJudgment(
            verdict=VERDICT_EXPOSED,
            baseline_status=baseline.status,
            anon_status=anon.status,
            similarity=similarity,
            byte_identical=byte_identical,
            baseline_sha256=b_sha,
            anon_sha256=a_sha,
            reasons=reasons,
        )

    # ④ 匿名 2xx 但内容不同也不像 → 判不了
    reasons.append(
        "匿名 2xx 但内容与已认证基准既不逐字节相同、相似度也低于阈值 → "
        "无法据此认定暴露（覆盖不全，不驳回不确认）"
    )
    return UnauthJudgment(
        verdict=VERDICT_BLOCKED,
        baseline_status=baseline.status,
        anon_status=anon.status,
        similarity=similarity,
        byte_identical=byte_identical,
        baseline_sha256=b_sha,
        anon_sha256=a_sha,
        reasons=reasons,
    )


def summary_to_json(summary: dict) -> str:
    """把送审摘要块序列化成 JSON（编排层写审计/判定 JSON 用；纯确定性）。"""
    return json.dumps(summary, ensure_ascii=False, sort_keys=True)


__all__ = [
    "PUBLIC_SIMILARITY_THRESHOLD",
    "UNAUTH_CONFIRMED_METHOD",
    "UNAUTH_EQUIVALENCE_EVIDENCE_KIND",
    "UnauthJudgment",
    "VERDICT_BLOCKED",
    "VERDICT_EXPOSED",
    "VERDICT_REQUIRES_AUTH",
    "judge_unauth",
    "summary_to_json",
]
