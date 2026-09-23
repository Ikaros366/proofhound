"""Verifier Agent（M3b，§5.4.4）：对验证结论做对抗校验的独立 Agent。

- 唯一职责是**攻击结论**：证据是否支持？是否存在更平凡的解释？前置条件
  当前是否满足？
- 走 **T2 档**（前沿推理模型；红线 4（M9b 重定义）：**校验独立性**——本
  agent 与发现端必须在独立上下文运行、输入仅限结构化摘要与证据索引，**不约束
  模型身份**，T1/T2 可配置同一模型；同模型时 ModelRouter 记
  ``llm_tiers_share_model`` 审计提示共享盲点）；
- 输入边界（红线 3）：只收 Finding 结构化摘要 + 证据包索引（文件名/sha256/
  锚点）+ diff 摘要，**不喂整篇原始输出**；prompt 超字符硬上限抛
  :class:`~proofhound.core.context.ContextOverflowError`（禁静默截断）；
- 输出 Pydantic 强校验 ``{"verdict": confirm|reject, "reason": ...}``；
  任何非法输出（坏 JSON、非法 verdict、空 reason）抛
  :class:`VerifierError`——**非法 verdict 拒收**，由编排层 fail-closed
  处理（Finding 不得因此晋级 Confirmed）；本刀不收 downgrade；
- 每次裁定落 ``Finding.verifier`` 并记审计 ``verifier_verdict``；
  预算超限（:class:`BudgetExceededError`）不捕获，向上抛给编排层；
- M6a：输出非法经 :func:`~proofhound.llm.repair.complete_structured`
  携带错误反馈修复重试一次（记 llm_repair_attempt）；二次仍失败走原
  VerifierError fail-closed 语义，预算硬闸覆盖重试。
- M6b（§5.4.2 注记）：confirm 裁定必须携带合法 CVSS v3.1 base 向量
  （``cvss_vector``，经 :func:`~proofhound.verify.cvss.parse_vector`
  强校验）——向量缺失/非法 = 整个 verdict 非法（fail-closed，无
  "无分数确认"降级路径）；reject 不得携带向量。**LLM 只产向量字符
  串**：分数与严重级由代码按官方公式计算（编排层置态时），模型不接受
  LLM 给的任何分数字段（schema 无此字段，多余键一律忽略）。
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, model_validator

from proofhound.compliance.audit import AuditLog
from proofhound.core.context import ContextOverflowError, ContextPolicy, messages_chars
from proofhound.findings.finding import Finding, VerifierVerdict
from proofhound.llm.repair import complete_structured
from proofhound.llm.router import ModelRouter, Tier
from proofhound.verify.cvss import parse_vector as parse_cvss_vector

SYSTEM_PROMPT = """\
你是渗透测试结论的对抗校验员（Verifier）。你的唯一职责是攻击结论：
1. 证据是否支持 Confirmed？确认手段是否为该漏洞类型的认可手段、证据链是否完整可溯源；
2. 是否存在更平凡的解释？（WAF 拦截页、自定义 404、通配路由、会话失效、工具误报等）；
3. 前置条件当前是否满足？（认证态、参数可达性、目标行为稳定性）。
你只收到结构化摘要与证据包索引（文件名/sha256/行号锚点），看不到原始输出——
若摘要不足以支撑结论，一律判 reject 并在 reason 说明缺什么。
确认手段语义：sqlmap-confirmed = sqlmap 明确判定注入点；browser-confirmed =
无头浏览器（playwright chromium）canary 探针捕获 payload 执行事件——XSS 的
唯一认可确认手段，仅"响应反射输入"不得判 confirm。dual-session-confirmed =
双会话属性对比：身份 A（低权限）会话与身份 B（reference/victim，对象属主）
会话请求同 URL，判定 JSON 中相似度/键重叠达写死阈值且属性违反成立——IDOR 的
唯一认可确认手段，仅单会话异常响应（无双会话对照）不得判 confirm；复核要点：
B 基准是否成立（2xx 实质数据）、判定数值是否达阈值、对象是否确属 B 私有。

CVSS 评分职责（仅 confirm 时）：你必须同时给出 cvss_vector（CVSS v3.1 base 向量，
恰好包含 8 个指标，形如 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H）与
cvss_rationale（逐项指标的选定理由）。**按证据定指标，不按漏洞类型套模板**：
向量必须反映证据实际证明的影响——例如 sqlmap 仅确认布尔/时间盲注、未拖取任何数据，
C 至多为 L；已拖出库名/表名等真实数据，C 方可为 H；摘要与证据索引中无法论证的
指标值不得给出。分数与严重级由系统按官方公式计算，你只产向量——不要输出任何
分数字段（会被忽略）。

只输出一个 JSON 对象，不要输出任何其他文字：
confirm → {"verdict": "confirm", "reason": "简要理由", "cvss_vector": "CVSS:3.1/...", "cvss_rationale": "逐项理由"}
reject → {"verdict": "reject", "reason": "简要理由"}（不带 cvss_vector/cvss_rationale）。"""


class VerifierError(RuntimeError):
    """Verifier 裁定失败：LLM 调用异常或输出非法（非法 verdict 拒收）。"""


class _VerdictOut(BaseModel):
    """Verifier 输出的 schema 强校验（本刀只收 confirm/reject）。

    M6b：``confirm`` 必须携带合法 CVSS v3.1 base 向量（缺失/非法 =
    整个 verdict 非法）；``reject`` 携带向量即非法。LLM 给的任何分数
    字段不在契约内（多余键默认忽略，零生效）。
    """

    verdict: Literal["confirm", "reject"]
    reason: str = Field(min_length=1)
    cvss_vector: str | None = None
    cvss_rationale: str | None = None

    @model_validator(mode="after")
    def _cvss_contract(self) -> "_VerdictOut":
        if self.verdict == "confirm":
            if self.cvss_vector is None:
                raise ValueError("confirm 必须携带 cvss_vector（M6b）")
            # 向量合法性由 cvss.py 判定；CVSSVectorError 是 ValueError，
            # Pydantic 收编为 ValidationError → 上层 VerifierError（fail-closed）
            parse_cvss_vector(self.cvss_vector)
        elif self.cvss_vector is not None:
            raise ValueError("reject 不得携带 cvss_vector（M6b）")
        return self


class Verifier:
    """对抗校验 Agent：T2 档，一次 review 一次裁定。"""

    def __init__(
        self,
        router: ModelRouter,
        audit: AuditLog | None = None,
        *,
        context_policy: ContextPolicy | None = None,
    ):
        self.router = router
        self.audit = audit
        self.context_policy = context_policy or ContextPolicy()

    def review(
        self,
        finding: Finding,
        *,
        evidence_index: list[dict],
        diff_summary: str | None = None,
    ) -> VerifierVerdict:
        """对 Finding 做对抗校验，返回并落盘裁定（同时记审计）。

        失败语义：输出非法抛 :class:`VerifierError`；prompt 超限抛
        :class:`ContextOverflowError`；预算/LLM 异常原样上抛——调用方
        必须 fail-closed（Finding 停留原态，不得晋级 Confirmed）。
        """
        messages = self._make_messages(
            finding, evidence_index=evidence_index, diff_summary=diff_summary
        )
        chars = messages_chars(messages)
        if chars > self.context_policy.max_chars:
            raise ContextOverflowError(chars=chars, limit=self.context_policy.max_chars)

        verdict = complete_structured(
            self.router,
            Tier.T2,
            messages,
            self._parse_verdict,
            audit=self.audit,
            caller="verifier",
            max_chars=self.context_policy.max_chars,
        )
        model = self._t2_model_name()
        result = VerifierVerdict(
            model=model,
            verdict=verdict.verdict,
            reason=verdict.reason,
            cvss_vector=verdict.cvss_vector,
            cvss_rationale=verdict.cvss_rationale,
        )
        finding.verifier = result
        if self.audit is not None:
            self.audit.record(
                "verifier_verdict",
                finding_id=finding.id,
                model=model,
                verdict=result.verdict,
                reason=result.reason,
                cvss_vector=result.cvss_vector,
                cvss_rationale=result.cvss_rationale,
            )
        return result

    # ---- prompt 组装（红线 3：只有结构化摘要与索引，无原始输出） ----

    def _make_messages(
        self,
        finding: Finding,
        *,
        evidence_index: list[dict],
        diff_summary: str | None,
    ) -> list[dict]:
        verification = finding.verification
        payload = {
            "finding": {
                "id": finding.id,
                "title": finding.title,
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "asset": finding.asset,
                "param": finding.param,
                "preconditions": finding.preconditions,
                "evidence_kinds": finding.evidence_kinds,
                "verification": (
                    {
                        "method": verification.method,
                        "verified_by": verification.verified_by,
                        "verified_at": verification.verified_at,
                        "evidence_refs": verification.evidence_refs,
                        "baseline_diff": verification.baseline_diff,
                        "reproduction_steps": verification.reproduction_steps,
                        # M8b 四段式（xss 链路；sqli 旧数据为 null）
                        "claim": verification.claim,
                        "expected": verification.expected,
                        "actual": verification.actual,
                    }
                    if verification
                    else None
                ),
            },
            "evidence_pack_index": evidence_index,  # manifest items：file/sha256/锚点
            "diff_summary": diff_summary,
        }
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False, indent=2)},
        ]

    @staticmethod
    def _parse_verdict(raw: str) -> _VerdictOut:
        """解析并强校验 LLM 输出；任何非法形态抛 :class:`VerifierError`。"""
        text = raw.strip()
        if text.startswith("```"):  # 宽容一层代码围栏
            lines = [l for l in text.splitlines() if not l.strip().startswith("```")]
            text = "\n".join(lines).strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start == -1 or end <= start:
                raise VerifierError(f"Verifier 输出非 JSON: {raw[:200]!r}") from None
            try:
                data = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                raise VerifierError(f"Verifier 输出非 JSON: {raw[:200]!r}") from None
        try:
            return _VerdictOut.model_validate(data)
        except ValidationError as exc:
            raise VerifierError(f"Verifier 输出未过 schema 校验: {exc}") from exc

    def _t2_model_name(self) -> str:
        configs = getattr(self.router, "configs", {})
        config = configs.get(Tier.T2) if configs else None
        return config.model if config is not None else "unknown"
