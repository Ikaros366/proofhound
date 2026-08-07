"""Verifier Agent（M3b，§5.4.4）：对验证结论做对抗校验的独立 Agent。

- 唯一职责是**攻击结论**：证据是否支持？是否存在更平凡的解释？前置条件
  当前是否满足？
- 走 **T2 档**（前沿推理模型；红线 4：与发现端 T1 必须用不同模型，
  同模型时 ModelRouter 启动即警告）；
- 输入边界（红线 3）：只收 Finding 结构化摘要 + 证据包索引（文件名/sha256/
  锚点）+ diff 摘要，**不喂整篇原始输出**；prompt 超字符硬上限抛
  :class:`~proofhound.core.context.ContextOverflowError`（禁静默截断）；
- 输出 Pydantic 强校验 ``{"verdict": confirm|reject, "reason": ...}``；
  任何非法输出（坏 JSON、非法 verdict、空 reason）抛
  :class:`VerifierError`——**非法 verdict 拒收**，由编排层 fail-closed
  处理（Finding 不得因此晋级 Confirmed）；本刀不收 downgrade；
- 每次裁定落 ``Finding.verifier`` 并记审计 ``verifier_verdict``；
  预算超限（:class:`BudgetExceededError`）不捕获，向上抛给编排层。
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from proofhound.compliance.audit import AuditLog
from proofhound.core.context import ContextOverflowError, ContextPolicy, messages_chars
from proofhound.findings.finding import Finding, VerifierVerdict
from proofhound.llm.router import ModelRouter, Tier

SYSTEM_PROMPT = """\
你是渗透测试结论的对抗校验员（Verifier）。你的唯一职责是攻击结论：
1. 证据是否支持 Confirmed？确认手段是否为该漏洞类型的认可手段、证据链是否完整可溯源；
2. 是否存在更平凡的解释？（WAF 拦截页、自定义 404、通配路由、会话失效、工具误报等）；
3. 前置条件当前是否满足？（认证态、参数可达性、目标行为稳定性）。
你只收到结构化摘要与证据包索引（文件名/sha256/行号锚点），看不到原始输出——
若摘要不足以支撑结论，一律判 reject 并在 reason 说明缺什么。
只输出一个 JSON 对象：{"verdict": "confirm" 或 "reject", "reason": "简要理由"}，
不要输出任何其他文字。"""


class VerifierError(RuntimeError):
    """Verifier 裁定失败：LLM 调用异常或输出非法（非法 verdict 拒收）。"""


class _VerdictOut(BaseModel):
    """Verifier 输出的 schema 强校验（本刀只收 confirm/reject）。"""

    verdict: Literal["confirm", "reject"]
    reason: str = Field(min_length=1)


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

        raw = self.router.complete(Tier.T2, messages)
        verdict = self._parse_verdict(raw)
        model = self._t2_model_name()
        result = VerifierVerdict(
            model=model, verdict=verdict.verdict, reason=verdict.reason
        )
        finding.verifier = result
        if self.audit is not None:
            self.audit.record(
                "verifier_verdict",
                finding_id=finding.id,
                model=model,
                verdict=result.verdict,
                reason=result.reason,
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
