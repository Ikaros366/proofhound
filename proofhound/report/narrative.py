"""叙述生成（M4，§5.7 数据与表现分离）：LLM 只产叙述，不碰事实字段。

- 走 **T1 档**（§5.6 路由表：报告润色/摘要类）；
- 输入边界（红线 3）：只收 Finding 结构化摘要 + 分桶统计，**无原始输出**；
  prompt 超字符硬上限抛
  :class:`~proofhound.core.context.ContextOverflowError`（禁静默截断）；
- 输出契约：``{"paragraphs": {键: 段落}}``，键必须是**请求过的 finding id**
  或固定章节键（``overview``/``remediation``）；Pydantic 强校验，**未知键
  （无锚文字）、坏 JSON、空段落一律抛 :class:`NarrativeError`，全量拒收、
  不落盘任何部分结果**；
- M4.5 叙述结构化：finding 键的段落为
  :class:`~proofhound.findings.finding.NarrativeParts` 三段对象
  （description/impact/remediation，章节键仍为字符串）；兼容旧字符串段落
  （只写 ``narrative``）。三段对象的单段 ``narrative`` 由三段确定性拼接
  派生（``\\n`` 连接）——单一事实源，default_template 契约不变；
- 落盘：finding 段落写 ``Finding.narrative``（+ ``Finding.narrative_parts``）
  （§5.5：叙述只存于此，不回写事实字段）→ ``FindingStore.append`` 快照 →
  重刷证据包；固定章节段落写 ``<evidence_dir>/narrative_sections.json``
  （衍生文件，覆盖写，非审计链）；
- 每段落记审计 ``narrative_generated{finding_id|section, model, tokens}``
  （单次调用产出全部段落，tokens 为该次调用的总量，各段事件同值；逐次
  调用计量以路由层 ``llm_call`` 审计为准）；
- 预算超限（:class:`BudgetExceededError`）不捕获，向上抛。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError, field_validator

from proofhound.compliance.audit import AuditLog
from proofhound.core.context import ContextOverflowError, ContextPolicy, messages_chars
from proofhound.findings.evidence import assemble_evidence_pack
from proofhound.findings.finding import (
    Finding,
    FindingState,
    FindingStore,
    NarrativeParts,
)
from proofhound.llm.router import ModelRouter, Tier
from proofhound.report.data import SECTION_KEYS, SECTIONS_FILE

#: 固定章节键（概述/修复建议）：段落绑定章节键而非 finding_id
FIXED_SECTIONS: tuple[str, ...] = SECTION_KEYS

#: 只给这两态 finding 生成叙述段落；rejected 走附录结构化 rejection_reason
_NARRATED_STATES = frozenset({FindingState.CONFIRMED, FindingState.REPRODUCED})

SYSTEM_PROMPT = """\
你是渗透测试报告的叙述撰写员。你只收到结构化摘要（无工具原始输出），职责：
1. 为每条 finding 写三段式叙述（中文，只能基于给定结构化字段，不得编造
   未提供的细节、不得虚构 payload 或数据），输出一个对象：
   {"description": "漏洞描述（客观陈述漏洞成因与位置）",
    "impact": "漏洞危害（可被利用造成的后果与影响面）",
    "remediation": "建议措施（针对该漏洞的修复/加固建议）"}；
2. 为固定章节写字符串段落：overview = 测试概述（范围/方法/结论统计层面），
   remediation = 修复建议（按漏洞类型归纳，指向 finding id）。
只输出一个 JSON 对象：{"paragraphs": {"<finding id>": {"description": "...",
"impact": "...", "remediation": "..."}, "overview": "...", "remediation": "..."}}，
键只能来自给出的 allowed_keys（finding 键给三段对象、章节键给字符串），
不要输出任何其他文字。"""


class NarrativeError(RuntimeError):
    """叙述生成失败：LLM 调用异常或输出非法（无锚文字/坏 JSON/空段落拒收）。"""


class _NarrativeOut(BaseModel):
    """叙述输出的 schema 强校验：段落非空、至少一段。

    M4.5：finding 键为三段对象（NarrativeParts，字段空白/多余键即非法），
    兼容旧字符串段落；章节键须为字符串（在 _parse_paragraphs 语义校验）。
    """

    paragraphs: dict[str, str | NarrativeParts] = Field(min_length=1)

    @field_validator("paragraphs")
    @classmethod
    def _non_empty(cls, value: dict[str, str | NarrativeParts]) -> dict:
        for key, item in value.items():
            if isinstance(item, str) and not item.strip():
                raise ValueError(f"段落为空: {key}")
        return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class NarrativeGenerator:
    """报告叙述撰写 Agent：T1 档，一次 generate 一次调用、全量校验后落盘。"""

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

    def generate(
        self,
        findings: list[Finding],
        *,
        store: FindingStore,
        evidence_dir: str | Path,
    ) -> dict[str, str | NarrativeParts]:
        """生成叙述并落盘，返回 {键: 段落}（键 = finding id 或固定章节键）。

        失败语义：输出非法抛 :class:`NarrativeError`（不落盘任何部分结果）；
        prompt 超限抛 :class:`ContextOverflowError`；预算/LLM 异常原样上抛。
        """
        evidence_dir = Path(evidence_dir)
        narrated = [f for f in findings if f.state in _NARRATED_STATES]
        allowed_keys = {f.id for f in narrated} | set(FIXED_SECTIONS)

        messages = self._make_messages(findings, narrated, allowed_keys)
        chars = messages_chars(messages)
        if chars > self.context_policy.max_chars:
            raise ContextOverflowError(chars=chars, limit=self.context_policy.max_chars)

        tracker = getattr(self.router, "tracker", None)
        before = len(tracker.records) if tracker is not None else 0
        raw = self.router.complete(Tier.T1, messages)  # 预算硬闸在路由层
        tokens: int | None = None
        if tracker is not None:
            used = sum(r.total_tokens for r in tracker.records[before:])
            tokens = used or None
        model = self._t1_model_name()

        paragraphs = self._parse_paragraphs(raw, allowed_keys)

        # 全部校验通过后一次性落盘（无部分结果）
        findings_by_id = {f.id: f for f in findings}
        for key, item in paragraphs.items():
            if key in FIXED_SECTIONS:
                continue
            finding = findings_by_id[key]
            if isinstance(item, NarrativeParts):
                # M4.5 三段叙述：单段 narrative 由三段确定性拼接派生
                finding.narrative_parts = item
                finding.narrative = "\n".join(
                    part.strip()
                    for part in (item.description, item.impact, item.remediation)
                )
            else:  # 旧字符串段落：只写 narrative，清掉可能残留的三段
                finding.narrative = item.strip()
                finding.narrative_parts = None
            finding.updated_at = _utc_now()
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=evidence_dir)
            if self.audit is not None:
                self.audit.record(
                    "narrative_generated",
                    finding_id=key,
                    model=model,
                    tokens=tokens,
                )
        sections = {
            k: v.strip()
            for k, v in paragraphs.items()
            if k in FIXED_SECTIONS and isinstance(v, str)
        }
        (evidence_dir / SECTIONS_FILE).write_text(
            json.dumps(sections, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if self.audit is not None:
            for section in sections:
                self.audit.record(
                    "narrative_generated", section=section, model=model, tokens=tokens
                )
        return paragraphs

    # ---- prompt 组装（红线 3：只有结构化摘要，无原始输出） ----

    def _make_messages(
        self,
        findings: list[Finding],
        narrated: list[Finding],
        allowed_keys: set[str],
    ) -> list[dict]:
        stats = {
            "confirmed": sum(
                1 for f in findings if f.state is FindingState.CONFIRMED
            ),
            "conditional": sum(
                1 for f in findings if f.state is FindingState.REPRODUCED
            ),
            "hypothesis": sum(
                1 for f in findings if f.state is FindingState.HYPOTHESIS
            ),
            "rejected": sum(
                1 for f in findings if f.state is FindingState.REJECTED
            ),
            "rejected_reasons": [
                {
                    "id": f.id,
                    "vuln_type": f.vuln_type,
                    "rejection_reason": f.rejection_reason,
                }
                for f in findings
                if f.state is FindingState.REJECTED
            ],
        }
        payload = {
            "allowed_keys": sorted(allowed_keys),
            "fixed_sections": {k: True for k in FIXED_SECTIONS},
            "stats": stats,
            "findings": [self._summary(f) for f in narrated],
        }
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False, indent=2)},
        ]

    @staticmethod
    def _summary(finding: Finding) -> dict:
        """单条 finding 的结构化摘要（无原始输出、无凭据）。"""
        verification = finding.verification
        verifier = finding.verifier
        return {
            "id": finding.id,
            "state": finding.state.value,
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
                    "baseline_diff": verification.baseline_diff,
                    "reproduction_steps": verification.reproduction_steps,
                }
                if verification
                else None
            ),
            "verifier": (
                {"model": verifier.model, "verdict": verifier.verdict}
                if verifier
                else None
            ),
        }

    @staticmethod
    def _parse_paragraphs(
        raw: str, allowed_keys: set[str]
    ) -> dict[str, str | NarrativeParts]:
        """解析并强校验 LLM 输出；无锚文字/坏 JSON/空段落抛 NarrativeError。"""
        text = raw.strip()
        if text.startswith("```"):  # 宽容一层代码围栏
            lines = [l for l in text.splitlines() if not l.strip().startswith("```")]
            text = "\n".join(lines).strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start == -1 or end <= start:
                raise NarrativeError(f"叙述输出非 JSON: {raw[:200]!r}") from None
            try:
                data = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                raise NarrativeError(f"叙述输出非 JSON: {raw[:200]!r}") from None
        try:
            out = _NarrativeOut.model_validate(data)
        except ValidationError as exc:
            raise NarrativeError(f"叙述输出未过 schema 校验: {exc}") from exc
        unknown = set(out.paragraphs) - allowed_keys
        if unknown:
            raise NarrativeError(
                f"叙述输出含无锚段落（键不在允许集合 {sorted(allowed_keys)}）: "
                f"{sorted(unknown)}——全量拒收"
            )
        for key in FIXED_SECTIONS:
            if key in out.paragraphs and not isinstance(out.paragraphs[key], str):
                raise NarrativeError(
                    f"固定章节段落必须为字符串（非三段对象）: {key}——全量拒收"
                )
        return out.paragraphs

    def _t1_model_name(self) -> str:
        configs = getattr(self.router, "configs", {})
        config = configs.get(Tier.T1) if configs else None
        return config.model if config is not None else "unknown"
