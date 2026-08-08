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
- 预算超限（:class:`BudgetExceededError`）不捕获，向上抛；
- M6a：输出非法（坏 JSON/schema/无锚）经
  :func:`~proofhound.llm.repair.complete_structured` 携带错误反馈修复
  重试一次（记 llm_repair_attempt，重试 token 计入 tokens 统计）；二次
  仍失败走原 NarrativeError 全量拒收零落盘语义，预算硬闸覆盖重试。
- M6c：叙事事实守卫（:func:`~proofhound.report.factguard.check_narrative_facts`
  确定性代码，零 LLM）——F-ID 幻觉引用、状态词共现（确认/误报/假设/
  有效验证措辞必须与实际状态一致）、确认/误报计数断言（须等于真实桶数），
  任一违规即 NarrativeError（错误写明 F-ID/声称词/真实状态/计数明细，
  随修复指令携带）；守卫在 parse callable 内执行，修复重试自然生效。
  附录 B 误报中文归因：LLM 为每条 Rejected finding 产 ``reasons_cn``
  （可选键，缺失容忍；键必须 ⊆ Rejected id 集合），同样过事实守卫，
  落 ``<evidence_dir>/rejected_reasons_cn.json``（衍生文件，恒写防陈旧），
  data 层透传进 rejected_findings.reason_cn。
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
from proofhound.llm.repair import complete_structured
from proofhound.llm.router import ModelRouter, Tier
from proofhound.report.data import REASONS_CN_FILE, SECTION_KEYS, SECTIONS_FILE
from proofhound.report.factguard import check_narrative_facts

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
   remediation = 修复建议（按漏洞类型归纳，指向 finding id）；
3. 措辞纪律（硬性，state_roster 给出每条 finding 的真实状态）：
   确认/证实/confirm 类措辞只能用于 state=confirmed；
   误报/排除/rejected 类只能用于 state=rejected；
   假设/待验证/hypothesis 类只能用于 state=hypothesis/signal；
   有效验证/行为复现/reproduced 类只能用于 state=reproduced；
   概述中的确认/误报计数必须与 stats 完全一致；一句话只表述一个状态
   类别，引用 finding id 时逐条分句，不在同句混排不同状态类别；
4. 附录 B 归因：为 rejected_reason_ids 中的每条 finding 写一两句中文归因
   （基于其 rejection_reason 原文浓缩，不得编造），放到顶层键
   "reasons_cn": {"<finding id>": "..."}（与 paragraphs 并列）。
只输出一个 JSON 对象：{"paragraphs": {"<finding id>": {"description": "...",
"impact": "...", "remediation": "..."}, "overview": "...", "remediation": "..."},
"reasons_cn": {"<rejected finding id>": "..."}}，
paragraphs 的键只能来自给出的 allowed_keys（finding 键给三段对象、章节键
给字符串），不要输出任何其他文字。"""


class NarrativeError(RuntimeError):
    """叙述生成失败：LLM 调用异常或输出非法（无锚文字/坏 JSON/空段落拒收）。"""


class _NarrativeOut(BaseModel):
    """叙述输出的 schema 强校验：段落非空、至少一段。

    M4.5：finding 键为三段对象（NarrativeParts，字段空白/多余键即非法），
    兼容旧字符串段落；章节键须为字符串（在 _parse_output 语义校验）。
    M6c：可选 ``reasons_cn``（附录 B 误报中文归因）——**缺失容忍**（旧
    回复格式仍合法），值非空白；键 ⊆ Rejected id 集合（语义校验）。
    """

    paragraphs: dict[str, str | NarrativeParts] = Field(min_length=1)
    reasons_cn: dict[str, str] = Field(default_factory=dict)

    @field_validator("paragraphs")
    @classmethod
    def _non_empty(cls, value: dict[str, str | NarrativeParts]) -> dict:
        for key, item in value.items():
            if isinstance(item, str) and not item.strip():
                raise ValueError(f"段落为空: {key}")
        return value

    @field_validator("reasons_cn")
    @classmethod
    def _reason_non_blank(cls, value: dict[str, str]) -> dict:
        for key, item in value.items():
            if not item.strip():
                raise ValueError(f"归因段落为空: {key}")
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
        # M6c 事实守卫输入：全量 id→真实状态 + 真实桶数 + Rejected id 集合
        states = {f.id: f.state for f in findings}
        rejected_ids = {
            f.id for f in findings if f.state is FindingState.REJECTED
        }
        confirmed_count = sum(
            1 for f in findings if f.state is FindingState.CONFIRMED
        )

        messages = self._make_messages(findings, narrated, allowed_keys)
        chars = messages_chars(messages)
        if chars > self.context_policy.max_chars:
            raise ContextOverflowError(chars=chars, limit=self.context_policy.max_chars)

        tracker = getattr(self.router, "tracker", None)
        before = len(tracker.records) if tracker is not None else 0
        # 预算硬闸在路由层（M6a：含修复重试那次调用；重试 token 计入下方差值）
        paragraphs, reasons_cn = complete_structured(
            self.router,
            Tier.T1,
            messages,
            lambda raw: self._parse_output(
                raw,
                allowed_keys,
                rejected_ids=rejected_ids,
                states=states,
                confirmed_count=confirmed_count,
                rejected_count=len(rejected_ids),
            ),
            audit=self.audit,
            caller="narrative",
            max_chars=self.context_policy.max_chars,
        )
        tokens: int | None = None
        if tracker is not None:
            used = sum(r.total_tokens for r in tracker.records[before:])
            tokens = used or None
        model = self._t1_model_name()

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
        # M6c：附录 B 误报中文归因（衍生文件，恒写——空 dict 也写，防陈旧）
        (evidence_dir / REASONS_CN_FILE).write_text(
            json.dumps(reasons_cn, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if self.audit is not None:
            for section in sections:
                self.audit.record(
                    "narrative_generated", section=section, model=model, tokens=tokens
                )
            for fid in reasons_cn:
                self.audit.record(
                    "narrative_generated",
                    finding_id=fid,
                    kind="reason_cn",
                    model=model,
                    tokens=tokens,
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
            # M6c：全量 id→状态清单（含 rejected/hypothesis）供措辞纪律对照；
            # rejected_reason_ids = 需要产中文归因的清单
            "state_roster": [
                {"id": f.id, "state": f.state.value} for f in findings
            ],
            "rejected_reason_ids": [r["id"] for r in stats["rejected_reasons"]],
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
    def _parse_output(
        raw: str,
        allowed_keys: set[str],
        *,
        rejected_ids: set[str],
        states: dict[str, FindingState],
        confirmed_count: int,
        rejected_count: int,
    ) -> tuple[dict[str, str | NarrativeParts], dict[str, str]]:
        """解析并强校验 LLM 输出，返回 (paragraphs, reasons_cn)。

        校验链（任一失败 NarrativeError，全量拒收）：坏 JSON → schema →
        无锚段落 → 章节类型 → 无锚归因键（M6c）→ 叙事事实守卫（M6c）。
        """
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
        unknown_reasons = set(out.reasons_cn) - rejected_ids
        if unknown_reasons:
            raise NarrativeError(
                f"叙述输出含无锚归因（键不在 Rejected 集合 {sorted(rejected_ids)}）: "
                f"{sorted(unknown_reasons)}——全量拒收"
            )
        # M6c 叙事事实守卫（确定性代码，零 LLM）：F-ID 幻觉 / 状态词共现 /
        # 计数断言；违规明细随 NarrativeError 进修复指令
        corpus: list[str] = []
        for item in out.paragraphs.values():
            if isinstance(item, NarrativeParts):
                corpus.extend([item.description, item.impact, item.remediation])
            else:
                corpus.append(item)
        corpus.extend(out.reasons_cn.values())
        violations = check_narrative_facts(
            corpus,
            states,
            confirmed_count=confirmed_count,
            rejected_count=rejected_count,
        )
        if violations:
            details = "\n".join(f"- {v}" for v in violations)
            raise NarrativeError(f"叙述事实守卫拒绝（全量拒收）：\n{details}")
        return out.paragraphs, out.reasons_cn

    def _t1_model_name(self) -> str:
        configs = getattr(self.router, "configs", {})
        config = configs.get(Tier.T1) if configs else None
        return config.model if config is not None else "unknown"
