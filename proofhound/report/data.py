"""报告数据组装（M4，§5.7 数据与表现分离）。

从 ``<evidence_dir>/findings.jsonl`` + 证据包（``findings/<id>/manifest.json``）
装配 :class:`ReportContext`：

- 分桶：``confirmed_findings``（Confirmed）/ ``conditional_findings``
  （Reproduced 未 Confirmed，"需特定条件"）/ ``hypothesis_findings``
  （Hypothesis，"疑似未验证"；Signal 态若出现也归此桶）/
  ``rejected_findings``（误报附录数据源）；
- 每条 finding 携带结构化字段 + 证据包索引（manifest 路径 + sha256 清单）
  + ``narrative`` 槽位；渲染器只读本模块产出的结构化字段；
- engagement 元信息：可选 ``<evidence_dir>/engagement.json`` 优先，缺字段
  派生（target 取资产最高频 host；时间窗取 audit.jsonl 首/末条 ts，无
  audit 退化为 findings 时间戳 min/max）；
- 固定章节叙述（narrative.py 产物）读 ``<evidence_dir>/narrative_sections.json``；
- M4.5 增补：engagement.json 任意额外键（extras）原样透传进渲染上下文；
  finding 增 ``severity_cn``（中文档位）、``narrative_parts``（三段叙述）、
  ``repro_text``（编号拼接复现文本）；context 增 ``evidence_index`` 扁平
  证据索引（confirmed+conditional 全部条目，稳定排序）；
- M6b 增补：finding 增 ``cvss_vector``/``cvss_score``——仅 Confirmed
  桶透传（非 Confirmed 不展示分数，代码层恒 None）；旧 engagement
  数据无此字段时容忍 None。

全程纯文件查询：不碰网络、不调 LLM。context 不含 wall-clock"报告生成
时间"——同输入同 context（渲染确定性，§5.7）。
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from proofhound.findings.finding import Finding, FindingState, FindingStore

ENGAGEMENT_FILE = "engagement.json"
SECTIONS_FILE = "narrative_sections.json"

#: 固定章节键（概述/修复建议）：narrative.py 的 FIXED_SECTIONS 同源于此
SECTION_KEYS: tuple[str, ...] = ("overview", "remediation")

#: severity 排序权重（小在前）；未知级别排最后
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

#: severity 中文档位映射（M4.5）；未知级别原样返回
SEVERITY_CN: dict[str, str] = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "提示",
}


class EvidenceItem(BaseModel):
    """证据包索引项（对应 manifest.json 的 items 元素）。"""

    file: str | None = None
    sha256: str | None = None
    source_ref: str
    line_anchor: int | None = None
    missing: bool = False


class EvidencePackIndex(BaseModel):
    """一条 Finding 的证据包索引：包目录 + 含 sha256 的清单。

    清单字段名用 ``entries`` 而非 manifest 里的 ``items``：渲染 context 为
    dict，Jinja2 属性解析先试 Python getattr，``dict.items`` 方法会遮蔽
    同名键导致 ``f.evidence_pack.items`` 取到内置方法（实测踩坑）。
    """

    pack_dir: str
    assembled: bool  # False = 证据包未组装（无 manifest.json），显式可见
    entries: list[EvidenceItem] = Field(default_factory=list)


class FindingReport(BaseModel):
    """报告中一条 finding 的结构化视图 + narrative 槽位。"""

    id: str
    state: str
    title: str | None = None
    vuln_type: str
    severity: str
    severity_cn: str  # M4.5：中文档位（critical→严重/high→高/...，未知原样）
    cvss_vector: str | None = None  # M6b：仅 Confirmed 桶透传（旧数据容忍 None）
    cvss_score: float | None = None  # M6b：代码算分；非 Confirmed 恒 None
    asset: str
    param: str | None = None
    preconditions: list[str] = Field(default_factory=list)
    confidence: str
    evidence_kinds: list[str] = Field(default_factory=list)
    verification: dict | None = None  # Verification 结构化原样
    verifier: dict | None = None  # VerifierVerdict 结构化原样
    rejection_reason: str | None = None
    narrative: str | None = None  # 叙述槽位：渲染器只读，不回写事实字段
    narrative_parts: dict | None = None  # M4.5 三段叙述（描述/危害/建议措施）
    repro_text: str = ""  # M4.5：编号拼接复现文本（\n 连接，供 {{r }} 富文本）
    evidence_pack: EvidencePackIndex


class EngagementMeta(BaseModel):
    """engagement 元信息（target/scope/时间窗）；字段均可派生。

    ``extra="allow"``（M4.5）：engagement.json 的任意额外键
    （company_name/system_name/report_date 等）原样透传进渲染上下文；
    只进模板渲染，不进叙述 prompt。已知字段类型校验不变。
    """

    model_config = ConfigDict(extra="allow")

    target: str | None = None
    scope: str | None = None
    started_at: str | None = None
    finished_at: str | None = None


class ReportSummary(BaseModel):
    """分桶计数 + confirmed 按 severity 计数（汇总表数据源）。"""

    confirmed: int = 0
    conditional: int = 0
    hypothesis: int = 0
    rejected: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)


class EvidenceIndexItem(BaseModel):
    """扁平证据索引项（M4.5，附录 A 数据源）：条目 + 所属 finding。"""

    finding_id: str
    file: str | None = None
    sha256: str | None = None
    source_ref: str = ""
    line_anchor: int | None = None


class ReportContext(BaseModel):
    """渲染器唯一输入（数据与表现分离：模板只读这里的结构化字段）。"""

    engagement: EngagementMeta
    summary: ReportSummary
    confirmed_findings: list[FindingReport] = Field(default_factory=list)
    conditional_findings: list[FindingReport] = Field(default_factory=list)
    hypothesis_findings: list[FindingReport] = Field(default_factory=list)
    rejected_findings: list[FindingReport] = Field(default_factory=list)
    sections: dict[str, str | None] = Field(
        default_factory=dict
    )  # 固定章节叙述段落；契约键恒在（值可为 None），StrictUndefined 下可判空
    evidence_index: list[EvidenceIndexItem] = Field(default_factory=list)  # M4.5 扁平证据索引（confirmed+conditional，稳定排序）

    def as_template_context(self) -> dict:
        """渲染输入：纯结构化 dict（JSON 类型），渲染器只读它。"""
        return self.model_dump(mode="json")


def _severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.strip().lower(), len(SEVERITY_ORDER))


def _severity_cn(severity: str) -> str:
    """中文档位映射；未知级别原样返回。"""
    return SEVERITY_CN.get(severity.strip().lower(), severity)


def _repro_text(finding: Finding) -> str:
    """编号拼接复现文本（\\n 连接供 {{r }} 富文本）；无步骤为空串。"""
    if finding.verification is None:
        return ""
    return "\n".join(
        f"{index}. {step}"
        for index, step in enumerate(finding.verification.reproduction_steps, 1)
    )


def _load_evidence_pack(finding: Finding, evidence_dir: Path) -> EvidencePackIndex:
    """读证据包 manifest 为索引；无 manifest 显式标记 assembled=False。"""
    pack_dir = evidence_dir / "findings" / finding.id
    manifest_path = pack_dir / "manifest.json"
    if not manifest_path.is_file():
        return EvidencePackIndex(pack_dir=str(pack_dir), assembled=False)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = [
        EvidenceItem(
            file=item.get("file"),
            sha256=item.get("sha256"),
            source_ref=item.get("source_ref", ""),
            line_anchor=item.get("line_anchor"),
            missing=bool(item.get("missing")),
        )
        for item in manifest.get("items", [])
    ]
    return EvidencePackIndex(pack_dir=str(pack_dir), assembled=True, entries=entries)


def _to_report(finding: Finding, evidence_dir: Path) -> FindingReport:
    return FindingReport(
        id=finding.id,
        state=finding.state.value,
        title=finding.title,
        vuln_type=finding.vuln_type,
        severity=finding.severity,
        severity_cn=_severity_cn(finding.severity),
        # M6b：分数只对 Confirmed 展示（Confirmed 前 severity 可为种子值）
        cvss_vector=(
            finding.cvss_vector
            if finding.state is FindingState.CONFIRMED
            else None
        ),
        cvss_score=(
            finding.cvss_score
            if finding.state is FindingState.CONFIRMED
            else None
        ),
        asset=finding.asset,
        param=finding.param,
        preconditions=list(finding.preconditions),
        confidence=finding.confidence,
        evidence_kinds=list(finding.evidence_kinds),
        verification=(
            finding.verification.model_dump(mode="json")
            if finding.verification
            else None
        ),
        verifier=(
            finding.verifier.model_dump(mode="json") if finding.verifier else None
        ),
        rejection_reason=finding.rejection_reason,
        narrative=finding.narrative,
        narrative_parts=(
            finding.narrative_parts.model_dump(mode="json")
            if finding.narrative_parts
            else None
        ),
        repro_text=_repro_text(finding),
        evidence_pack=_load_evidence_pack(finding, evidence_dir),
    )


def _derive_target(findings: list[Finding]) -> str | None:
    """target 派生：全部 finding 资产中最高频的 host（netloc）。"""
    hosts = Counter()
    for finding in findings:
        host = urlparse(finding.asset).netloc or finding.asset
        hosts[host] += 1
    if not hosts:
        return None
    # most_common 同票数保持首见顺序，确定性
    return hosts.most_common(1)[0][0]


def _derive_time_window(
    findings: list[Finding], evidence_dir: Path
) -> tuple[str | None, str | None]:
    """时间窗派生：audit.jsonl 首/末条 ts；无 audit 退化为 findings 时间戳。"""
    audit_path = evidence_dir / "audit.jsonl"
    if audit_path.is_file():
        timestamps = [
            json.loads(line).get("ts")
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        timestamps = [ts for ts in timestamps if ts]
        if timestamps:
            return timestamps[0], timestamps[-1]
    stamps = [ts for f in findings for ts in (f.created_at, f.updated_at) if ts]
    if not stamps:
        return None, None
    return min(stamps), max(stamps)


def _load_engagement(
    findings: list[Finding], evidence_dir: Path
) -> EngagementMeta:
    """engagement.json 优先；缺字段就地补派生（保住 extras，M4.5）。"""
    meta = EngagementMeta()
    path = evidence_dir / ENGAGEMENT_FILE
    if path.is_file():
        meta = EngagementMeta.model_validate(
            json.loads(path.read_text(encoding="utf-8"))
        )
    started, finished = _derive_time_window(findings, evidence_dir)
    meta.target = meta.target or _derive_target(findings)
    meta.started_at = meta.started_at or started
    meta.finished_at = meta.finished_at or finished
    return meta


def _load_sections(evidence_dir: Path) -> dict[str, str | None]:
    """固定章节叙述（narrative.py 产物）；契约键恒在（缺省 None）。

    模板渲染用 StrictUndefined：键缺失会在 ``or`` 判空时也报错，因此
    overview/remediation 恒在、值为 None 表示未生成。坏 JSON 按空处理。
    """
    sections: dict[str, str | None] = {key: None for key in SECTION_KEYS}
    path = evidence_dir / SECTIONS_FILE
    if not path.is_file():
        return sections
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return sections
    if not isinstance(data, dict):
        return sections
    sections.update({str(k): str(v) for k, v in data.items()})
    return sections


def build_context(evidence_dir: str | Path) -> ReportContext:
    """从 evidence 目录装配报告上下文（纯文件查询，确定性）。"""
    evidence_dir = Path(evidence_dir)
    store = FindingStore(evidence_dir / "findings.jsonl")
    findings = store.load_all()

    buckets: dict[str, list[FindingReport]] = {
        "confirmed": [],
        "conditional": [],
        "hypothesis": [],
        "rejected": [],
    }
    for finding in findings:
        report = _to_report(finding, evidence_dir)
        if finding.state is FindingState.CONFIRMED:
            buckets["confirmed"].append(report)
        elif finding.state is FindingState.REPRODUCED:
            buckets["conditional"].append(report)
        elif finding.state is FindingState.REJECTED:
            buckets["rejected"].append(report)
        else:  # hypothesis / signal：疑似未验证
            buckets["hypothesis"].append(report)
    for bucket in buckets.values():
        bucket.sort(key=lambda f: (_severity_rank(f.severity), f.id))

    severity_counts = Counter(
        f.severity.strip().lower() for f in buckets["confirmed"]
    )
    summary = ReportSummary(
        confirmed=len(buckets["confirmed"]),
        conditional=len(buckets["conditional"]),
        hypothesis=len(buckets["hypothesis"]),
        rejected=len(buckets["rejected"]),
        severity_counts=dict(
            sorted(severity_counts.items(), key=lambda kv: _severity_rank(kv[0]))
        ),
    )
    # M4.5 扁平证据索引：confirmed → conditional 桶序（桶内已 severity,id
    # 排序），entries 按 manifest 原序展开——稳定确定；未组装的包跳过。
    evidence_index: list[EvidenceIndexItem] = []
    for report in buckets["confirmed"] + buckets["conditional"]:
        if not report.evidence_pack.assembled:
            continue
        for entry in report.evidence_pack.entries:
            evidence_index.append(
                EvidenceIndexItem(
                    finding_id=report.id,
                    file=entry.file,
                    sha256=entry.sha256,
                    source_ref=entry.source_ref,
                    line_anchor=entry.line_anchor,
                )
            )
    return ReportContext(
        engagement=_load_engagement(findings, evidence_dir),
        summary=summary,
        confirmed_findings=buckets["confirmed"],
        conditional_findings=buckets["conditional"],
        hypothesis_findings=buckets["hypothesis"],
        rejected_findings=buckets["rejected"],
        sections=_load_sections(evidence_dir),
        evidence_index=evidence_index,
    )
