"""report 模块（M4，§5.7）：报告引擎——数据与表现分离。

- :mod:`~proofhound.report.data`：findings.jsonl + 证据包 → ReportContext
  （分桶 + 证据索引 + engagement 元信息 + narrative 槽位）；
- :mod:`~proofhound.report.narrative`：T1 档叙述生成，段落绑定 finding id
  或固定章节键，无锚文字拒收；
- :mod:`~proofhound.report.render`：docxtpl 渲染（StrictUndefined）；
- CLI：``python -m proofhound.report build``（见 __main__.py）。
"""

from proofhound.report.data import (
    EngagementMeta,
    EvidenceItem,
    EvidencePackIndex,
    FindingReport,
    ReportContext,
    ReportSummary,
    build_context,
)
from proofhound.report.narrative import (
    FIXED_SECTIONS,
    NarrativeError,
    NarrativeGenerator,
)
from proofhound.report.render import RenderError, render_docx

__all__ = [
    "EngagementMeta",
    "EvidenceItem",
    "EvidencePackIndex",
    "FIXED_SECTIONS",
    "FindingReport",
    "NarrativeError",
    "NarrativeGenerator",
    "RenderError",
    "ReportContext",
    "ReportSummary",
    "build_context",
    "render_docx",
]
