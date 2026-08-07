"""findings 模块：Signal 模型（M2b 起）+ Finding 生命周期（M3a 起）。

M3a：Finding 数据模型与状态机（铁律硬编码）、append-only FindingStore
（findings.jsonl 快照追加）、去重指纹、证据包组装与离线 show 入口。
SQLite 存储（§5.5）属后续里程碑。
"""

from proofhound.findings.dedup import compute_dedup_key, normalize_asset
from proofhound.findings.evidence import assemble_evidence_pack, split_evidence_ref
from proofhound.findings.finding import (
    Finding,
    FindingState,
    FindingStore,
    InvalidTransitionError,
    IronRuleViolationError,
    Verification,
    VerifierVerdict,
)
from proofhound.findings.signal import Signal

__all__ = [
    "Finding",
    "FindingState",
    "FindingStore",
    "InvalidTransitionError",
    "IronRuleViolationError",
    "Signal",
    "Verification",
    "VerifierVerdict",
    "assemble_evidence_pack",
    "compute_dedup_key",
    "normalize_asset",
    "split_evidence_ref",
]
