"""Finding 数据模型与生命周期状态机（M3a，§5.4.1/§5.5）。

- 状态机：Signal → Hypothesis → Reproduced → Confirmed；任意非终态 →
  Rejected；Confirmed/Rejected 为终态。非法迁移抛
  :class:`InvalidTransitionError`；
- 铁律硬编码在本层（不是 prompt 层，红线 2 / §5.4.1）：版本匹配型 CVE、
  或证据仅含 status-code 的 Finding **永远禁止迁入 Confirmed**，尝试即抛
  :class:`IronRuleViolationError`；Confirmed 另须携带
  ``verification.evidence_refs``（证据完备率 100%）；
- 每次迁移记审计 ``finding_state{finding_id, from, to, actor, reason}``；
- 落盘：``findings.jsonl``（append-only）——每次变更追加一行完整快照，
  加载按 id 回放 last-wins；迁移历史由 audit.jsonl 承载。
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from proofhound.compliance.audit import AuditLog


class FindingState(str, Enum):
    SIGNAL = "signal"
    HYPOTHESIS = "hypothesis"
    REPRODUCED = "reproduced"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class InvalidTransitionError(RuntimeError):
    """非法状态迁移。"""


class IronRuleViolationError(InvalidTransitionError):
    """铁律拒绝（§5.4.1）：属非法迁移，但语义上可与普通非法迁移区分。"""


_TRANSITIONS: dict[FindingState, frozenset[FindingState]] = {
    FindingState.SIGNAL: frozenset({FindingState.HYPOTHESIS, FindingState.REJECTED}),
    FindingState.HYPOTHESIS: frozenset({FindingState.REPRODUCED, FindingState.REJECTED}),
    FindingState.REPRODUCED: frozenset({FindingState.CONFIRMED, FindingState.REJECTED}),
    FindingState.CONFIRMED: frozenset(),
    FindingState.REJECTED: frozenset(),
}

TERMINAL_STATES: frozenset[FindingState] = frozenset(
    {FindingState.CONFIRMED, FindingState.REJECTED}
)

# 铁律 1：版本匹配型 CVE 永远只能是 Signal（§5.4.1）
VERSION_MATCH_VULN_TYPES: frozenset[str] = frozenset({"version-cve"})

# 铁律 2：证据种类标签——仅含 status-code（或无任何行为类证据）禁止 Confirmed
STATUS_CODE_EVIDENCE_KIND = "status-code"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Verification(BaseModel):
    """验证信息（§5.5）：Confirmed 必须携带且 evidence_refs 非空。"""

    method: str = Field(min_length=1)
    evidence_refs: list[str] = Field(min_length=1)
    baseline_diff: str | None = None
    reproduction_steps: list[str] = Field(default_factory=list)
    verified_by: str | None = None  # verify-* skill 标识
    verified_at: str | None = None


class VerifierVerdict(BaseModel):
    """Verifier Agent 裁定（§5.4.4，M3 后续切片接入）。"""

    model: str = Field(min_length=1)
    verdict: str = Field(min_length=1)  # confirm / downgrade / reject
    reason: str = ""


class Finding(BaseModel):
    """一条发现（§5.5）。Confirmed 只能经状态机 + 铁律闸到达（红线 2）。"""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(min_length=1)
    state: FindingState = FindingState.SIGNAL
    title: str | None = None
    vuln_type: str = Field(min_length=1)
    severity: str = "info"
    asset: str = Field(min_length=1)  # M3a 为字符串（Signal 原样），结构化形态延后
    param: str | None = None  # 去重指纹的"参数/路径"分量
    preconditions: list[str] = Field(default_factory=list)
    confidence: str = "low"
    evidence_kinds: list[str] = Field(default_factory=list)  # 证据种类标签（铁律 2 判定依据）
    verification: Verification | None = None
    verifier: VerifierVerdict | None = None
    dedup_key: str = Field(min_length=1)
    cvss: float | None = None
    rejection_reason: str | None = None
    narrative: str | None = None  # 报告阶段 LLM 叙述只存于此，不回写事实字段
    source_signal_refs: list[str] = Field(default_factory=list)
    created_at: str = Field(min_length=1)
    updated_at: str = Field(min_length=1)
    audit: AuditLog | None = Field(default=None, exclude=True)  # 运行期句柄，不落盘

    def transition(
        self, to: FindingState, *, actor: str, reason: str = ""
    ) -> None:
        """状态迁移；非法迁移抛 :class:`InvalidTransitionError`，违反铁律抛
        :class:`IronRuleViolationError`；每次迁移记审计 ``finding_state``。"""
        if to not in _TRANSITIONS[self.state]:
            raise InvalidTransitionError(
                f"Finding {self.id} 非法迁移: {self.state.value} -> {to.value}"
            )
        if to is FindingState.CONFIRMED:
            self._check_confirm_gates()
        old = self.state
        self.state = to
        self.updated_at = _utc_now()
        if to is FindingState.CONFIRMED:
            self.confidence = "confirmed"  # §5.5：确认即提升置信度
        if to is FindingState.REJECTED and reason:
            self.rejection_reason = reason
        if self.audit is not None:
            self.audit.record(
                "finding_state",
                finding_id=self.id,
                **{"from": old.value, "to": to.value, "actor": actor, "reason": reason},
            )

    def _check_confirm_gates(self) -> None:
        """迁入 Confirmed 的铁律闸（代码层硬编码，不可经 prompt 绕过）。"""
        if self.vuln_type in VERSION_MATCH_VULN_TYPES:
            raise IronRuleViolationError(
                f"Finding {self.id} 铁律拒绝：版本匹配型 CVE（{self.vuln_type}）"
                "永远禁止迁入 Confirmed，必须经行为验证晋级"
            )
        if not any(k != STATUS_CODE_EVIDENCE_KIND for k in self.evidence_kinds):
            raise IronRuleViolationError(
                f"Finding {self.id} 铁律拒绝：证据仅含 status-code（或无行为类"
                "证据），永远禁止迁入 Confirmed，必须经行为验证晋级"
            )
        if self.verification is None or not self.verification.evidence_refs:
            raise IronRuleViolationError(
                f"Finding {self.id} 铁律拒绝：Confirmed 必须携带 "
                "verification.evidence_refs（证据完备率 100%）"
            )


_ID_PATTERN = re.compile(r"^F-(\d{4})-(\d{4,})$")


class FindingStore:
    """findings.jsonl 的 append-only 存取：快照追加 + last-wins 回放。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, finding: Finding) -> None:
        """追加一行完整快照（只追加，不提供修改/删除能力）。"""
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(finding.model_dump_json() + "\n")

    def load_all(self) -> list[Finding]:
        """回放全部快照：同 id 后者覆盖前者，保持首见顺序。"""
        findings: dict[str, Finding] = {}
        if not self.path.exists():
            return []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            finding = Finding.model_validate(json.loads(line))
            findings[finding.id] = finding
        return list(findings.values())

    def get(self, finding_id: str) -> Finding | None:
        for finding in self.load_all():
            if finding.id == finding_id:
                return finding
        return None

    def get_by_dedup_key(self, dedup_key: str) -> Finding | None:
        """按去重指纹找合并目标：跳过 Rejected（已判误报不吸收新证据）。"""
        match = None
        for finding in self.load_all():
            if finding.dedup_key == dedup_key and finding.state is not FindingState.REJECTED:
                match = finding
        return match

    def next_id(self, *, now: datetime | None = None) -> str:
        """分配 ``F-<YYYY>-<NNNN>``：取本 store 现存同年最大序号 + 1。"""
        now = now or datetime.now(timezone.utc)
        year = f"{now.year:04d}"
        seq = 0
        for finding in self.load_all():
            match = _ID_PATTERN.match(finding.id)
            if match and match.group(1) == year:
                seq = max(seq, int(match.group(2)))
        return f"F-{year}-{seq + 1:04d}"
