"""单题成本聚合（M11a，§5.6 成本可观测）。

**为什么需要本模块**：M2c 起每次 LLM 调用都记 ``llm_call`` 审计，但事件里
**没有归属信息**（不知是 triage、Verifier 还是叙述花的），于是「单条 Finding
的确认成本」与「哪个阶段最贵」都算不出来。M10a 实测记录了三组互不相同的
token 数字（连大小关系都反），根因之一就是口径未定 + 无法按调用方归属。

**本模块定义的口径**（维护者 M11a 裁决）：

- **归属维度** = 调用方（``caller``）+ 阶段（``phase``，由调用方映射）
  + Finding（``finding_id``，仅 Verifier 逐 Finding 有值）+ 档位（``tier``）；
- **含修复重试**：M6a 的修复重试是真实成本，计入主口径；因其在审计上带
  ``retry=True``，可**确定性**单列（``retry_calls`` / ``retry_tokens``），
  不需推断事件顺序；
- **估计值单列**：``estimated=True`` 的事件（响应无 usage，按 4 字符≈1 token
  估算）单独计数，估算与真实不混算（已知限制 6）；
- **旧数据容忍**：M11a 之前的 ``llm_call`` 缺 ``caller``/``finding_id``，
  一律归入 ``unknown`` 桶并计数——**绝不静默丢弃**（丢弃会让总量对不上，
  正是"数字不可复现"的来源）。

红线 3 相关性：本模块只读审计结构化字段（tier/tokens/caller/finding_id），
不读响应体、不读证据原文，纯确定性、零 LLM。
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

#: 审计事件名（每次 LLM 调用一条）
LLM_CALL_EVENT = "llm_call"

#: 阶段枚举（稳定顺序，供 CLI/API/控制台渲染）
PHASES: tuple[str, ...] = ("discovery", "planning", "verification", "report", "unknown")

#: 调用方 → 阶段映射（M11a 四个结构化调用点）
CALLER_PHASE: dict[str, str] = {
    "triage": "discovery",
    "planner": "planning",
    "verifier": "verification",
    "narrative": "report",
}

#: 归属信息缺失时的归集键（旧审计事件 / 旧替身路径）
UNKNOWN = "unknown"


def phase_of(caller: str | None) -> str:
    """调用方 → 阶段；未登记的调用方归 ``unknown``（不猜、不丢弃）。"""
    return CALLER_PHASE.get(caller or "", UNKNOWN)


@dataclass(frozen=True)
class CostCall:
    """一次 LLM 调用的成本记录（``llm_call`` 审计事件的只读视图）。"""

    tier: str
    caller: str
    finding_id: str | None
    prompt_tokens: int
    completion_tokens: int
    retry: bool
    estimated: bool
    ts: str | None = None

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def phase(self) -> str:
        return phase_of(self.caller)


@dataclass
class CostEntry:
    """一个归属桶的聚合值。"""

    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    estimated_calls: int = 0
    retry_calls: int = 0
    retry_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def add(self, call: CostCall) -> None:
        self.calls += 1
        self.prompt_tokens += call.prompt_tokens
        self.completion_tokens += call.completion_tokens
        if call.estimated:
            self.estimated_calls += 1
        if call.retry:
            self.retry_calls += 1
            self.retry_tokens += call.total_tokens

    def as_dict(self) -> dict:
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_calls": self.estimated_calls,
            "retry_calls": self.retry_calls,
            "retry_tokens": self.retry_tokens,
        }


def _as_int(value) -> int:
    """审计字段宽容转 int（缺失/None/非数值 → 0；不抛错）。"""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def calls_from_events(events: list[dict]) -> list[CostCall]:
    """从审计事件流提取 LLM 调用记录（只认 ``llm_call``，顺序保持）。"""
    calls: list[CostCall] = []
    for event in events:
        if event.get("event") != LLM_CALL_EVENT:
            continue
        caller = event.get("caller")
        finding_id = event.get("finding_id")
        calls.append(
            CostCall(
                tier=str(event.get("tier") or UNKNOWN),
                caller=str(caller) if caller else UNKNOWN,
                finding_id=str(finding_id) if finding_id else None,
                prompt_tokens=_as_int(event.get("prompt_tokens")),
                completion_tokens=_as_int(event.get("completion_tokens")),
                retry=bool(event.get("retry")),
                estimated=bool(event.get("estimated")),
                ts=event.get("ts"),
            )
        )
    return calls


@dataclass
class CostReport:
    """一次聚合的完整结果（总额 + 四个归属维度 + 逐次调用明细）。"""

    total: CostEntry = field(default_factory=CostEntry)
    by_caller: dict[str, CostEntry] = field(default_factory=dict)
    by_phase: dict[str, CostEntry] = field(default_factory=dict)
    by_finding: dict[str, CostEntry] = field(default_factory=dict)
    by_tier: dict[str, CostEntry] = field(default_factory=dict)
    calls: list[CostCall] = field(default_factory=list)

    @property
    def attributability(self) -> float:
        """可归属比例 = 非 unknown 调用数 / 总调用数（0 调用时记 1.0）。

        这是口径的**诚实性指标**：旧审计（M11a 之前）没有 caller，该值会低；
        低值意味着「按调用方归属」的数字只覆盖了一部分调用，不可当全量读。
        """
        if not self.calls:
            return 1.0
        known = sum(1 for c in self.calls if c.caller != UNKNOWN)
        return known / len(self.calls)

    def as_dict(self, *, include_calls: bool = True) -> dict:
        payload = {
            "total": self.total.as_dict(),
            "by_caller": {k: v.as_dict() for k, v in sorted(self.by_caller.items())},
            "by_phase": {k: v.as_dict() for k, v in self.by_phase.items()},
            "by_finding": {k: v.as_dict() for k, v in sorted(self.by_finding.items())},
            "by_tier": {k: v.as_dict() for k, v in sorted(self.by_tier.items())},
            "attributability": self.attributability,
        }
        if include_calls:
            payload["calls"] = [
                {
                    "tier": c.tier,
                    "caller": c.caller,
                    "phase": c.phase,
                    "finding_id": c.finding_id,
                    "prompt_tokens": c.prompt_tokens,
                    "completion_tokens": c.completion_tokens,
                    "total_tokens": c.total_tokens,
                    "retry": c.retry,
                    "estimated": c.estimated,
                    "ts": c.ts,
                }
                for c in self.calls
            ]
        return payload


def _bump(bucket: dict[str, CostEntry], key: str, call: CostCall) -> None:
    bucket.setdefault(key, CostEntry()).add(call)


def aggregate(calls: list[CostCall]) -> CostReport:
    """把调用记录聚合成 :class:`CostReport`（纯函数，确定性，零 LLM）。

    同一桶口径纪律：``by_caller``/``by_phase``/``by_finding``/``by_tier``
    各自独立聚合，**四者各自求和都等于** ``total``（测试逐项核对）。
    """
    report = CostReport(calls=list(calls))
    for call in calls:
        report.total.add(call)
        _bump(report.by_caller, call.caller, call)
        _bump(report.by_phase, call.phase, call)
        _bump(report.by_tier, call.tier, call)
        # 无 finding 归属的调用（planner/triage/narrative）也显式成桶，
        # 键为 "（无）"，避免"没出现"与"零成本"被混淆
        _bump(report.by_finding, call.finding_id or "（无）", call)
    return report


def load_calls(audit_path: str | Path) -> list[CostCall]:
    """从 ``audit.jsonl`` 读取调用记录（纯文件读取，不碰网络/LLM）。

    文件不存在 → 空列表（成本为 0，而非报错）。
    """
    path = Path(audit_path)
    if not path.is_file():
        return []
    events: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # 半截行（进程中断）容忍：跳过该行，不整体失败
    return calls_from_events(events)


def report_from_audit(audit_path: str | Path) -> CostReport:
    """从 ``audit.jsonl`` 直接得到聚合报告（CLI / API 共用入口）。"""
    return aggregate(load_calls(audit_path))


def render_markdown(report: CostReport, *, title: str = "单题成本归属") -> str:
    """渲染可读的 Markdown 摘要（CLI 打印用；数字全部来自聚合，零手写）。"""

    def _row(name: str, entry: CostEntry) -> str:
        return (
            f"| {name} | {entry.calls} | {entry.total_tokens} | "
            f"{entry.prompt_tokens} | {entry.completion_tokens} | "
            f"{entry.retry_calls} | {entry.retry_tokens} | {entry.estimated_calls} |"
        )

    lines = [
        f"# {title}",
        "",
        f"- 总调用次数：**{report.total.calls}**",
        f"- 总 token：**{report.total.total_tokens}**"
        f"（prompt {report.total.prompt_tokens} / completion "
        f"{report.total.completion_tokens}）",
        f"- 修复重试：**{report.total.retry_calls}** 次，"
        f"**{report.total.retry_tokens}** token（已含在总 token 内）",
        f"- 估算事件：{report.total.estimated_calls} 次"
        f"（响应无 usage，按 4 字符≈1 token 估算）",
        f"- 可归属比例：**{report.attributability:.1%}**"
        f"（1 - unknown 占比；旧审计无 caller 时该值偏低）",
        "",
    ]
    header = (
        "| 归属 | 调用 | token | prompt | completion | 重试次 | 重试token | 估算次 |",
        "|---|---|---|---|---|---|---|---|",
    )
    for key, bucket, label in (
        ("caller", report.by_caller, "按调用方"),
        ("phase", report.by_phase, "按阶段"),
        ("finding", report.by_finding, "按 Finding"),
        ("tier", report.by_tier, "按档位"),
    ):
        lines.append(f"## {label}")
        lines.append("")
        lines.append(header[0])
        lines.append(header[1])
        for name in sorted(bucket):
            lines.append(_row(name, bucket[name]))
        lines.append("")
    return "\n".join(lines)


__all__ = [
    "CALLER_PHASE",
    "LLM_CALL_EVENT",
    "PHASES",
    "UNKNOWN",
    "CostCall",
    "CostEntry",
    "CostReport",
    "aggregate",
    "calls_from_events",
    "load_calls",
    "phase_of",
    "render_markdown",
    "report_from_audit",
]
