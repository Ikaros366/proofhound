"""最小编排器（M2b+M2c+M3a，§5.3）：scan 阶段链路的驱动者。

链路：registry 命中 skill → 规划器产计划（结构化 JSON，强校验）→
tools/build.py 拼装 argv（红线 1：LLM 不碰命令）→ SandboxRunner 执行
（红线 5：scope 强校验不变）→ 解析器产 Signal 落盘 → 全程审计。

- 阶段间串行、阶段内子任务并行（run_dag）；M2b 仅实现 scan 阶段；
  M3a 增加确定性 triage 阶段（run_triage_phase，规则表、零 LLM 调用）；
- 失败预算：同类失败默认上限 2 次，命中置 blocked 并升级（task_blocked）；
  验证码/锁定一次即硬阻塞；scope 拒绝与命令构造失败视为规划缺陷，
  直接 failed、不重试；
- LLM 上下文只进结构化 state（目标/次数/Signal 摘要），原始输出只给
  evidence 引用路径（红线 3）；
- M2c：LLM 调用经 ModelRouter（T1 档）；token 预算为硬闸——调用前检查，
  超限即停止规划循环、节点 blocked 并记审计 llm_budget_exceeded
  （与 scope 同级，任何自治模式不可绕过，无关闭开关）；上下文超硬上限
  （压缩后仍超）节点 failed 并记 context_overflow，禁止静默截断。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from proofhound.compliance.audit import AuditLog
from proofhound.findings.dedup import compute_dedup_key
from proofhound.findings.evidence import assemble_evidence_pack
from proofhound.findings.finding import (
    STATUS_CODE_EVIDENCE_KIND,
    Finding,
    FindingState,
    FindingStore,
)
from proofhound.findings.signal import Signal
from proofhound.core.context import ContextOverflowError, ContextPolicy
from proofhound.core.failures import FailureBudget, classify
from proofhound.core.plan import PlanAction, PlanValidationError
from proofhound.core.planner import Planner
from proofhound.core.tasks import (
    TaskNode,
    TaskStatus,
    aggregate_phase,
    run_dag,
)
from proofhound.llm.client import LLMError
from proofhound.llm.usage import BudgetExceededError
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.build import UnknownToolError, build_command, known_tools
from proofhound.tools.manifest import load_manifest
from proofhound.tools.parsers import PARSER_REGISTRY
from proofhound.tools.sandbox import RunResult, SandboxRunner

_OUTPUT_SAMPLE_LIMIT = 4096  # 失败分类的输出采样上限（字节）

# 确定性 triage 规则表（M3a）：web-probe 存活状态 → web-exposure 假设。
# 与 web-scan SKILL.md"存活"判定一致（2xx/3xx/401/403）；LLM triage 留后续切片。
_EXPOSED_STATUSES = frozenset({200, 201, 204, 301, 302, 307, 308, 401, 403})


def _triage_vuln_type(signal: Signal) -> str | None:
    """triage 规则映射：可映射返回 vuln_type，不可映射返回 None（保持 Signal）。"""
    if signal.kind == "web-probe" and signal.status_code in _EXPOSED_STATUSES:
        return "web-exposure"
    return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _default_tool_parsers() -> dict:
    """工具名 → 解析函数：由打包 manifests 的 parser 标识桥接 PARSER_REGISTRY。"""
    manifests_dir = Path(__file__).parent.parent / "tools" / "manifests"
    mapping = {}
    for path in sorted(manifests_dir.glob("*.yaml")):
        manifest = load_manifest(path)
        parser = PARSER_REGISTRY.get(manifest.parser or "")
        if parser is not None:
            mapping[manifest.name] = parser
    return mapping


class Orchestrator:
    """M2b 最小编排器：单模型规划 + scan 阶段执行。"""

    def __init__(
        self,
        registry: SkillRegistry,
        runner: SandboxRunner,
        llm,
        audit: AuditLog,
        evidence_dir: str | Path,
        *,
        budget: FailureBudget | None = None,
        tools: set[str] | None = None,
        parsers: dict | None = None,
        max_workers: int = 4,
        context_policy: ContextPolicy | None = None,
    ):
        # llm 接受 ModelRouter（M2c 推荐：选路/计量/预算硬闸在路由层）；
        # 旧式单模型客户端由 Planner 自动包装适配（不计量）。
        self.registry = registry
        self.runner = runner
        self.audit = audit
        self.evidence_dir = Path(evidence_dir)
        self.budget = budget or FailureBudget()
        self.tools = set(tools) if tools is not None else set(known_tools())
        self.parsers = parsers if parsers is not None else _default_tool_parsers()
        self.max_workers = max_workers
        self.planner = Planner(
            llm, registry, self.tools, audit, context_policy=context_policy
        )

    def run_scan_phase(self, targets: list[str], *, skill_name: str = "web-scan") -> TaskNode:
        """跑 scan 阶段：每目标一个子任务并行，返回阶段节点（含整棵树）。"""
        skill = self.registry.get(skill_name)
        if skill is None:
            raise KeyError(f"未注册的 skill: {skill_name}")
        if not skill.enabled:
            raise PermissionError(f"skill 未启用: {skill_name}")

        phase = TaskNode(name=f"phase:scan", kind="phase", audit=self.audit)
        phase.transition(TaskStatus.RUNNING, reason=f"scan 阶段启动，{len(targets)} 个目标")
        phase.children = [
            TaskNode(
                name=f"scan:{target}",
                kind="subtask",
                audit=self.audit,
                meta={"target": target},
            )
            for target in targets
        ]
        run_dag(
            phase.children,
            lambda node: self._run_subtask(node, skill),
            max_workers=self.max_workers,
        )
        phase.transition(aggregate_phase(phase), reason="阶段聚合")
        return phase

    # ---- triage 阶段（M3a，确定性、零 LLM 调用） ----

    def run_triage_phase(self) -> list[Finding]:
        """确定性 triage：加载 scan 阶段 Signals → 规则映射 → findings.jsonl。

        可映射 vuln_type 的 Signal 建/并 Finding 置 Hypothesis（同 dedup_key
        合并证据并记审计 finding_deduplicated）；不可映射保持 Signal。
        全程规则表判定，不接 LLM。
        """
        store = FindingStore(self.evidence_dir / "findings.jsonl")
        signals, skipped = self._load_phase_signals()
        findings: list[Finding] = []
        created = merged = 0
        for signal in signals:
            vuln_type = _triage_vuln_type(signal)
            if vuln_type is None:
                continue  # 不可映射：保持 Signal
            dedup_key = compute_dedup_key(signal.asset, vuln_type)
            existing = store.get_by_dedup_key(dedup_key)
            if existing is not None:
                if signal.evidence_ref in existing.source_signal_refs:
                    continue  # 幂等：该证据已归并过
                existing.source_signal_refs.append(signal.evidence_ref)
                if STATUS_CODE_EVIDENCE_KIND not in existing.evidence_kinds:
                    existing.evidence_kinds.append(STATUS_CODE_EVIDENCE_KIND)
                existing.updated_at = _utc_now()
                store.append(existing)
                self.audit.record(
                    "finding_deduplicated",
                    finding_id=existing.id,
                    dedup_key=dedup_key,
                    evidence_ref=signal.evidence_ref,
                )
                assemble_evidence_pack(existing, evidence_base=self.evidence_dir)
                merged += 1
                findings.append(existing)
                continue
            finding = Finding(
                id=store.next_id(),
                state=FindingState.SIGNAL,
                vuln_type=vuln_type,
                severity="info",
                asset=signal.asset,
                confidence="low",
                evidence_kinds=[STATUS_CODE_EVIDENCE_KIND],
                dedup_key=dedup_key,
                source_signal_refs=[signal.evidence_ref],
                created_at=_utc_now(),
                updated_at=_utc_now(),
                audit=self.audit,
            )
            finding.transition(
                FindingState.HYPOTHESIS,
                actor="triage",
                reason=f"规则映射 {signal.kind}→{vuln_type}",
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            created += 1
            findings.append(finding)
        self.audit.record(
            "triage_completed",
            signals=len(signals),
            mapped=created + merged,
            created=created,
            merged=merged,
            kept_signal=len(signals) - created - merged,
            skipped_lines=skipped,
        )
        return findings

    def _load_phase_signals(self) -> tuple[list[Signal], int]:
        """加载 evidence_dir 下全部 *.signals.jsonl（坏行跳过并计数）。"""
        signals: list[Signal] = []
        skipped = 0
        for path in sorted(self.evidence_dir.glob("*.signals.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    signals.append(Signal.model_validate(json.loads(line)))
                except ValidationError:
                    skipped += 1
        return signals, skipped

    # ---- 子任务主循环 ----

    def _run_subtask(self, node: TaskNode, skill) -> None:
        node.transition(TaskStatus.RUNNING, reason="子任务启动")
        while True:
            state = {
                "target": node.meta["target"],
                "attempts": node.attempts,
                "failure_counts": dict(node.failure_counts),
                "signals": node.meta.get("signals", []),
            }
            try:
                plan = self.planner.plan(state, skill)
            except BudgetExceededError as exc:
                # token 预算硬闸：停止规划循环、节点 blocked（与 scope 同级不可绕过）
                self.audit.record(
                    "llm_budget_exceeded",
                    node_id=node.id,
                    name=node.name,
                    tier=exc.tier,
                    used=exc.used,
                    limit=exc.limit,
                    scope=exc.scope,
                )
                node.transition(TaskStatus.BLOCKED, reason=f"LLM 预算硬闸: {exc}")
                return
            except ContextOverflowError as exc:
                # 上下文超硬上限（压缩后仍超）：failed，禁止静默截断
                self.audit.record(
                    "context_overflow",
                    node_id=node.id,
                    name=node.name,
                    chars=exc.chars,
                    limit=exc.limit,
                )
                node.transition(TaskStatus.FAILED, reason=f"上下文超限: {exc}")
                return
            except (PlanValidationError, LLMError) as exc:
                node.transition(TaskStatus.FAILED, reason=f"规划失败: {exc}")
                return
            outcome = "ok"
            for action in plan.actions:
                if action.action == "finish":
                    node.transition(
                        TaskStatus.DONE, reason=action.rationale or "规划器判定完成"
                    )
                    return
                if action.action == "escalate":
                    reason = action.rationale or "规划器升级人工"
                    self.audit.record(
                        "task_blocked", node_id=node.id, name=node.name, reason=reason
                    )
                    node.transition(TaskStatus.BLOCKED, reason=reason)
                    return
                outcome = self._exec_run_tool(node, action, skill)
                if outcome != "ok":
                    break
            if outcome == "ok":
                node.transition(TaskStatus.DONE, reason="计划动作全部完成")
                return
            if outcome == "retry":
                continue  # 带着失败计数重新规划
            return  # failed / blocked 已在 _exec_run_tool 完成迁移

    # ---- 单动作执行 ----

    def _exec_run_tool(self, node: TaskNode, action: PlanAction, skill) -> str:
        """执行 run_tool 动作，返回 ok/retry/failed/blocked。"""
        try:
            argv = build_command(
                action.tool,
                action.params,
                egress_proxy_url=self.runner.egress_proxy_url,
            )
        except (UnknownToolError, ValidationError) as exc:
            node.transition(TaskStatus.FAILED, reason=f"命令构造失败（规划缺陷）: {exc}")
            return "failed"

        node.attempts += 1
        result = self.runner.run(argv[0], argv[1:])

        if result.rejected:
            node.transition(
                TaskStatus.FAILED,
                reason=f"scope 拒绝（规划缺陷）: {'; '.join(result.violations)}",
            )
            return "failed"
        if result.exit_code == 0:
            self._record_signals(node, action, skill, result)
            return "ok"

        category = classify(self._sample_output(result))
        exhausted = self.budget.record(node, category)
        self.audit.record(
            "attempt_failed",
            node_id=node.id,
            tool=action.tool,
            exit_code=result.exit_code,
            category=category.value,
            count=node.failure_counts[category.value],
            budget_limit=self.budget.limit_per_category,
        )
        if exhausted:
            reason = f"失败预算耗尽（{category.value} × {node.failure_counts[category.value]}），升级人工"
            self.audit.record(
                "task_blocked",
                node_id=node.id,
                name=node.name,
                category=category.value,
                count=node.failure_counts[category.value],
                reason=reason,
            )
            node.transition(TaskStatus.BLOCKED, reason=reason)
            return "blocked"
        return "retry"

    # ---- Signal 落盘 ----

    def _record_signals(
        self, node: TaskNode, action: PlanAction, skill, result: RunResult
    ) -> None:
        parser = self.parsers.get(action.tool)
        if parser is None:
            self.audit.record(
                "signals_recorded",
                node_id=node.id,
                tool=action.tool,
                count=0,
                note=f"工具 {action.tool} 无解析器",
            )
            return
        text = result.stdout_path.read_text(encoding="utf-8", errors="replace")
        signals, skipped = parser(
            text, evidence_path=str(result.stdout_path), skill=skill.name
        )
        signals_path = self.evidence_dir / f"{result.stdout_path.stem}.signals.jsonl"
        with signals_path.open("w", encoding="utf-8") as fh:
            for signal in signals:
                fh.write(signal.model_dump_json() + "\n")
        node.meta.setdefault("signals", []).extend(
            {
                "asset": s.asset,
                "status_code": s.status_code,
                "kind": s.kind,
                "evidence_ref": s.evidence_ref,
            }
            for s in signals
        )
        self.audit.record(
            "signals_recorded",
            node_id=node.id,
            tool=action.tool,
            count=len(signals),
            skipped_lines=skipped,
            signals_path=str(signals_path),
        )

    @staticmethod
    def _sample_output(result: RunResult) -> str:
        """取 stdout/stderr 尾部采样用于失败分类（有界，不进 LLM 上下文）。"""
        chunks = []
        for path in (result.stderr_path, result.stdout_path):
            if path and Path(path).is_file():
                chunks.append(
                    Path(path)
                    .read_bytes()[-_OUTPUT_SAMPLE_LIMIT:]
                    .decode("utf-8", errors="replace")
                )
        return "\n".join(chunks)
