"""最小编排器（M2b+M2c+M3a，§5.3）：scan 阶段链路的驱动者。

链路：registry 命中 skill → 规划器产计划（结构化 JSON，强校验）→
tools/build.py 拼装 argv（红线 1：LLM 不碰命令）→ SandboxRunner 执行
（红线 5：scope 强校验不变）→ 解析器产 Signal 落盘 → 全程审计。

- 阶段间串行、阶段内子任务并行（run_dag）；M2b 仅实现 scan 阶段；
  M3a 增加确定性 triage 阶段（run_triage_phase，规则表、零 LLM 调用）；
  M3b 增加确定性 verify 阶段（run_verify_phase：带会话 baseline → sqlmap
  行为确认 → 证据门 → Verifier T2 终审 → CONFIRMED/REJECTED，唯一 LLM
  调用是 Verifier 终审）；M3d 扩展 triage：katana 爬参 Signal
  （param-endpoint）按 query 参数键启发式展开 sqli 候选（上限 20 条防
  确认洪泛 + 建/并前 check_scope 第三层纵深）；
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
from typing import NamedTuple
from urllib.parse import parse_qsl, urlparse

from pydantic import ValidationError

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import check_scope
from proofhound.compliance.session import SessionConfig, secret_marker
from proofhound.findings.dedup import compute_dedup_key
from proofhound.findings.evidence import assemble_evidence_pack
from proofhound.findings.finding import (
    STATUS_CODE_EVIDENCE_KIND,
    Finding,
    FindingState,
    FindingStore,
    IronRuleViolationError,
    Verification,
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
from proofhound.llm.router import ensure_router
from proofhound.llm.usage import BudgetExceededError
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.build import UnknownToolError, build_command, known_tools
from proofhound.tools.manifest import load_manifest
from proofhound.tools.parsers import PARSER_REGISTRY, parse_sqlmap_stdout
from proofhound.tools.sandbox import RunResult, SandboxRunner
from proofhound.verify.gate import BEHAVIORAL_EVIDENCE_KIND
from proofhound.verify.gate import check as gate_check
from proofhound.verify.verifier import Verifier, VerifierError

_OUTPUT_SAMPLE_LIMIT = 4096  # 失败分类的输出采样上限（字节）

# 确定性 triage 规则表（M3a）：web-probe 存活状态 → web-exposure 假设。
# 与 web-scan SKILL.md"存活"判定一致（2xx/3xx/401/403）；LLM triage 留后续切片。
_EXPOSED_STATUSES = frozenset({200, 201, 204, 301, 302, 307, 308, 401, 403})

# M3d：katana 爬参（kind="param-endpoint"）→ sqli 假设的参数键启发式。
# 精确匹配（键小写比对）：宁可漏报（保持 Signal）不可滥建——每条 sqli
# Hypothesis 都会在 verify 阶段消耗一次 L2 确认与一次行为验证。
_SQLI_PARAM_HINTS = frozenset(
    {
        "id", "uid", "user", "username", "page", "file", "include", "cat",
        "category", "search", "q", "query", "name", "order", "sort", "dir",
        "path", "item", "view", "pid",
    }
)

# M3d：每 engagement 新建 sqli Hypothesis 上限（防确认洪泛，超出记 triage_capped）
_TRIAGE_SQLI_CAP = 20

# param-endpoint 候选的证据种类标签（爬行发现的带参端点，非行为证据）
CRAWL_ENDPOINT_EVIDENCE_KIND = "crawl-endpoint"


class _TriageCandidate(NamedTuple):
    """一条 triage 候选；一个 Signal 可展开多条（param-endpoint 按参数键）。"""

    vuln_type: str
    param: str | None
    severity: str
    evidence_kind: str


def _query_param_keys(url: str) -> list[str]:
    """从 URL query 展开参数键（保序去重、小写化；空值键保留）。"""
    keys: list[str] = []
    for key, _value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        key = key.strip().lower()
        if key and key not in keys:
            keys.append(key)
    return keys


def _triage_candidates(signal: Signal) -> list[_TriageCandidate]:
    """triage 规则映射：可映射返回候选列表，不可映射返回空（保持 Signal）。"""
    if signal.kind == "web-probe" and signal.status_code in _EXPOSED_STATUSES:
        return [
            _TriageCandidate(
                vuln_type="web-exposure",
                param=None,
                severity="info",
                evidence_kind=STATUS_CODE_EVIDENCE_KIND,
            )
        ]
    if signal.kind == "param-endpoint":
        return [
            _TriageCandidate(
                vuln_type="sqli",
                param=key,
                severity="medium",
                evidence_kind=CRAWL_ENDPOINT_EVIDENCE_KIND,
            )
            for key in _query_param_keys(signal.asset)
            if key in _SQLI_PARAM_HINTS
        ]
    return []


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


def _default_tool_images() -> dict:
    """工具名 → 沙箱镜像覆盖（M3b）：由打包 manifests 的 image 字段聚合。"""
    manifests_dir = Path(__file__).parent.parent / "tools" / "manifests"
    mapping = {}
    for path in sorted(manifests_dir.glob("*.yaml")):
        manifest = load_manifest(path)
        if manifest.image:
            mapping[manifest.name] = manifest.image
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
        tool_images: dict | None = None,
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
        self.router = ensure_router(llm)  # M3b：Verifier 走 T2 档复用同一路由
        self.tool_images = (
            tool_images if tool_images is not None else _default_tool_images()
        )
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

        M3d：param-endpoint Signal 按 query 参数键展开 sqli 候选（启发式
        键名精确匹配 + 每 engagement 新建上限 ``_TRIAGE_SQLI_CAP`` 条防确认
        洪泛，超出记 ``triage_capped``）；建/并 Hypothesis 前对 asset 过
        check_scope（三层纵深第二层；runner 未挂 scope 时本层不触发，沙箱
        层仍是最终强校验），越界丢弃记 ``triage_out_of_scope``。
        """
        store = FindingStore(self.evidence_dir / "findings.jsonl")
        signals, skipped = self._load_phase_signals()
        scope = getattr(self.runner, "scope", None)
        sqli_existing = sum(1 for f in store.load_all() if f.vuln_type == "sqli")
        findings: list[Finding] = []
        created = merged = kept = capped = 0
        created_by_type: dict[str, int] = {}
        merged_by_type: dict[str, int] = {}
        for signal in signals:
            candidates = _triage_candidates(signal)
            if not candidates:
                kept += 1
                continue
            if scope is not None:
                decision = check_scope(scope, [signal.asset])
                if not decision.allowed:
                    self.audit.record(
                        "triage_out_of_scope",
                        asset=signal.asset,
                        kind=signal.kind,
                        violations=decision.violations,
                    )
                    kept += 1
                    continue
            signal_mapped = False
            for cand in candidates:
                dedup_key = compute_dedup_key(signal.asset, cand.vuln_type, cand.param)
                existing = store.get_by_dedup_key(dedup_key)
                if existing is not None:
                    if signal.evidence_ref in existing.source_signal_refs:
                        continue  # 幂等：该证据已归并过
                    existing.source_signal_refs.append(signal.evidence_ref)
                    if cand.evidence_kind not in existing.evidence_kinds:
                        existing.evidence_kinds.append(cand.evidence_kind)
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
                    merged_by_type[cand.vuln_type] = (
                        merged_by_type.get(cand.vuln_type, 0) + 1
                    )
                    signal_mapped = True
                    findings.append(existing)
                    continue
                if cand.vuln_type == "sqli" and sqli_existing >= _TRIAGE_SQLI_CAP:
                    capped += 1  # 防确认洪泛：每 engagement sqli 新建上限
                    continue
                finding = Finding(
                    id=store.next_id(),
                    state=FindingState.SIGNAL,
                    vuln_type=cand.vuln_type,
                    severity=cand.severity,
                    asset=signal.asset,
                    param=cand.param,
                    confidence="low",
                    evidence_kinds=[cand.evidence_kind],
                    dedup_key=dedup_key,
                    source_signal_refs=[signal.evidence_ref],
                    created_at=_utc_now(),
                    updated_at=_utc_now(),
                    audit=self.audit,
                )
                finding.transition(
                    FindingState.HYPOTHESIS,
                    actor="triage",
                    reason=f"规则映射 {signal.kind}→{cand.vuln_type}",
                )
                store.append(finding)
                assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
                created += 1
                created_by_type[cand.vuln_type] = (
                    created_by_type.get(cand.vuln_type, 0) + 1
                )
                if cand.vuln_type == "sqli":
                    sqli_existing += 1
                signal_mapped = True
                findings.append(finding)
            if not signal_mapped:
                kept += 1
        if capped:
            self.audit.record(
                "triage_capped",
                vuln_type="sqli",
                limit=_TRIAGE_SQLI_CAP,
                dropped=capped,
            )
        self.audit.record(
            "triage_completed",
            signals=len(signals),
            mapped=created + merged,
            created=created,
            merged=merged,
            kept_signal=kept,
            skipped_lines=skipped,
            created_by_type=created_by_type,
            merged_by_type=merged_by_type,
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

    # ---- verify 阶段（M3b，确定性编排：无 planner、无 LLM 规划） ----

    def _verify_handlers(self) -> dict:
        """verify skill 名 → (覆盖的 vuln_type 集合, 处理函数)。"""
        return {"verify-sqli": (frozenset({"sqli"}), self._verify_sqli)}

    def verify_skill_coverage(self, skill_name: str = "verify-sqli") -> frozenset[str]:
        """verify skill 覆盖的 vuln_type 集合（M5a：API 自主模式闸门按此
        圈定待确认的 Hypothesis Finding）。"""
        handlers = self._verify_handlers()
        if skill_name not in handlers:
            raise KeyError(f"skill 无 verify handler: {skill_name}")
        return handlers[skill_name][0]

    def run_verify_phase(self, *, skill_name: str = "verify-sqli") -> list[Finding]:
        """跑 verify 阶段：对 Hypothesis 做行为验证 + 证据门 + Verifier 终审。

        Confirmed 迁移条件（三者缺一不得确认，§5.4.2/§5.4.4）：
        行为证据存在（evidence_kinds 含 behavioral）∧ 证据门通过 ∧
        Verifier confirm；状态机铁律在 ``transition`` 层兜底（双层防守）。
        无 handler 的 Hypothesis 记 ``verify_skipped`` 跳过；返回实际处理的
        Finding 列表。
        """
        skill = self.registry.get(skill_name)
        if skill is None:
            raise KeyError(f"未注册的 skill: {skill_name}")
        if not skill.enabled:
            raise PermissionError(f"skill 未启用: {skill_name}")
        handlers = self._verify_handlers()
        if skill_name not in handlers:
            raise KeyError(f"skill 无 verify handler: {skill_name}")
        vuln_types, handler = handlers[skill_name]

        store = FindingStore(self.evidence_dir / "findings.jsonl")
        counts = {"confirmed": 0, "rejected": 0, "blocked": 0, "skipped": 0}
        processed: list[Finding] = []
        for finding in store.load_all():
            if finding.state is not FindingState.HYPOTHESIS:
                continue
            if finding.vuln_type not in vuln_types:
                self.audit.record(
                    "verify_skipped",
                    finding_id=finding.id,
                    vuln_type=finding.vuln_type,
                    reason=f"skill {skill_name} 不覆盖该漏洞类型",
                )
                counts["skipped"] += 1
                continue
            finding.audit = self.audit  # store 回放出的 Finding 无审计句柄
            outcome = handler(finding, skill, store)
            counts[outcome] += 1
            processed.append(finding)
        self.audit.record(
            "verify_completed",
            skill=skill_name,
            processed=len(processed),
            **counts,
        )
        return processed

    def _verify_sqli(self, finding: Finding, skill, store: FindingStore) -> str:
        """verify-sqli SOP（skills/verify-sqli/SKILL.md）的确定性执行。

        返回 confirmed/rejected/blocked；blocked = 证据不足以外的一切
        未完成形态（Finding 停留原态，fail-closed）。
        """
        session = self._session()
        if session is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="scope 未配置预置会话（session），无法进行带认证验证",
            )
            return "blocked"

        # 1. 带会话 baseline（不跟随跳转：未认证会被 302 到登录页，2xx 才算数）
        baseline = self._run_baseline(finding, session)
        if baseline is None:
            return "blocked"  # 审计已在 _run_baseline 内记录
        baseline_ref, baseline_status = baseline

        # 2. sqlmap 行为确认（沙箱内执行，scope 强校验不变）
        try:
            argv = build_command(
                "sqlmap",
                {
                    "url": finding.asset,
                    "param": finding.param,
                    "with_session": True,
                    "level": 1,
                    "risk": 1,
                },
                egress_proxy_url=getattr(self.runner, "egress_proxy_url", None),
                session=session,
            )
        except ValueError as exc:
            self.audit.record(
                "verify_blocked", finding_id=finding.id, reason=f"命令构造失败: {exc}"
            )
            return "blocked"
        result = self.runner.run(
            argv[0],
            argv[1:],
            timeout=600,
            image=self.tool_images.get("sqlmap"),
        )
        if result.rejected:
            self.audit.record(
                "verify_scope_rejected",
                finding_id=finding.id,
                violations=result.violations,
            )
            return "blocked"
        if result.exit_code != 0:
            self.audit.record(
                "verify_tool_failed",
                finding_id=finding.id,
                tool="sqlmap",
                exit_code=result.exit_code,
                stderr_path=str(result.stderr_path),
            )
            return "blocked"

        # 3. 解析验证结论：未确认 → Rejected（验证失败，§5.4.1 状态机）
        text = result.stdout_path.read_text(encoding="utf-8", errors="replace")
        report = parse_sqlmap_stdout(text)
        sqlmap_ref = f"{result.stdout_path}#L{report.anchor_line or 1}"
        if not report.confirmed:
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason=f"sqlmap 未确认注入：{report.note or '无注入点'}",
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 4. 证据入包：behavioral 标签 + method + 复现步骤（凭据只记 sha256 标记）
        techniques = "；".join(
            f"{t.type}（{t.title}）" if t.title else t.type for t in report.techniques
        )
        cookie_mark = secret_marker(session.cookie_header())
        finding.verification = Verification(
            method="sqlmap-confirmed",
            evidence_refs=[baseline_ref, sqlmap_ref],
            baseline_diff=(
                f"带会话 baseline {baseline_status}（认证有效，非登录跳转）；"
                f"sqlmap 确认参数 {report.parameter}（{report.param_kind}）注入："
                f"{techniques}；共 {report.requests_total or '未知'} 次 HTTP 请求"
            ),
            reproduction_steps=[
                f"以预置会话（Cookie {cookie_mark}）GET {finding.asset} "
                f"→ baseline {baseline_status}（认证有效）",
                f"沙箱内执行 sqlmap -u '{finding.asset}' --cookie '{cookie_mark}' "
                f"-p {report.parameter} --level 1 --risk 1 --batch",
                f"sqlmap 判定注入点：Parameter {report.parameter} "
                f"（{report.param_kind}）；技术：{techniques}",
                f"复现 payload 示例：{report.techniques[0].payload}",
            ],
            verified_by=f"{skill.name}@{skill.manifest.version}",
            verified_at=_utc_now(),
        )
        if BEHAVIORAL_EVIDENCE_KIND not in finding.evidence_kinds:
            finding.evidence_kinds.append(BEHAVIORAL_EVIDENCE_KIND)
        finding.transition(
            FindingState.REPRODUCED,
            actor=skill.name,
            reason=f"sqlmap 确认注入（{report.parameter}，{len(report.techniques)} 种技术）",
        )
        store.append(finding)

        # 5. 证据门（§5.4.2）：Confirmed 前必过；不过停于 Reproduced
        gate_result = gate_check(finding)
        if not gate_result.passed:
            self.audit.record(
                "verify_gate_failed",
                finding_id=finding.id,
                missing=gate_result.missing,
            )
            return "blocked"

        # 6. Verifier 终审（T2，对抗校验；失败 fail-closed 停于 Reproduced）
        pack_dir = assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
        manifest = json.loads((pack_dir / "manifest.json").read_text(encoding="utf-8"))
        verifier = Verifier(
            self.router, self.audit, context_policy=self.planner.context_policy
        )
        try:
            verdict = verifier.review(
                finding,
                evidence_index=manifest.get("items", []),
                diff_summary=finding.verification.baseline_diff,
            )
        except (VerifierError, LLMError, BudgetExceededError, ContextOverflowError) as exc:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=f"Verifier 未完成（fail-closed）: {exc}",
            )
            return "blocked"

        # 7. 终审裁定 → 终态迁移（铁律在状态机层兜底，双层防守）
        if verdict.verdict == "confirm":
            try:
                finding.transition(
                    FindingState.CONFIRMED, actor="verifier", reason=verdict.reason
                )
            except IronRuleViolationError as exc:
                self.audit.record(
                    "verify_iron_rule_blocked", finding_id=finding.id, reason=str(exc)
                )
                return "blocked"
            outcome = "confirmed"
        else:
            finding.transition(
                FindingState.REJECTED, actor="verifier", reason=verdict.reason
            )
            outcome = "rejected"
        store.append(finding)
        assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
        return outcome

    def _run_baseline(
        self, finding: Finding, session: SessionConfig
    ) -> tuple[str, int] | None:
        """带会话 baseline：httpx 探目标 URL（不跟随跳转），返回
        ``(evidence_ref, status_code)``；失败记审计并返回 None。"""
        try:
            argv = build_command(
                "httpx",
                {
                    "target": finding.asset,
                    "with_session": True,
                    "follow_redirects": False,
                    "tech_detect": False,
                },
                egress_proxy_url=getattr(self.runner, "egress_proxy_url", None),
                session=session,
            )
        except ValueError as exc:
            self.audit.record(
                "verify_blocked", finding_id=finding.id, reason=f"命令构造失败: {exc}"
            )
            return None
        result = self.runner.run(argv[0], argv[1:])
        if result.rejected:
            self.audit.record(
                "verify_scope_rejected",
                finding_id=finding.id,
                violations=result.violations,
            )
            return None
        if result.exit_code != 0:
            self.audit.record(
                "verify_baseline_failed",
                finding_id=finding.id,
                reason=f"httpx exit={result.exit_code}",
                stderr_path=str(result.stderr_path),
            )
            return None
        parser = self.parsers.get("httpx")
        text = result.stdout_path.read_text(encoding="utf-8", errors="replace")
        signals, _ = parser(text, evidence_path=str(result.stdout_path), skill="verify")
        for signal in signals:
            if signal.status_code is not None and 200 <= signal.status_code < 300:
                return signal.evidence_ref, signal.status_code
        statuses = [s.status_code for s in signals]
        self.audit.record(
            "verify_baseline_failed",
            finding_id=finding.id,
            reason=f"带会话请求未获 2xx（疑似会话失效或登录跳转）: {statuses}",
        )
        return None

    def _session(self) -> SessionConfig | None:
        """当前 engagement 的预置会话（来自 scope 配置；无则 None）。"""
        scope = getattr(self.runner, "scope", None)
        return getattr(scope, "session", None) if scope is not None else None

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
                session=self._session(),
            )
        except (UnknownToolError, ValueError) as exc:
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
