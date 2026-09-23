"""后台任务执行器（M5a，§5.9）：一个 engagement 一条后台线程 + 确认队列。

- 状态机：``created → scanning → triaging → verifying → confirming（可往返）
  → done/failed``，全部迁移写审计事件 ``engagement_state``；
- 阶段复用编排器现成的 ``run_scan_phase / run_triage_phase /
  run_verify_phase``——**本层只是编排器的薄壳**：不含任何命令构造/scope
  绕过逻辑，所有命令仍走 ``tools/build.py`` + ScopeEnforcer（红线 1/5）；
- 自主模式闸门（``proofhound/autonomy.py``）：scan/verify 动作按 risk_level
  过闸；``confirm`` 裁定进确认队列阻塞等待（带超时，超时默认拒绝并写审计）；
- 确认队列：内存态 + engagement 目录 ``confirmations.jsonl`` 追加持久化，
  重启可恢复——重建 app 后待确认队列仍在，已批准的裁定随文件存活可复用；
- 线程安全：engagement 状态读写走锁；审计沿用 append-only JSONL 单行追加
  （与编排器 run_dag 线程池同一纪律）；
- **不可旁路**：任何自治模式下 scope 校验、token 预算硬闸、cookie 脱敏、
  审计追加永远生效（见 autonomy.py 模块 docstring 声明）。
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from proofhound.autonomy import AutonomyGate, AutonomyMode, GateDecision
from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope, check_scope
from proofhound.compliance.session import SessionConfig
from proofhound.findings.evidence import assemble_evidence_pack
from proofhound.findings.finding import FindingState, FindingStore
from proofhound.llm.usage import BudgetExceededError


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ---- 领域错误（server.py 翻译成 HTTP 响应） ----


class ApiError(RuntimeError):
    """API 领域错误基类：携带 HTTP 状态码与统一 error code。"""

    status_code = 500
    error_code = "internal"

    def __init__(self, message: str):
        super().__init__(message)


class NotFoundError(ApiError):
    status_code = 404
    error_code = "not_found"


class InvalidStateError(ApiError):
    status_code = 409
    error_code = "invalid_state"


class ScopeViolationError(ApiError):
    status_code = 403
    error_code = "scope_violation"


class BudgetBlockedError(ApiError):
    """预算硬闸（与 llm.usage.BudgetExceededError 区分：这是 API 入口预检）。"""

    status_code = 402
    error_code = "budget_exceeded"


# ---- engagement 状态机 ----


class EngagementState(str, Enum):
    """created → scanning → triaging → verifying → confirming（可往返）→ done/failed。"""

    CREATED = "created"
    SCANNING = "scanning"
    TRIAGING = "triaging"
    VERIFYING = "verifying"
    CONFIRMING = "confirming"  # 等待人工确认中（可往返：裁定后回到原阶段态）
    DONE = "done"
    FAILED = "failed"


_TERMINAL = frozenset({EngagementState.DONE, EngagementState.FAILED})


# ---- 确认队列（内存态 + confirmations.jsonl 追加持久化，重启可恢复） ----


@dataclass
class Confirmation:
    """一个待人工确认的动作（L1/L2，由自主模式闸门产出）。"""

    cid: str
    engagement_id: str
    action: str  # skill 名（web-scan / verify-sqli ...）
    risk_level: str  # L1 / L2
    summary: str  # 人类可读动作说明
    status: str = "pending"  # pending / approved / rejected
    target: str | None = None
    finding_id: str | None = None
    operator: str | None = None
    note: str = ""
    created_at: str = ""
    decided_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "cid": self.cid,
            "engagement_id": self.engagement_id,
            "action": self.action,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "status": self.status,
            "target": self.target,
            "finding_id": self.finding_id,
            "operator": self.operator,
            "note": self.note,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
        }


class ConfirmationStore:
    """``confirmations.jsonl`` 的 append-only 存取：快照追加 + last-wins 回放。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _append(self, conf: Confirmation) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(conf.to_dict(), ensure_ascii=False) + "\n")

    def load_all(self) -> list[Confirmation]:
        """回放全部快照：同 cid 后者覆盖前者，保持首见顺序。"""
        confs: dict[str, Confirmation] = {}
        if not self.path.exists():
            return []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            data = json.loads(line)
            confs[data["cid"]] = Confirmation(**data)
        return list(confs.values())

    def get(self, cid: str) -> Confirmation | None:
        for conf in self.load_all():
            if conf.cid == cid:
                return conf
        return None

    def list_pending(self) -> list[Confirmation]:
        return [c for c in self.load_all() if c.status == "pending"]

    def find(
        self,
        *,
        action: str,
        target: str | None = None,
        finding_id: str | None = None,
    ) -> Confirmation | None:
        """找同一动作的最新一条确认记录（重启恢复：复用既有裁定）。"""
        match = None
        for conf in self.load_all():
            if (
                conf.action == action
                and conf.target == target
                and conf.finding_id == finding_id
            ):
                match = conf
        return match

    def create(
        self,
        *,
        engagement_id: str,
        action: str,
        risk_level: str,
        summary: str,
        target: str | None = None,
        finding_id: str | None = None,
    ) -> Confirmation:
        conf = Confirmation(
            cid=f"c-{uuid.uuid4().hex[:8]}",
            engagement_id=engagement_id,
            action=action,
            risk_level=risk_level,
            summary=summary,
            target=target,
            finding_id=finding_id,
            created_at=_utc_now(),
        )
        self._append(conf)
        return conf

    def decide(
        self,
        cid: str,
        *,
        approved: bool,
        operator: str,
        note: str = "",
    ) -> Confirmation | None:
        """裁定一个待确认动作（追加快照）；cid 不存在返回 None。"""
        conf = self.get(cid)
        if conf is None:
            return None
        conf.status = "approved" if approved else "rejected"
        conf.operator = operator
        conf.note = note
        conf.decided_at = _utc_now()
        self._append(conf)
        return conf


# ---- engagement 记录（线程安全） ----


class Engagement:
    """一个 engagement 的运行期记录；元数据持久化在 ``api.json``。"""

    def __init__(self, manager: "EngagementManager", directory: Path, meta: dict):
        self._manager = manager
        self.dir = directory
        self.id: str = meta["id"]
        self.target: str = meta["target"]
        self.scope_paths: list[str] = list(meta["scope_paths"])
        # M9a：从目标派生的授权范围（落盘于 api.json）；无派生时为 None。
        self.derived_scope: dict | None = meta.get("derived_scope")
        self.budget: int | None = meta.get("budget")
        self.created_at: str = meta["created_at"]
        self.with_session: bool = bool(meta.get("with_session"))
        # M8c：第二身份会话（reference/victim）是否配置（值永不进响应体）
        self.with_reference_session: bool = bool(meta.get("with_reference_session"))
        self._mode = AutonomyMode(meta["autonomy_mode"])
        self._state = EngagementState(meta["state"])
        self._lock = threading.RLock()
        self.thread: threading.Thread | None = None
        self.audit = AuditLog(self.dir / "audit.jsonl")

    @property
    def state(self) -> EngagementState:
        with self._lock:
            return self._state

    def current_mode(self) -> AutonomyMode:
        with self._lock:
            return self._mode

    def set_mode(self, mode: AutonomyMode) -> None:
        with self._lock:
            self._mode = AutonomyMode(mode)
            self._persist()

    def transition(self, to: EngagementState, *, reason: str = "") -> None:
        with self._lock:
            old = self._state
            self._state = to
            self._persist()
        self.audit.record(
            "engagement_state",
            engagement_id=self.id,
            **{"from": old.value, "to": to.value, "reason": reason},
        )

    @property
    def running(self) -> bool:
        with self._lock:
            return self.thread is not None and self.thread.is_alive()

    def _persist(self) -> None:
        """把当前元数据重写进 api.json（元数据文件，非审计；审计在 audit.jsonl）。"""
        meta = {
            "id": self.id,
            "target": self.target,
            "scope_paths": self.scope_paths,
            "autonomy_mode": self._mode.value,
            "budget": self.budget,
            "state": self._state.value,
            "created_at": self.created_at,
            "with_session": self.with_session,
            "with_reference_session": self.with_reference_session,
        }
        if self.derived_scope is not None:
            # M9a：派生范围必须随之持久化——否则每次状态迁移写回都会把它抹掉，
            # start() 重校验时读到空 scope，授权范围静默消失（= 拒绝一切）。
            meta["derived_scope"] = self.derived_scope
        (self.dir / "api.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


# ---- 执行期上下文（phases_factory 的入参） ----


@dataclass
class EngagementRuntime:
    """一次 run 的执行期上下文：真实/伪造阶段执行器都以此接线。"""

    manager: "EngagementManager"
    engagement: Engagement
    scope: Scope  # 已从 scope_paths 重新加载并过 check_scope；session 已挂
    audit: AuditLog
    confirmations: ConfirmationStore

    @property
    def workspace_root(self) -> Path:
        return self.manager.workspace_root

    @property
    def env_file(self) -> Path:
        return self.manager.env_file


# ---- 后台执行器 ----


class EngagementRunner:
    """一个 engagement 的后台线程：阶段驱动 + 自主模式闸门 + 确认队列。"""

    def __init__(
        self,
        runtime: EngagementRuntime,
        phases_factory,
        confirm_timeout: float,
    ):
        self.rt = runtime
        self.phases_factory = phases_factory
        self.confirm_timeout = confirm_timeout

    # ---- 主流程 ----

    def run(self) -> None:
        eng = self.rt.engagement
        try:
            phases = self.phases_factory(self.rt)
        except Exception as exc:
            self.rt.audit.record(
                "engagement_failed", error=f"执行环境构建失败: {exc}"[:500]
            )
            eng.transition(EngagementState.FAILED, reason=f"执行环境构建失败: {exc}"[:200])
            self._finish_meta()
            return
        try:
            self._scan(phases)
            self._triage(phases)
            self._verify(phases)
            eng.transition(EngagementState.DONE, reason="全部阶段完成")
        except BudgetExceededError as exc:
            # token 预算硬闸：任何自治模式不可绕过（与 scope 同级）
            self.rt.audit.record(
                "llm_budget_exceeded",
                tier=exc.tier,
                used=exc.used,
                limit=exc.limit,
                scope=exc.scope,
            )
            eng.transition(EngagementState.FAILED, reason=f"预算硬闸: {exc}"[:200])
        except Exception as exc:  # fail-closed：engagement 失败但审计完整
            self.rt.audit.record("engagement_failed", error=str(exc)[:500])
            eng.transition(EngagementState.FAILED, reason=str(exc)[:200])
        finally:
            self._finish_meta()

    def _scan(self, phases) -> None:
        eng = self.rt.engagement
        eng.transition(EngagementState.SCANNING, reason="scan 阶段启动")
        # M3d：多 scan skill（web-scan + recon-crawl）逐 skill 过闸，确认/审计
        # 粒度到 skill；无 scan_skills 属性的旧式 phases（FakePhases 等）
        # 回退单 skill 接口，行为与 M5a 一致。
        scan_skills = getattr(phases, "scan_skills", None)
        legacy = scan_skills is None
        if legacy:
            scan_skills = [(phases.scan_skill, phases.scan_risk_level)]
        for skill_name, risk_level in scan_skills:
            approved = [
                target
                for target in [eng.target]
                if self._gate(
                    skill_name,
                    risk_level,
                    target=target,
                    summary=f"{skill_name} 扫描目标 {target}",
                    resume_state=EngagementState.SCANNING,
                    mutating=_skill_mutating(phases, skill_name),
                )
                in ("auto", "approved")
            ]
            if approved:
                if legacy:
                    phases.scan(approved)
                else:
                    phases.scan_with_skill(skill_name, approved)
            else:
                self.rt.audit.record(
                    "phase_skipped",
                    phase="scan" if legacy else f"scan:{skill_name}",
                    reason="全部目标被拒绝或未授权",
                )

    def _triage(self, phases) -> None:
        self.rt.engagement.transition(EngagementState.TRIAGING, reason="triage 阶段启动")
        phases.triage()

    def _verify(self, phases) -> None:
        eng = self.rt.engagement
        eng.transition(EngagementState.VERIFYING, reason="verify 阶段启动")
        store = FindingStore(eng.dir / "findings.jsonl")
        # M8b：多 verify skill（verify-sqli + verify-xss）逐 skill 过闸，确认/
        # 审计粒度到 skill；无 verify_skills 属性的旧式 phases（FakePhases 等）
        # 回退单 skill 接口，行为与 M5a 一致（对齐 M3d scan_skills 先例）。
        verify_skills = getattr(phases, "verify_skills", None)
        legacy = verify_skills is None
        if legacy:
            verify_skills = [(phases.verify_skill, phases.verify_risk_level)]
        for skill_name, risk_level in verify_skills:
            covered = (
                phases.verify_covered_vuln_types()
                if legacy
                else phases.verify_covered_vuln_types(skill_name)
            )
            for finding in store.load_all():
                if finding.state is not FindingState.HYPOTHESIS:
                    continue
                if finding.vuln_type not in covered:
                    continue  # 该 verify skill 不覆盖：保持原态（编排器内记 verify_skipped）
                outcome = self._gate(
                    skill_name,
                    risk_level,
                    finding_id=finding.id,
                    summary=(
                        f"{skill_name} 行为验证 {finding.id}"
                        f"（{finding.vuln_type} {finding.asset}）"
                    ),
                    resume_state=EngagementState.VERIFYING,
                    mutating=_skill_mutating(phases, skill_name),
                )
                if outcome in ("auto", "approved"):
                    continue
                if outcome == "rejected":
                    # 拒绝（人工或超时）→ 对应 Hypothesis 终态 rejected（归报告
                    # rejected 桶）；归因取确认记录（operator/system + note）
                    conf = self.rt.confirmations.find(
                        action=skill_name, finding_id=finding.id
                    )
                    who = (conf.operator if conf else None) or "operator"
                    detail = f"（{conf.note}）" if conf and conf.note else ""
                    finding.audit = self.rt.audit
                    finding.transition(
                        FindingState.REJECTED,
                        actor=who,
                        reason=(
                            f"operator_rejected: {who} 拒绝执行 "
                            f"{skill_name}{detail}"
                        ),
                    )
                    store.append(finding)
                    assemble_evidence_pack(finding, evidence_base=eng.dir)
                # forbidden：fail-closed 停留 Hypothesis（审计已在 _gate 内记录）
            if legacy:
                phases.verify()
            else:
                phases.verify_with_skill(skill_name)

    # ---- 自主模式闸门 ----

    def _gate(
        self,
        action: str,
        risk_level: str,
        *,
        target: str | None = None,
        finding_id: str | None = None,
        summary: str,
        resume_state: EngagementState,
        mutating: bool = True,
    ) -> str:
        """过自主模式闸门，返回 auto/approved/rejected/forbidden。

        模式在每次判定时重读：运行中切换自治模式即时生效。

        M9c③：``mutating`` 来自发起该动作的 skill 的 manifest 声明（**缺省
        True = fail-closed**，调用方不声明即按写操作对待）。只在 semi_auto ×
        L2 上区分：只读验证（不改目标状态）可自动执行，写操作仍进确认队列。
        """
        gate = AutonomyGate(self.rt.engagement.current_mode(), self.rt.audit)
        decision = gate.decide(risk_level, mutating=mutating)
        if decision is GateDecision.AUTO and risk_level == "L2" and not mutating:
            # M9c③：只读验证被判 auto 是**细分级**的结果（而非模式本就全自动），
            # 落审计便于区分"为什么这次没人被问"。
            self.rt.audit.record(
                "action_read_only_auto",
                action=action,
                risk_level=risk_level,
                finding_id=finding_id,
                target=target,
                mode=self.rt.engagement.current_mode().value,
                reason="skill 声明 mutating=false（只读验证），且模式允许自动执行",
            )
        if decision is GateDecision.AUTO:
            return "auto"
        if decision is GateDecision.FORBIDDEN:
            self.rt.audit.record(
                "action_forbidden",
                action=action,
                risk_level=risk_level,
                target=target,
                finding_id=finding_id,
                reason="未知/未分级的风险等级（fail-closed）",
            )
            return "forbidden"

        # CONFIRM：先查既有记录（重启恢复——已批准的裁定随 confirmations.jsonl 存活）
        existing = self.rt.confirmations.find(
            action=action, target=target, finding_id=finding_id
        )
        if existing is not None and existing.status == "approved":
            self.rt.audit.record(
                "action_resumed",
                cid=existing.cid,
                action=action,
                finding_id=finding_id,
                target=target,
                note="重启后复用既有批准裁定",
            )
            return "approved"
        if existing is not None and existing.status != "pending":
            return "rejected"
        if existing is None:
            existing = self.rt.confirmations.create(
                engagement_id=self.rt.engagement.id,
                action=action,
                risk_level=risk_level,
                summary=summary,
                target=target,
                finding_id=finding_id,
            )
            self.rt.audit.record(
                "action_confirmation_requested",
                cid=existing.cid,
                action=action,
                risk_level=risk_level,
                target=target,
                finding_id=finding_id,
                summary=summary,
            )
        eng = self.rt.engagement
        eng.transition(
            EngagementState.CONFIRMING, reason=f"等待确认 {existing.cid}（{action}）"
        )
        outcome = self._wait(existing.cid)
        eng.transition(resume_state, reason=f"确认 {existing.cid} 裁定：{outcome}")
        return outcome

    def _wait(self, cid: str) -> str:
        """阻塞等待裁定（带超时；超时默认拒绝并写审计）。"""
        event = self.rt.manager.confirmation_event(cid)
        conf = self.rt.confirmations.get(cid)  # 注册后再查一次防竞态
        if conf is not None and conf.status == "pending":
            event.wait(self.confirm_timeout)
            conf = self.rt.confirmations.get(cid)
        self.rt.manager.release_confirmation_event(cid)
        if conf is not None and conf.status == "pending":
            # 超时：默认拒绝（fail-closed）
            self.rt.confirmations.decide(
                cid, approved=False, operator="system", note="确认超时自动拒绝"
            )
            self.rt.audit.record(
                "action_rejected",
                cid=cid,
                action=conf.action,
                risk_level=conf.risk_level,
                target=conf.target,
                finding_id=conf.finding_id,
                operator="system",
                note="确认超时自动拒绝",
            )
            return "rejected"
        if conf is not None and conf.status == "approved":
            return "approved"
        return "rejected"

    # ---- 报告元信息收尾 ----

    def _finish_meta(self) -> None:
        """终态时补 engagement.json 的 finished_at（报告时间窗数据源）。"""
        meta_path = self.rt.engagement.dir / "engagement.json"
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}
        meta["finished_at"] = _utc_now()
        meta_path.write_text(
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


# ---- 真实阶段执行器：编排器的薄壳（红线自查：本层不做命令构造） ----


class OrchestratorPhases:
    """把 ``Orchestrator`` 包装成 EngagementRunner 的阶段接口。

    M3d：``scan_skills`` 暴露多 scan skill 清单（web-scan + recon-crawl），
    供 EngagementRunner 逐 skill 过闸；recon-crawl 未注册/未启用则跳过并记
    审计（爬行扫描是增强项，缺失不阻塞主链路）。

    M8b：``verify_skills`` 暴露多 verify skill 清单（verify-sqli +
    verify-xss），供 EngagementRunner 逐 skill 过闸（沿用 scan_skills 的
    getattr 回退先例）；verify-xss 未注册/未启用则跳过并记审计
    ``verify_skill_skipped``（XSS 浏览器验证是增强项，缺失不阻塞主链路）。

    M8c：``verify_skills`` 增第三槽位 verify-idor（IDOR 双会话属性验证），
    未注册/未启用同样记 ``verify_skill_skipped`` 跳过（增强项不阻塞主链路）。
    """

    def __init__(
        self,
        orchestrator,
        registry,
        *,
        scan_skill: str = "web-scan",
        verify_skill: str = "verify-sqli",
        crawl_skill: str = "recon-crawl",
        verify_xss_skill: str = "verify-xss",
        verify_idor_skill: str = "verify-idor",
    ):
        self._orch = orchestrator
        self.scan_skill = scan_skill
        self.verify_skill = verify_skill
        self.scan_risk_level = _builtin_risk_level(
            scan_skill, registry.get(scan_skill).manifest.risk_level
        )
        self.verify_risk_level = _builtin_risk_level(
            verify_skill, registry.get(verify_skill).manifest.risk_level
        )
        # M9c③：skill → 是否改变目标状态（用于 L2 只读/写细分级）。
        # 全部注册 skill 都收进来（不只 scan/verify 槽位），缺声明即 True。
        from proofhound.skills.profiles import SKILL_PROFILES

        self.mutating_by_skill: dict[str, bool] = {}
        for entry in registry.list():
            skill = registry.get(entry["name"])
            if skill is None:
                continue
            # M9d：内置 skill 以 profiles 为唯一真相源；非内置回退 manifest 声明
            profile = SKILL_PROFILES.get(entry["name"])
            self.mutating_by_skill[entry["name"]] = (
                profile.mutating if profile is not None else bool(skill.manifest.mutating)
            )
        self.scan_skills: list[tuple[str, str]] = [
            (scan_skill, self.scan_risk_level)
        ]
        crawl = registry.get(crawl_skill)
        if crawl is None or not crawl.enabled:
            reason = "skill 未注册" if crawl is None else "skill 未启用"
            orchestrator.audit.record(
                "scan_skill_skipped",
                skill=crawl_skill,
                reason=f"{reason}，跳过爬行扫描",
            )
        else:
            self.scan_skills.append(
                (crawl_skill, _builtin_risk_level(crawl_skill, crawl.manifest.risk_level))
            )
        # M8b：多 verify skill 清单（首项即旧式单 skill 接口的 verify_skill）
        self.verify_skills: list[tuple[str, str]] = [
            (verify_skill, self.verify_risk_level)
        ]
        xss = registry.get(verify_xss_skill)
        if xss is None or not xss.enabled:
            reason = "skill 未注册" if xss is None else "skill 未启用"
            orchestrator.audit.record(
                "verify_skill_skipped",
                skill=verify_xss_skill,
                reason=f"{reason}，跳过 XSS 浏览器验证",
            )
        else:
            self.verify_skills.append(
                (
                    verify_xss_skill,
                    _builtin_risk_level(verify_xss_skill, xss.manifest.risk_level),
                )
            )
        # M8c：第三 verify skill 槽位（IDOR 双会话验证是增强项，缺失不阻塞主链路）
        idor = registry.get(verify_idor_skill)
        if idor is None or not idor.enabled:
            reason = "skill 未注册" if idor is None else "skill 未启用"
            orchestrator.audit.record(
                "verify_skill_skipped",
                skill=verify_idor_skill,
                reason=f"{reason}，跳过 IDOR 双会话验证",
            )
        else:
            self.verify_skills.append(
                (
                    verify_idor_skill,
                    _builtin_risk_level(verify_idor_skill, idor.manifest.risk_level),
                )
            )

    def scan(self, targets: list[str]) -> None:
        self._orch.run_scan_phase(targets, skill_name=self.scan_skill)

    def scan_with_skill(self, skill_name: str, targets: list[str]) -> None:
        self._orch.run_scan_phase(targets, skill_name=skill_name)

    def triage(self) -> list:
        return self._orch.run_triage_phase()

    def verify_covered_vuln_types(self, skill_name: str | None = None) -> frozenset[str]:
        return self._orch.verify_skill_coverage(skill_name or self.verify_skill)

    def verify(self) -> list:
        return self._orch.run_verify_phase(skill_name=self.verify_skill)

    def verify_with_skill(self, skill_name: str) -> list:
        """M8b 多 skill 接口：按 skill 跑 verify 阶段。"""
        return self._orch.run_verify_phase(skill_name=skill_name)


def _skill_mutating(phases, skill_name: str) -> bool:
    """skill 是否改变目标状态（M9c③）；查不到即 True（fail-closed）。

    ``OrchestratorPhases.mutating_by_skill`` 由 registry 的 manifest 声明填充；
    旧式 phases（测试替身 FakePhases 等）无该属性 → 一律 True，行为与 M9c③
    之前逐字节一致。
    """
    return getattr(phases, "mutating_by_skill", {}).get(skill_name, True)


def _builtin_risk_level(skill_name: str, fallback: str) -> str:
    """内置 skill 的风险等级以 ``skills/profiles.py`` 为准（M9d 单一真相源）。

    非内置/未登记的名字（用户自建目录、测试替身）回退到 manifest 声明值——
    保持既有行为，不因收敛真相源而改变对外语义。
    """
    from proofhound.skills.profiles import SKILL_PROFILES

    profile = SKILL_PROFILES.get(skill_name)
    return profile.risk_level if profile is not None else fallback


def _env_flag(name: str) -> bool:
    """布尔环境变量（M9c）：``1/true/yes/on`` 为真，其余（含未设）为假。"""
    value = (os.environ.get(name) or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def default_phases_factory(rt: EngagementRuntime) -> OrchestratorPhases:
    """构建真实执行栈：Docker 沙箱 + skill registry + 模型路由 + 编排器。

    - scope 由 manager 在 run 前重新加载（含 session 挂接），此处不重复校验；
    - 工具经安装器 ``ensure``（白名单源 + SHA256，本地已装则幂等跳过）；
    - token 预算：engagement 级 ``budget`` 优先，未设走 ``.env`` 的
      ``PROOFHOUND_MAX_TOKENS_PER_RUN*``；硬闸在 ModelRouter 层强制。
    """
    import docker

    from proofhound.core.orchestrator import Orchestrator
    from proofhound.llm.router import ModelRouter
    from proofhound.llm.usage import TokenBudget, UsageTracker
    from proofhound.skills.registry import SkillRegistry
    from proofhound.tools.egress import EgressPolicy
    from proofhound.tools.installer import ToolInstaller
    from proofhound.tools.manifest import load_manifest
    from proofhound.tools.sandbox import SandboxConfig, SandboxRunner

    client = docker.from_env()
    client.ping()
    workspace = rt.workspace_root
    # manifest 是包内数据（版本/安装配方的权威来源），从包装载而非 workspace
    manifests_dir = Path(__file__).resolve().parent.parent / "tools" / "manifests"
    installer = ToolInstaller(workspace / "tools.d")
    for tool in ("httpx", "sqlmap", "katana"):
        installer.ensure(load_manifest(manifests_dir / f"{tool}.yaml"))
    # M9a：默认 restricted——容器接入 proofhound-egress（internal，无网关/NAT），
    # HTTP(S) 强制经白名单正向代理出站，白名单 = scope（+ 安装白名单源）。
    # scope 现在由目标派生并落盘，白名单因此始终有据可依。
    #
    # 逃生阀：某些环境无法创建 internal 网络或绑定网关代理（如受限的 Docker
    # 环境），可显式设 PROOFHOUND_SANDBOX_EGRESS=open 退回演示取向。默认严格。
    egress_mode = (os.environ.get("PROOFHOUND_SANDBOX_EGRESS") or "restricted").strip().lower()
    if egress_mode not in {"restricted", "open", "none"}:
        raise ValueError(
            f"PROOFHOUND_SANDBOX_EGRESS 非法取值 {egress_mode!r}（可选 restricted/open/none）"
        )
    runner = SandboxRunner(
        rt.scope,
        rt.audit,
        evidence_dir=rt.engagement.dir,
        tools_dir=workspace / "tools.d",
        config=SandboxConfig(
            image="alpine:3.20",
            network_mode="bridge",
            egress=EgressPolicy(mode=egress_mode),
        ),
        client=client,
    )
    registry = SkillRegistry(workspace / "skills", rt.audit).discover()
    if rt.engagement.budget is not None:
        budget = TokenBudget(max_total=rt.engagement.budget)
    else:
        budget = TokenBudget.from_env(rt.env_file)
    router = ModelRouter.from_env(
        rt.env_file, audit=rt.audit, tracker=UsageTracker(), budget=budget
    )
    orch = Orchestrator(
        registry,
        runner,
        router,
        rt.audit,
        evidence_dir=rt.engagement.dir,
        # M9c：发现侧去锁。两者缺省关闭，保持与 M9c 之前逐字节等价；
        # 显式开启后：模型 triage 补关键词盲区，廉价粗筛只出建议、不丢候选。
        triage_model=_env_flag("PROOFHOUND_TRIAGE_MODEL"),
        verify_prefilter=_env_flag("PROOFHOUND_VERIFY_PREFILTER"),
    )
    return OrchestratorPhases(orch, registry)


# ---- engagement 管理器 ----


class EngagementManager:
    """engagement 的创建/查询/启动/确认裁定；app 启动时从磁盘恢复。"""

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        phases_factory=None,
        confirm_timeout: float = 300.0,
        env_file: str | Path | None = None,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        self.engagements_dir = self.workspace_root / "engagements"
        self.templates_dir = self.workspace_root / "templates"
        # M6a 管理面：skills/ 与 scopes/ 约定目录 + workspace 级管理审计通道
        # （management.jsonl，append-only，skill/scope 变更全进它）
        self.skills_dir = self.workspace_root / "skills"
        self.scopes_dir = self.workspace_root / "scopes"
        self.scopes_dir.mkdir(exist_ok=True)  # 约定目录：不存在则创建
        self.management_audit = AuditLog(self.workspace_root / "management.jsonl")
        self.env_file = (
            Path(env_file).resolve()
            if env_file is not None
            else self.workspace_root / ".env"
        )
        self.phases_factory = (
            phases_factory if phases_factory is not None else default_phases_factory
        )
        self.confirm_timeout = confirm_timeout
        self._lock = threading.RLock()
        self._engagements: dict[str, Engagement] = {}
        self._events: dict[str, threading.Event] = {}
        self._load_all()

    # ---- 启动恢复 ----

    def _load_all(self) -> None:
        """扫描 engagements 目录恢复记录；中断的运行态回退 created（可重跑推进）。"""
        if not self.engagements_dir.is_dir():
            return
        for child in sorted(self.engagements_dir.iterdir()):
            api_json = child / "api.json"
            if not child.is_dir() or not api_json.is_file():
                continue
            try:
                meta = json.loads(api_json.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            eng = Engagement(self, child, meta)
            if eng.state not in (
                EngagementState.CREATED,
                EngagementState.DONE,
                EngagementState.FAILED,
            ):
                # 线程已随进程死亡：回退 created，重跑时经确认队列断点续跑
                eng._state = EngagementState.CREATED
                eng._persist()
            self._engagements[eng.id] = eng

    # ---- scope 加载与目标重校验（创建后改 scope 文件是合法运维操作） ----

    def _resolve_scope_path(self, raw: str) -> Path:
        path = Path(raw)
        if not path.is_absolute():
            path = self.workspace_root / path
        return path

    def load_scope(
        self,
        scope_paths: list[str],
        *,
        derived_scope: dict | None = None,
        target: str | None = None,
    ) -> Scope:
        """加载并合并 scope；文件缺失/非法一律 fail-closed 拒绝。

        M9a：``derived_scope`` 是建 engagement 时从种子目标派生并**落盘**的授权
        范围（``api.json`` 的 ``derived_scope``）。它作为基底并入，scope 文件项
        叠加其上——两者**并集**生效。派生结果持久化而非每次现算，保证
        "操作员看到的"与"实际生效的"是同一份（可审计）。

        ``scope_paths`` 为空且无派生范围时返回空 Scope；此时 ``check_scope``
        的 fail-closed 语义会拒绝一切目标，调用方须自行给出清晰报错。
        """
        domains: list[str] = []
        networks: list[str] = []
        ports: list[int] = []

        if derived_scope:
            domains.extend(derived_scope.get("domains") or [])
            networks.extend(derived_scope.get("networks") or [])
            ports.extend(derived_scope.get("ports") or [])

        for raw in scope_paths:
            path = self._resolve_scope_path(raw)
            try:
                loaded = Scope.from_file(path)
            except Exception as exc:
                raise ScopeViolationError(f"scope 文件不可用: {raw}（{exc}）") from None
            domains.extend(loaded.domains)
            networks.extend(loaded.networks)
            ports.extend(loaded.ports)

        merged = Scope(domains=domains, networks=networks, ports=ports)
        if not (merged.domains or merged.networks):
            where = target or "（未提供目标）"
            raise ScopeViolationError(
                f"没有任何授权范围：scope_paths 为空且未从目标 {where} 派生。"
                "请显式提供 scope 文件，或给一个可解析的目标以自动派生"
            )
        return merged

    def check_target(self, scope: Scope, target: str) -> None:
        """目标过 check_scope；越界抛 :class:`ScopeViolationError`。"""
        decision = check_scope(scope, [target])
        if not decision.allowed:
            raise ScopeViolationError("; ".join(decision.violations))

    @staticmethod
    def _scope_summary(scope: Scope) -> str:
        parts = []
        if scope.domains:
            parts.append("domains: " + ", ".join(scope.domains))
        if scope.networks:
            parts.append("networks: " + ", ".join(scope.networks))
        if scope.ports:
            parts.append("ports: " + ", ".join(str(p) for p in scope.ports))
        return "; ".join(parts) or "（空授权范围）"

    @staticmethod
    def _load_session(eng: Engagement) -> SessionConfig | None:
        session_path = eng.dir / "session.json"
        if not session_path.is_file():
            return None
        data = json.loads(session_path.read_text(encoding="utf-8"))
        reference = None
        raw_reference = data.get("reference")  # M8c：第二身份会话（可无）
        if isinstance(raw_reference, dict):
            reference = SessionConfig(
                cookies=raw_reference.get("cookies", {}),
                headers=raw_reference.get("headers", {}),
            )
        return SessionConfig(
            cookies=data.get("cookies", {}),
            headers=data.get("headers", {}),
            reference=reference,
        )

    # ---- engagement CRUD ----

    def create(self, request) -> Engagement:
        """创建 engagement。**先校验后建目录**：scope 违规时零目录零审计。

        M9a：``scope_paths`` 为空时从 ``target`` 派生 scope（零手写 YAML），
        并把派生结果落盘为**实际生效的那一份**。派生是纯确定性动作，不构成
        授权——授权由 ``acknowledge_authorization`` 显式确认并落审计。
        """
        from proofhound.compliance.derive import (
            ScopeDerivationError,
            derive_scope,
            derived_scope_marker,
        )

        derived_meta: dict | None = None
        if request.scope_paths:
            scope = self.load_scope(request.scope_paths)  # 文件问题即 403
        else:
            # 无 scope 文件：从目标派生。派生失败即 403，不建任何目录。
            try:
                scope = derive_scope(request.target)
            except ScopeDerivationError as exc:
                raise ScopeViolationError(f"无法从目标派生 scope：{exc}") from None
            derived_meta = derived_scope_marker(scope, target=request.target)
            if not getattr(request, "acknowledge_authorization", False):
                # 自动派生出的范围就是这次测试的授权边界，必须显式确认。
                raise ScopeViolationError(
                    "从目标自动派生了授权范围，需要显式确认授权："
                    "请设置 acknowledge_authorization=true（表示你已获得对该范围的书面测试授权）"
                )
        self.check_target(scope, request.target)  # 越界即 403，无任何副作用
        eng_id = f"eng-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        directory = self.engagements_dir / eng_id
        directory.mkdir(parents=True)
        created_at = _utc_now()

        if request.cookie is not None or request.reference_cookie is not None:
            from proofhound.api.models import parse_cookie

            session_data: dict = {}
            if request.cookie is not None:
                session_data["cookies"] = parse_cookie(request.cookie)
            if request.reference_cookie is not None:
                # M8c：第二身份会话（reference/victim，verify-idor 双会话验证用）
                session_data["reference"] = {
                    "cookies": parse_cookie(request.reference_cookie)
                }
            session_path = directory / "session.json"
            session_path.write_text(
                json.dumps(session_data, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            session_path.chmod(0o600)  # 凭据文件 0600

        meta = {
            "id": eng_id,
            "target": request.target,
            "scope_paths": list(request.scope_paths),
            "autonomy_mode": AutonomyMode(request.autonomy_mode).value,
            "budget": request.budget,
            "state": EngagementState.CREATED.value,
            "created_at": created_at,
            "with_session": request.cookie is not None,
            "with_reference_session": request.reference_cookie is not None,  # M8c
        }
        if derived_meta is not None:
            # 派生范围落盘为实际生效的那一份（M9a）：api.json 是 engagement
            # 元数据的权威来源，start() 重校验时从这里读回。
            meta["derived_scope"] = derived_meta
        eng = Engagement(self, directory, meta)
        eng._persist()
        # 报告元信息（§5.7 engagement.json：target/scope/started_at）
        # extras（M4.5 透传键，如 company_name/system_name/report_date）
        # 在模型层已拒绝保留键，直接并入；_finish_meta 收尾保留这些键
        engagement_meta = {
            "target": request.target,
            "scope": self._scope_summary(scope),
            "started_at": created_at,
        }
        if request.extras:
            engagement_meta.update(request.extras)
        (directory / "engagement.json").write_text(
            json.dumps(
                engagement_meta,
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        eng.audit.record(
            "engagement_created",
            engagement_id=eng_id,
            target=request.target,
            scope_paths=list(request.scope_paths),
            autonomy_mode=meta["autonomy_mode"],
            budget=request.budget,
            with_session=meta["with_session"],
            with_reference_session=meta["with_reference_session"],  # M8c
            extras=sorted(request.extras or {}),  # 只记键名
        )
        if derived_meta is not None:
            # M9a：派生范围的全量留痕 + 授权确认留痕（两者分开，便于事后归因）
            eng.audit.record("scope_derived", engagement_id=eng_id, **derived_meta)
            eng.audit.record(
                "authorization_acknowledged",
                engagement_id=eng_id,
                target=request.target,
                derived=True,
                scope=derived_meta,
            )
        with self._lock:
            self._engagements[eng_id] = eng
        return eng

    def get(self, eng_id: str) -> Engagement:
        eng = self._engagements.get(eng_id)
        if eng is None:
            raise NotFoundError(f"engagement 不存在: {eng_id}")
        return eng

    def list_all(self) -> list[Engagement]:
        with self._lock:
            return sorted(self._engagements.values(), key=lambda e: e.created_at)

    # ---- 启动 / 推进 ----

    def start(self, eng_id: str) -> Engagement:
        """启动后台执行线程（异步）；启动前目标重新过 check_scope。"""
        eng = self.get(eng_id)
        with eng._lock:
            if eng.running:
                raise InvalidStateError("engagement 正在运行中")
            if eng.state is not EngagementState.CREATED:
                raise InvalidStateError(
                    f"当前状态 {eng.state.value} 不可启动（仅 created 可启动/重跑）"
                )
        # 不信任创建时校验结果：scope 文件可能已合法变更，重新加载 + 重新校验；
        # M9a 派生范围（若有）一并读回并集生效——5 层 check_scope 因此自动覆盖
        # 派生范围，无需改动任何一层。
        scope = self.load_scope(
            eng.scope_paths, derived_scope=eng.derived_scope, target=eng.target
        )
        decision = check_scope(scope, [eng.target])
        eng.audit.record(
            "scope_recheck",
            target=eng.target,
            allowed=decision.allowed,
            violations=decision.violations,
        )
        if not decision.allowed:
            raise ScopeViolationError("; ".join(decision.violations))
        scope.session = self._load_session(eng)
        if eng.budget == 0:
            # token 预算硬闸（与 scope 同级）：预算 0 = 拒绝一切 LLM 调用
            eng.audit.record(
                "budget_exceeded",
                engagement_id=eng.id,
                limit=0,
                note="预算为 0：拒绝启动（预算硬闸任何自治模式不可绕过）",
            )
            raise BudgetBlockedError("token 预算为 0：任何 LLM 调用均被预算硬闸拒绝")
        runtime = EngagementRuntime(
            manager=self,
            engagement=eng,
            scope=scope,
            audit=eng.audit,
            confirmations=ConfirmationStore(eng.dir / "confirmations.jsonl"),
        )
        runner = EngagementRunner(runtime, self.phases_factory, self.confirm_timeout)
        thread = threading.Thread(
            target=runner.run, name=f"proofhound-{eng.id}", daemon=True
        )
        with eng._lock:
            eng.thread = thread
        thread.start()
        return eng

    # ---- 确认队列 ----

    def confirmation_event(self, cid: str) -> threading.Event:
        with self._lock:
            return self._events.setdefault(cid, threading.Event())

    def release_confirmation_event(self, cid: str) -> None:
        with self._lock:
            self._events.pop(cid, None)

    def list_confirmations(self, eng_id: str) -> list[Confirmation]:
        eng = self.get(eng_id)
        store = ConfirmationStore(eng.dir / "confirmations.jsonl")
        return store.list_pending()

    def decide_confirmation(
        self,
        cid: str,
        *,
        approved: bool,
        operator: str,
        note: str = "",
    ) -> tuple[Engagement, Confirmation]:
        """批准/拒绝待确认动作：落 confirmations.jsonl + 审计，唤醒等待线程。"""
        for eng in self._engagements.values():
            store = ConfirmationStore(eng.dir / "confirmations.jsonl")
            conf = store.get(cid)
            if conf is None:
                continue
            if conf.status != "pending":
                raise InvalidStateError(f"确认 {cid} 已裁定（{conf.status}）")
            conf = store.decide(cid, approved=approved, operator=operator, note=note)
            eng.audit.record(
                "action_approved" if approved else "action_rejected",
                cid=cid,
                action=conf.action,
                risk_level=conf.risk_level,
                target=conf.target,
                finding_id=conf.finding_id,
                operator=operator,
                note=note,
            )
            with self._lock:
                event = self._events.get(cid)
            if event is not None:
                event.set()
            return eng, conf
        raise NotFoundError(f"确认不存在: {cid}")
