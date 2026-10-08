"""FastAPI 应用工厂（M5a，§5.9.1）：本机 Web API，只做后端，不含前端。

- ``create_app(workspace_root)``：workspace 内含 scope 文件、``templates/``、
  ``skills/``、``tools.d/``；engagement 落 ``<workspace>/engagements/<id>/``
  （证据/审计/findings/确认队列/报告全部在其中）；
- **本层是编排器的薄壳**：不构造命令、不旁路 scope——执行走
  :class:`~proofhound.api.runner.EngagementRunner` → ``Orchestrator`` →
  ``tools/build.py`` + ScopeEnforcer（红线 1/5 不变）；
- 每次请求目标重新过 ``check_scope``（创建后改 scope 文件是合法运维）；
  模板路径限制在 workspace ``templates/`` 内（同 M4 纪律）；
- **cookie 值永不进任何响应体**：只在创建时写 ``session.json``（0600），
  响应只回显 ``with_session: true``；
- 错误统一：403 scope_violation / 402 budget_exceeded / 409 invalid_state /
  404 not_found，响应体 ``{"detail": {"error", "message"}}``；
- **HTTP Basic 单账户认证（M14）**：``create_app`` 缺省启用（deny-by-default），
  覆盖含控制台首页与静态资源在内的全部路径；凭据由 :func:`auth.resolve_auth`
  解析（环境变量 > ``.env`` > 仓库默认值），默认口令是公开的，故 ``__main__``
  对「默认口令 + 非回环绑定」直接拒绝启动；
- 网络暴露红线（§5.9.3）：只监听 localhost/内网；Basic 口令不经 TLS 加密，
  多人访问须前置反向代理 + 登录认证，严禁直接暴露公网。
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from proofhound.autonomy import AutonomyGate, AutonomySwitchError, gate_matrix
from proofhound.api.auth import REALM, ApiAuth, resolve_auth
from proofhound.api.management import ManagementService
from proofhound.api.models import (
    AutonomySwitchRequest,
    ConfirmationDecisionRequest,
    CreateEngagementRequest,
    ReportBuildRequest,
    ScopeCreateRequest,
    ScopeUpdateRequest,
)
from proofhound.api.runner import (
    ApiError,
    BudgetBlockedError,
    Engagement,
    EngagementManager,
    EngagementState,
    InvalidStateError,
    NotFoundError,
    ScopeViolationError,
)
from proofhound.findings.finding import FindingStore
from proofhound.llm.cost import report_from_audit
from proofhound.llm.usage import BudgetExceededError

DOCX_MEDIA_TYPE = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
)

#: 证据文件单文件响应上限（M5b 控制台证据查看器）：超过即截断 + 响应头标记
EVIDENCE_FILE_MAX_BYTES = 2 * 1024 * 1024


def _findings_counts(eng: Engagement) -> dict:
    """findings 分桶计数（含 rejected；文件不存在时全零）。"""
    counts = {"confirmed": 0, "reproduced": 0, "hypothesis": 0, "signal": 0, "rejected": 0}
    store = FindingStore(eng.dir / "findings.jsonl")
    for finding in store.load_all():
        counts[finding.state.value] = counts.get(finding.state.value, 0) + 1
    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    return counts


def _tokens_used(eng: Engagement) -> int:
    """累计 LLM token 用量（由审计 llm_call 事件聚合，重启也可查）。

    M11a：改用 :func:`~proofhound.llm.cost.report_from_audit` 的同一聚合口径
    ——``/cost`` 端点与列表/详情里的 ``tokens_used`` 因此**必然同源同值**，
    不会再出现同一份数据两个数字。数值语义与改造前逐字节等价（缺失/None
    字段按 0 计）。
    """
    return report_from_audit(eng.dir / "audit.jsonl").total.total_tokens


def _engagement_summary(eng: Engagement) -> dict:
    """列表项视图（不含 cookie，永不回显凭据）。"""
    return {
        "id": eng.id,
        "target": eng.target,
        "state": eng.state.value,
        "autonomy_mode": eng.current_mode().value,
        "created_at": eng.created_at,
        "with_session": eng.with_session,
        "with_reference_session": eng.with_reference_session,  # M8c
        "findings": _findings_counts(eng),
    }


def _engagement_detail(manager: EngagementManager, eng: Engagement) -> dict:
    detail = _engagement_summary(eng)
    detail.update(
        {
            "scope_paths": eng.scope_paths,
            "budget": eng.budget,
            "tokens_used": _tokens_used(eng),
            "pending_confirmations": len(manager.list_confirmations(eng.id)),
            "running": eng.running,
        }
    )
    return detail


def create_app(
    workspace_root: str | Path,
    *,
    phases_factory=None,
    confirm_timeout: float = 300.0,
    env_file: str | Path | None = None,
    auth: ApiAuth | None = None,
) -> FastAPI:
    """创建 FastAPI 应用。``phases_factory``/``confirm_timeout`` 供测试注入。

    ``auth`` 缺省由 :func:`~proofhound.api.auth.resolve_auth` 解析（环境变量 >
    ``.env`` > 仓库默认凭据）——**认证缺省开启**，不传即 HTTP Basic 生效。
    """
    manager = EngagementManager(
        workspace_root,
        phases_factory=phases_factory,
        confirm_timeout=confirm_timeout,
        env_file=env_file,
    )
    management = ManagementService(manager)  # M6a 管理面（skill/scope）
    app = FastAPI(title="ProofHound API", version="0.4.0")
    app.state.manager = manager
    auth_config = auth or resolve_auth(workspace_root, env_file)
    app.state.auth = auth_config

    @app.middleware("http")
    async def _require_auth(request: Request, call_next):
        """M14：deny-by-default——含控制台首页与静态资源在内，全路径都要凭据。

        ``Authorization`` 头只在此处读取用于常量时间比对，**不落审计、不落日志**；
        401 响应体不回显任何提交内容（避免把尝试的口令回显进日志/浏览器）。
        """
        if not auth_config.accepts(request.headers.get("authorization")):
            return JSONResponse(
                status_code=401,
                content={
                    "detail": {
                        "error": "unauthorized",
                        "message": "需要 HTTP Basic 认证",
                    }
                },
                headers={"WWW-Authenticate": f'Basic realm="{REALM}"'},
            )
        return await call_next(request)

    @app.exception_handler(ApiError)
    async def _api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": {"error": exc.error_code, "message": str(exc)}},
        )

    # ---- 健康 ----

    @app.get("/api/health")
    def health() -> dict:
        return {
            "status": "ok",
            "service": "proofhound-api",
            "version": app.version,
            "confirm_timeout": manager.confirm_timeout,
            "autonomy_gate": gate_matrix(),
            # M14：控制台顶栏据此显示当前账户，并在仍用公开默认口令时提醒改掉
            "auth": {
                "enabled": True,
                "user": auth_config.username,
                "default_credentials": auth_config.is_default,
            },
        }

    # ---- engagement 生命周期 ----

    @app.post("/api/engagements", status_code=201)
    def create_engagement(request: CreateEngagementRequest) -> dict:
        eng = manager.create(request)  # scope 违规：403 且零目录零审计
        return _engagement_detail(manager, eng)

    @app.get("/api/engagements")
    def list_engagements() -> dict:
        return {"engagements": [_engagement_summary(e) for e in manager.list_all()]}

    @app.get("/api/engagements/{eng_id}")
    def get_engagement(eng_id: str) -> dict:
        return _engagement_detail(manager, manager.get(eng_id))

    @app.post("/api/engagements/{eng_id}/run", status_code=202)
    def run_engagement(eng_id: str) -> dict:
        eng = manager.start(eng_id)  # 目标重新过 check_scope；预算 0 直接 402
        return {
            "detail": "engagement 已启动（异步）",
            "id": eng.id,
            "state": eng.state.value,
        }

    @app.post("/api/engagements/{eng_id}/autonomy")
    def switch_autonomy(eng_id: str, request: AutonomySwitchRequest) -> dict:
        eng = manager.get(eng_id)
        gate = AutonomyGate(eng.current_mode(), eng.audit)
        try:
            record = gate.switch_mode(
                request.mode, operator=request.operator, note=request.note
            )
        except AutonomySwitchError as exc:
            raise InvalidStateError(str(exc)) from None
        if record["changed"]:
            eng.set_mode(request.mode)
        return {"engagement_id": eng.id, "mode": eng.current_mode().value, **record}

    # ---- findings / 证据包 ----

    @app.get("/api/engagements/{eng_id}/findings")
    def list_findings(eng_id: str) -> dict:
        eng = manager.get(eng_id)
        store = FindingStore(eng.dir / "findings.jsonl")
        return {
            "findings": [f.model_dump(mode="json") for f in store.load_all()],
        }

    @app.get("/api/engagements/{eng_id}/findings/{finding_id}/evidence")
    def get_evidence(eng_id: str, finding_id: str) -> dict:
        """证据包内容 + sha256（等价 ``python -m proofhound.findings show``）。"""
        eng = manager.get(eng_id)
        store = FindingStore(eng.dir / "findings.jsonl")
        finding = store.get(finding_id)
        if finding is None:
            raise NotFoundError(f"Finding 不存在: {finding_id}")
        pack_dir = eng.dir / "findings" / finding.id
        manifest_path = pack_dir / "manifest.json"
        items = []
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for item in manifest.get("items", []):
                entry = dict(item)
                anchor = item.get("line_anchor")
                if anchor is not None and item.get("file") and not item.get("missing"):
                    evidence_file = pack_dir / item["file"]
                    lines = evidence_file.read_text(
                        encoding="utf-8", errors="replace"
                    ).split("\n")
                    entry["anchor_line_text"] = (
                        lines[anchor - 1] if 1 <= anchor <= len(lines) else None
                    )
                items.append(entry)
        return {
            "finding": finding.model_dump(mode="json"),
            "pack_dir": str(pack_dir),
            "assembled": manifest_path.is_file(),
            "items": items,
        }

    @app.get("/api/engagements/{eng_id}/findings/{finding_id}/evidence/{filename}")
    def get_evidence_file(eng_id: str, finding_id: str, filename: str):
        """证据包单文件全文（M5b 控制台证据查看器数据源，只读）。

        守卫（fail-closed 双层）：文件名须精确命中 manifest items 白名单
        （未列入/missing 即 404），且 resolve 后不得越出 pack_dir（防穿越）；
        超过 ``EVIDENCE_FILE_MAX_BYTES`` 截断并带 ``X-ProofHound-Truncated`` 头。
        响应文本做行尾归一化（``\r\n`` 与裸 ``\r`` 均归一为 ``\n``，与上方
        evidence 端点 ``anchor_line_text`` 的 read_text 行为同款）——#L 行号
        锚点按归一化后文本定义，控制台按 ``\n`` 分行渲染才能与锚点严格对齐；
        证据完整性以 manifest sha256 对磁盘字节核验为准（本端点是展示层）。
        """
        eng = manager.get(eng_id)
        store = FindingStore(eng.dir / "findings.jsonl")
        finding = store.get(finding_id)
        if finding is None:
            raise NotFoundError(f"Finding 不存在: {finding_id}")
        pack_dir = (eng.dir / "findings" / finding.id).resolve()
        manifest_path = pack_dir / "manifest.json"
        if not manifest_path.is_file():
            raise NotFoundError(f"证据包尚未组装: {finding_id}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        listed = {
            item["file"]
            for item in manifest.get("items", [])
            if item.get("file") and not item.get("missing")
        }
        if filename not in listed:
            raise NotFoundError(f"证据文件不在证据包清单内: {filename}")
        candidate = (pack_dir / filename).resolve()
        if not candidate.is_relative_to(pack_dir) or not candidate.is_file():
            raise NotFoundError(f"证据文件不存在: {filename}")
        raw = candidate.read_bytes()
        truncated = len(raw) > EVIDENCE_FILE_MAX_BYTES
        if truncated:
            raw = raw[:EVIDENCE_FILE_MAX_BYTES]
        text = raw.decode("utf-8", errors="replace")
        text = text.replace("\r\n", "\n").replace("\r", "\n")  # 行尾归一化（见 docstring）
        headers = {"X-ProofHound-Truncated": "true"} if truncated else None
        return PlainTextResponse(text, headers=headers)

    # ---- 报告 ----

    @app.post("/api/engagements/{eng_id}/report")
    def build_report(eng_id: str, request: ReportBuildRequest) -> dict:
        eng = manager.get(eng_id)
        if eng.state not in (EngagementState.DONE, EngagementState.FAILED):
            raise InvalidStateError(
                f"当前状态 {eng.state.value} 不可构建报告（需 done/failed 终态）"
            )
        store = FindingStore(eng.dir / "findings.jsonl")
        if not store.path.is_file():
            raise InvalidStateError("无 findings 存储（triage 尚未产出）")
        template = _resolve_template(manager, request.template)
        out = eng.dir / "report.docx"

        from proofhound.report.data import build_context
        from proofhound.report.render import RenderError, render_docx

        context = build_context(eng.dir)
        if request.narrative:
            context = _generate_narrative(manager, eng, store)
        try:
            render_docx(context.as_template_context(), template, out)
        except RenderError as exc:
            raise ApiError(f"报告渲染失败: {exc}") from None
        eng.audit.record(
            "report_built",
            engagement_id=eng.id,
            template=template.name,
            narrative=request.narrative,
            out=out.name,
        )
        summary = context.summary
        return {
            "report": out.name,
            "narrative": request.narrative,
            "summary": {
                "confirmed": summary.confirmed,
                "conditional": summary.conditional,
                "hypothesis": summary.hypothesis,
                "rejected": summary.rejected,
            },
        }

    @app.get("/api/engagements/{eng_id}/report")
    def download_report(eng_id: str):
        from fastapi.responses import FileResponse

        eng = manager.get(eng_id)
        out = eng.dir / "report.docx"
        if not out.is_file():
            raise NotFoundError("报告尚未生成（先 POST report 构建）")
        return FileResponse(
            out, media_type=DOCX_MEDIA_TYPE, filename=f"{eng.id}.docx"
        )

    @app.get("/api/templates")
    def list_templates() -> dict:
        """报告模板清单（workspace ``templates/`` 内 *.docx，M5b 控制台报告区
        下拉数据源；只读，与 :func:`_resolve_template` 同源目录）。"""
        templates_dir = manager.templates_dir
        names = (
            sorted(p.name for p in templates_dir.glob("*.docx") if p.is_file())
            if templates_dir.is_dir()
            else []
        )
        return {"templates": names}

    # ---- 审计 ----

    @app.get("/api/engagements/{eng_id}/audit")
    def get_audit(
        eng_id: str,
        tail: int | None = Query(default=None, ge=1),
    ) -> dict:
        eng = manager.get(eng_id)
        events = eng.audit.read_all()
        total = len(events)
        if tail is not None:
            events = events[-tail:]
        return {"total": total, "events": events}

    # ---- 成本（M11a）----

    @app.get("/api/engagements/{eng_id}/cost")
    def get_cost(eng_id: str, include_calls: bool = True) -> dict:
        """单题成本归属（只读、纯文件聚合、零 LLM）。

        口径 = 调用方 + 阶段（含修复重试，重试单列）；数据源 = ``llm_call``
        审计。``include_calls=false`` 时只回聚合值（体积更小，供轮询）。
        响应中不含任何凭据：本端点只读 tier/caller/finding_id/tokens 等结构化
        字段。
        """
        eng = manager.get(eng_id)
        report = report_from_audit(eng.dir / "audit.jsonl")
        return report.as_dict(include_calls=include_calls)

    # ---- 确认队列 ----

    @app.get("/api/engagements/{eng_id}/confirmations")
    def list_confirmations(eng_id: str) -> dict:
        return {
            "confirmations": [
                c.to_dict() for c in manager.list_confirmations(eng_id)
            ]
        }

    @app.post("/api/confirmations/{cid}/approve")
    def approve_confirmation(cid: str, request: ConfirmationDecisionRequest) -> dict:
        eng, conf = manager.decide_confirmation(
            cid, approved=True, operator=request.operator, note=request.note
        )
        return {"confirmation": conf.to_dict(), "engagement_id": eng.id}

    @app.post("/api/confirmations/{cid}/reject")
    def reject_confirmation(cid: str, request: ConfirmationDecisionRequest) -> dict:
        eng, conf = manager.decide_confirmation(
            cid, approved=False, operator=request.operator, note=request.note
        )
        return {"confirmation": conf.to_dict(), "engagement_id": eng.id}

    # ---- M6a 管理面：scope 授权文件管理（仅限 workspace scopes/ 内） ----
    #
    # M9d：skill 管理端点（GET/POST/PUT/DELETE /api/skills）已移除——不开放
    # 用户自写 skill，skill 库全部内置并随仓库交付。

    @app.get("/api/scopes")
    def list_scopes() -> dict:
        """scope 列表（控制台创建任务表单下拉数据源）。"""
        return {"scopes": management.list_scopes()}

    @app.get("/api/scopes/{name}")
    def get_scope(name: str) -> dict:
        return management.get_scope(name)

    @app.post("/api/scopes", status_code=201)
    def create_scope(request: ScopeCreateRequest) -> dict:
        return management.create_scope(request.name, request.content)

    @app.put("/api/scopes/{name}")
    def update_scope(name: str, request: ScopeUpdateRequest) -> dict:
        return management.update_scope(name, request.content)

    @app.delete("/api/scopes/{name}")
    def delete_scope(name: str) -> dict:
        return management.delete_scope(name)

    # ---- M5b Web 控制台静态资源（挂载于全部 API 路由之后）----
    # 纯静态零依赖（无 CDN/无构建链，完全离线可用）；前端只是本 API 的消费者，
    # 不含任何业务逻辑/命令构造。

    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="console-static")

    @app.get("/", include_in_schema=False)
    def console_index():
        return FileResponse(static_dir / "index.html")

    return app


def _resolve_template(manager: EngagementManager, name: str | None) -> Path:
    """模板解析：限制在 workspace ``templates/`` 内（同 M4 纪律）。"""
    raw = name or "default_template.docx"
    root = manager.templates_dir.resolve()
    candidate = (root / raw).resolve()
    if not candidate.is_relative_to(root):
        raise ScopeViolationError(f"模板路径越出 templates/: {raw}")
    if not candidate.is_file():
        raise NotFoundError(f"报告模板不存在: {raw}")
    return candidate


def _generate_narrative(manager: EngagementManager, eng: Engagement, store):
    """T1 叙述生成（可选）；预算硬闸 402，其余叙述失败 500。"""
    from proofhound.llm.client import LLMError
    from proofhound.llm.router import ModelRouter, Tier
    from proofhound.llm.usage import TokenBudget, UsageTracker
    from proofhound.report.data import build_context
    from proofhound.report.narrative import NarrativeError, NarrativeGenerator

    if eng.budget is not None:
        budget = TokenBudget(max_total=eng.budget)
    else:
        budget = TokenBudget.from_env(manager.env_file)
    try:
        router = ModelRouter.from_env(
            manager.env_file, audit=eng.audit, tracker=UsageTracker(), budget=budget
        )
    except LLMError as exc:
        raise ApiError(f"叙述生成配置错误: {exc}") from None
    if Tier.T1 not in router.configs:
        raise ApiError("叙述生成需要 T1 档配置（PROOFHOUND_T1_*）；或用 narrative=false")
    generator = NarrativeGenerator(router, eng.audit)
    try:
        generator.generate(store.load_all(), store=store, evidence_dir=eng.dir)
    except BudgetExceededError as exc:
        raise BudgetBlockedError(str(exc)) from None
    except (NarrativeError, LLMError) as exc:
        raise ApiError(f"叙述生成失败: {exc}") from None
    return build_context(eng.dir)
