"""规划器（§5.3）：LLM 基于结构化状态 + 命中 skill 的 SOP 生成计划。

- 输入 = 当前结构化状态（红线 3：只含摘要与证据引用，无原始输出）
  + skill 正文 SOP（渐进式披露，命中才读全文）；
- 输出 = :class:`~proofhound.core.plan.Plan`，先过 schema 强校验
  （core/plan.py），再过语义校验：skill 已注册且启用、tool 有命令
  构造器且在 skill 的 required_tools 内；
- 任何校验失败抛 :class:`PlanValidationError` 并记审计 plan_rejected；
- M2c：LLM 调用经 :class:`~proofhound.llm.router.ModelRouter` 走 T1 档
  （计量 + 预算硬闸在路由层）；规划前先做上下文治理（core/context.py）：
  Signal 摘要超限确定性压缩（记 context_compressed），prompt 超字符硬
  上限抛 :class:`ContextOverflowError`（记 context_overflow，禁静默截断）。
"""

from __future__ import annotations

import json

from proofhound.compliance.audit import AuditLog
from proofhound.core.context import (
    ContextOverflowError,
    ContextPolicy,
    compress_state,
    messages_chars,
)
from proofhound.core.plan import Plan, PlanValidationError, parse_plan
from proofhound.llm.router import Tier, ensure_router
from proofhound.skills.registry import Skill, SkillRegistry
from proofhound.tools.build import params_schema

SYSTEM_PROMPT = """\
你是渗透测试编排器的规划器。根据当前结构化状态和 skill 的 SOP，输出下一步计划。

硬性规则：
1. 只输出一个 JSON 对象，格式 {"actions": [...]}，不要输出任何其他文字。
2. 每个 action 字段：action（run_tool/finish/escalate 之一）、skill、tool、
   params、expected_output（预期产出）、rationale。
3. 严禁生成 shell 命令：你只能声明 tool 与结构化 params，命令由工具管理器拼装。
4. 只能使用给定可用工具清单中的工具，且工具须在 skill 的 required_tools 内；
   params 必须严格符合该工具的 params_schema（字段名与类型以 schema 为准）。
5. run_tool 必须给 tool 和 params；finish（任务完成）与 escalate（升级人工）
   不得携带 tool/params。
"""


class Planner:
    """一轮一答的规划器（M2c：经 ModelRouter 走 T1 档，带上下文治理）。"""

    def __init__(
        self,
        llm,
        registry: SkillRegistry,
        tools: set[str],
        audit: AuditLog | None = None,
        *,
        context_policy: ContextPolicy | None = None,
    ):
        # llm 接受 ModelRouter（推荐）；旧式单模型客户端自动包装适配（不计量）
        self.router = ensure_router(llm)
        self.registry = registry
        self.tools = set(tools)
        self.audit = audit
        self.context_policy = context_policy or ContextPolicy()

    def make_prompt(self, state: dict, skill: Skill) -> list[dict]:
        """组装 system + user 消息（user = 结构化状态 + skill SOP + 工具清单）。"""
        user = json.dumps(
            {
                "state": state,
                "skill": skill.summary(),
                "skill_sop": skill.read_body(),
                # 附带 params_schema：LLM 不需要猜字段名（真实模型曾把
                # target 猜成 targets 被构造器拒收）
                "available_tools": [
                    {"name": name, "params_schema": params_schema(name)}
                    for name in sorted(self.tools)
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ]

    def plan(self, state: dict, skill: Skill) -> Plan:
        """调 LLM 生成计划并做 schema + 语义校验；失败抛 PlanValidationError。

        预算超限抛 :class:`BudgetExceededError`、上下文超硬上限抛
        :class:`ContextOverflowError`（均不在此捕获，由编排器分级处理）。
        """
        state, compressed = compress_state(state, self.context_policy)
        if compressed is not None:
            self._audit(
                "context_compressed",
                skill=skill.name,
                total=compressed["total"],
                kept=compressed["kept"],
                by_kind=compressed["by_kind"],
            )
        messages = self.make_prompt(state, skill)
        chars = messages_chars(messages)
        if chars > self.context_policy.max_chars:
            # 审计由编排器捕获后统一记录（带 node_id），此处不重复记
            raise ContextOverflowError(chars=chars, limit=self.context_policy.max_chars)
        raw = self.router.complete(Tier.T1, messages)
        try:
            plan = parse_plan(raw)
            self._validate_semantics(plan)
        except PlanValidationError as exc:
            self._audit("plan_rejected", skill=skill.name, reason=str(exc)[:500])
            raise
        self._audit(
            "plan_generated",
            skill=skill.name,
            actions=len(plan.actions),
            action_kinds=[a.action for a in plan.actions],
        )
        return plan

    def _validate_semantics(self, plan: Plan) -> None:
        """skill 注册/启用、tool 有构造器且在 skill required_tools 内。"""
        for action in plan.actions:
            skill = self.registry.get(action.skill)
            if skill is None:
                raise PlanValidationError(f"未注册的 skill: {action.skill}")
            if not skill.enabled:
                raise PlanValidationError(f"skill 未启用: {action.skill}")
            if action.action != "run_tool":
                continue
            if action.tool not in self.tools:
                raise PlanValidationError(f"工具无命令构造器: {action.tool}")
            if action.tool not in skill.manifest.required_tools:
                raise PlanValidationError(
                    f"工具 {action.tool} 不在 skill {action.skill} 的 required_tools 内"
                )

    def _audit(self, event: str, **fields) -> None:
        if self.audit is not None:
            self.audit.record(event, **fields)
