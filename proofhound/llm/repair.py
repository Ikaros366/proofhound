"""结构化输出修复重试（M6a）：一次携带错误反馈的追问，原失败语义不变。

- 结构化输出调用点（T1 规划 / T1 叙述 / T2 Verifier）在 JSON 解析或校验
  失败时，携带原始输出（assistant 轮次）+ 错误描述追问一次，要求仅输出
  修正后的 JSON；**全程最多 1 次修复重试**（无循环）；
- 重试仍走 ``router.complete``（同档）：token 计量与 Run 级预算硬闸天然
  覆盖——中途超预算照旧 :class:`BudgetExceededError` 原样上抛；
- 第二次仍失败 → 抛**第二次的异常**（与首次同类型），调用点既有失败语义
  （plan_rejected / NarrativeError 零写入 / VerifierError fail-closed）
  逐字保留，fail-closed 不变；
- 修复是"尽力而为"：修复调用本身失败时回退抛**首次**校验错误（首次失败
  已是确定性结论）——``LLMError`` 记审计 ``result="error"``，其余异常
  （含测试替身回复队列耗尽）不记审计直接回退；
- ``max_chars`` 给定且修复消息超字符硬上限 → 记 ``skipped_overflow``，
  抛首次错误（禁静默截断纪律不因重试破坏）；
- 审计 ``llm_repair_attempt{tier, caller, error_type, result}``，
  result ∈ success / failed / error / skipped_overflow。
"""

from __future__ import annotations

from typing import Callable, TypeVar

from proofhound.compliance.audit import AuditLog
from proofhound.llm.client import LLMError
from proofhound.llm.usage import BudgetExceededError

T = TypeVar("T")

#: 修复追问的用户指令模板（错误描述截断上限，防止异常文本无限膨胀 prompt）
_ERROR_SNIPPET_MAX = 1000


def _messages_chars(messages: list[dict]) -> int:
    """与 core.context.messages_chars 同款的字符估算（内联以保持 llm/ 零 core 依赖）。"""
    return sum(len(str(m.get("content", ""))) for m in messages)


def _audit(audit: AuditLog | None, tier: str, caller: str, error: Exception, result: str) -> None:
    if audit is not None:
        audit.record(
            "llm_repair_attempt",
            tier=tier,
            caller=caller,
            error_type=type(error).__name__,
            result=result,
        )


def complete_structured(
    router,
    tier,
    messages: list[dict],
    parse: Callable[[str], T],
    *,
    audit: AuditLog | None = None,
    caller: str = "",
    max_chars: int | None = None,
) -> T:
    """结构化输出调用 + 一次修复重试。

    - ``router``：ModelRouter 或兼容替身（``complete(tier, messages)``）；
    - ``parse``：调用点现成的完整校验可调用（schema + 语义），非法输出抛
      调用点自己的错误类型——原失败语义由此自动保留；
    - 首轮的 ``LLMError``/``BudgetExceededError``/``ContextOverflowError``
      （调用前检查在调用点）不触发重试，原样上抛——非结构化调用不受影响。
    """
    tier_value = tier.value if hasattr(tier, "value") else str(tier)
    raw = router.complete(tier, messages)
    try:
        return parse(raw)
    except Exception as exc:
        first_error = exc  # 进入修复分支（仅限校验/解析失败）

    instruction = (
        f"你的上一次输出未通过校验（{caller or '结构化输出调用'}）：\n"
        f"{str(first_error)[:_ERROR_SNIPPET_MAX]}\n"
        "请针对上述错误修正，仅输出修正后的 JSON 对象"
        "（不要任何解释文字、不要代码围栏）。"
    )
    repair_messages = list(messages) + [
        {"role": "assistant", "content": raw},
        {"role": "user", "content": instruction},
    ]
    if max_chars is not None and _messages_chars(repair_messages) > max_chars:
        _audit(audit, tier_value, caller, first_error, "skipped_overflow")
        raise first_error

    try:
        retry_raw = router.complete(tier, repair_messages)  # 计量/预算硬闸在路由层
    except BudgetExceededError:
        raise  # 预算硬闸覆盖重试：原样上抛，不回退
    except LLMError:
        _audit(audit, tier_value, caller, first_error, "error")
        raise first_error from None
    except Exception:
        # 尽力而为：替身/实现缺陷不掩盖首次校验结论，不记审计
        raise first_error from None

    try:
        parsed = parse(retry_raw)
    except Exception:
        _audit(audit, tier_value, caller, first_error, "failed")
        raise  # 第二次的异常（同类型）：调用点原失败语义
    _audit(audit, tier_value, caller, first_error, "success")
    return parsed


__all__ = ["complete_structured"]
