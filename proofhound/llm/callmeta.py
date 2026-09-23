"""归属元数据的**尽力**传参助手（M11a）。

成本可见性的前置是「每次 LLM 调用能归属到调用方 / Finding」。但生产路径与
测试替身/旧实现的签名并不一致：

- 生产：``ModelRouter.complete(tier, messages, *, caller, finding_id, retry)``
  （M11a 起接受这三个可选 kwargs）；
- 替身/旧实现：常写成 ``def complete(self, tier, messages)``——直接传
  kwargs 会 TypeError。

**本模块把分派做成确定性的**：调用前按签名判定，而不是捕获 ``TypeError``
去猜（猜法会把真实业务异常也吞掉）。两条纪律：

1. 目标**接受全部**待传键 → 原样传（生产路径，归属信息完整）；
2. 否则**一个都不传**（旧契约，逐字节等价于 M11a 之前；归属信息缺省，
   由 ``llm/cost.py`` 归入 ``unknown`` 桶而非静默丢弃）。

调用形态为 ``func(*leading, messages, **meta)``——``leading`` 是消息之前的
位置参数（路由器为 ``(tier,)``，档位客户端为 ``()``），故与真实签名
逐位对齐、不可能错位。

``functools.wraps`` 会保留 ``__wrapped__``，而 :func:`inspect.signature`
默认跟随它——故被包装过的可调用对象仍能按内层真实签名正确判定。
"""

from __future__ import annotations

import inspect
from typing import Callable


def accepts_kwargs(func: Callable, meta: dict) -> bool:
    """目标函数是否显式接受 ``meta`` 的全部键（``**kwargs`` 视为接受）。"""
    try:
        params = inspect.signature(func).parameters
    except (TypeError, ValueError):  # 内建/不可反射对象：保守不传
        return False
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return True
    return all(
        key in params
        and params[key].kind
        in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
        for key in meta
    )


def call_with_meta(
    func: Callable,
    *leading,
    messages: list[dict],
    meta: dict | None = None,
    error_wrapper: Callable[[str], Exception] | None = None,
):
    """调用 ``func(*leading, messages, **meta)``；目标不接受这些键时退化为
    ``func(*leading, messages)``。

    ``error_wrapper`` 给定且调用抛 ``TypeError`` 时，用其包装成调用方自己的
    错误类型（路由器沿用"档位调用失败即 LLMError"的既有契约）；给 ``None``
    则原样上抛（修复重试路径的旧语义）。
    """
    meta = dict(meta or {})
    if meta and not accepts_kwargs(func, meta):
        meta = {}
    try:
        return func(*leading, messages, **meta)
    except TypeError as exc:
        if error_wrapper is None:
            raise
        raise error_wrapper(f"{exc}") from exc


__all__ = ["accepts_kwargs", "call_with_meta"]
