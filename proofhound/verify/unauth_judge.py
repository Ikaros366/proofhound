"""未授权暴露的**独立 AI 判定器**（M16-c，形态 B 的落地；§5.4.2 / design.md §7.15）。

## 它在链路里的位置（以及为什么放在这里）

    web-probe Signal → web-exposure 候选（确定性规则表，M3a）
                                   ↓
                    verify-unauth 编排（`_verify_unauth`）
                                   ↓
        ① 确定性前置门 `unauth_control.judge_unauth`  ← 唯一产证据的地方
                                   ↓（仅 exposed 态才往下走）
        ② 本模块：独立 AI 判定器       ← 只产"结论 + 行号锚点"
                                   ↓
        ③ Verifier 终审（T2）          ← 只收枚举/数值/锚点，响应体不进 prompt

## 三条硬边界（都不是"约定"，是可测的性质）

1. **本模块的结论不构成 Confirmed 的证据**。`GATE_MATRIX["unauth-exposure"]` 的
   `methods` / `behavioral_kinds` 只认前置门的产物（`unauth-equivalence-confirmed` /
   `unauth-response-equivalence`）。故**判定器即使判错，也不可能造成误确认**——
   它最多影响报告的叙述与敏感度分类。这是 M16-c 裁定里"AI 结论不得当证据"的
   可测落地：`tests/test_unauth_judge.py` 用"判定器说 not sensitive 但门判 exposed"
   证明 Finding **照样能** Confirmed（证据来自门，不来自判定器）。

2. **只看过了门的那份响应，且输入经脱敏 + 截断**。截断上限
   :data:`MAX_JUDGE_BODY_CHARS` 与脱敏清单由调用方给出；**实际送审的文本落盘**
   （`evidence/unauth_judge_<id>_sent.txt`），使"判定器到底看到了什么"可离线复核。

3. **输出 Pydantic 强校验，非法即 fail-closed**（抛 :class:`UnauthJudgeError`，
   零结论、不降级、不猜）。

## 与 Verifier 的关系（输入边界不动）

判定器的输出是**结构化结论 + 行号锚点**，与 Verifier 的输入纪律同源；
编排层把它塞进 `Verifier.review(extra_summary=...)` 的确定性块里——
**它是结论，不是证据**。红线 3 对 Verifier 的约束**一字未改**。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from proofhound.llm.repair import complete_structured
from proofhound.llm.router import Tier

#: 送判定器的响应正文**字符**上限（截断，不是拒绝）。
#:
#: 取这个量级的原因：判定器只需要判断"这段内容是否敏感"，不需要读完整页面；
#: 而超大响应既费 token 又把无关内容塞进上下文。截断事实会写进送审记录与审计，
#: 使"判定器没看到全文"这一覆盖边界**可见**（宁漏勿滥方向）。
MAX_JUDGE_BODY_CHARS = 8000

#: 敏感度分类枚举（判定器只能从这里选；白名单 fail-closed）。
SENSITIVE_CATEGORIES: frozenset[str] = frozenset(
    {
        "credentials",       # 口令/密钥/token/证书类
        "pii",               # 个人身份信息（姓名/证件/联系方式/地址）
        "internal_config",   # 内部配置/调试信息/环境变量/堆栈
        "business_data",     # 业务数据（订单/客户/财务/报表）
        "admin_function",    # 管理功能界面/后台入口
        "other",             # 敏感但不属上述
        "none",              # 判定为不敏感（与 sensitive=False 搭配）
    }
)


class UnauthJudgeError(RuntimeError):
    """判定失败：LLM 异常或输出非法（非法输出零结论，不降级）。"""


class _JudgmentOut(BaseModel):
    """判定器输出的 schema（强校验，非法即整个结论作废）。"""

    sensitive: bool
    category: Literal[
        "credentials", "pii", "internal_config", "business_data",
        "admin_function", "other", "none",
    ]
    anchors: list[str] = Field(default_factory=list)
    reason: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("anchors")
    @classmethod
    def _anchors_shape(cls, value: list[str]) -> list[str]:
        """锚点必须是 ``L<数字>`` 形态（行号锚点，不是自由文本）。"""
        out: list[str] = []
        for item in value:
            if not re.fullmatch(r"L\d{1,7}", item.strip()):
                raise ValueError(f"锚点必须是 L<行号> 形态：{item!r}")
            if item.strip() not in out:
                out.append(item.strip())
        return out


@dataclass
class UnauthJudgmentResult:
    """判定器结论（结构化；**不是证据**）。"""

    sensitive: bool
    category: str
    anchors: list[str] = field(default_factory=list)
    reason: str = ""
    confidence: float = 0.0
    model: str = ""
    truncated: bool = False
    sent_chars: int = 0

    def as_summary(self) -> dict:
        """塞进 Verifier `extra_summary` 的块（**无响应体**，只有结论与锚点）。"""
        return {
            "judge_sensitive": self.sensitive,
            "judge_category": self.category,
            "judge_anchors": list(self.anchors),
            "judge_confidence": round(self.confidence, 3),
            "judge_model": self.model,
            "judge_input_truncated": self.truncated,
            "judge_input_chars": self.sent_chars,
        }


_SYSTEM_PROMPT = """你是渗透测试报告里的**敏感度评审员**。

给你一段 HTTP 响应正文（可能被截断）。它已经被**独立于你的确定性判据**确认为：
匿名未认证客户端与已认证客户端请求同一 URL 得到**等价内容**。
所以**不要**再判断"是否未授权暴露"——那已经确定。

你只需回答一件事：**这段内容里是否存在不该对未认证者公开的信息**。

输出严格 JSON（不要 markdown 代码围栏、不要解释文字）：

{
  "sensitive": true/false,
  "category": "credentials|pii|internal_config|business_data|admin_function|other|none",
  "anchors": ["L12", "L40"],
  "reason": "一句话说明依据（中文）",
  "confidence": 0.0~1.0
}

纪律：

- `anchors` 是**行号锚点**，形如 `L12`，指向上文正文里支撑你结论的那几行。
  必须来自给定文本的真实行；不要编造。
- `sensitive=false` 时 `category` 必须是 `"none"`，`anchors` 可为空。
- **纯导航/欢迎页/公开文档/静态资源列表** → `sensitive=false`。
- **只判内容是否敏感**，不要因为"这是管理页"就自动判敏感；要看内容本身。
- 拿不准就 `sensitive=false` 并降低 `confidence`（本项目宁漏勿滥）。
"""


def _sanitize(body: str, secrets: list[str]) -> tuple[str, bool]:
    """脱敏 + 截断；返回 ``(文本, 是否截断)``。

    脱敏与 `compliance/session.redact_bytes` 同源（同一份 secrets 清单），
    但此处作用于 str 并按**字符**截断（送审上限以字符计）。
    """
    text = body
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, "sha256:REDACTED")
    if len(text) > MAX_JUDGE_BODY_CHARS:
        return text[:MAX_JUDGE_BODY_CHARS], True
    return text, False


class UnauthJudge:
    """独立 AI 判定器（T1 档：分类任务，按 §5.3 分级用中档模型）。"""

    def __init__(self, router, audit=None):
        self.router = router
        self.audit = audit

    def judge(
        self,
        body: str,
        *,
        finding_id: str,
        url: str,
        secrets: list[str] | None = None,
    ) -> UnauthJudgmentResult:
        """判定 ``body`` 是否含不宜公开的敏感信息。

        失败语义：LLM 异常/预算/上下文超限**原样上抛**；输出非法抛
        :class:`UnauthJudgeError`——调用方必须 fail-closed（**不确认**，
        但**不驳回**：判定器失败属"覆盖不全"，不是"没暴露"）。
        """
        sent, truncated = _sanitize(body, list(secrets or []))
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"URL: {url}\n"
                    f"（正文{len(sent)}字符"
                    + ("，已截断" if truncated else "，未截断")
                    + "）\n\n----- 正文开始 -----\n"
                    f"{sent}\n"
                    "----- 正文结束 -----"
                ),
            },
        ]
        parsed = complete_structured(
            self.router,
            Tier.T1,
            messages,
            self._parse,
            audit=self.audit,
            caller="unauth_judge",
            finding_id=finding_id,
        )
        if self.audit is not None:
            self.audit.record(
                "unauth_judge_verdict",
                finding_id=finding_id,
                sensitive=parsed.sensitive,
                category=parsed.category,
                anchors=list(parsed.anchors),
                confidence=round(parsed.confidence, 3),
                truncated=truncated,
                sent_chars=len(sent),
            )
        return UnauthJudgmentResult(
            sensitive=parsed.sensitive,
            category=parsed.category,
            anchors=list(parsed.anchors),
            reason=parsed.reason,
            confidence=parsed.confidence,
            model=self._model_name(),
            truncated=truncated,
            sent_chars=len(sent),
        )

    def _parse(self, raw: str) -> _JudgmentOut:
        """严格解析（非法即抛，由 `complete_structured` 决定是否修复重试一次）。"""
        text = raw.strip()
        # 容错：模型偶尔仍会包 markdown 围栏
        if text.startswith("```"):
            text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
            text = re.sub(r"\s*```$", "", text).strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise UnauthJudgeError(f"判定器输出非 JSON：{exc}") from exc
        if not isinstance(data, dict):
            raise UnauthJudgeError("判定器输出不是 JSON 对象")
        try:
            out = _JudgmentOut.model_validate(data)
        except ValidationError as exc:
            raise UnauthJudgeError(f"判定器输出不合 schema：{exc}") from exc
        # 语义一致性（fail-closed：不自洽的输出一律作废）
        if not out.sensitive and out.category != "none":
            raise UnauthJudgeError(
                f"sensitive=false 但 category={out.category!r}（应为 none）"
            )
        if out.sensitive and out.category == "none":
            raise UnauthJudgeError("sensitive=true 但 category=none（不自洽）")
        return out

    def _model_name(self) -> str:
        try:
            configs = getattr(self.router, "configs", {})
            cfg = configs.get(Tier.T1)
            return getattr(cfg, "model", "") or ""
        except Exception:  # noqa: BLE001 —— 只用于展示，绝不影响判定
            return ""


__all__ = [
    "MAX_JUDGE_BODY_CHARS",
    "SENSITIVE_CATEGORIES",
    "UnauthJudge",
    "UnauthJudgeError",
    "UnauthJudgmentResult",
]
