"""黑盒未授权数据暴露判定（M35）：不依赖"已认证视图"的未授权确认。

## 为什么需要这个模块

`unauth-exposure` 原先只有一条确认手段：**匿名视图 ≡ 已认证视图**（M16-c 裁定，
见 :func:`proofhound.verify.unauth_control.judge_unauth`）。这在黑盒 engagement
（真实渗透的常态起点：根本没有凭据）里=恒不可用——13 条候选实测全部停在
`verify_type_unavailable`。

但"**未认证客户端拿到了不该公开的数据**"本身是可复现的二值事实，缺的只是一个
不依赖第二身份的判据。M16-c 拒绝的是"让 LLM 的语义判断当证据"，不是"拒绝一切
没有第二视图的确认"。

## 判据（四条，全部确定性、零 LLM）

1. **匿名 2xx** 且响应是**结构化数据**（JSON 可解析）——非 2xx 是"资源要求认证"，
   直接驳回；
2. **无效凭据对照逐字节相同**：再发一次同样的请求，只多带一个
   ``Cookie: ph_invalid=<随机>``。正文与匿名响应**完全相同** ⇒ 该端点**忽略凭据**
   （而不是把我们当成了某个已登录用户，也不是"每次响应都不同"的随机页面）；
3. **≥2 个敏感字段的取值**（而不是 ≥2 条记录）：字段名命中硬编码词表
   （email/phone/token/password/id_card/...）且取值非空。两条独立敏感值足以把
   "就一个公开对象的某个公开字段"排除掉；
4. 命中即确认；**零命中 → 驳回**（测过了，匿名拿到的内容不含敏感数据——与
   `error-disclosure` 的"零标记 → rejected"同一语义：测过且干净）。

其余一切（网络错、非结构化、对照不可用、对照与匿名不一致、状态码不同）→
``blocked``：判不了就停 Hypothesis，**既不驳回也不确认**（宁漏勿滥）。

## 敏感度为什么不算"语义判断"

字段词表是**硬编码常量**，取值判定是"非空字符串"——两者都可复现、可单测。
M16-c 的 T1 敏感度判定器（`verify/unauth_judge.py`）仍然**只做报告分类、不产证据**。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from proofhound.verify.idor import IdorResponse

#: 确认手段（写进 ``verification.method``，进 `VULN_REGISTRY` 的 methods 白名单）
UNAUTH_ANON_METHOD = "unauth-anon-data-confirmed"

#: 三态
ANON_CONFIRMED = "confirmed"
ANON_REJECTED = "rejected"
ANON_BLOCKED = "blocked"

#: 敏感字段名（小写精确匹配）。刻意**不收** ``id``/``name``/``type`` 这类泛化字段：
#: 它们既可能是敏感数据，也可能是完全公开的元数据。
SENSITIVE_FIELD_HINTS = frozenset(
    {
        "email",
        "mail",
        "e_mail",
        "user_email",
        "phone",
        "mobile",
        "telephone",
        "tel",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "secret",
        "password",
        "passwd",
        "pwd",
        "id_card",
        "idcard",
        "id_number",
        "ssn",
        "passport",
        "internal_ip",
        "private_ip",
        "session_id",
        "sessionid",
    }
)

#: 确认所需的**独立敏感值**条数（见模块 docstring 第 3 条）
MIN_SENSITIVE_VALUES = 2
#: 单次遍历的命中上限（防止大响应体把证据撑爆）
MAX_HITS = 20
#: 数组遍历上限
MAX_ITEMS = 50


@dataclass
class AnonJudgment:
    """黑盒未授权判定的结构化结果（全部依据落判定 JSON，供离线复核）。"""

    verdict: str
    anon_status: int | None
    control_status: int | None
    byte_identical: bool
    structured: bool
    sensitive_hits: list[dict] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def as_summary(self) -> dict:
        return {
            "verdict": self.verdict,
            "anon_status": self.anon_status,
            "control_status": self.control_status,
            "byte_identical": self.byte_identical,
            "structured": self.structured,
            "sensitive_values": len(self.sensitive_hits),
            "sensitive_hits": self.sensitive_hits,
            "reasons": self.reasons,
        }


def _nonempty(value) -> bool:
    """取值是否"有内容"（空串/None/纯空白不算；数字/布尔不算敏感）。"""
    return isinstance(value, str) and len(value.strip()) >= 3


def collect_sensitive(node, path: str = "", out: list[dict] | None = None) -> list[dict]:
    """递归提取敏感字段（字段名命中词表且取值非空），保序、有上限。"""
    if out is None:
        out = []
    if len(out) >= MAX_HITS:
        return out
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            if isinstance(value, (dict, list)):
                collect_sensitive(value, child, out)
            elif str(key).lower() in SENSITIVE_FIELD_HINTS and _nonempty(value):
                out.append({"path": child, "field": str(key).lower()})
            if len(out) >= MAX_HITS:
                break
    elif isinstance(node, list):
        for index, item in enumerate(node[:MAX_ITEMS]):
            collect_sensitive(item, f"{path}[{index}]", out)
            if len(out) >= MAX_HITS:
                break
    return out


def parse_structured(body: str):
    """响应正文 → 结构化对象；不是 JSON 即 ``None``（不做 XML/CSV 猜测）。"""
    text = (body or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def judge_anon_data(anon: IdorResponse, control: IdorResponse) -> AnonJudgment:
    """黑盒未授权判定的确定性实现（零 LLM、零网络）。

    ``anon``    = **完全不发凭据**请求该 URL 的响应；
    ``control`` = 同一请求 + ``Cookie: ph_invalid=<随机>`` 的响应（无效凭据对照）。
    """
    base = dict(
        anon_status=anon.status,
        control_status=control.status,
        byte_identical=False,
        structured=False,
    )

    if anon.error is not None:
        return AnonJudgment(
            verdict=ANON_BLOCKED,
            reasons=[f"匿名请求失败（覆盖不全）: {anon.error}"],
            **base,
        )

    status = anon.status
    if status is None or not (200 <= status < 300):
        if status is not None and (status in (401, 403) or 300 <= status < 400):
            return AnonJudgment(
                verdict=ANON_REJECTED,
                reasons=[f"匿名被拒（{status}）→ 该资源本就要求认证，未授权暴露不成立"],
                **base,
            )
        return AnonJudgment(
            verdict=ANON_BLOCKED,
            reasons=[f"匿名响应状态异常（{status}），判不了"],
            **base,
        )

    payload = parse_structured(anon.body)
    if payload is None:
        return AnonJudgment(
            verdict=ANON_BLOCKED,
            reasons=["匿名 2xx 但响应不是结构化数据（JSON），本判据不适用"],
            **base,
        )
    base["structured"] = True

    if control.error is not None or control.status != status:
        return AnonJudgment(
            verdict=ANON_BLOCKED,
            reasons=[
                "无效凭据对照不可用"
                f"（status={control.status}, error={control.error}）→ 无法排除"
                "『凭据被忽略』之外的其他解释"
            ],
            **base,
        )

    identical = anon.body == control.body
    base["byte_identical"] = identical
    if not identical:
        return AnonJudgment(
            verdict=ANON_BLOCKED,
            reasons=[
                "无效凭据对照与匿名响应不同（长度/内容有差异）→ 判不了"
                "（可能是随机内容，也可能把无效凭据当成了某个身份）"
            ],
            **base,
        )

    hits = collect_sensitive(payload)
    if len(hits) < MIN_SENSITIVE_VALUES:
        return AnonJudgment(
            verdict=ANON_REJECTED,
            sensitive_hits=hits,
            reasons=[
                f"匿名拿到的是结构化数据，但敏感值仅 {len(hits)} 个"
                f"（要求 ≥{MIN_SENSITIVE_VALUES}）→ 不构成未授权数据暴露"
            ],
            **base,
        )

    return AnonJudgment(
        verdict=ANON_CONFIRMED,
        sensitive_hits=hits,
        reasons=[
            f"匿名 2xx 且无效凭据对照逐字节相同（凭据被忽略）；"
            f"提取到 {len(hits)} 个敏感值"
        ],
        **base,
    )


__all__ = [
    "ANON_BLOCKED",
    "ANON_CONFIRMED",
    "ANON_REJECTED",
    "MAX_HITS",
    "MIN_SENSITIVE_VALUES",
    "SENSITIVE_FIELD_HINTS",
    "UNAUTH_ANON_METHOD",
    "AnonJudgment",
    "collect_sensitive",
    "judge_anon_data",
    "parse_structured",
]
