"""IDOR 判定加固（M11b）：未认证对照探测 + 确定性属性归属提取。

**动因**（M10a 限制 35/37 与 M11a 裁决）：M10a 实测同一个真 IDOR 在 4 个臂里
出现 4 种结果。M11a 逐条复核 4 臂全部 11 条 IDOR 终审原文后把归因**修正为
规格歧义**——11 条里 7 条 reject 有 6 条判得正确（那些是对 ``/a/sqli``、
``/b/sqli2``、``/d/safe`` 之类**非 IDOR 端点**的类型误报，即限制 37），
真 IDOR 的驳回理由则逐字同构：① 无对象归属证据；② 两份响应 sha256 完全相同，
更平凡的解释是"公开内容"；③ 缺一个能排除公开端点的对照。决定性证据是同一
``/b/idor2`` 在**同一次运行**的两个臂里被判了两种标准。

维护者据此裁决三条，本模块落第 1 与第 3 条（第 2 条的"要求归属证据"由
``judge_ownership`` 提供判据，编排层据其收紧终态）：

1. **未认证对照探测**：对同一 URL 追加一次**不带任何凭据**的请求，用**纯确定性
   代码**判定该资源是否为公开/与会话无关——这是 Verifier 反复索要却拿不到的
   那个对照（其原话："缺少第三对照（未认证请求、A 请求自有对象、或响应中含可
   归属 B 的私有字段的证据）来排除此解释"）；
2. （判据由本模块的 :func:`judge_ownership` 提供）
3. **归属由确定性代码提取，Verifier 只收结论 + 行号锚点**：归属事实由本模块
   纯函数从响应中提取并归一化为**结论**（`matched` / `mismatched` /
   `absent` + 匹配字面量 + 证据文件#行号锚点），**响应体原文一行不进 prompt**
   ——红线 3 的输入边界**零放松**（红线 3 约束的是 **LLM 上下文**不得含原始
   输出，不是禁止代码读取磁盘上的证据文件）。

本模块与 :mod:`proofhound.verify.idor` 的分工：那里负责"双会话属性违反"本身，
这里负责"该违反是否可信"的两个**否定性**判据（是否公开资源、归属是否成立）。
两者都是纯函数、阈值写死、判定依据全量结构化记录。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from proofhound.verify.idor import (
    IdorResponse,
    body_similarity,
    status_class,
)

#: 对照判定：未认证响应与 B 基准正文相似度 ≥ 该值即视为"同一份内容" → 公开资源
PUBLIC_SIMILARITY_THRESHOLD = 0.9

#: 对照判定：未认证响应正文与 B 基准**逐字节相同**（sha256 相同）→ 公开资源（铁证）
#: 该判据不依赖相似度阈值，优先于阈值判据。

#: 归属提取：值字段的最大长度（防止把整段正文当值抓进来）
_OWNER_VALUE_MAX = 64

# ---- 归属提取：字段名标记 + 值标记，两族都要命中才算证据 --------------------

#: 字段名标记（归属字段的**名**部分，中英双语）
_OWNER_KEYS: tuple[str, ...] = (
    "owner",
    "所有者",
    "所属",
    "归属",
    "拥有人",
    "属主",
    "创建者",
    "created_by",
    "creator",
    "author",
    "用户",
    "user",
    "username",
    "account",
    "account_owner",
    "holder",
    "uid",
    "user_id",
)

#: **非归属**字段名（用户名/账号类字段是"当前登录者"而非"对象所有者"，混入会
#: 把"页面回显登录名"误判成归属证据——宁漏勿滥）
#: 注：`username`/`user` 归入上方是刻意的（多数系统确用它表达归属），
#: 但 `session_user`/`current_user`/`login` 这类明确指"当前会话者"的排除。
_NOT_OWNER_KEYS: tuple[str, ...] = (
    "current_user",
    "session_user",
    "login_user",
    "loginuser",
    "logged_in",
    "viewer",
    "me",
)

#: 归属字段名（文本形态用；与 JSON 形态共用一份，避免两处漂移）
_OWNER_TEXT_KEYS = r"(?:所有者|拥有人|创建者|owner|created_by|creator|author)"

#: 文本形态 ①：有明确分隔符（``所有者：owner``、``Owner: owner``、``所有者=owner``）
_OWNER_TEXT_RE = re.compile(
    r"(" + _OWNER_TEXT_KEYS + r")\s*[:：=]\s*"
    r"([^\s<>\"',，。；;]{1," + str(_OWNER_VALUE_MAX) + r"})",
    re.IGNORECASE,
)

#: 文本形态 ②：无分隔符、仅空白（``所有者 owner``）；值在标点/空白处终止。
#: **排除类必须含全角标点**：中文正文里值后常紧跟 ``，``/``。``，漏掉会让正则把
#: 后续散文一并吃掉（实测 ``所有者 owner，金额 800`` → 值 ``owner，金额``）。
_OWNER_TEXT_SPACE_RE = re.compile(
    r"(" + _OWNER_TEXT_KEYS + r")\s+"
    r"([^\s<>\"'=：:，。；;、,）)】\]]{1," + str(_OWNER_VALUE_MAX) + r"})",
    re.IGNORECASE,
)

#: **刻意不含** ``属主``/``所属``/``归属`` 这类**泛化叙述词**：它们在中文正文里常作
#: 散文出现（如 ``（属主 B）``），若纳入正则会把它当成归属字段、值被截成 ``B）``
#: ——实测该缺陷会让 mismatched 分支取到散文而非真正的 ``owner=`` 字段。

#: JSON 形态：``"owner": "owner"`` / ``"所有者": "owner"``
_OWNER_JSON_RE = re.compile(
    r'"(?:owner|所有者|所属|归属|拥有人|属主|创建者|created_by|creator|author|'
    r'user|username|account|holder|uid|user_id)"\s*:\s*"?([^",}\s]{1,'
    + str(_OWNER_VALUE_MAX)
    + r'})"?',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class OwnerEvidence:
    """归属提取结果（判定结论 + 匹配字面量 + **证据锚点**）。

    ``line_no`` 是**落盘证据文件里的行号**（1-based），使 Verifier 能凭
    "结论 + 行号锚点"复核，而无需看到响应体原文（红线 3）。
    """

    verdict: str  # matched / mismatched / absent
    field: str | None = None
    value: str | None = None
    line_no: int | None = None

    def as_summary(self) -> dict:
        return {
            "verdict": self.verdict,
            "field": self.field,
            "value": self.value,
            "line_anchor": self.line_no,
        }


def body_sha256(body: str) -> str:
    """正文 sha256（对照判定的铁证；也用于审计/摘要的一致性核对）。"""
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _iter_owner_matches(body: str):
    """产出 ``(shape, field, value)`` 候选；``shape`` ∈ ``{"json", "text"}``。

    两形态分别产出，由调用方决定优先级（结构化 JSON 形态优先于散文文本形态）。
    """
    for match in _OWNER_JSON_RE.finditer(body):
        raw_key = match.group(0)
        key = raw_key.split(":", 1)[0].strip().strip('"')
        value = match.group(1).strip().strip('"')
        if key.lower() in _NOT_OWNER_KEYS:
            continue
        if value:
            yield "json", key, value
    for regex in (_OWNER_TEXT_RE, _OWNER_TEXT_SPACE_RE):
        for match in regex.finditer(body):
            key = match.group(1).strip(" :：=")
            # 剥离首尾标点/空白：中文正文里值后面常紧跟全角逗号/句号
            # （实测 ``所有者 owner，金额 800`` 会被抓成 ``owner，金额``）
            value = match.group(2).strip().strip("，。；;、,.:：=）)】]\"'")
            if key.lower() in _NOT_OWNER_KEYS:
                continue
            # 排除"把字段名本身当值"的退化情形（如 `owner owner`）
            if value and value.lower() != key.lower():
                yield "text", key, value


def _line_of(body: str, needle: str) -> int | None:
    """``needle`` 在正文中的行号（1-based）；找不到返回 None。"""
    if not needle:
        return None
    for index, line in enumerate(body.splitlines(), start=1):
        if needle in line:
            return index
    return None


def judge_ownership(baseline: IdorResponse, victim_identity: str | None) -> OwnerEvidence:
    """从 **B（reference/victim）基准响应** 中确定性提取对象归属证据。

    判据（两族都要命中）：① 字段名像归属字段（``owner``/``所有者``/...，
    且不在 ``_NOT_OWNER_KEYS`` 排除表内）；② 该字段的**值**等于 reference
    身份标识（大小写不敏感）。

    - 命中且值 == reference 身份 → ``matched``（对象确属 reference 私有）；
    - 命中但值 != reference 身份 → ``mismatched``（对象属**别人**：要么归属
      是第三方，要么目标在自报一个与会话无关的公共所有者）；
    - 一个都没命中 → ``absent``（**无归属证据**——按 M11a 裁决第 2 条不得确认）。

    ``victim_identity`` 为 None（操作员未提供 reference 身份标识）时一律
    ``absent``：没有可比对的期望值，就无法把字段值认定为"归属证据"
    （**不做"只要有 owner 字段就算证据"的放松**，那会把任意第三方归属也当证据）。

    fail-closed：本函数只读入参、不抛异常、不联网、不调 LLM。
    """
    if not victim_identity or not victim_identity.strip():
        return OwnerEvidence(verdict="absent")
    wanted = victim_identity.strip().lower()
    mismatch: OwnerEvidence | None = None
    # 两轮：**先 JSON 形态**（结构化字段比散文可信），再文本形态。原实现"先命中
    # 先记"会让更早出现的散文命中盖过真正的结构化归属字段。
    for shapes in (("json",), ("text",)):
        for shape, key, value in _iter_owner_matches(baseline.body):
            if shape not in shapes:
                continue
            line_no = _line_of(baseline.body, value)
            if value.strip().lower() == wanted:
                return OwnerEvidence(
                    verdict="matched", field=key, value=value, line_no=line_no
                )
            if mismatch is None:
                mismatch = OwnerEvidence(
                    verdict="mismatched", field=key, value=value, line_no=line_no
                )
    if mismatch is not None:
        return mismatch
    return OwnerEvidence(verdict="absent")


@dataclass(frozen=True)
class ControlJudgment:
    """未认证对照判定结果（判定依据全量结构化记录）。"""

    verdict: str  # public / protected / blocked
    c_status: int | None
    c_error: str | None
    similarity: float
    same_bytes: bool
    reasons: list[str] = field(default_factory=list)

    def as_summary(self) -> dict:
        return {
            "verdict": self.verdict,
            "control_status": self.c_status,
            "control_error": self.c_error,
            "similarity_to_baseline": round(self.similarity, 3),
            "byte_identical_to_baseline": self.same_bytes,
            "reasons": list(self.reasons),
        }


def judge_control(baseline: IdorResponse, control: IdorResponse) -> ControlJudgment:
    """未认证（第三对照）请求的确定性判定。

    语义：**"未认证也能拿到与 B 基准同样的内容"就是公开资源**——此时两个身份
    拿到相同内容属预期行为，谈不上属性违反（这正是 Verifier 反复指出的更平凡
    解释）。反之未认证被拒（3xx/4xx/5xx 或网络错误）或拿到明显不同的内容，
    说明资源与会话相关，属性违反的解释站得住。

    三态：

    - ``public``：未认证 2xx **且**（正文与 B 基准逐字节相同 **或** 相似度 ≥
      :data:`PUBLIC_SIMILARITY_THRESHOLD`）→ **属性违反不成立**，编排层驳回；
    - ``protected``：未认证非 2xx（3xx/4xx/5xx）→ 资源受会话保护，属性违反
      解释成立，放行给 Verifier；
    - ``blocked``：未认证请求网络错误，或未认证 2xx 但内容与 B 基准既不逐字节
      相同、相似度也低于阈值 → **判定不了**（覆盖不全）→ 编排层 **blocked**，
      不驳回也不确认（fail-closed；宁可不判，也不猜）。

    为什么 ``blocked`` 不直接放行：内容"不同但不相似"同样符合"两个身份看到
    不同数据"这一**合法**形态，把它当成越权证据是会误报的方向；而"相同/高度
    相似"才是可以**否定**违反的硬证据。故只否定、不肯定。
    """
    reasons: list[str] = []
    c_status = control.status
    c_class = status_class(c_status)
    similarity = body_similarity(baseline.body, control.body)
    same_bytes = (
        bool(control.body) and body_sha256(baseline.body) == body_sha256(control.body)
    )

    reasons.append(f"未认证对照响应：状态 {c_status}（{c_class}）")
    if same_bytes:
        reasons.append("未认证响应与 B 基准**逐字节相同**（sha256 一致）")
    else:
        reasons.append(f"未认证响应与 B 基准正文相似度 {similarity:.3f}")

    if control.error is not None:
        reasons.append(f"未认证对照请求失败（覆盖不全，不驳回）：{control.error}")
        return ControlJudgment(
            verdict="blocked",
            c_status=c_status,
            c_error=control.error,
            similarity=similarity,
            same_bytes=False,
            reasons=reasons,
        )

    if c_class != "ok":
        reasons.append(
            f"未认证被拒（{c_class}）→ 资源与会话相关，属性违反解释成立"
        )
        return ControlJudgment(
            verdict="protected",
            c_status=c_status,
            c_error=None,
            similarity=similarity,
            same_bytes=same_bytes,
            reasons=reasons,
        )

    if same_bytes or similarity >= PUBLIC_SIMILARITY_THRESHOLD:
        reasons.append(
            "未认证即可获得与 B 基准等价的内容 → 更平凡的解释是**公开/与会话"
            "无关的资源**，属性违反不成立"
        )
        return ControlJudgment(
            verdict="public",
            c_status=c_status,
            c_error=None,
            similarity=similarity,
            same_bytes=same_bytes,
            reasons=reasons,
        )

    reasons.append(
        "未认证 2xx 但内容与 B 基准既不逐字节相同、相似度也低于阈值 → "
        "无法据此排除公开资源（覆盖不全）"
    )
    return ControlJudgment(
        verdict="blocked",
        c_status=c_status,
        c_error=None,
        similarity=similarity,
        same_bytes=same_bytes,
        reasons=reasons,
    )


def control_summary(
    control: ControlJudgment, ownership: OwnerEvidence
) -> dict:
    """送审摘要里的确定性结论块（**含行号锚点**，不含响应体原文）。

    这是"归属由代码提取、Verifier 只收结论 + 锚点"的落地形态：``owner`` 只给
    结论与匹配字面量/行号，``verdict`` 只给三态枚举与数值，红线 3 的输入边界
    不放松。
    """
    return {
        "unauthenticated_control": control.as_summary(),
        "object_ownership": ownership.as_summary(),
    }


def summary_to_json(summary: dict) -> str:
    """把送审摘要块序列化成 JSON（编排层写审计/判定 JSON 用；纯确定性）。"""
    return json.dumps(summary, ensure_ascii=False, sort_keys=True)


__all__ = [
    "PUBLIC_SIMILARITY_THRESHOLD",
    "ControlJudgment",
    "OwnerEvidence",
    "body_sha256",
    "control_summary",
    "judge_control",
    "judge_ownership",
    "summary_to_json",
]
