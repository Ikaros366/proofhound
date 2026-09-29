"""M16-c：未授权暴露的确定性前置门（`verify/unauth_control.py`）。

锁四件事：

1. **三态语义**：`exposed` / `requires_auth` / `blocked`；
2. **与 `judge_control` 方向相反**（同一份输入、两个漏洞类型、结论相反）——
   防后人图省事合并两处逻辑（合并即静默改变其中一个类型的判定语义）；
3. **判据陷阱**：判据必须落在**响应字节**上，**不能**落在"正文提到某关键词"上；
4. **红线 3**：送审摘要里**不得**出现响应体原文。
"""

from __future__ import annotations

import json

import pytest

from proofhound.verify.idor import IdorResponse
from proofhound.verify.idor_control import judge_control
from proofhound.verify.unauth_control import (
    PUBLIC_SIMILARITY_THRESHOLD,
    UNAUTH_CONFIRMED_METHOD,
    UNAUTH_EQUIVALENCE_EVIDENCE_KIND,
    UnauthJudgment,
    judge_unauth,
    summary_to_json,
)

URL = "http://127.0.0.1:8080/admin/users"
OTHER = "http://127.0.0.1:8080/other"


def _resp(url=URL, status=200, body="", error=None):
    return IdorResponse(url=url, status=status, body=body, error=error)


# --------------------------------------------------------------- 三态语义


def test_byte_identical_is_exposed():
    """匿名拿到与已认证**逐字节相同**的内容 → 暴露成立（铁证，不依赖阈值）。"""
    j = judge_unauth(_resp(body="SECRET"), _resp(body="SECRET"))
    assert j.verdict == "exposed"
    assert j.byte_identical is True
    assert j.similarity == 1.0
    assert j.baseline_sha256 == j.anon_sha256


def test_high_similarity_is_exposed():
    """相似度达阈值也算（时间戳/CSRF token 等逐字节必然不同）。"""
    base = "A" * 500 + "csrf=aaa"
    anon = "A" * 500 + "csrf=bbb"
    j = judge_unauth(_resp(body=base), _resp(body=anon))
    assert j.verdict == "exposed"
    assert j.byte_identical is False
    assert j.similarity >= PUBLIC_SIMILARITY_THRESHOLD


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 404, 500, 503])
def test_anonymous_denied_is_requires_auth(status):
    """匿名被拒 → 资源本就要求认证 → **不成立**（编排层确定性驳回）。"""
    j = judge_unauth(_resp(body="SECRET"), _resp(status=status, body="denied"))
    assert j.verdict == "requires_auth"
    assert any("本就要求认证" in r for r in j.reasons)


def test_anonymous_2xx_but_different_content_is_blocked():
    """匿名 2xx 但内容既不同也不像 → **判不了**（不驳回也不确认）。"""
    j = judge_unauth(
        _resp(body="SECRET-ADMIN-DATA-" * 20),
        _resp(body="<html>public landing page</html>"),
    )
    assert j.verdict == "blocked"
    assert any("覆盖不全" in r for r in j.reasons)


def test_anonymous_network_error_is_blocked():
    j = judge_unauth(_resp(body="SECRET"), _resp(status=None, error="connection refused"))
    assert j.verdict == "blocked"
    assert any("覆盖不全" in r for r in j.reasons)


def test_url_mismatch_is_blocked_fail_closed():
    """同 URL 自检：两侧 URL 不同 → 对比不成立（fail-closed）。"""
    j = judge_unauth(_resp(url=URL, body="X"), _resp(url=OTHER, body="X"))
    assert j.verdict == "blocked"
    assert any("URL 不一致" in r for r in j.reasons)


# ------------------------------------------- 判据陷阱（关键词 ≠ 证据）


def test_mentioning_password_without_equivalence_is_not_exposed():
    """**判据陷阱**：正文里出现 `password` 字样，但两视图**不等价** ⇒ 必须 blocked。

    这条用例存在的理由：如果把判据落在"正文是否含敏感关键词"上，就会把
    "已认证看到完整配置、匿名只看到登录页"这种**合法**形态误判成暴露。
    本模块的判据只认**响应字节等价**，故必须 blocked。
    """
    authed = "<html>config: password=REAL_SECRET, apikey=ABC123</html>"
    anon = "<html>请先登录。password 字段需要认证</html>"
    j = judge_unauth(_resp(body=authed), _resp(body=anon))
    assert j.verdict == "blocked", (
        "两视图不等价却被判 exposed —— 说明判据落到了关键词上"
    )
    assert j.verdict != "exposed"


def test_equivalence_without_any_keyword_is_still_exposed():
    """反向：两视图逐字节相同但正文**不含任何敏感关键词** ⇒ 仍必须 exposed。

    证明本模块**不做关键词判断**（敏感度是判定器与报告层的事，不是门的事）。
    """
    body = "<html>just a plain page with nothing special</html>"
    j = judge_unauth(_resp(body=body), _resp(body=body))
    assert j.verdict == "exposed"


def test_empty_bodies_are_blocked_not_exposed():
    """**空正文不得算暴露**：0 字节相等不构成"拿到了信息"的证据。

    实现期实测：`body_similarity("", "")` 为 0.0，且 `byte_identical` 要求正文非空，
    故两个空响应落到 `blocked`（宁漏勿滥方向）——**这是刻意的**：一个 0 字节的
    响应既可能"匿名也能拿到"也可能"匿名拿到了空的错误页"，不足以支撑暴露结论。
    """
    j = judge_unauth(_resp(body=""), _resp(body=""))
    assert j.byte_identical is False
    assert j.verdict == "blocked"


# ------------------------------------------ 与 judge_control 方向相反


def test_direction_is_opposite_to_judge_control():
    """**同一份输入**：idor 判 public（否定越权）↔ exposure 判 exposed（肯定暴露）。

    这条是本仓库最容易被"复用"毁掉的一处语义：两者判据形态同构、方向相反。
    """
    b = _resp(body="SAME-CONTENT")
    c = _resp(body="SAME-CONTENT")
    idor_verdict = judge_control(b, c).verdict
    unauth_verdict = judge_unauth(b, c).verdict
    assert idor_verdict == "public"      # idor：公开资源 ⇒ 属性违反不成立 ⇒ 驳回
    assert unauth_verdict == "exposed"   # exposure：匿名即可得 ⇒ 暴露成立 ⇒ 确认
    assert idor_verdict != unauth_verdict


def test_direction_opposite_also_for_denied_case():
    """反向也成立：匿名被拒时 idor 判 protected（成立）而 exposure 判 requires_auth（不成立）。"""
    b = _resp(body="PRIVATE")
    c = _resp(status=403, body="Forbidden")
    assert judge_control(b, c).verdict == "protected"
    assert judge_unauth(b, c).verdict == "requires_auth"


# --------------------------------------------------------- 红线 3 / 常量


def test_summary_contains_no_response_body():
    """送审摘要**不得**含响应体原文（红线 3）。"""
    marker = "ULTRA-SECRET-RESPONSE-MARKER"
    j = judge_unauth(_resp(body=marker), _resp(body=marker))
    blob = summary_to_json(j.as_summary())
    assert marker not in blob
    parsed = json.loads(blob)
    assert set(parsed) == {
        "unauth_verdict",
        "baseline_status",
        "anon_status",
        "similarity_to_authenticated",
        "byte_identical",
        "baseline_body_sha256",
        "anon_body_sha256",
        "reasons",
    }


def test_summary_serialization_is_deterministic():
    """同一输入两次序列化必须逐字节相同（判定 JSON 可复核）。"""
    j1 = judge_unauth(_resp(body="X"), _resp(body="X"))
    j2 = judge_unauth(_resp(body="X"), _resp(body="X"))
    assert summary_to_json(j1.as_summary()) == summary_to_json(j2.as_summary())


def test_constants_are_the_agreed_names():
    """M16-c 裁定定的两个具名常量（不得被改名——报告与审计都依赖它们）。"""
    assert UNAUTH_CONFIRMED_METHOD == "unauth-equivalence-confirmed"
    assert UNAUTH_EQUIVALENCE_EVIDENCE_KIND == "unauth-response-equivalence"


def test_judgment_dataclass_shape():
    j = judge_unauth(_resp(body="X"), _resp(body="X"))
    assert isinstance(j, UnauthJudgment)
    for attr in ("verdict", "baseline_status", "anon_status", "similarity",
                 "byte_identical", "baseline_sha256", "anon_sha256", "reasons"):
        assert hasattr(j, attr)
