"""M11b：IDOR 判据加固的纯函数测试（未认证对照探测 + 确定性归属提取）。

本文件只测 :mod:`proofhound.verify.idor_control` 的纯逻辑——零网络、零 LLM、
零 Docker。编排接线与 fixture 语义另有测试（``tests/test_idor.py`` 与
``tests/test_bench_fixture.py``）。
"""

from __future__ import annotations

import json

import pytest

from proofhound.verify.idor import IdorResponse
from proofhound.verify.idor_control import (
    PUBLIC_SIMILARITY_THRESHOLD,
    body_sha256,
    control_summary,
    judge_control,
    judge_ownership,
    summary_to_json,
)

VICTIM = "owner"


def _res(status=200, body="", error=None, url="http://t/x?id=1"):
    return IdorResponse(url=url, status=status, body=body, error=error)


def _obj_page(owner_value="owner", *, pad="", token=None):
    """仿基准 fixture 的对象详情页（含归属字段）。"""
    footer = f"<footer>session={token}</footer>" if token else ""
    return (
        "<html><head><title>对象详情</title></head><body><h1>对象详情</h1>"
        f"<div>no=1 对象 1：所有者 {owner_value}，金额 800，状态已发货。{pad}</div>"
        f"{footer}</body></html>"
    )


# ------------------------------------------------------------ 归属提取


def test_ownership_matched_on_text_field():
    ev = judge_ownership(_res(body=_obj_page("owner")), VICTIM)
    assert ev.verdict == "matched"
    assert ev.field == "所有者"
    assert ev.value == "owner"
    assert ev.line_no == 1


def test_ownership_matched_is_case_insensitive():
    ev = judge_ownership(_res(body=_obj_page("OWNER")), VICTIM)
    assert ev.verdict == "matched"


def test_ownership_matched_on_json_field():
    body = json.dumps({"id": 1, "owner": "owner", "amount": 800}, indent=2)
    ev = judge_ownership(_res(body=body), VICTIM)
    assert ev.verdict == "matched"
    assert ev.field == "owner"
    assert ev.value == "owner"


def test_ownership_mismatched_when_value_is_someone_else():
    """归属字段指向第三方 → mismatched（不是"证据"，但**有信息**：可反驳私有性）。"""
    ev = judge_ownership(_res(body=_obj_page("someone-else")), VICTIM)
    assert ev.verdict == "mismatched"
    assert ev.value == "someone-else"


def test_ownership_absent_without_any_owner_field():
    ev = judge_ownership(_res(body="<html><body>记录 1：正文内容</body></html>"), VICTIM)
    assert ev.verdict == "absent"
    assert ev.line_no is None


def test_ownership_absent_when_victim_identity_unknown():
    """**关键 fail-closed**：操作员未给 reference 身份标识时，任何 owner 字段都

    不得被当成归属证据（不做"有 owner 字段就算证据"的放松——那会把任意第三方
    归属也当证据）。
    """
    ev = judge_ownership(_res(body=_obj_page("owner")), None)
    assert ev.verdict == "absent"
    assert ev.value is None


def test_ownership_absent_when_victim_identity_blank():
    assert judge_ownership(_res(body=_obj_page("owner")), "   ").verdict == "absent"


def test_ownership_excludes_current_user_style_keys():
    """``current_user`` 这类"当前登录者"字段是会话回显，**不是**对象归属。"""
    body = json.dumps({"current_user": "owner", "id": 1})
    assert judge_ownership(_res(body=body), VICTIM).verdict == "absent"


def test_ownership_ignores_bare_identity_in_body():
    """正文里出现身份字样但**没有归属字段名** → 不算证据（防误判）。"""
    body = "<html><body>欢迎 owner，这里是公开的公告列表。</body></html>"
    assert judge_ownership(_res(body=body), VICTIM).verdict == "absent"


def test_ownership_line_anchor_points_at_real_line():
    body = "<html>\n<head></head>\n<body>所有者 owner</body>\n</html>"
    ev = judge_ownership(_res(body=body), VICTIM)
    assert ev.verdict == "matched"
    assert ev.line_no == 3
    # 锚点必须真的指向含该值的行（Verifier 靠它复核）
    assert "owner" in body.splitlines()[ev.line_no - 1]


def test_ownership_prefers_match_over_earlier_mismatch():
    """先出现第三方归属、后出现与 reference 匹配的归属 → 仍应判 matched。"""
    body = "<html><body>所有者 nobody\n记录所有者 owner</body></html>"
    ev = judge_ownership(_res(body=body), VICTIM)
    assert ev.verdict == "matched"


def test_ownership_summary_contains_no_raw_body():
    """红线 3：送审摘要只给结论 + 锚点，**不得**含响应体原文。"""
    body = _obj_page("owner", pad="机密正文段落")
    ev = judge_ownership(_res(body=body), VICTIM)
    payload = json.dumps(ev.as_summary(), ensure_ascii=False)
    assert "机密正文段落" not in payload
    assert "<html>" not in payload
    assert ev.as_summary()["line_anchor"] == 1


# ---------------------------------------------------------- 对照探测判定


def test_control_public_on_byte_identical_body():
    """未认证拿到**逐字节相同**的内容 → 公开资源（铁证，不依赖相似度阈值）。"""
    body = "<html><body>公开内容，任何人都可以访问。</body></html>"
    j = judge_control(_res(body=body), _res(body=body))
    assert j.verdict == "public"
    assert j.same_bytes is True
    assert j.similarity == 1.0


def test_control_public_on_high_similarity():
    """逐字节不同但高度相似（仅尾部微差）→ 仍判公开（阈值判据）。"""
    base = "<html><body>" + "x" * 200 + " 尾部A</body></html>"
    ctrl = "<html><body>" + "x" * 200 + " 尾部B</body></html>"
    j = judge_control(_res(body=base), _res(body=ctrl))
    assert j.similarity >= PUBLIC_SIMILARITY_THRESHOLD
    assert j.verdict == "public"


@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 500])
def test_control_protected_when_unauthenticated_denied(status):
    """未认证被拒（3xx/4xx/5xx）→ 资源与会话相关，属性违反解释成立。"""
    base = _obj_page("owner")
    j = judge_control(_res(body=base), _res(status=status, body="<html>denied</html>"))
    assert j.verdict == "protected"
    assert j.c_status == status
    assert any("属性违反解释成立" in r for r in j.reasons)


def test_control_blocked_when_two_hundred_but_dissimilar():
    """未认证 2xx 但内容与基准既不逐字节相同、相似度也未达阈值 → blocked。

    语义：内容"不同但不相似"同样符合"两个身份看到不同数据"这一**合法**形态，
    把它当成越权证据是会误报的方向；故本实现只**否定**（public），不**肯定**。
    """
    # 构造相似度明显低于 0.9 的两份正文（长度接近但内容完全不同）
    base = "".join(f"<p>base-{i}</p>" for i in range(40))
    ctrl = "".join(f"<p>ctrl-{i}</p>" for i in range(40))
    j = judge_control(_res(body=base), _res(body=ctrl))
    assert j.similarity < PUBLIC_SIMILARITY_THRESHOLD
    assert j.verdict == "blocked"
    assert j.same_bytes is False
    assert any("覆盖不全" in r for r in j.reasons)


def test_control_public_when_near_identical_with_small_insert():
    """仅插入少量字符 → 相似度仍 ≥ 阈值 → 公开（阈值判据生效）。

    实测刻度：在 100+ 字符的正文里插入约 30 字符会把相似度压到 0.894（**低于**
    0.9 阈值 → 判 blocked）；插入 5 字符才稳定落在 0.96 以上。这条测试把该刻度
    固定下来，因为"多接近才算同一份内容"正是本判据的语义边界。
    """
    base = "".join(f"<p>line-{i}</p>" for i in range(20))
    ctrl = base.replace("line-0", "line-0x")
    j = judge_control(_res(body=base), _res(body=ctrl))
    assert j.similarity >= PUBLIC_SIMILARITY_THRESHOLD
    assert j.verdict == "public"


def test_control_blocked_on_network_error():
    base = _obj_page("owner")
    j = judge_control(_res(body=base), _res(status=None, body="", error="URLError: timed out"))
    assert j.verdict == "blocked"
    assert j.c_error == "URLError: timed out"


def test_control_never_false_positive_on_empty_control_body():
    """空正文不得被当成"逐字节相同"（空 == 空 是退化情形，不算铁证）。"""
    j = judge_control(_res(body=""), _res(body=""))
    assert j.same_bytes is False


def test_control_reasons_are_recorded():
    j = judge_control(_res(body=_obj_page()), _res(body=_obj_page()))
    assert j.reasons and any("公开" in r or "会话无关" in r for r in j.reasons)


# ------------------------------------------------------- 摘要与锚点契约


def test_control_summary_shape_is_structured_only():
    base = _obj_page("owner", pad="SECRET-BODY-MARKER")
    j = judge_control(_res(body=base), _res(body="<html>公开内容任何人都可以访问</html>"))
    ev = judge_ownership(_res(body=base), VICTIM)
    summary = control_summary(j, ev)
    assert set(summary) == {"unauthenticated_control", "object_ownership"}
    rendered = json.dumps(summary, ensure_ascii=False)
    assert "SECRET-BODY-MARKER" not in rendered
    assert "<html>" not in rendered
    control = summary["unauthenticated_control"]
    assert {"verdict", "control_status", "similarity_to_baseline"} <= set(control)
    assert summary["object_ownership"]["verdict"] == "matched"


def test_summary_to_json_is_deterministic():
    j = judge_control(_res(body="a" * 64), _res(body="b" * 64))
    ev = judge_ownership(_res(body=_obj_page()), VICTIM)
    first = summary_to_json(control_summary(j, ev))
    second = summary_to_json(control_summary(j, ev))
    assert first == second


def test_body_sha256_is_stable_and_distinguishes():
    assert body_sha256("abc") == body_sha256("abc")
    assert body_sha256("abc") != body_sha256("abd")
    assert len(body_sha256("abc")) == 64


# ------------------------------------------- 声明式身份（M11b，与会话凭据解耦）


def test_session_identity_prefers_declared_identity():
    """声明式 ``identity`` 优先于会话凭据值。

    真系统里对象页展示的是用户名/所有者名，而会话凭据常是随机 session id——
    只推凭据会让归属判定一律 absent（demo fixture 实测即如此）。
    """
    from proofhound.compliance.scope import Scope
    from proofhound.compliance.session import SessionConfig

    scope = Scope(
        networks=["127.0.0.0/8"],
        session=SessionConfig(
            cookies={"phsess": "aaaa"},
            reference=SessionConfig(
                cookies={"phsess": "random-session-id"}, identity="b"
            ),
        ),
    )
    assert scope.session_identity() == "b"


def test_session_identity_falls_back_to_credential_value():
    """未声明 identity → 回退凭据值（向后兼容既有配置）。"""
    from proofhound.compliance.scope import Scope
    from proofhound.compliance.session import SessionConfig

    scope = Scope(
        networks=["127.0.0.0/8"],
        session=SessionConfig(
            cookies={"phsess": "aaaa"},
            reference=SessionConfig(cookies={"phsess": "ccccccccdddddddd"}),
        ),
    )
    assert scope.session_identity() == "ccccccccdddddddd"


def test_session_identity_blank_declared_falls_back():
    """identity 只给空白 → 视为未声明，回退凭据值（不产生空期望值）。"""
    from proofhound.compliance.scope import Scope
    from proofhound.compliance.session import SessionConfig

    scope = Scope(
        networks=["127.0.0.0/8"],
        session=SessionConfig(
            cookies={"phsess": "aaaa"},
            reference=SessionConfig(
                cookies={"phsess": "ccccccccdddddddd"}, identity="   "
            ),
        ),
    )
    assert scope.session_identity() == "ccccccccdddddddd"


def test_session_identity_none_without_reference():
    from proofhound.compliance.scope import Scope
    from proofhound.compliance.session import SessionConfig

    scope = Scope(
        networks=["127.0.0.0/8"], session=SessionConfig(cookies={"phsess": "a"})
    )
    assert scope.session_identity() is None
    assert Scope(networks=["127.0.0.0/8"]).session_identity() is None


def test_declared_identity_does_not_relax_ownership_judgement():
    """给出声明式身份**不放宽**判据：字段名与字段值仍须同时命中。"""
    # 值匹配但无归属字段名 → 仍 absent
    body_welcome = "<html>欢迎 b，这里是公开列表</html>"
    assert judge_ownership(_res(body=body_welcome), "b").verdict == "absent"
    # 有归属字段名但值不匹配 → mismatched
    assert judge_ownership(_res(body="<html>所有者：carol</html>"), "b").verdict == "mismatched"
    # 两者同时命中 → matched
    assert judge_ownership(_res(body="<html>所有者：b</html>"), "b").verdict == "matched"
