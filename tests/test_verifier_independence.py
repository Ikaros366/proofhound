"""M9b：Verifier 校验独立性锁死测试。

M9b 把架构红线 4 从「T1 与 T2 必须用不同模型」重定义为「**校验独立性**」：
Verifier 必须在独立 agent、独立上下文中运行，输入仅限结构化摘要与证据索引。
模型身份不再作约束后，「独立性」从一个不可验证的配置事实，变成了一组必须被
测试锁死的工程属性。本文件就是那把锁。

锁死四条性质：

A. **输入白名单**（红线 3）——Verifier 的消息里不得出现发现端的过程字段：
   state / confidence / source_signal_refs / dedup_key / rejection_reason /
   narrative，也不得出现原始工具输出或凭据原文。
B. **超限 fail-closed**——prompt 超字符上限抛 ContextOverflowError，
   禁止静默截断（截断会改变证据语义，等于污染裁判输入）。
C. **输出契约**——非法 verdict / 空 reason / confirm 缺合法 CVSS 向量一律
   VerifierError（fail-closed，Finding 不得晋级）。
D. **同模型下 A/B/C 依然成立**——这是 M9b 的核心主张：独立性来自隔离而非模型差异。
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.core.context import ContextOverflowError, ContextPolicy
from proofhound.findings import Finding, FindingState, Verification
from proofhound.llm.router import Tier
from proofhound.verify.verifier import Verifier, VerifierError

#: 令牌用于在被排除字段里埋“哨兵”。若它们出现在送进 Verifier 的消息里，
#: 说明发现端的过程上下文泄漏进了裁判输入。
SENTINEL_STATE = "SENTINEL_STATE_DISCOVERER"
SENTINEL_CONFIDENCE = "SENTINEL_CONFIDENCE_DISCOVERER"
SENTINEL_SIGNAL_REF = "SENTINEL_SOURCE_SIGNAL_REF"
SENTINEL_DEDUP = "SENTINEL_DEDUP_KEY"
SENTINEL_REJECTION = "SENTINEL_REJECTION_REASON"
SENTINEL_NARRATIVE = "SENTINEL_NARRATIVE_TEXT"
SENTINEL_RAWTOOL = "SENTINEL_RAW_TOOL_OUTPUT"
SENTINEL_COOKIE = "SENTINEL_COOKIE_VALUE"

EXCLUDED_SENTINELS = [
    SENTINEL_STATE,
    SENTINEL_CONFIDENCE,
    SENTINEL_SIGNAL_REF,
    SENTINEL_DEDUP,
    SENTINEL_REJECTION,
    SENTINEL_NARRATIVE,
    SENTINEL_RAWTOOL,
    SENTINEL_COOKIE,
]

CONFIRM_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class RecordingRouter:
    """记录每一次 complete 的 messages，返回罐头回复。"""

    def __init__(self, reply: str, *, model: str = "shared-model"):
        self.reply = reply
        self.calls: list[list[dict]] = []
        self.configs = {Tier.T2: SimpleNamespace(model=model)}

    def complete(self, tier, messages):
        self.calls.append(messages)
        return self.reply

    @property
    def last_prompt_text(self) -> str:
        assert self.calls, "router 未被调用"
        return "\n".join(str(m.get("content", "")) for m in self.calls[-1])


def _finding_with_discoverer_context() -> Finding:
    """构造一个“发现端过程上下文很丰满”的 Finding。

    所有 [SENTINEL_*] 都埋在**不该进 Verifier** 的字段里；
    只有 verification 摘要与证据索引是允许进入的。
    """
    f = Finding(
        id="F-2026-9001",
        state=FindingState.REPRODUCED,
        title="SQL 注入（id 参数）",
        vuln_type="sqli",
        severity="medium",
        asset="http://127.0.0.1:8080/vulnerabilities/sqli/?id=1",
        param="id",
        confidence=SENTINEL_CONFIDENCE,
        evidence_kinds=["behavioral"],
        verification=Verification(
            method="sqlmap-confirmed",
            evidence_refs=["evidence/a.log#L1"],
            baseline_diff="带会话 baseline 200；sqlmap 确认 id（GET）",
            reproduction_steps=["以预置会话 GET ..."],
            verified_by="verify-sqli@1.0.0",
            verified_at="2026-08-07T00:00:00.000+00:00",
            claim="id 参数输入进入 SQL 执行上下文",
            expected="布尔对照出现可复现差异",
            actual="TRUE/FALSE 对照差异稳定复现 3 次",
        ),
        dedup_key=SENTINEL_DEDUP,
        source_signal_refs=[SENTINEL_SIGNAL_REF],
        rejection_reason=SENTINEL_REJECTION,
        narrative=SENTINEL_NARRATIVE,
        created_at="2026-08-07T00:00:00.000+00:00",
        updated_at="2026-08-07T00:00:00.000+00:00",
    )
    # 这些不是 Finding 的正式字段，但发现端真实环境里会有类似旁路信息；
    # 用 setattr 模拟“对象上挂着过程数据”，断言白名单构造不受其影响。
    object.__setattr__(f, "raw_tool_output", SENTINEL_RAWTOOL)
    object.__setattr__(f, "session_cookie", SENTINEL_COOKIE)
    return f


def _evidence_index() -> list[dict]:
    return [
        {
            "file": "a-aaaaaaaa.log",
            "sha256": "a" * 64,
            "source_ref": "evidence/a.log#L1",
            "line_anchor": 1,
        }
    ]


def _review(router, finding, **kwargs):
    audit = kwargs.pop("audit", None)
    return Verifier(router, audit, **kwargs).review(
        finding, evidence_index=_evidence_index(), diff_summary="baseline diff 摘要"
    )


# ---------------------------------------------------------------- A. 输入白名单


def test_discoverer_process_fields_never_reach_verifier():
    """A：发现端过程字段（state/confidence/signal_refs/dedup/narrative…）不得进入裁判输入。"""
    router = RecordingRouter(
        json.dumps({"verdict": "reject", "reason": "证据不足"}, ensure_ascii=False)
    )
    finding = _finding_with_discoverer_context()

    _review(router, finding)

    prompt = router.last_prompt_text
    leaked = [s for s in EXCLUDED_SENTINELS if s in prompt]
    assert leaked == [], f"以下发现端上下文泄漏进了 Verifier 输入: {leaked}"


def test_allowed_summary_fields_do_reach_verifier():
    """A（反向）：允许进入的摘要字段必须在——否则 Verifier 无从判断。"""
    router = RecordingRouter(
        json.dumps({"verdict": "reject", "reason": "证据不足"}, ensure_ascii=False)
    )
    _review(router, _finding_with_discoverer_context())
    prompt = router.last_prompt_text

    assert "F-2026-9001" in prompt
    assert "sqlmap-confirmed" in prompt
    assert "id 参数输入进入 SQL 执行上下文" in prompt  # claim
    assert "布尔对照出现可复现差异" in prompt  # expected
    assert "a-aaaaaaaa.log" in prompt  # 证据索引（文件名）
    assert "a" * 64 in prompt  # 证据索引（sha256）
    assert "baseline diff 摘要" in prompt


def test_prompt_has_exactly_system_and_user_message():
    """A：prompt 形态固定——system（对抗校验员角色）+ user（结构化 payload）。"""
    router = RecordingRouter(
        json.dumps({"verdict": "reject", "reason": "证据不足"}, ensure_ascii=False)
    )
    _review(router, _finding_with_discoverer_context())
    messages = router.calls[-1]
    assert [m["role"] for m in messages] == ["system", "user"]
    assert "对抗校验" in messages[0]["content"]


def test_user_payload_is_structured_json_not_freeform():
    """A：user 消息是结构化 JSON（可机检），不是发现端的自由文本。"""
    router = RecordingRouter(
        json.dumps({"verdict": "reject", "reason": "证据不足"}, ensure_ascii=False)
    )
    _review(router, _finding_with_discoverer_context())
    payload = json.loads(router.calls[-1][1]["content"])
    assert set(payload) == {"finding", "evidence_pack_index", "diff_summary"}
    assert set(payload["finding"]) <= {
        "id",
        "title",
        "vuln_type",
        "severity",
        "asset",
        "param",
        "preconditions",
        "evidence_kinds",
        "verification",
    }


# ------------------------------------------------------------- B. 超限 fail-closed


def test_oversized_prompt_raises_instead_of_truncating():
    """B：超字符上限抛 ContextOverflowError，禁止静默截断。"""
    router = RecordingRouter(
        json.dumps({"verdict": "reject", "reason": "证据不足"}, ensure_ascii=False)
    )
    huge_index = [{"file": f"f{i}.log", "sha256": "b" * 64} for i in range(400)]
    tiny_policy = ContextPolicy(max_chars=200)

    with pytest.raises(ContextOverflowError):
        Verifier(router, None, context_policy=tiny_policy).review(
            _finding_with_discoverer_context(), evidence_index=huge_index
        )
    assert router.calls == [], "超限时不应调用模型（fail-closed 在调用前）"


# --------------------------------------------------------------- C. 输出契约


@pytest.mark.parametrize(
    "reply",
    [
        "not json at all",
        '{"verdict": "maybe", "reason": "x"}',
        '{"verdict": "confirm", "reason": "", "cvss_vector": "%s"}' % CONFIRM_VECTOR,
        '{"verdict": "confirm", "reason": "ok"}',  # confirm 缺向量
        '{"verdict": "confirm", "reason": "ok", "cvss_vector": "CVSS:3.1/AV:X"}',  # 非法向量
    ],
)
def test_illegal_verdict_is_rejected(reply):
    """C：非法输出一律 VerifierError（fail-closed，Finding 不得晋级）。"""
    router = RecordingRouter(reply)
    finding = _finding_with_discoverer_context()
    with pytest.raises(VerifierError):
        _review(router, finding)
    assert finding.verifier is None


def test_legal_confirm_lands_and_audits():
    """C（反向）：合法 confirm 落 finding.verifier 并记审计。"""
    reply = json.dumps(
        {
            "verdict": "confirm",
            "reason": "证据链完整",
            "cvss_vector": CONFIRM_VECTOR,
            "cvss_rationale": "按证据定指标",
        },
        ensure_ascii=False,
    )
    router = RecordingRouter(reply)
    finding = _finding_with_discoverer_context()
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as td:
        audit = AuditLog(Path(td) / "audit.jsonl")
        verdict = _review(router, finding, audit=audit)
        events = [e["event"] for e in audit.read_all()]
    assert verdict.verdict == "confirm"
    assert "verifier_verdict" in events


# ------------------------------------------------- D. 同模型下独立性依然成立


def test_independence_holds_when_t1_and_t2_share_a_model():
    """D（M9b 核心主张）：T1/T2 同模型时，A + C 的保证必须原样成立。

    独立性来自 agent 隔离与输入边界，而非模型差异——本测试把这个主张钉死。
    """
    shared = "shared-model-x"
    router = RecordingRouter(
        json.dumps({"verdict": "reject", "reason": "证据不足"}, ensure_ascii=False),
        model=shared,
    )
    finding = _finding_with_discoverer_context()

    _review(router, finding)

    # A：白名单依然生效
    assert [s for s in EXCLUDED_SENTINELS if s in router.last_prompt_text] == []
    # 角色隔离依然存在
    assert router.calls[-1][0]["role"] == "system"
    # C：非法输出依然 fail-closed
    bad = RecordingRouter("garbage", model=shared)
    with pytest.raises(VerifierError):
        _review(bad, _finding_with_discoverer_context())


def test_same_model_router_records_shared_model_audit(tmp_path):
    """D：同模型配置在 router 层留痕（llm_tiers_share_model），便于事后归因。"""
    from proofhound.llm.router import ModelRouter, TierConfig

    audit = AuditLog(tmp_path / "audit.jsonl")
    configs = {
        Tier.T0: TierConfig(base_url="https://x/v1", api_key="k", model="cheap"),
        Tier.T1: TierConfig(base_url="https://x/v1", api_key="k", model="shared-model-x"),
        Tier.T2: TierConfig(base_url="https://x/v1", api_key="k", model="shared-model-x"),
    }
    router = ModelRouter(configs, audit=audit)
    assert router.shared_model_across_tiers == "shared-model-x"
    entry = [e for e in audit.read_all() if e["event"] == "llm_tiers_share_model"]
    assert len(entry) == 1
    assert entry[0]["model"] == "shared-model-x"
