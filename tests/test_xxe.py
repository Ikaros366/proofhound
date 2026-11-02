"""M25-a：XXE 判定器的纯函数测试（**零网络**）。

这份文件钉住五件事：

1. **canary 白名单只有两个**（Linux ``/etc/passwd`` / Windows ``win.ini``），
   且由 :data:`CANARIES` 派生——没有第二个真相源，构造其它路径直接抛错；
2. **模板是无害的**：外部实体恒 1 条、alive 用字符引用（请求体里不出现裸标记）、
   实体值不含 ``&``、同一实体只引用一次（不发 billion laughs）；
3. **判定表逐条**：两条通道各自的 confirmed、以及 rejected / blocked 的**优先级**
   （对照污染、探针出错、网关代答、阳性对照失效、canary 不可判）；
4. **回显陷阱**：响应里出现 ``file:///etc/passwd`` 字样**不是**证据；原样回显
   端点由"未展开的 alive 字面量"识别，判 rejected 而不是 confirmed；
5. **操作员模板派生**：只换实体目标、不换信封结构；基线必须去掉 DOCTYPE。
"""

from __future__ import annotations

import pytest

from proofhound.verify import xxe

CALLBACK = "http://127.0.0.1:9/c/phxxe_" + "a" * 32
CONTROL = "http://127.0.0.1:9/c/phxxe_" + "b" * 32


def _obs(name: str, body: bytes = b"", status: int | None = 200, error: str | None = None):
    return xxe.ProbeObservation(name=name, status=status, error=error, body=body)


CLEAN_BASELINE = _obs("baseline", b"<r>1</r>")
CLEAN_FILE = _obs("file", b"<ctrl>PROOFHOUND-ALIVE</ctrl>")
CLEAN_NEGATIVE = _obs("file-negative", b"<ctrl>PROOFHOUND-ALIVE</ctrl>")
CLEAN_CALLBACK = _obs("callback", b"<ok/>")
ALIVE_BODY = b"<value>root:x:0:0</value><ctrl>PROOFHOUND-ALIVE</ctrl>"


def _judge(**overrides) -> xxe.XxeJudgment:
    kwargs: dict = {
        "canary": xxe.CANARY_LINUX,
        "baseline": CLEAN_BASELINE,
        "file_probe": CLEAN_FILE,
        "negative": CLEAN_NEGATIVE,
        "callback": CLEAN_CALLBACK,
        "callback_hit": False,
        "control_hit": False,
    }
    kwargs.update(overrides)
    return xxe.judge(**kwargs)


# =====================================================================
# 一、canary 白名单
# =====================================================================


def test_canary_table_has_exactly_two_well_known_files():
    assert [canary.label for canary in xxe.CANARIES] == ["linux", "windows"]
    assert xxe.CANARY_LINUX.url == "file:///etc/passwd"
    assert xxe.CANARY_LINUX.signature == "root:x:0:0"
    assert xxe.CANARY_WINDOWS.url == "file:///C:/Windows/win.ini"
    assert xxe.CANARY_WINDOWS.signature == "[fonts]"


def test_whitelist_is_derived_from_canary_table():
    assert xxe.CANARY_WHITELIST == frozenset({"/etc/passwd", "c:/windows/win.ini"})
    assert "/etc/shadow" not in xxe.CANARY_WHITELIST


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("file:///etc/passwd", "/etc/passwd"),
        ("file:///C:/Windows/win.ini", "c:/windows/win.ini"),
        ("C:\\Windows\\win.ini", "c:/windows/win.ini"),
        ("file:////etc/passwd", "/etc/passwd"),
        ("/etc/passwd", "/etc/passwd"),
        ("  file:///etc/passwd  ", "/etc/passwd"),
    ],
)
def test_normalize_file_target(raw: str, expected: str):
    assert xxe.normalize_file_target(raw) == expected


def test_file_urls_in_dedupes_and_keeps_order():
    text = '<!ENTITY a SYSTEM "file:///etc/passwd"> <!ENTITY b SYSTEM "file:///etc/passwd">' \
           ' <!ENTITY c SYSTEM "file:///C:/Windows/win.ini">'
    assert xxe.file_urls_in(text) == (
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
    )


def test_scan_file_targets_allows_canary():
    scan = xxe.scan_file_targets('<!ENTITY x SYSTEM "file:///etc/passwd">')
    assert scan.ok
    assert scan.allowed == ("file:///etc/passwd",)
    assert scan.rejected == ()
    assert scan.overrides == ()


def test_scan_file_targets_rejects_unknown_path_by_default():
    scan = xxe.scan_file_targets('<!ENTITY x SYSTEM "file:///etc/shadow">')
    assert not scan.ok
    assert scan.rejected == ("file:///etc/shadow",)
    assert scan.overrides == ()


def test_scan_file_targets_override_requires_explicit_allow():
    scan = xxe.scan_file_targets(
        '<!ENTITY x SYSTEM "file:///etc/shadow">', allow=("/etc/shadow",)
    )
    assert scan.ok
    assert scan.overrides == ("file:///etc/shadow",)
    assert scan.rejected == ()
    assert scan.to_dict()["normalized"] == ["/etc/shadow"]


def test_require_whitelisted_returns_canary():
    assert xxe.require_whitelisted("file:///etc/passwd") is xxe.CANARY_LINUX
    assert xxe.require_whitelisted("file:///C:/Windows/win.ini") is xxe.CANARY_WINDOWS


def test_require_whitelisted_rejects_shadow():
    with pytest.raises(xxe.XxeFileTargetError):
        xxe.require_whitelisted("file:///etc/shadow")


def test_default_canary_uses_platform(monkeypatch):
    monkeypatch.setattr(xxe.os, "name", "nt")
    assert xxe.default_canary() is xxe.CANARY_WINDOWS
    monkeypatch.setattr(xxe.os, "name", "posix")
    assert xxe.default_canary() is xxe.CANARY_LINUX


def test_canary_for_unknown_label_raises():
    with pytest.raises(xxe.XxeError):
        xxe.canary_for("plan9")


# =====================================================================
# 二、模板构造（无害性）
# =====================================================================


def test_file_body_has_one_external_entity_and_char_ref_alive():
    body = xxe.file_body(xxe.CANARY_LINUX).decode("utf-8")
    assert body.count("SYSTEM") == 1
    assert "file:///etc/passwd" in body
    # 阳性对照用字符引用：请求体里**不出现**裸标记
    assert xxe.ALIVE_LITERAL in body
    assert xxe.ALIVE_MARKER not in body
    assert "&x;" in body and "&alive;" in body
    assert xxe.entity_amplification_reasons(body.encode()) == ()


def test_file_body_rejects_non_whitelisted_path():
    with pytest.raises(xxe.XxeFileTargetError):
        xxe.file_body("file:///etc/shadow")


def test_baseline_body_has_no_doctype():
    body = xxe.baseline_body().decode("utf-8")
    assert "DOCTYPE" not in body
    assert "&" not in body


def test_baseline_body_carries_control_url():
    body = xxe.baseline_body(callback_url=CONTROL).decode("utf-8")
    assert CONTROL in body
    assert "DOCTYPE" not in body


def test_callback_control_body_is_baseline_with_url():
    assert xxe.callback_control_body(callback_url=CALLBACK) == xxe.baseline_body(
        callback_url=CALLBACK
    )


def test_callback_body_requires_http_scheme():
    with pytest.raises(xxe.XxeError):
        xxe.callback_body(callback_url="file:///etc/passwd")


def test_alive_body_has_only_internal_entity():
    body = xxe.alive_body().decode("utf-8")
    assert "SYSTEM" not in body
    assert "DOCTYPE" in body
    assert xxe.entity_amplification_reasons(body.encode()) == ()


def test_negative_body_points_at_nonexistent_file():
    body = xxe.negative_body("file:///nonexistent_deadbeef").decode("utf-8")
    assert "file:///nonexistent_deadbeef" in body
    assert xxe.entity_amplification_reasons(body.encode()) == ()


def test_probe_plan_order_and_size():
    plan = xxe.probe_plan(canary=xxe.CANARY_LINUX, callback_url=CALLBACK, control_url=CONTROL)
    assert [spec.name for spec in plan] == [
        xxe.PROBE_BASELINE,
        xxe.PROBE_FILE,
        xxe.PROBE_NEGATIVE,
        xxe.PROBE_CALLBACK,
    ]
    assert [spec.role for spec in plan] == [
        xxe.ROLE_BASELINE,
        xxe.ROLE_FILE,
        xxe.ROLE_NEGATIVE,
        xxe.ROLE_CALLBACK,
    ]
    assert len(plan) == xxe.MAX_REQUESTS_PER_ENDPOINT


def test_probe_plan_uses_two_distinct_callback_urls():
    plan = xxe.probe_plan(canary=xxe.CANARY_LINUX, callback_url=CALLBACK, control_url=CONTROL)
    baseline = plan[0].body.decode("utf-8")
    callback = plan[3].body.decode("utf-8")
    assert CONTROL in baseline and CALLBACK not in baseline
    assert CALLBACK in callback and CONTROL not in callback


def test_nonexistent_file_url_is_unique():
    first = xxe.nonexistent_file_url()
    second = xxe.nonexistent_file_url()
    assert first.startswith("file:///nonexistent_")
    assert first != second


# =====================================================================
# 三、实体膨胀的结构性检查
# =====================================================================


def test_amplification_allows_single_external_entity():
    assert xxe.entity_amplification_reasons(xxe.file_body(xxe.CANARY_LINUX)) == ()


def test_amplification_detects_multiple_system_entities():
    body = (
        '<!DOCTYPE r [<!ENTITY a SYSTEM "file:///etc/passwd">'
        '<!ENTITY b SYSTEM "file:///C:/Windows/win.ini">]><r>&a;&b;</r>'
    ).encode()
    reasons = xxe.entity_amplification_reasons(body)
    assert any("外部实体定义 2 条" in reason for reason in reasons)


def test_amplification_detects_billion_laughs_shape():
    body = (
        '<!DOCTYPE r [<!ENTITY a "lol">]><r>&a;&a;&a;&a;</r>'
    ).encode()
    reasons = xxe.entity_amplification_reasons(body)
    assert any("被引用多次" in reason for reason in reasons)


def test_amplification_detects_recursive_entity_values():
    body = (
        '<!DOCTYPE r [<!ENTITY a "x"><!ENTITY b "&a;&a;">]><r>&b;</r>'
    ).encode()
    reasons = xxe.entity_amplification_reasons(body)
    assert any("递归风险" in reason for reason in reasons)


def test_amplification_ignores_character_references():
    body = (
        '<!DOCTYPE r [<!ENTITY a "PROOFHOUND&#45;ALIVE">]><r>&a;</r>'
    ).encode()
    assert xxe.entity_amplification_reasons(body) == ()


# =====================================================================
# 四、判定表
# =====================================================================


def test_judge_file_confirmed():
    judgment = _judge(file_probe=_obs("file", ALIVE_BODY))
    assert judgment.verdict == "confirmed"
    assert judgment.channels == ("file",)
    assert "canary" in judgment.reasons[0]


def test_judge_file_confirmed_requires_alive():
    judgment = _judge(file_probe=_obs("file", b"<value>root:x:0:0</value>"))
    assert judgment.verdict == "blocked"
    assert judgment.channels == ()
    assert "阳性对照未被替换" in judgment.reasons[0]


def test_judge_file_confirmed_requires_clean_baseline():
    judgment = _judge(
        file_probe=_obs("file", ALIVE_BODY),
        baseline=_obs("baseline", b"root:x:0:0"),
    )
    assert judgment.verdict == "blocked"
    assert "基线体" in judgment.reasons[0]


def test_judge_file_confirmed_requires_clean_negative():
    judgment = _judge(
        file_probe=_obs("file", ALIVE_BODY),
        negative=_obs("file-negative", b"root:x:0:0"),
    )
    assert judgment.verdict == "blocked"
    assert "阴性对照" in judgment.reasons[0]


def test_judge_callback_confirmed():
    judgment = _judge(callback_hit=True)
    assert judgment.verdict == "confirmed"
    assert judgment.channels == ("callback",)


def test_judge_callback_not_confirmed_when_control_fires():
    judgment = _judge(callback_hit=True, control_hit=True)
    assert judgment.verdict == "blocked"
    assert "callback-control" in judgment.reasons[0]


def test_judge_both_channels():
    judgment = _judge(file_probe=_obs("file", ALIVE_BODY), callback_hit=True)
    assert judgment.verdict == "confirmed"
    assert judgment.channels == ("file", "callback")


def test_judge_clean_run_is_rejected():
    judgment = _judge()
    assert judgment.verdict == "rejected"
    assert judgment.channels == ()
    assert any("阳性对照成立" in reason for reason in judgment.reasons)


def test_judge_echo_trap_is_rejected_with_echo_reason():
    echoed = _obs("file", ("<r>&x;</r>" + xxe.ALIVE_LITERAL).encode())
    judgment = _judge(file_probe=echoed)
    assert judgment.verdict == "rejected"
    assert any("原样回显" in reason for reason in judgment.reasons)
    assert any("回显陷阱" in reason for reason in judgment.reasons)
    assert judgment.facts["alive_literal_echoed"] is True


def test_judge_literal_path_without_signature_is_never_confirmed():
    echoed = _obs("file", b"<value>file:///etc/passwd</value>" + xxe.ALIVE_LITERAL.encode())
    judgment = _judge(file_probe=echoed)
    assert judgment.verdict != "confirmed"


def test_judge_probe_error_is_blocked():
    judgment = _judge(file_probe=_obs("file", error="URLError: refused", status=None))
    assert judgment.verdict == "blocked"
    assert "探针请求失败" in judgment.reasons[0]


def test_judge_gateway_response_is_blocked():
    judgment = _judge(callback=_obs("callback", b"<html>bad gateway</html>", status=502))
    assert judgment.verdict == "blocked"
    assert "未被当 XML 处理" in judgment.reasons[0]


def test_judge_soap_fault_500_can_still_confirm():
    fault = _obs(
        "file",
        b"<soap:Fault><faultstring>root:x:0:0 PROOFHOUND-ALIVE</faultstring></soap:Fault>",
        status=500,
    )
    judgment = _judge(file_probe=fault)
    assert judgment.verdict == "confirmed"
    assert judgment.channels == ("file",)


def test_judge_soap_fault_500_without_signature_is_rejected():
    fault = _obs(
        "file",
        b"<soap:Fault><faultstring>PROOFHOUND-ALIVE</faultstring></soap:Fault>",
        status=500,
    )
    judgment = _judge(file_probe=fault)
    assert judgment.verdict == "rejected"


def test_judge_listener_error_is_blocked():
    judgment = _judge(listener_error=True)
    assert judgment.verdict == "blocked"
    assert "listener 不可用" in judgment.reasons[0]


def test_judge_alive_evidence_unsound_is_blocked():
    judgment = _judge(alive_evidence_sound=False)
    assert judgment.verdict == "blocked"
    assert "阳性对照失效" in judgment.reasons[0]


def test_judge_canary_unavailable_is_blocked():
    judgment = _judge(canary_available=False)
    assert judgment.verdict == "blocked"
    assert "内容通道零覆盖" in judgment.reasons[0]


def test_type_is_registered_with_named_methods_and_evidence_kind():
    """M30：xxe 已登记（M25-a 当时刻意只定义常量、不登记）。

    本用例锁住"常量名 ↔ 登记值"的对应关系，防止两处各写一份字符串。
    """
    from proofhound.verify.gate import VULN_REGISTRY

    spec = VULN_REGISTRY["xxe"]
    assert spec.methods == frozenset(
        {xxe.XXE_FILE_METHOD, xxe.XXE_CALLBACK_METHOD}
    )
    assert spec.behavioral_kinds == frozenset({xxe.XXE_EVIDENCE_KIND})
    assert spec.verify_skill == "verify-xxe"
    assert spec.requires_session is False
    assert spec.in_model_whitelist is False


def test_judge_facts_record_all_negatives():
    judgment = _judge(file_probe=_obs("file", ALIVE_BODY))
    facts = judgment.facts
    assert facts["file_canary_hit"] is True
    assert facts["baseline_canary_hit"] is False
    assert facts["negative_canary_hit"] is False
    assert facts["alive_replaced"] is True
    assert facts["callback_hit"] is False
    assert facts["callback_control_hit"] is False
    assert facts["all_probes_answered"] is True
    assert facts["canary_path"] == "/etc/passwd"
    assert facts["canary_signature"] == "root:x:0:0"


def test_judgment_to_dict_is_json_shaped():
    payload = _judge(file_probe=_obs("file", ALIVE_BODY)).to_dict()
    assert payload["verdict"] == "confirmed"
    assert payload["channels"] == ["file"]
    assert isinstance(payload["reasons"], list)
    assert isinstance(payload["facts"], dict)


@pytest.mark.parametrize(
    ("status", "error", "body", "expected"),
    [
        (200, None, b"", True),
        (500, None, b"", True),
        (500, None, b"<faultstring>x</faultstring>", True),
        (502, None, b"<html>bad gateway</html>", False),
        (503, None, b"<html>unavailable</html>", False),
        (504, None, b"", False),
        (502, None, b"<Fault>x</Fault>", True),
        (None, "URLError", b"", False),
        (None, None, b"", False),
    ],
)
def test_is_answered(status, error, body, expected):
    assert xxe.is_answered(status, error, body) is expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b"<soap:Fault><faultcode>x</faultcode></soap:Fault>", True),
        (b"<faultstring>boom</faultstring>", True),
        (b"<detail>boom</detail>", True),
        (b"<html>Internal Server Error</html>", False),
        (b"", False),
    ],
)
def test_looks_like_soap_fault(body, expected):
    assert xxe.looks_like_soap_fault(body) is expected


def test_observation_canary_seen_ignores_empty_signature():
    observation = _obs("file", b"root:x:0:0")
    assert observation.canary_seen("") is False
    assert observation.canary_seen("root:x:0:0") is True


def test_observation_to_dict_excludes_body():
    observation = _obs("file", b"root:x:0:0")
    payload = observation.to_dict()
    assert "root:x:0:0" not in str(payload)
    assert payload["probe"] == "file"
    assert payload["bytes"] == len(observation.body)


def test_new_xxe_token_prefix_and_uniqueness():
    first = xxe.new_xxe_token()
    second = xxe.new_xxe_token()
    assert first.startswith("phxxe_")
    assert len(first) == len("phxxe_") + 32
    assert first != second


# =====================================================================
# 五、操作员模板派生
# =====================================================================

TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [
  <!ENTITY alive "PROOFHOUND&#45;ALIVE">
  <!ENTITY x SYSTEM "file:///etc/passwd">
]>
<r><value>&x;</value><ctrl>&alive;</ctrl></r>
"""


def test_derive_template_probes_replaces_urls():
    derived = xxe.derive_template_probes(
        TEMPLATE, callback_url=CALLBACK, nonexistent_url="file:///nonexistent_deadbeef"
    )
    assert derived.file == TEMPLATE.encode()
    assert b"file:///nonexistent_deadbeef" in derived.negative
    assert CALLBACK.encode() in derived.callback
    assert b"file:///etc/passwd" not in derived.negative
    assert b"file:///etc/passwd" not in derived.callback
    assert derived.file_urls == ("file:///etc/passwd",)


def test_derive_template_probes_baseline_strips_doctype():
    derived = xxe.derive_template_probes(TEMPLATE, callback_url=CALLBACK)
    baseline = derived.baseline.decode("utf-8")
    assert "DOCTYPE" not in baseline
    assert "&x;" not in baseline
    assert "&alive;" not in baseline
    assert ">baseline<" in baseline


def test_derive_template_probes_reports_alive_state():
    derived = xxe.derive_template_probes(TEMPLATE, callback_url=CALLBACK)
    assert derived.alive_declared is True
    assert derived.alive_literal_present is False  # 字符引用形态 ⇒ 证据可靠
    assert derived.entity_names == ("alive", "x")


def test_derive_template_detects_literal_alive():
    template = '<!DOCTYPE r [<!ENTITY alive "PROOFHOUND-ALIVE">]><r>&alive;</r>'
    derived = xxe.derive_template_probes(template, callback_url=CALLBACK)
    assert derived.alive_literal_present is True


def test_derive_template_requires_file_or_entity():
    with pytest.raises(xxe.XxeError):
        xxe.derive_template_probes("<r><value>1</value></r>", callback_url=CALLBACK)


def test_strip_doctype_handles_internal_subset():
    text = '<!DOCTYPE r [\n  <!ENTITY x "1">\n]>\n<r/>'
    assert xxe.strip_doctype(text) == "\n<r/>"


def test_strip_doctype_handles_simple_form():
    assert xxe.strip_doctype('<!DOCTYPE r SYSTEM "x.dtd">\n<r/>') == "\n<r/>"


def test_entity_names_are_deduped():
    text = '<!ENTITY a "1"><!ENTITY a "2"><!ENTITY b SYSTEM "x">'
    assert xxe.entity_names(text) == ("a", "b")


# =====================================================================
# 六、模块常量（登记契约）
# =====================================================================


def test_methods_and_evidence_kind_are_named():
    """常量名固定（M25-a 定义，M30 登记）；且两个 method 跨类型唯一。"""
    assert xxe.XXE_FILE_METHOD == "xml-entity-file-confirmed"
    assert xxe.XXE_CALLBACK_METHOD == "xml-entity-callback-confirmed"
    assert xxe.XXE_EVIDENCE_KIND == "xml-entity-resolution"

    from proofhound.verify.gate import VULN_REGISTRY

    assert VULN_REGISTRY["xxe"].methods == frozenset(
        {xxe.XXE_FILE_METHOD, xxe.XXE_CALLBACK_METHOD}
    )
    registered = [method for spec in VULN_REGISTRY.values() for method in spec.methods]
    assert len(registered) == len(set(registered)), "method 名跨类型重用了"
