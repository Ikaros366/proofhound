"""M26-a：fastjson 判定面（``proofhound/verify/fastjson.py``）的单元测试。

这份文件钉住七件事（**纯函数、零网络**）：

1. **base64 三变体 + raw** 都能编出可解码的 body（服务端用哪种只有打了才知道）；
2. **矩阵形态**：A 层两步链与 ``L…;`` 变体必须在计划里（§7 断言 5），
   且**没有** ``$ref`` / >32KB / 深嵌套（§7 断言 8）；
3. **阳性对照**用转义形态：真解析器报错是解码形态，原样回显只剩转义形态；
4. **阴性对照**与所对照的 gadget 同 URL、且**不含** ``@type``；
5. **三态**：confirmed 要求"观测 + 对照干净 + 阳性对照成立"，rejected 要求
   "**全部** gadget 族都被明确拒绝"，其余一律 blocked（宁漏勿滥）；
6. **回显陷阱**：响应里有域名/``@type`` 字样但没观测 ⇒ 绝不 confirmed；
7. 判定理由里**不出现 token 原文**（证据链只认 sha8）。
"""

from __future__ import annotations

import base64
import json
import urllib.parse

import pytest

from proofhound.verify import fastjson as fj
from proofhound.verify.observe import Observation, host_label, new_token


# --------------------------------------------------------------- 固件


def _dns_callback(token: str | None = None, qname: str | None = None) -> fj.CallbackPlan:
    token = token or new_token()
    return fj.CallbackPlan(
        token=token,
        channel=fj.CHANNEL_DNS,
        qname=qname or f"{host_label(token)}.stub.local",
    )


def _tcp_callback(
    *, channel: str = fj.CHANNEL_TCP_LDAP, port: int = 12345, token: str | None = None
) -> fj.CallbackPlan:
    return fj.CallbackPlan(
        token=token or new_token(), channel=channel, host="127.0.0.1", port=port
    )


def _result(
    name: str,
    role: str,
    *,
    body: bytes = b"",
    status: int | None = 200,
    error: str | None = None,
    gadget: str | None = None,
    channel: str | None = None,
    json_text: str = "{}",
) -> fj.ProbeResult:
    return fj.ProbeResult(
        name=name,
        role=role,
        gadget=gadget,
        channel=channel,
        status=status,
        error=error,
        body=body,
        json_text=json_text,
    )


def _observation(channel: str, token: str) -> Observation:
    return Observation(
        channel=channel,
        token=token,
        source="127.0.0.1",
        at="2026-11-02T10:00:00.000+00:00",
        port=12345,
        detail={"attribution": "token", "protocol": "ldap"},
    )


MARKER = "0123abcd"
HELD = ("ClassNotFoundException: " + fj.parse_control_class(MARKER)).encode()


# --------------------------------------------------------------- 编码


@pytest.mark.parametrize("encoding", fj.ENCODINGS)
def test_encode_decode_round_trip(encoding):
    text = '{"data":{"@type":"java.net.Inet4Address","val":"phfjabc.local"}}'
    body = fj.encode_body(text, encoding=encoding, field="json")
    assert fj.decode_body(body, encoding=encoding, field="json") == text


def test_b64_body_is_form_encoded():
    text = '{"a":1}'
    body = fj.encode_body(text, encoding=fj.ENCODING_B64, field="json")
    parsed = urllib.parse.parse_qs(body.decode("ascii"))
    assert list(parsed) == ["json"]
    raw = base64.b64decode(parsed["json"][0]).decode()
    assert raw == text
    # 填充里的 '=' 必须被 URL-encode（手工拼接会把它原样留在表单里）
    assert parsed["json"][0].endswith("=")
    assert "%3D" in body.decode("ascii")


def test_b64_nopad_has_no_padding():
    text = '{"a":"1"}'
    standard = urllib.parse.parse_qs(
        fj.encode_body(text, encoding=fj.ENCODING_B64, field="json").decode()
    )["json"][0]
    nopad = urllib.parse.parse_qs(
        fj.encode_body(text, encoding=fj.ENCODING_B64NOPAD, field="json").decode()
    )["json"][0]
    assert nopad == standard.rstrip("=")


def test_b64url_uses_urlsafe_alphabet():
    # 三个 U+00FF 编码成 c3bfc3bfc3bf，标准 base64 里会出现 '/'，urlsafe 换成 '_'
    text = '{"v":"\u00ff\u00ff\u00ff"}'
    standard = base64.b64encode(text.encode()).decode()
    assert "/" in standard or "+" in standard
    urlsafe = base64.urlsafe_b64encode(text.encode()).decode()
    body = fj.encode_body(text, encoding=fj.ENCODING_B64URL, field="json")
    value = urllib.parse.parse_qs(body.decode())["json"][0]
    assert value == urlsafe
    assert "+" not in value and "/" not in value


def test_raw_encoding_is_json_body():
    text = '{"a":1}'
    body = fj.encode_body(text, encoding=fj.ENCODING_RAW)
    assert body == text.encode()
    assert fj.content_type_for(fj.ENCODING_RAW) == fj.JSON_CONTENT_TYPE
    assert fj.content_type_for(fj.ENCODING_B64) == fj.FORM_CONTENT_TYPE


def test_unknown_encoding_is_rejected():
    with pytest.raises(fj.FastjsonError):
        fj.encode_body("{}", encoding="rot13")


def test_alternate_encodings():
    assert fj.alternate_encodings(fj.ENCODING_B64) == (
        fj.ENCODING_B64URL,
        fj.ENCODING_B64NOPAD,
    )
    assert fj.alternate_encodings(fj.ENCODING_RAW) == ()


def test_decode_body_returns_none_on_garbage():
    assert fj.decode_body(b"not-a-form", encoding=fj.ENCODING_B64) is None
    assert fj.decode_body(b"json=@@@", encoding=fj.ENCODING_B64) is None


# --------------------------------------------------------------- 模板


def test_parse_json_template_requires_object():
    with pytest.raises(fj.FastjsonError):
        fj.parse_json_template("[1,2]")
    with pytest.raises(fj.FastjsonError):
        fj.parse_json_template("{}")
    with pytest.raises(fj.FastjsonError):
        fj.parse_json_template("not json")
    assert fj.parse_json_template('{"logname":"a"}') == {"logname": "a"}


def test_parse_json_template_rejects_placeholder_literal():
    with pytest.raises(fj.FastjsonError):
        fj.parse_json_template('{"a":"__PROOFHOUND_GADGET_PLACEHOLDER__"}')


def test_choose_injection_key():
    template = {"trace": 1, "logname": "alice", "nested": {"x": 1}}
    assert fj.choose_injection_key(template) == "logname"
    assert fj.choose_injection_key(template, "nested") == "nested"
    with pytest.raises(fj.FastjsonError):
        fj.choose_injection_key(template, "missing")
    with pytest.raises(fj.FastjsonError):
        fj.choose_injection_key({"n": 1})


def test_embed_keeps_other_fields():
    template = {"logname": "alice", "passwd": "x", "trace": 7}
    text = fj._embed(template, "logname", '{"@type":"java.net.Inet4Address","val":"h"}')
    parsed = json.loads(text)
    assert parsed["passwd"] == "x"
    assert parsed["trace"] == 7
    assert parsed["logname"]["@type"] == "java.net.Inet4Address"
    # 不污染调用方的模板
    assert template["logname"] == "alice"


# --------------------------------------------------------------- gadget 片段


@pytest.mark.parametrize("gadget", [item.name for item in fj.GADGETS])
def test_every_gadget_is_valid_json(gadget):
    if fj._GADGET_BY_NAME[gadget].channel == fj.CHANNEL_DNS:
        callback = _dns_callback()
    else:
        callback = _tcp_callback(channel=fj._GADGET_BY_NAME[gadget].channel)
    fragment = fj.gadget_fragment(gadget, callback)
    assert isinstance(json.loads(fragment), (dict, list))


def test_class_cache_two_step_chain_is_present():
    """A 层（默认配置即可命中）必须覆盖：Class 缓存 + JdbcRowSetImpl 两步链。"""
    callback = _tcp_callback()
    fragment = json.loads(fj.gadget_fragment(fj.GADGET_CLASS_CACHE, callback))
    assert fragment["a"]["@type"] == "java.lang.Class"
    assert fragment["a"]["val"] == "com.sun.rowset.JdbcRowSetImpl"
    assert fragment["b"]["@type"] == "com.sun.rowset.JdbcRowSetImpl"
    assert fragment["b"]["dataSourceName"] == callback.ldap_url
    assert fragment["b"]["autoCommit"] is True


def test_ldap_gadget_points_at_callback():
    callback = _tcp_callback()
    fragment = json.loads(fj.gadget_fragment(fj.GADGET_LDAP_ROWSET, callback))
    assert fragment["@type"] == "com.sun.rowset.JdbcRowSetImpl"
    assert fragment["dataSourceName"].startswith("ldap://127.0.0.1:12345/")
    assert callback.token in fragment["dataSourceName"]


def test_jdbc_gadget_uses_basic_datasource():
    callback = _tcp_callback(channel=fj.CHANNEL_TCP_JDBC, port=3306)
    fragment = json.loads(fj.gadget_fragment(fj.GADGET_JDBC_BASIC, callback))
    assert fragment["@type"] == "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"
    assert fragment["url"].startswith("jdbc:mysql://127.0.0.1:3306/")


def test_l_prefix_variant():
    fragment = fj.gadget_fragment(fj.GADGET_DNS_LCLASS, _dns_callback())
    assert "Ljava.net.Inet4Address;" in fragment


def test_unicode_variant_has_single_escape():
    fragment = fj.gadget_fragment(fj.GADGET_DNS_UNICODE, _dns_callback())
    assert r"java.net.Inet4\u0041ddress" in fragment
    assert json.loads(fragment)["@type"] == "java.net.Inet4Address"


def test_dns_nested_wraps_under_json_key():
    callback = _dns_callback()
    spec = fj.gadget_spec(
        fj.GADGET_DNS_NESTED, callback, template=None, json_key="logname"
    )
    parsed = json.loads(spec.json_text)
    assert list(parsed) == ["logname"]
    assert parsed["logname"]["@type"] == "java.net.Inet4Address"
    assert parsed["logname"]["val"] == callback.qname


def test_array_wrapper():
    spec = fj.gadget_spec(
        fj.GADGET_DNS_ARRAY, _dns_callback(), template=None, json_key="data"
    )
    parsed = json.loads(spec.json_text)
    assert isinstance(parsed, list) and parsed[0]["@type"] == "java.net.Inet4Address"


def test_gadget_spec_with_template_injects_into_field():
    template = fj.parse_json_template('{"logname":"alice","passwd":"x"}')
    spec = fj.gadget_spec(
        fj.GADGET_DNS_NESTED,
        _dns_callback(),
        template=template,
        json_key="logname",
    )
    parsed = json.loads(spec.json_text)
    assert parsed["passwd"] == "x"
    assert parsed["logname"]["@type"] == "java.net.Inet4Address"


def test_gadget_and_channel_must_match():
    with pytest.raises(fj.FastjsonError):
        fj.gadget_spec(
            fj.GADGET_LDAP_ROWSET, _dns_callback(), template=None, json_key="data"
        )


# --------------------------------------------------------------- 阴性对照


@pytest.mark.parametrize("gadget", [item.name for item in fj.GADGETS])
def test_control_has_same_url_and_no_at_type(gadget):
    channel = fj._GADGET_BY_NAME[gadget].channel
    callback = (
        _dns_callback()
        if channel == fj.CHANNEL_DNS
        else _tcp_callback(channel=channel)
    )
    spec = fj.control_spec(gadget, callback, template=None, json_key="data")
    assert "@type" not in spec.json_text
    if channel == fj.CHANNEL_DNS:
        # DNS 主机名里只能有下划线**外**的形态
        assert host_label(callback.token) in spec.json_text
        assert callback.qname in spec.json_text
    else:
        assert callback.token in spec.json_text
        assert callback.port is not None
        assert str(callback.port) in spec.json_text


def test_control_role_and_name():
    spec = fj.control_spec(
        fj.GADGET_DNS_NESTED, _dns_callback(), template=None, json_key="data"
    )
    assert (spec.name, spec.role) == (fj.ROLE_CONTROL, fj.ROLE_CONTROL)


# --------------------------------------------------------------- 计划


def test_build_plan_order_and_gadgets():
    callbacks = {
        fj.GADGET_DNS_NESTED: _dns_callback(),
        fj.GADGET_CLASS_CACHE: _tcp_callback(),
        fj.GADGET_LDAP_ROWSET: _tcp_callback(),
        fj.GADGET_JDBC_BASIC: _tcp_callback(channel=fj.CHANNEL_TCP_JDBC),
    }
    plan = fj.build_plan(callbacks, marker=MARKER, json_key="logname")
    names = [spec.name for spec in plan]
    assert names[0] == fj.ROLE_BASELINE
    assert names[1] == fj.ROLE_PARSE_CONTROL
    assert names[2:] == [item.name for item in fj.GADGETS if item.name in callbacks]
    assert "@type" not in plan[0].json_text


def test_build_plan_skips_unavailable_channels():
    plan = fj.build_plan({fj.GADGET_LDAP_ROWSET: _tcp_callback()}, marker=MARKER)
    names = [spec.name for spec in plan]
    assert fj.GADGET_DNS_NESTED not in names
    assert fj.GADGET_LDAP_ROWSET in names


def test_mandatory_gadgets_are_declared():
    assert set(fj.GADGETS_MANDATORY) <= {item.name for item in fj.GADGETS}
    # A 层必做项排在最前（预算被裁时最后被丢）
    order = [item.name for item in fj.GADGETS]
    assert order.index(fj.GADGET_CLASS_CACHE) <= 1


def test_retest_spec_gets_fresh_callback():
    first = _dns_callback()
    retest = _dns_callback()
    spec = fj.retest_spec(
        fj.GADGET_DNS_NESTED, retest, template=None, json_key="data"
    )
    assert spec.role == fj.ROLE_RETEST
    assert spec.name.endswith("-retest")
    assert spec.token == retest.token
    assert first.qname not in spec.json_text


# --------------------------------------------------------------- 安全闸


def test_safety_rejects_ref_loop():
    reasons = fj.safety_reasons('{"a":{"$ref":"$"}}')
    assert any("$ref" in item for item in reasons)


def test_safety_rejects_oversized_body():
    big = '{"a":"' + "A" * (fj.MAX_BODY_BYTES + 1) + '"}'
    assert any("字节" in item for item in fj.safety_reasons(big))


def test_safety_rejects_deep_nesting():
    text = "1"
    for _ in range(fj.MAX_JSON_DEPTH + 1):
        text = '{"a":' + text + "}"
    assert any("嵌套深度" in item for item in fj.safety_reasons(text))


def test_safety_rejects_remote_class_loading_fragments():
    for fragment in ("javaCodebase", "javaFactory", "JNDIReferenceFactory"):
        assert any(
            fragment in item for item in fj.safety_reasons('{"a":"%s"}' % fragment)
        )


@pytest.mark.parametrize("gadget", [item.name for item in fj.GADGETS])
def test_planned_payloads_pass_safety(gadget):
    channel = fj._GADGET_BY_NAME[gadget].channel
    callback = _dns_callback() if channel == fj.CHANNEL_DNS else _tcp_callback(channel=channel)
    spec = fj.gadget_spec(gadget, callback, template=None, json_key="data")
    assert fj.safety_reasons(spec.json_text) == ()
    assert fj.safety_reasons(fj.control_spec(gadget, callback, template=None, json_key="data").json_text) == ()


def test_parse_control_payload_passes_safety():
    spec = fj.parse_control_spec(marker=MARKER, template=None, json_key="data")
    assert fj.safety_reasons(spec.json_text) == ()


# --------------------------------------------------------------- 响应判读


def test_parse_control_held_only_when_decoded_form_appears():
    assert fj.parse_control_state(HELD, MARKER) == "held"
    assert fj.parse_control_state(b"", MARKER) == "absent"
    assert fj.parse_control_state(b"login failed", MARKER) == "absent"


def test_parse_control_echo_is_suspect():
    escaped = (fj.PARSE_CONTROL_PREFIX + fj.PARSE_CONTROL_ESCAPED_DOT + MARKER).encode()
    body = b'{"data":{"@type":"' + escaped + b'"}}'
    assert fj.parse_control_state(body, MARKER) == "echo_suspect"
    # 两种形态同时出现（既回显又解析）按保守处理
    both = body + b" ClassNotFoundException: " + fj.parse_control_class(MARKER).encode()
    assert fj.parse_control_state(both, MARKER) == "echo_suspect"


def test_is_refusal_markers():
    assert fj.is_refusal(b"autoType is not support. Foo")
    assert fj.is_refusal(b"java.lang.SecurityException: safeMode not support autoType")
    assert fj.is_refusal(b"com.alibaba.fastjson.JSONException: autoType is not supported")
    assert not fj.is_refusal(b"")
    assert not fj.is_refusal(b"login failed")


def test_reflected_request_detects_verbatim_echo():
    json_text = '{"data":{"@type":"proofhound\\u002e0123abcd"}}'
    assert fj.reflected_request(("prefix " + json_text).encode(), json_text)
    assert not fj.reflected_request(b"login failed", json_text)


# --------------------------------------------------------------- judge：confirmed


def _confirmed_inputs(**overrides):
    dns_callback = _dns_callback()
    results = [
        _result(fj.ROLE_BASELINE, fj.ROLE_BASELINE, body=b"welcome"),
        _result(fj.ROLE_PARSE_CONTROL, fj.ROLE_PARSE_CONTROL, body=HELD),
        _result(
            fj.GADGET_DNS_NESTED,
            fj.ROLE_GADGET,
            body=b"login failed",
            gadget=fj.GADGET_DNS_NESTED,
            channel=fj.CHANNEL_DNS,
        ),
        _result(
            fj.ROLE_CONTROL,
            fj.ROLE_CONTROL,
            body=b"welcome",
            gadget=fj.GADGET_DNS_NESTED,
            channel=fj.CHANNEL_DNS,
        ),
    ]
    attributed = {
        fj.GADGET_DNS_NESTED: (_observation(fj.CHANNEL_DNS, dns_callback.token),)
    }
    kwargs = dict(
        results=results,
        attributed=attributed,
        channel_states={"tcp": (True, ""), "dns": (True, "")},
        marker=MARKER,
    )
    kwargs.update(overrides)
    return kwargs


def test_judge_confirms_on_attributed_callback():
    judgment = fj.judge(**_confirmed_inputs())
    assert judgment.verdict == fj.VERDICT_CONFIRMED
    assert judgment.channels == (fj.CHANNEL_DNS,)
    assert judgment.confirmed is True
    assert any("唯一 token" in reason for reason in judgment.reasons)


def test_judge_confirmed_requires_positive_control():
    kwargs = _confirmed_inputs()
    kwargs["results"] = [
        _result(fj.ROLE_BASELINE, fj.ROLE_BASELINE, body=b"welcome"),
        _result(fj.ROLE_PARSE_CONTROL, fj.ROLE_PARSE_CONTROL, body=b""),
        kwargs["results"][2],
        kwargs["results"][3],
    ]
    assert fj.judge(**kwargs).verdict == fj.VERDICT_BLOCKED


def test_judge_echo_trap_never_confirms():
    kwargs = _confirmed_inputs()
    escaped = fj.PARSE_CONTROL_PREFIX + fj.PARSE_CONTROL_ESCAPED_DOT + MARKER
    kwargs["results"] = [
        _result(fj.ROLE_BASELINE, fj.ROLE_BASELINE, body=b"welcome"),
        _result(
            fj.ROLE_PARSE_CONTROL,
            fj.ROLE_PARSE_CONTROL,
            body=('{"data":{"@type":"%s"}}' % escaped).encode(),
        ),
        kwargs["results"][2],
        kwargs["results"][3],
    ]
    judgment = fj.judge(**kwargs)
    assert judgment.verdict == fj.VERDICT_BLOCKED
    assert judgment.facts["echo_suspect"] is True


def test_judge_control_hit_blocks_even_with_callback():
    kwargs = _confirmed_inputs()
    kwargs["attributed"] = {
        **kwargs["attributed"],
        fj.ROLE_CONTROL: (_observation(fj.CHANNEL_DNS, new_token()),),
    }
    judgment = fj.judge(**kwargs)
    assert judgment.verdict == fj.VERDICT_BLOCKED
    assert judgment.facts["control_hit"] is True


def test_judge_reflected_request_blocks():
    control_json = '{"data":{"@type":"proofhound\\\\u002e%s"}}' % MARKER
    kwargs = _confirmed_inputs()
    kwargs["results"] = [
        _result(fj.ROLE_BASELINE, fj.ROLE_BASELINE, body=b"welcome"),
        _result(
            fj.ROLE_PARSE_CONTROL,
            fj.ROLE_PARSE_CONTROL,
            body=HELD + control_json.encode(),
            json_text=control_json,
        ),
        kwargs["results"][2],
        kwargs["results"][3],
    ]
    judgment = fj.judge(**kwargs)
    assert judgment.verdict == fj.VERDICT_BLOCKED
    assert judgment.facts["echo_suspect"] is True


# --------------------------------------------------------------- judge：rejected


def _rejected_inputs(gadget_count: int = 3):
    results = [
        _result(fj.ROLE_BASELINE, fj.ROLE_BASELINE, body=b"welcome"),
        _result(fj.ROLE_PARSE_CONTROL, fj.ROLE_PARSE_CONTROL, body=HELD),
    ]
    for index in range(gadget_count):
        results.append(
            _result(
                f"gadget-{index}",
                fj.ROLE_GADGET,
                body=b"autoType is not support.",
                gadget=fj.GADGET_DNS_NESTED,
                channel=fj.CHANNEL_DNS,
            )
        )
    results.append(
        _result(
            fj.ROLE_CONTROL,
            fj.ROLE_CONTROL,
            body=b"welcome",
            gadget=fj.GADGET_DNS_NESTED,
            channel=fj.CHANNEL_DNS,
        )
    )
    return dict(
        results=results,
        attributed={},
        channel_states={"dns": (True, ""), "tcp": (True, "")},
        marker=MARKER,
    )


def test_judge_rejects_when_all_gadgets_refused():
    judgment = fj.judge(**_rejected_inputs())
    assert judgment.verdict == fj.VERDICT_REJECTED
    assert judgment.channels == ()
    assert any("明确拒绝语义" in reason for reason in judgment.reasons)


def test_judge_partial_silence_blocks():
    kwargs = _rejected_inputs()
    kwargs["results"][2] = _result(
        "gadget-0",
        fj.ROLE_GADGET,
        body=b"",
        gadget=fj.GADGET_DNS_NESTED,
        channel=fj.CHANNEL_DNS,
    )
    judgment = fj.judge(**kwargs)
    assert judgment.verdict == fj.VERDICT_BLOCKED
    assert any("部分 gadget 族沉默" in reason for reason in judgment.reasons)


def test_judge_rejected_needs_at_least_one_gadget():
    kwargs = _rejected_inputs(gadget_count=0)
    assert fj.judge(**kwargs).verdict == fj.VERDICT_BLOCKED


def test_judge_baseline_refusal_disables_rejected():
    kwargs = _rejected_inputs()
    kwargs["results"][0] = _result(
        fj.ROLE_BASELINE, fj.ROLE_BASELINE, body=b"autoType is not support."
    )
    judgment = fj.judge(**kwargs)
    assert judgment.verdict == fj.VERDICT_BLOCKED
    assert judgment.facts["baseline_refusal"] is True


# --------------------------------------------------------------- judge：blocked 其余分支


def test_judge_blocked_without_positive_control():
    kwargs = _rejected_inputs()
    kwargs["results"][1] = _result(fj.ROLE_PARSE_CONTROL, fj.ROLE_PARSE_CONTROL, body=b"")
    judgment = fj.judge(**kwargs)
    assert judgment.verdict == fj.VERDICT_BLOCKED
    assert any("阳性对照未成立" in reason for reason in judgment.reasons)


def test_judge_blocked_when_observer_unavailable():
    kwargs = _rejected_inputs()
    kwargs["results"][1] = _result(fj.ROLE_PARSE_CONTROL, fj.ROLE_PARSE_CONTROL, body=b"")
    kwargs["channel_states"] = {"dns": (False, "provider 未配置")}
    judgment = fj.judge(**kwargs)
    assert judgment.verdict == fj.VERDICT_BLOCKED
    assert judgment.facts["unavailable_channels"] == ["dns"]


def test_judge_blocked_on_failed_request():
    kwargs = _rejected_inputs()
    kwargs["results"][2] = _result(
        "gadget-0",
        fj.ROLE_GADGET,
        body=b"",
        status=None,
        error="URLError: timed out",
        gadget=fj.GADGET_DNS_NESTED,
        channel=fj.CHANNEL_DNS,
    )
    judgment = fj.judge(**kwargs)
    assert judgment.verdict == fj.VERDICT_BLOCKED
    assert "gadget-0" in judgment.facts["unanswered_probes"]


def test_judge_reasons_never_contain_tokens():
    dns_callback = _dns_callback()
    kwargs = _confirmed_inputs()
    kwargs["attributed"] = {
        fj.GADGET_DNS_NESTED: (_observation(fj.CHANNEL_DNS, dns_callback.token),)
    }
    judgment = fj.judge(**kwargs)
    text = json.dumps(judgment.to_dict(), ensure_ascii=False)
    assert dns_callback.token not in text
    assert dns_callback.qname not in text


def test_judge_facts_are_stable_shapes():
    judgment = fj.judge(**_rejected_inputs())
    facts = judgment.facts
    assert set(facts) >= {
        "parse_control",
        "parse_control_holds",
        "echo_suspect",
        "baseline_refusal",
        "gadget_hits",
        "control_hit",
        "all_gadgets_refused",
        "unanswered_probes",
        "unavailable_channels",
        "ignored_observations",
        "requests",
    }
    assert facts["requests"] == len(judgment.facts["gadget_probes"]) + 3


# --------------------------------------------------------------- CallbackPlan


def test_callback_plan_validation():
    with pytest.raises(fj.FastjsonError):
        fj.CallbackPlan(token="nope", channel=fj.CHANNEL_DNS, qname="a.local")
    with pytest.raises(fj.FastjsonError):
        fj.CallbackPlan(token=new_token(), channel=fj.CHANNEL_DNS)
    with pytest.raises(fj.FastjsonError):
        fj.CallbackPlan(token=new_token(), channel=fj.CHANNEL_TCP_LDAP, host="", port=1)
    with pytest.raises(fj.FastjsonError):
        fj.CallbackPlan(
            token=new_token(),
            channel=fj.CHANNEL_TCP_LDAP,
            host='x"y',
            port=1,
        )
    with pytest.raises(fj.FastjsonError):
        fj.CallbackPlan(token=new_token(), channel="carrier-pigeon")


def test_callback_plan_urls():
    callback = _tcp_callback(port=4444)
    assert callback.ldap_url == f"ldap://127.0.0.1:4444/{callback.token}"
    jdbc = _tcp_callback(channel=fj.CHANNEL_TCP_JDBC, port=3306)
    assert jdbc.jdbc_url == f"jdbc:mysql://127.0.0.1:3306/{jdbc.token}"
