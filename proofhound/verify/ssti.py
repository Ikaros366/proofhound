"""SSTI（服务端模板注入）的**差分求值**判定器（M22，§7.25/§7.26）。

## 这个模块要回答的**二值事实**

「服务端把这个参数当**模板**求值了」——判据不是"页面里出现了报错/特殊字符"，
而是**同一语法下两个不同的乘法表达式都算出了正确乘积**，且基线响应里没有这两个
数字。这条事实与模板引擎的类型无关（Jinja2 / Twig / Django / EL / FreeMarker /
ERB / EJS 都成立），也与身份无关（故 `VULN_REGISTRY` 里 `requires_session=False`）。

## 三道对照（缺一不可）

1. **基线**：``finding.asset`` 原样响应不含探针乘积 —— 没有它就是"数字巧合"，
   不是求值（反事实不可测 ⇒ ``blocked``，不是 ``rejected``）；
2. **两个乘积**：同一语法下换操作数，**两个**乘积都要出现 —— 只中一个说明不了
   求值（可能是静态文本、也可能是取值被拼接）；
3. **畸形模板对照**：少一个右括号的探针**不得**算出乘积 —— 它挡的正是
   「strip 掉非数字后照样算乘法」这类端点：表达式探针全中，但**判不了**
   （只能 ``blocked``），因为"少一个括号也能算"证明不了"是模板引擎算的"。

## 与其它类型的关系

判据形态是「同一 URL 换取值，看两处响应里的确定性产物」，与 sqli 的布尔/时间
差分**同构但不同源**：SSTI 的产物是**模板引擎算出来的值**，不需要错误回显、
不需要时间差异、不需要数据库。故 method（:data:`SSTI_CONFIRMED_METHOD`）与
具名证据标签（:data:`SSTI_EVALUATION_EVIDENCE_KIND`）都与其余六类**互不染指**
（``tests/test_ssrf.py`` / ``tests/test_cmdi.py`` 的全矩阵断言）。

## 本模块的边界（诚实记录）

- 只看**响应里有没有乘积**：不做模板指纹识别、不产可用 RCE 载荷、不读文件、
  不反弹 shell —— 探针固定、无副作用、只 GET；
- **不覆盖盲注**（求值结果不回显到响应里的 SSTI）——那需要另外的带外观测手段；
- 乘积匹配用**数字边界**（前后不得紧邻数字），否则 ``136481`` 会假命中；
  被截断到只剩部分数字时匹配不上（宁漏勿滥的保守方向）；
- 真引擎覆盖只到 jinja2（``{{ }}`` 一族）：``${ }`` 与 ``<%= %>`` 两族的探针由本
  模块的纯函数支撑，但**未在真靶上验证**（本机无 Java/Ruby 引擎，见限制 70）。

## 判定优先级（宁漏勿滥）

```
基线失败 / 基线本身含乘积            → blocked（反事实不可测）
某语法两个乘积都中 + 畸形对照干净    → confirmed
某语法两个乘积都中 + 畸形对照也出数  → blocked（疑似"strip 后强算"，不是模板求值）
只中一个乘积                         → blocked（不足以证明求值）
全部探针干净未命中、无请求错误        → rejected（真阴性）
任一探针请求出错、且未命中            → blocked（覆盖不全，不驳回）
```
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Sequence

from proofhound.verify.prefilter import with_query_param

#: 唯一认可确认手段（``verification.method`` 白名单成员）。
#: 与其余六类互不染指（全矩阵断言见 ``tests/test_ssrf.py`` / ``tests/test_cmdi.py``）。
SSTI_CONFIRMED_METHOD = "template-eval-confirmed"

#: 具名行为类证据标签（``evidence_kinds``）。刻意**不用**笼统的 ``behavioral``：
#: 让"这条 Confirmed 靠的是模板求值产物"在证据层可分辨（同 ``unauth-exposure`` 的
#: ``unauth-response-equivalence`` 先例）。铁律 2 只要求"存在任一非 status-code
#: 标签"，具名标签同样满足。
SSTI_EVALUATION_EVIDENCE_KIND = "template-evaluation"

#: 探针乘积：两个**不同**的 5 位数（191²=36481、191×192=36672）。
#: 用 5 位数而不是 49：页面里本来就有 49 的概率高得离谱，有 36481 的概率极低。
PRODUCT_A = "36481"
PRODUCT_B = "36672"

#: 每候选的只读 GET 预算（交接单硬上限）：1 基线 + 3 语法 × 2 探针 + 1 畸形对照。
PROBE_BUDGET = 8

#: 乘积匹配：**数字边界**（前后不得紧邻数字）——否则 ``136481`` 会假命中。
_PRODUCT_RE = re.compile(r"(?<!\d)(" + PRODUCT_A + "|" + PRODUCT_B + r")(?!\d)")

#: 默认请求超时（秒）。SSTI 是同步渲染，正常远快于此。
DEFAULT_TIMEOUT = 10.0


@dataclass(frozen=True)
class SyntaxFamily:
    """一个模板语法族：两条表达式探针 + 一条**畸形**对照探针。"""

    #: 内部标签（进审计与判定 JSON，不进 prompt）。
    label: str
    #: 人类可读的引擎清单（进 SKILL.md 与判定 JSON 的说明）。
    engines: str
    expr_a: str
    expr_b: str
    #: 畸形对照：少一个右括号（语法不完整，真引擎应报错而**不算**出乘积）。
    malformed: str


#: 三个语法族（**顺序即探测顺序**：Jinja2 系最常见，先试它）。
SYNTAX_FAMILIES: tuple[SyntaxFamily, ...] = (
    SyntaxFamily(
        label="double-brace",
        engines="Jinja2 / Twig / Django / Nunjucks",
        expr_a="{{191*191}}",
        expr_b="{{191*192}}",
        malformed="{{191*191}",
    ),
    SyntaxFamily(
        label="dollar-brace",
        engines="EL / FreeMarker / JSP",
        expr_a="${191*191}",
        expr_b="${191*192}",
        malformed="${191*191",
    ),
    SyntaxFamily(
        label="erb-tag",
        engines="ERB / EJS",
        expr_a="<%= 191*191 %>",
        expr_b="<%= 191*192 %>",
        malformed="<%= 191*191 %",
    ),
)

#: 判定结论（三态；与编排层 `verify_blocked` 语义对齐）。
VERDICT_CONFIRMED = "confirmed"
VERDICT_REJECTED = "rejected"
VERDICT_BLOCKED = "blocked"

#: 探针种类标签（进审计与判定 JSON）。
KIND_BASELINE = "baseline"
KIND_EXPRESSION = "expression"
KIND_CONTROL = "control"


def match_products(text: str) -> frozenset[str]:
    """从响应正文里取出**出现了的探针乘积**（数字边界匹配，纯函数）。"""
    return frozenset(_PRODUCT_RE.findall(text or ""))


def build_probe_url(asset: str, param: str, value: str) -> str:
    """把 ``asset`` 的 ``param`` 换成探针取值（保留其余参数，确定性重编码）。"""
    return with_query_param(asset, param, value)


@dataclass(frozen=True)
class ProbeResponse:
    """一次探针请求的结果（网络错误不抛出，置 ``error``）。"""

    url: str
    status: int | None = None
    body: str = ""
    error: str | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随重定向：3xx 原样暴露（登录跳转 / 跳转型 WAF 都能被看见）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def fetch(url: str, session, *, timeout: float = DEFAULT_TIMEOUT) -> ProbeResponse:
    """以给定会话请求 URL（GET，不跟随重定向）。

    ``session`` 可为 ``None``（SSTI 判据与身份无关：有预置会话就带上，提高
    可达性；没有也照判）。凭据由代码注入请求头，LLM 零接触。网络/超时异常
    不抛出而是置 ``error``——编排层转 ``blocked``（覆盖不全不驳回）。
    """
    headers: dict[str, str] = {}
    if session is not None:
        cookie = session.cookie_header()
        if cookie:
            headers["Cookie"] = cookie
        for key, value in session.headers.items():
            headers[key] = value
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as resp:
            return ProbeResponse(
                url=url,
                status=resp.status,
                body=resp.read().decode("utf-8", errors="replace"),
            )
    except urllib.error.HTTPError as exc:  # 4xx/5xx/3xx（不跟随）也是响应
        return ProbeResponse(
            url=url,
            status=exc.code,
            body=exc.read().decode("utf-8", errors="replace"),
        )
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return ProbeResponse(url=url, error=f"{type(exc).__name__}: {exc}")


@dataclass(frozen=True)
class Probe:
    """一条探针记录（判定输入；也是判定 JSON 落盘的原料）。"""

    label: str
    kind: str
    syntax: str | None
    url: str
    status: int | None
    error: str | None
    products: frozenset[str] = frozenset()

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "kind": self.kind,
            "syntax": self.syntax,
            "status": self.status,
            "error": self.error,
            "products": sorted(self.products),
        }


@dataclass(frozen=True)
class Judgment:
    """差分求值判定结论（三态 + 依据）。"""

    verdict: str
    syntax: str | None = None
    engines: str | None = None
    products: tuple[str, ...] = ()
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def confirmed(self) -> bool:
        return self.verdict == VERDICT_CONFIRMED


def _blocked(reason: str, *, syntax: str | None = None) -> Judgment:
    return Judgment(verdict=VERDICT_BLOCKED, syntax=syntax, reasons=(reason,))


def judge(probes: Sequence[Probe]) -> Judgment:
    """差分求值判定（纯函数、零网络、零 LLM）。

    输入顺序约定：``probes[0]`` 是基线（``kind=baseline``），其余按探测顺序。
    判定优先级见模块 docstring（**顺序本身就是优先级**：越靠前的否定条件越强）。
    """
    if not probes:
        return _blocked("无探针记录（覆盖不全）")
    baseline = probes[0]
    if baseline.kind != KIND_BASELINE:
        return _blocked("探针顺序错误：首条不是基线")
    if baseline.error is not None:
        return _blocked(f"基线请求失败（反事实不可测）: {baseline.error}")
    if baseline.products:
        return _blocked(
            "基线响应本身含探针乘积 "
            f"{sorted(baseline.products)}（反事实不可测：无法区分「本来就有」与「被算出来」）"
        )

    grouped: dict[str, list[Probe]] = {}
    for probe in probes[1:]:
        grouped.setdefault(probe.syntax or "", []).append(probe)

    # 先找**任一语法族**的两个乘积都命中；只中一个的留作 blocked 证据。
    full_hit: SyntaxFamily | None = None
    partial: list[str] = []
    errored: list[Probe] = []
    for family in SYNTAX_FAMILIES:
        group = grouped.get(family.label) or []
        expressions = [p for p in group if p.kind == KIND_EXPRESSION]
        errors = [p for p in group if p.error is not None]
        errored.extend(errors)
        if len(expressions) < 2:
            continue  # 该语法没探到（提前停止）
        first, second = expressions[0], expressions[1]
        observed = first.products | second.products
        if not observed:
            continue
        if PRODUCT_A in first.products and PRODUCT_B in second.products:
            full_hit = family
            break
        partial.append(f"{family.label}={sorted(observed)}")

    if full_hit is not None:
        controls = [
            p
            for p in grouped.get(full_hit.label, [])
            if p.kind == KIND_CONTROL
        ]
        if not controls:
            return _blocked(
                f"{full_hit.label} 两个乘积都命中，但缺畸形模板对照（覆盖不全，判不了）",
                syntax=full_hit.label,
            )
        control = controls[0]
        if control.error is not None:
            return _blocked(
                f"畸形模板对照请求失败（判不了）: {control.error}",
                syntax=full_hit.label,
            )
        if control.products:
            return _blocked(
                "畸形模板对照（缺一个右括号）也算出乘积 "
                f"{sorted(control.products)} —— 疑似「strip 非数字后强算」而非模板求值，判不了",
                syntax=full_hit.label,
            )
        return Judgment(
            verdict=VERDICT_CONFIRMED,
            syntax=full_hit.label,
            engines=full_hit.engines,
            products=(PRODUCT_A, PRODUCT_B),
            reasons=(
                f"{full_hit.engines} 语法下两个不同乘积 {PRODUCT_A} / {PRODUCT_B} 都被算出",
                "基线干净（原样响应不含这两个数字）",
                "畸形模板对照未算出乘积（排除「强算非数字」形态）",
            ),
        )

    if partial:
        return _blocked(
            "只命中一个乘积，不足以证明求值（" + "；".join(partial) + "）"
        )
    if errored:
        return _blocked(
            f"探针请求出错 {len(errored)} 次且未命中，覆盖不全（不驳回）: "
            f"{errored[0].error}"
        )
    return Judgment(
        verdict=VERDICT_REJECTED,
        reasons=(
            f"三个语法族的表达式探针（{' / '.join(f.label for f in SYNTAX_FAMILIES)}）"
            "全部未算出乘积",
            "基线干净、无请求错误 ⇒ 参数未被当模板求值（真阴性）",
        ),
    )


def summary_for_verifier(
    judgment: Judgment, probes: Sequence[Probe], *, url: str, param: str
) -> dict:
    """给 Verifier 的**结构化结论**（红线 3：响应体一行都不进）。

    只含枚举、计数、乘积与状态码——足以复核判定，不足以泄漏页面内容。
    """
    baseline = probes[0] if probes else None
    controls = [p for p in probes if p.kind == KIND_CONTROL]
    return {
        "vuln_type": "ssti",
        "judge": "差分求值：三语法族 × 两个不同乘积 + 基线 + 畸形模板对照",
        "endpoint": url,
        "param": param,
        "verdict": judgment.verdict,
        "syntax": judgment.syntax,
        "engines": judgment.engines,
        "products_observed": list(judgment.products),
        "baseline_clean": bool(baseline is not None and not baseline.products),
        "malformed_checked": bool(controls),
        "malformed_clean": bool(controls and not controls[0].products),
        "probe_count": len(probes),
        "probe_budget": PROBE_BUDGET,
        "probes": [p.to_dict() for p in probes],
        "reasons": list(judgment.reasons),
    }


__all__ = [
    "DEFAULT_TIMEOUT",
    "Judgment",
    "KIND_BASELINE",
    "KIND_CONTROL",
    "KIND_EXPRESSION",
    "PROBE_BUDGET",
    "PRODUCT_A",
    "PRODUCT_B",
    "Probe",
    "ProbeResponse",
    "SSTI_CONFIRMED_METHOD",
    "SSTI_EVALUATION_EVIDENCE_KIND",
    "SYNTAX_FAMILIES",
    "SyntaxFamily",
    "VERDICT_BLOCKED",
    "VERDICT_CONFIRMED",
    "VERDICT_REJECTED",
    "build_probe_url",
    "fetch",
    "judge",
    "match_products",
    "summary_for_verifier",
]
