"""服务器报错信息泄露（error-disclosure）的确定性判定器（M23，§7.26）。

## 这个类型回答的**二值事实**

「把畸形请求发给同一个 host，中间件会不会把**内部异常/堆栈/源码路径**回显给
客户端」——判据不是"错误页看起来像堆栈"（那是观感，不是事实），而是**差分**：

| 请求 | 期望 |
|---|---|
| 正常 GET（基线） | 正文**不含**任何技术披露标记 |
| 同一 host 的畸形请求（探针） | 4xx/5xx **且**正文命中 **≥2 类**标记 |

同一个 host、只改请求形态，两次响应一个干净一个有堆栈 ⇒ 可归因。全部确定性
正则，零 LLM（唯一的 LLM 调用是收尾的 Verifier 终审）。

## 为什么必须「≥2 类」

只命中 1 类（例如正文里只有一个 ``Exception`` 单词、或只有 ``Fatal error:``
没有路径）不足以说明**服务端内部信息**被回显：通用错误页、文档、示例代码都能
命中单个词。两类同时出现（如 Java 堆栈帧 + Tomcat 版本、PHP 错误 + 源码绝对
路径）才把"这是运行时吐出来的"与"这是页面本来就有的"分开。

## 与版本头的界线（维护者裁定）

``Server: nginx/1.25`` 这类**版本头**是另一件更弱的事——几乎所有站点都有，
把它算进结论会得到 100% 误报率。故版本头**只记审计**
（``server_header_disclosed``）与判定 JSON，**不构成** confirmed 的证据。

## 判定优先级（宁漏勿滥）

```
基线请求失败 / 基线本身命中标记        → blocked（反事实不可测）
某条畸形请求 4xx/5xx 且命中 ≥2 类      → confirmed
某条畸形请求 4xx/5xx 但只命中 1 类     → blocked（不足以归因）
畸形请求没能完成（连接重置/超时/不可解析）→ blocked（覆盖不全，不驳回）
畸形请求全部有响应、零标记、至少一条 4xx/5xx → rejected（真阴性）
畸形请求未被拒绝（全 2xx/3xx）          → blocked（没触发错误路径，没测到）
```

## 边界（诚实记录）

- 只探 **HTTP 层**的畸形请求，不做请求走私（``Content-Length`` 与
  ``Transfer-Encoding`` 冲突）、不做 header 洪泛、不做 ``Host`` 注入——那些
  要么危险、要么是另一个类型；
- 只测 **host 级**一次（中间件错误页通常与路径无关），不按端点放大；
- 不跟随重定向（裸 socket 本来就不跟）；不发送任何凭据；
- 只保留响应正文前 256KB（``raw_http.MAX_BODY_BYTES``）；
- 代理/WAF 会把畸形请求直接拦掉，此时响应是网关页 ⇒ 会落 ``rejected``；
  判定 JSON 里记录状态行与 ``Server`` 头，blocked 原因里写明"响应来自哪一层"
  （见 ``reasons`` 与 ``server_header``）。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from proofhound.verify.raw_http import DEFAULT_TIMEOUT, RawResponse

#: 唯一认可确认手段（``verification.method`` 白名单成员）。
#: 与其余七类互不染指（全矩阵断言见 ``tests/test_ssrf.py`` / ``tests/test_cmdi.py``）。
ERROR_DISCLOSURE_CONFIRMED_METHOD = "error-trace-confirmed"

#: 具名行为类证据标签（``evidence_kinds``）。刻意**不用**笼统的 ``behavioral``：
#: 让"这条 Confirmed 靠的是错误页里的技术披露标记"在证据层可分辨
#: （同 ``unauth-exposure`` 的 ``unauth-response-equivalence`` 先例）。
ERROR_TRACE_EVIDENCE_KIND = "error-trace"

#: 每 host 的畸形探针预算（交接单硬上限：≤5 条；基线另计 1 次）。
PROBE_BUDGET = 5

#: 超长 URI 探针的路径长度（>8KB；部分中间件返回 414 且栈里带路径）。
LONG_URI_BYTES = 8200

#: U+2026 的 UTF-8 字节（``E2 80 A6``）——交接单里的真实案例字符。
ELLIPSIS_BYTES = "\u2026".encode("utf-8")

#: 探针 User-Agent（可识别，便于目标侧审计；不含任何凭据）。
USER_AGENT = "ProofHound/error-disclosure-probe"

#: ``with_query_param`` 之外的探针描述（进审计与判定 JSON）。
#: **刻意不记原始请求字节**（含控制字符）：证据里只记 sha256 + repr 摘要。
PROBE_LABELS: dict[str, str] = {
    "baseline": "正常 GET（基线对照）",
    "unicode-path": "路径里插入 U+2026（E2 80 A6）",
    "bad-percent": "路径里插入非法百分号编码 %zz",
    "bad-version": "请求行用非法版本 HTTP/9.9",
    "ctl-method": "方法 token 里嵌控制字符（G\\x01ET）",
    "long-uri": "超长 URI（>8KB）",
}

#: 标记类别 → 中文标签（进审计/判定 JSON/报告摘录；**不进** Verifier prompt）。
CLASS_LABELS: dict[str, str] = {
    "java_stack": "Java 堆栈",
    "php_error": "PHP 错误",
    "python_traceback": "Python 异常",
    "dotnet_exception": ".NET 异常",
    "node_stack": "Node 堆栈",
    "middleware_version": "中间件版本",
    "path_disclosure": "源码路径",
}

#: **七类标记**（逐类独立匹配；≥2 类才够确认）。正则全部确定性、零 LLM。
#:
#: 第 7 类 ``path_disclosure`` 是维护者 2026-10-28 裁定新增的：PHP 的
#: ``Fatal error:`` 与 ``#0 /...`` 在**同一类**里，若只保留六类，交接单 §7 的
#: ``php-like`` 靶（500 + Fatal error + 路径 + #0）只命中 PHP 一类，会被判
#: blocked，与"期望 confirmed"冲突。把「绝对源码路径 + 行号」单独成类既解决了
#: 这个冲突，也对应一类独立的真实披露（路径泄露）。
MARKER_CLASSES: dict[str, tuple[re.Pattern[str], ...]] = {
    "java_stack": (
        re.compile(r"\bat\s+[\w.$]+\([\w$]+\.java:\d+\)"),
        re.compile(r"\bjava\.lang\.[A-Z]\w*"),
        re.compile(r"Caused by:\s*[\w.$]+"),
    ),
    "php_error": (
        re.compile(r"Fatal error(?:</b>|</strong>)?:"),
        re.compile(r"Parse error(?:</b>|</strong>)?:"),
        re.compile(r"Stack trace(?:</b>|</strong>)?:"),
        re.compile(r"#0\s+/"),
    ),
    "python_traceback": (
        re.compile(r"Traceback \(most recent call last\)"),
        re.compile(r'File "[^"\r\n]+", line \d+'),
    ),
    "dotnet_exception": (
        re.compile(r"\bSystem\.[\w.]+Exception\b"),
        re.compile(r"Microsoft\.[\w.]+"),
        re.compile(r"\[HttpException\]"),
    ),
    "node_stack": (
        re.compile(r"at Object\.<anonymous>"),
        re.compile(r"\bnode_modules/"),
        re.compile(r"at\s+[\w.$<>]+\s+\([^)\r\n]*node:"),
    ),
    "middleware_version": (
        re.compile(r"Apache Tomcat/\d+(?:\.\d+)*"),
        re.compile(r"Jetty\(\d"),
        re.compile(r"\bnginx/\d+\.\d+"),
        re.compile(r"Werkzeug/\d"),
        re.compile(r"Microsoft-IIS/\d"),
    ),
    # 绝对源码路径 + 行号（POSIX / Windows）。刻意要求「多级目录 + 源码扩展名 +
    # 行号」三件同时出现：单独的 ``/admin`` 或 ``#0 /`` 不算。
    "path_disclosure": (
        re.compile(
            r"(?<![\w.:/])/(?:[\w.-]+/){2,}[\w.-]+"
            r"\.(?:php|phtml|py|rb|jsp|js|java|cs|aspx?|go|pl):\d+"
        ),
        re.compile(
            r"\b[A-Za-z]:\\[\w.\\ -]+\.(?:php|py|jsp|aspx?|cs|java):\d+"
        ),
    ),
}

#: 版本头识别（**只记审计，不算证据**）。
_VERSION_HEADER_RE = re.compile(
    r"(?:Apache(?:[ -][\w.]+)?/|nginx/|Jetty(?:/|\()|Werkzeug/"
    r"|Microsoft-IIS/|PHP/|OpenSSL/|Kestrel/|Express/)",
    re.IGNORECASE,
)

#: 判定结论（三态；与编排层 `verify_blocked` 语义对齐）。
VERDICT_CONFIRMED = "confirmed"
VERDICT_REJECTED = "rejected"
VERDICT_BLOCKED = "blocked"

#: 证据里单条命中片段的截断长度（避免整页正文进 JSON）。
_SAMPLE_LIMIT = 120


def classify_markers(text: str) -> dict[str, tuple[str, ...]]:
    """从响应正文里取出命中的**标记类别**与片段（纯函数、零网络）。

    返回 ``{类别: (片段, ...)}``，只含命中的类别；每类最多 3 条片段，每条截断到
    120 字符。片段只用于证据与判定 JSON，**不进** Verifier prompt。
    """
    body = text or ""
    found: dict[str, tuple[str, ...]] = {}
    for name, patterns in MARKER_CLASSES.items():
        samples: list[str] = []
        for pattern in patterns:
            match = pattern.search(body)
            if match is None:
                continue
            snippet = " ".join(match.group(0).split())
            if len(snippet) > _SAMPLE_LIMIT:
                snippet = snippet[:_SAMPLE_LIMIT] + "…"
            if snippet not in samples:
                samples.append(snippet)
            if len(samples) >= 3:
                break
        if samples:
            found[name] = tuple(samples)
    return found


def matched_class_names(text: str) -> frozenset[str]:
    """命中类别名集合（判定只看类别数，不看片段）。"""
    return frozenset(classify_markers(text))


def server_header_disclosed(headers: Mapping[str, str]) -> str | None:
    """响应头里是否披露了带版本的服务端标识（**审计用，不是证据**）。

    只看 ``Server`` 与 ``X-Powered-By``；命中返回头值原文，否则 None。
    """
    for name in ("server", "x-powered-by"):
        value = headers.get(name)
        if value and _VERSION_HEADER_RE.search(value):
            return value.strip()
    return None


def build_request(
    method: bytes,
    target: bytes,
    host_header: str,
    *,
    version: bytes = b"HTTP/1.1",
) -> bytes:
    """构造一条 HTTP/1.1 请求（**保留**调用方给的方法/target/版本原始字节）。"""
    authority = host_header.encode("latin-1", "replace")
    return (
        method
        + b" "
        + target
        + b" "
        + version
        + b"\r\nHost: "
        + authority
        + b"\r\nUser-Agent: "
        + USER_AGENT.encode("ascii")
        + b"\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )


def build_baseline(host_header: str) -> bytes:
    """基线请求：一条**完全正常**的 GET /。"""
    return build_request(b"GET", b"/", host_header)


@dataclass(frozen=True)
class ProbeSpec:
    """一条畸形探针：标签 + 说明 + **原始请求字节**。"""

    label: str
    description: str
    request: bytes

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(self.request).hexdigest()

    @property
    def request_repr(self) -> str:
        """转义后的请求摘要（**不含**原始控制字符，最多 160 字符）。"""
        text = repr(self.request)
        return text if len(text) <= 160 else text[:160] + "…"


def build_probes(host_header: str) -> tuple[ProbeSpec, ...]:
    """交接单 §4.1 的五条畸形探针（固定顺序、确定性字节）。"""
    specs = (
        ProbeSpec(
            "unicode-path",
            PROBE_LABELS["unicode-path"],
            build_request(b"GET", b"/" + ELLIPSIS_BYTES + b"proof", host_header),
        ),
        ProbeSpec(
            "bad-percent",
            PROBE_LABELS["bad-percent"],
            build_request(b"GET", b"/%zz", host_header),
        ),
        ProbeSpec(
            "bad-version",
            PROBE_LABELS["bad-version"],
            build_request(b"GET", b"/", host_header, version=b"HTTP/9.9"),
        ),
        ProbeSpec(
            "ctl-method",
            PROBE_LABELS["ctl-method"],
            build_request(b"G\x01ET", b"/", host_header),
        ),
        ProbeSpec(
            "long-uri",
            PROBE_LABELS["long-uri"],
            build_request(b"GET", b"/" + b"a" * LONG_URI_BYTES, host_header),
        ),
    )
    assert len(specs) == PROBE_BUDGET  # noqa: S101 —— 常量与探针表同步的本地断言
    return specs


@dataclass(frozen=True)
class ProbeOutcome:
    """一次探针的结果（判定输入；也是判定 JSON 的原料）。"""

    label: str
    description: str
    request_sha256: str
    request_repr: str
    status: int | None = None
    error: str | None = None
    error_kind: str | None = None
    classes: frozenset[str] = frozenset()
    samples: tuple[str, ...] = ()
    body_bytes: int = 0
    server_header: str | None = None

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "description": self.description,
            "status": self.status,
            "error": self.error,
            "error_kind": self.error_kind,
            "classes": sorted(self.classes),
            "body_bytes": self.body_bytes,
            "server_header": self.server_header,
            "request_sha256": self.request_sha256,
            "request_repr": self.request_repr,
        }


def outcome_from_response(
    spec: ProbeSpec, response: RawResponse
) -> ProbeOutcome:
    """把一次裸响应归一成 :class:`ProbeOutcome`（纯函数）。"""
    classes: frozenset[str] = frozenset()
    samples: tuple[str, ...] = ()
    if response.body:
        markers = classify_markers(response.body_text)
        classes = frozenset(markers)
        samples = () if not markers else tuple(
            f"{name}: {sample}" for name, group in markers.items() for sample in group
        )
    return ProbeOutcome(
        label=spec.label,
        description=spec.description,
        request_sha256=spec.request_sha256,
        request_repr=spec.request_repr,
        status=response.status,
        error=response.error,
        error_kind=response.error_kind,
        classes=classes,
        samples=samples,
        body_bytes=len(response.body),
        server_header=server_header_disclosed(response.headers),
    )


def _is_error_status(status: int | None) -> bool:
    return status is not None and 400 <= status <= 599


def _classes_text(classes: frozenset[str]) -> str:
    return " / ".join(CLASS_LABELS.get(name, name) for name in sorted(classes))


@dataclass(frozen=True)
class Judgment:
    """差分判定结论（三态 + 依据）。"""

    verdict: str
    matched: tuple[str, ...] = ()
    reasons: tuple[str, ...] = field(default_factory=tuple)
    server_header: str | None = None
    probe: str | None = None

    @property
    def confirmed(self) -> bool:
        return self.verdict == VERDICT_CONFIRMED


def _blocked(reason: str, *, server_header: str | None = None) -> Judgment:
    return Judgment(
        verdict=VERDICT_BLOCKED, reasons=(reason,), server_header=server_header
    )


def judge(
    baseline: ProbeOutcome | None,
    probes: Sequence[ProbeOutcome],
) -> Judgment:
    """差分判定（纯函数、零网络、零 LLM）。

    判定优先级见模块 docstring（**顺序本身就是优先级**：越靠前的否定条件越强）。
    ``baseline`` 是正常 GET；``probes`` 是畸形请求（顺序即探测顺序）。
    """
    if baseline is None:
        return _blocked("缺基线响应（反事实不可测）")
    header = baseline.server_header
    if baseline.error is not None:
        return _blocked(
            f"基线请求失败（反事实不可测）: {baseline.error}", server_header=header
        )
    if baseline.status is None:
        return _blocked("基线响应不可解析（反事实不可测）", server_header=header)
    if baseline.classes:
        return _blocked(
            "基线响应本身命中技术披露标记 "
            f"[{_classes_text(baseline.classes)}] —— 站点平时就在展示堆栈/版本/路径，"
            "无法归因到畸形请求（反事实不可测）",
            server_header=header,
        )
    if not probes:
        return _blocked("无畸形探针记录（覆盖不全）", server_header=header)

    # 1) 确认：任一条 4xx/5xx 且 ≥2 类标记（**先于**单类/错误判断，
    #    否则一条单类探针会把另一条两类探针的正确结论盖掉）。
    for probe in probes:
        if _is_error_status(probe.status) and len(probe.classes) >= 2:
            return Judgment(
                verdict=VERDICT_CONFIRMED,
                matched=tuple(sorted(probe.classes)),
                reasons=(
                    f"畸形请求 {probe.label}（{probe.description}）返回 "
                    f"{probe.status}，正文命中 {len(probe.classes)} 类技术披露标记："
                    f"{_classes_text(probe.classes)}",
                    "基线干净（同一 host 的正常 GET 不含任何标记）⇒ 可归因到畸形请求",
                    "版本头仅作审计，不构成本结论的证据",
                ),
                server_header=probe.server_header or header,
                probe=probe.label,
            )

    # 2) 只命中 1 类：不足以归因（通用错误页/文档/示例代码都能命中单个词）。
    for probe in probes:
        if _is_error_status(probe.status) and len(probe.classes) == 1:
            return _blocked(
                f"畸形请求 {probe.label} 返回 {probe.status}，但只命中 1 类标记 "
                f"[{_classes_text(probe.classes)}] —— 不足以确认内部信息泄露",
                server_header=probe.server_header or header,
            )

    # 3) 探针没能完成：连接重置/超时/不可解析 ⇒ 覆盖不全，不驳回。
    failed = [probe for probe in probes if probe.error is not None]
    if failed:
        first = failed[0]
        return _blocked(
            f"畸形请求未能完成 {len(failed)}/{len(probes)} 条（覆盖不全，不驳回）: "
            f"{first.label}={first.error_kind or 'error'}: {first.error}",
            server_header=first.server_header or header,
        )

    # 4) 标记出现在非 4xx/5xx 响应里：不是错误页泄露（可能是正常页面的示例文本）。
    if any(probe.classes for probe in probes):
        odd = next(probe for probe in probes if probe.classes)
        return _blocked(
            f"标记出现在非错误响应里（{odd.label} status={odd.status}），"
            "不构成「错误页泄露」",
            server_header=odd.server_header or header,
        )

    # 5) 真阴性：全部探针都有响应、零标记、至少一条被 4xx/5xx 拒绝。
    rejected = [probe for probe in probes if _is_error_status(probe.status)]
    if rejected:
        statuses = sorted({probe.status for probe in probes if probe.status})
        return Judgment(
            verdict=VERDICT_REJECTED,
            reasons=(
                f"畸形请求被 {rejected[0].status} 拒绝，但正文零技术披露标记"
                f"（探针状态码 {statuses}）",
                "基线干净 ⇒ 通用错误页/统一 400，未回显内部信息（真阴性）",
            ),
            server_header=rejected[0].server_header or header,
        )

    return _blocked(
        "畸形请求未被拒绝（响应均非 4xx/5xx），未触发错误路径（覆盖不全，不驳回）",
        server_header=header,
    )


def summary_for_verifier(
    judgment: Judgment,
    baseline: ProbeOutcome,
    probes: Sequence[ProbeOutcome],
    *,
    origin: str,
) -> dict:
    """给 Verifier 的**结构化结论**（红线 3：响应体一行都不进）。

    只含枚举、计数、类别名、状态码与被转义过的请求摘要——足以复核判定，不足以
    泄漏页面内容。
    """
    return {
        "vuln_type": "error-disclosure",
        "judge": "差分：基线干净 ∧ 畸形请求 4xx/5xx ∧ 正文命中 ≥2 类技术披露标记",
        "origin": origin,
        "verdict": judgment.verdict,
        "matched_classes": list(judgment.matched),
        "probe": judgment.probe,
        "baseline": baseline.to_dict(),
        "probes": [probe.to_dict() for probe in probes],
        "probe_count": len(probes),
        "probe_budget": PROBE_BUDGET,
        "server_header_disclosed": judgment.server_header,
        "server_header_note": (
            "版本头只记审计，不构成确认证据（几乎所有站点都有，误报率 100%）"
        ),
        "reasons": list(judgment.reasons),
    }


__all__ = [
    "CLASS_LABELS",
    "DEFAULT_TIMEOUT",
    "ELLIPSIS_BYTES",
    "ERROR_DISCLOSURE_CONFIRMED_METHOD",
    "ERROR_TRACE_EVIDENCE_KIND",
    "Judgment",
    "LONG_URI_BYTES",
    "MARKER_CLASSES",
    "PROBE_BUDGET",
    "PROBE_LABELS",
    "ProbeOutcome",
    "ProbeSpec",
    "USER_AGENT",
    "VERDICT_BLOCKED",
    "VERDICT_CONFIRMED",
    "VERDICT_REJECTED",
    "build_baseline",
    "build_probes",
    "build_request",
    "classify_markers",
    "judge",
    "matched_class_names",
    "outcome_from_response",
    "server_header_disclosed",
    "summary_for_verifier",
]
