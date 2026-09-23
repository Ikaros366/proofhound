"""廉价自动筛选层（M9c②）：把 cap 从「候选生成侧」移到「贵验证档」。

## 为什么需要它

M9c① 之前，``_TRIAGE_*_CAP``（20/10/10）是在**发现侧**设卡防确认洪泛——
因为每条候选都要过一次 L2 人工确认 + 一次**昂贵**行为验证（起 Chromium /
跑 sqlmap / 双会话请求）。把 cap 卡在候选生成上，等于用"少发现"换"不洪泛"。

本模块提供一层**零 LLM、纯 httpx、确定性**的粗筛：它不过的候选不进 Chromium /
sqlmap。cap 因此可以卡在**贵验证档**（``_TRIAGE_EXPENSIVE_CAP``，M9c② 起
生效），发现侧随之放开。

## 语义纪律（不许含糊）

- **过筛 ≠ 确认**（红线 2）。本模块只回答"值不值得花贵的验证"，**不产生任何
  证据**、不写 ``verification``、不影响证据门。Confirmed 仍只能来自
  verify-* 的行为确认 + 证据门 + Verifier。
- **只读**：只发 GET，不改任何状态；不跟随重定向（与 verify/idor.py 同纪律）。
- **无法判定一律 ``UNKNOWN`` 放行**（宁漏勿滥）——只有拿到**明确的负面信号**
  才判 ``UNLIKELY``。网络错误、基准非 2xx、响应体太短、探测结果含糊，全部放行。
- 判定输入全部结构化落盘（状态码/长度/差异），可离线复核。

## 判定依据：参数影响力差分（确定性、可单测）

对同一端点发**两个语义上应当产生不同结果的取值**（默认 ``1`` 与 ``999999``）：

============  ==========================  ==========================  ==========
基准状态      探测状态                    长度差                      裁定
============  ==========================  ==========================  ==========
2xx           两个探测都非 2xx            —                           UNKNOWN
2xx           —                           任一探测与基准长度差 > 0     PROMISING
2xx           两个探测都 2xx              两者长度完全相同             UNLIKELY
2xx           —                           其余含糊情形                 UNKNOWN
============  ==========================  ==========================  ==========

即：**改一个值完全不影响响应长度**，才判定"该参数对响应没有可观测影响力"。
这条**不是**漏洞的负面证据（blind 注入、定长模板都会命中同一格子），故它只作
**排序建议**，绝不丢弃候选——M9c② 实测确认丢弃是负收益（见 ``passed`` 注释）。
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Callable, NamedTuple

#: 探测取值对：语义上应当产生不同结果的两个输入（确定性、零随机）
PROBE_VALUES: tuple[str, str] = ("1", "999999")

#: 基准/探测响应体的最短可比长度；短于此一律 UNKNOWN（模板太小，长度无信息量）
MIN_COMPARABLE_BYTES = 64

#: 默认单请求超时（秒）
DEFAULT_TIMEOUT = 10.0


class ScreenDecision(str, Enum):
    """粗筛裁定：值得花贵验证 / 明确没有可观测影响力 / 无法判定（放行）。"""

    PROMISING = "promising"
    UNLIKELY = "unlikely"
    UNKNOWN = "unknown"


class Probe(NamedTuple):
    """一次廉价请求的结构化结果（不保存响应体，只保存可比特征）。"""

    status: int | None
    length: int
    error: str = ""


@dataclass(frozen=True)
class ScreenResult:
    """粗筛结论（含判定依据，供审计与离线复核）。"""

    decision: ScreenDecision
    reason: str
    baseline: Probe | None = None
    probes: tuple[Probe, ...] = ()
    length_deltas: tuple[int, ...] = ()

    @property
    def passed(self) -> bool:
        """是否放行到贵验证档。

        **M9c② 实测结论（重要）**：三个取值一律放行——本层**不做丢弃**。
        初版把 ``UNLIKELY`` 当作"不进贵验证档"，在本仓库基座上实测为负收益：
        ``rules+model`` 臂的发现率被从 100% 砍到 83.3%，而误报率**一点没降**。
        原因是差分假设不成立——"两个取值响应等长"同样出现在 blind 注入、
        模板定长、参数不影响输出等大量情形里，它**不是**漏洞的负面证据。

        故本层收窄为**建议性信号**：只产出 ``decision`` 供贵验证档排序与人工
        参考，永不自行拒绝候选。红线 2 亦要求如此——廉价粗筛不是判定。
        """
        return True

    @property
    def advisory(self) -> bool:
        """是否给出"不值得优先验证"的建议（仅排序提示，不丢候选）。"""
        return self.decision is ScreenDecision.UNLIKELY

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "baseline_status": self.baseline.status if self.baseline else None,
            "baseline_length": self.baseline.length if self.baseline else None,
            "probe_statuses": [p.status for p in self.probes],
            "probe_lengths": [p.length for p in self.probes],
            "probe_errors": [p.error for p in self.probes],
            "length_deltas": list(self.length_deltas),
            "thresholds": {
                "min_comparable_bytes": MIN_COMPARABLE_BYTES,
                "probe_values": list(PROBE_VALUES),
            },
        }


def _http_get(url: str, timeout: float = DEFAULT_TIMEOUT) -> Probe:
    """默认取数：stdlib GET，**不跟随重定向**，异常只置 error 不抛出。

    与 ``verify/idor.py::fetch`` 同纪律（3xx 以状态码暴露；网络错误由上层
    判为"无法判定"而非"无漏洞"）。
    """
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return Probe(status=response.status, length=len(response.read()))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()
        except Exception:  # noqa: BLE001 - 读失败只影响长度精度
            body = b""
        return Probe(status=exc.code, length=len(body))
    except Exception as exc:  # noqa: BLE001 - 网络错误不抛出，交由判定处理
        return Probe(status=None, length=0, error=f"{type(exc).__name__}: {exc}"[:200])


def with_query_param(url: str, param: str, value: str) -> str:
    """把 query 里 ``param`` 替换为 ``value``（保留其余参数，确定性重编码）。"""
    parsed = urllib.parse.urlparse(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    out = []
    for key, _old in pairs:
        if key == param and not replaced:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, _old))
    if not replaced:
        out.append((param, value))
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(out))
    )


def decide(baseline: Probe, probes: tuple[Probe, ...]) -> ScreenResult:
    """纯判定函数（零网络、零 LLM）——所有判定规则都在这里，可穷举单测。"""
    deltas = tuple(p.length - baseline.length for p in probes)

    if baseline.error or baseline.status is None:
        return ScreenResult(
            ScreenDecision.UNKNOWN,
            f"基准不可达（{baseline.error or '无状态码'}），无法判定",
            baseline, probes, deltas,
        )
    if not (200 <= (baseline.status or 0) < 300):
        return ScreenResult(
            ScreenDecision.UNKNOWN,
            f"基准非 2xx（{baseline.status}），无法判定",
            baseline, probes, deltas,
        )
    if baseline.length < MIN_COMPARABLE_BYTES:
        return ScreenResult(
            ScreenDecision.UNKNOWN,
            f"基准响应体过短（{baseline.length} < {MIN_COMPARABLE_BYTES}），"
            "长度无信息量",
            baseline, probes, deltas,
        )

    real = [p for p in probes if p.status is not None and 200 <= (p.status or 0) < 300]
    if len(real) < len(probes):
        return ScreenResult(
            ScreenDecision.UNKNOWN,
            "存在非 2xx 或不可达的探测，判定含糊（可能是漏洞也可能是错误页）",
            baseline, probes, deltas,
        )
    if any(abs(d) > 0 for d in deltas):
        return ScreenResult(
            ScreenDecision.PROMISING,
            f"参数取值对响应长度有可观测影响（长度差 {list(deltas)}），值得验证",
            baseline, probes, deltas,
        )
    return ScreenResult(
        ScreenDecision.UNLIKELY,
        f"两个语义不同的取值产生**逐字节等长**响应（{baseline.length} 字节），"
        "该参数对响应无可观测影响力",
        baseline, probes, deltas,
    )


def screen(
    url: str,
    param: str | None,
    *,
    fetcher: Callable[[str], Probe] | None = None,
    probe_values: tuple[str, str] = PROBE_VALUES,
) -> ScreenResult:
    """对一条候选做廉价粗筛（零 LLM；最多 3 个只读 GET 请求）。

    ``param`` 为 None（表单/路径型候选）→ 直接 UNKNOWN：没有可扰动的 query
    参数，就没有廉价差分可做，交给贵验证档。

    **方法感知**：``url`` 里带 query 才做 GET 差分。POST 表单候选的 asset 是
    **页面 URL 本身**（无 query，字段名走 ``form_field``）——对它发 GET 探测在
    语义上不成立（两个取值必然等长），那不是"无可观测影响力"而是"无法判定"，
    必须 UNKNOWN。
    """
    fetch = fetcher or _http_get
    if not param:
        return ScreenResult(
            ScreenDecision.UNKNOWN, "候选无 query 参数，廉价差分不适用"
        )
    if not urllib.parse.urlparse(url).query:
        return ScreenResult(
            ScreenDecision.UNKNOWN,
            "候选 asset 无 query 串（POST 表单型），GET 差分不适用",
        )
    baseline = fetch(url)
    probes = tuple(fetch(with_query_param(url, param, v)) for v in probe_values)
    return decide(baseline, probes)


__all__ = [
    "DEFAULT_TIMEOUT",
    "MIN_COMPARABLE_BYTES",
    "PROBE_VALUES",
    "Probe",
    "ScreenDecision",
    "ScreenResult",
    "decide",
    "screen",
    "with_query_param",
]