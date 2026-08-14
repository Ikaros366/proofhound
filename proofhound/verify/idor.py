"""IDOR/水平越权 双会话属性验证器（M8c，§5.4.2 越权/IDOR 行落地）。

first-party 验证器代码（定位同 :mod:`proofhound.verify.cvss` /
:mod:`proofhound.verify.browser`）：不走 tools/manifests 外部二进制注册
体系，纯 stdlib 零新依赖。

Security Property 验证第一刀（§9.1 北极星呼应）：属性 = "身份 A 不可访问
身份 B 的私有对象"；验证 = 双会话对比——B（reference/victim，对象属主）
会话基准请求同 URL，A（主会话，低权限身份）会话对比请求，确定性代码判定
属性是否违反（红线 1：LLM 只推理，相似度/属性判定全是确定性代码；红线 2：
IDOR 的 Confirmed 只能来自双会话属性违反证据，单会话异常响应不确认）。

判定标准（写死阈值，宁漏勿滥）：

- B 基准须成立：2xx 且含实质数据（非空非错误页，:data:`MIN_SUBSTANTIVE_BYTES`）；
- A 对比请求同 URL：2xx 且与 B 基准正文相似度 ≥ 0.9
  （:data:`SIMILARITY_THRESHOLD`，difflib.SequenceMatcher），
  或 JSON 响应键集合重叠（Jaccard）≥ 0.8
  （:data:`JSON_KEY_OVERLAP_THRESHOLD`）→ 属性违反成立（violation=True）；
- A 被 403/404/重定向登录页（3xx）或数据不相似 → 判定不成立；
- 判定依据全部结构化记录（双状态码、相似度数值、键重叠度、阈值），
  供审计与判定 JSON 落盘。

本模块只负责"取响应 + 纯函数判定"；证据落盘与审计归编排层
（``Orchestrator._verify_idor``，browser.py 同范式）。``fetch`` 不跟随
重定向（3xx 以状态码暴露，"重定向到登录页"是判定不成立的关键形态）；
任何网络/超时异常只置 ``IdorResponse.error`` 字段不抛出（编排层据此转
blocked，fail-closed）。
"""

from __future__ import annotations

import difflib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

#: 属性违反判定：A 响应与 B 基准的正文相似度阈值（≥ 即相似）
SIMILARITY_THRESHOLD = 0.9
#: 属性违反判定：JSON 响应键集合重叠度（Jaccard）阈值（≥ 即重叠）
JSON_KEY_OVERLAP_THRESHOLD = 0.8
#: B 基准"实质数据"最小字节数（去空白后；同时排除空 JSON ``{}``/``[]``）
MIN_SUBSTANTIVE_BYTES = 32
#: 相似度比对的正文长度硬顶（SequenceMatcher 最坏 O(n²)，确定性截前段）
MAX_COMPARE_CHARS = 20000
#: 单次请求超时（秒）
DEFAULT_TIMEOUT = 15.0


@dataclass
class IdorResponse:
    """一次会话请求的结构化结果（error 只置字段不抛出，fail-closed）。"""

    url: str
    status: int | None = None
    body: str = ""
    error: str | None = None


@dataclass
class IdorJudgment:
    """双会话属性判定结果（全部判定依据结构化记录，供判定 JSON 落盘）。"""

    b_status: int | None
    a_status: int | None
    similarity: float
    json_overlap: float | None
    violation: bool
    reasons: list[str] = field(default_factory=list)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随重定向：3xx 以状态码暴露（重定向登录页 = 判定不成立形态）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def fetch(url: str, session, *, timeout: float = DEFAULT_TIMEOUT) -> IdorResponse:
    """以给定会话请求 URL（GET，不跟随重定向），返回结构化响应。

    ``session`` 为 :class:`~proofhound.compliance.session.SessionConfig`
    （主会话或 reference 会话，调用方选择）；凭据由代码注入请求头，LLM
    零接触。网络/超时异常不抛出，置 ``IdorResponse.error``（编排层转
    blocked，覆盖不全不驳回）。
    """
    headers = {}
    cookie = session.cookie_header()
    if cookie:
        headers["Cookie"] = cookie
    for key, value in session.headers.items():
        headers[key] = value
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as resp:
            return IdorResponse(
                url=url,
                status=resp.status,
                body=resp.read().decode("utf-8", errors="replace"),
            )
    except urllib.error.HTTPError as exc:  # 4xx/5xx/3xx（不跟随）也是响应
        return IdorResponse(
            url=url,
            status=exc.code,
            body=exc.read().decode("utf-8", errors="replace"),
        )
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return IdorResponse(url=url, error=f"{type(exc).__name__}: {exc}")


def status_class(status: int | None) -> str:
    """状态码分类：ok(2xx)/redirect(3xx)/client_error(4xx)/server_error(5xx)/other。"""
    if status is None:
        return "none"
    if 200 <= status < 300:
        return "ok"
    if 300 <= status < 400:
        return "redirect"
    if 400 <= status < 500:
        return "client_error"
    if 500 <= status < 600:
        return "server_error"
    return "other"


def body_similarity(a: str, b: str) -> float:
    """正文相似度：difflib.SequenceMatcher.ratio()（0.0~1.0，确定性）。

    双侧均空 → 0.0（空正文不构成实质数据，相似无意义）；超
    :data:`MAX_COMPARE_CHARS` 截前段（SequenceMatcher 最坏 O(n²)，
    截断长度是代码常量，确定性可复现）。
    """
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(
        None, a[:MAX_COMPARE_CHARS], b[:MAX_COMPARE_CHARS]
    ).ratio()


def json_key_paths(obj, _prefix: str = "") -> set[str]:
    """JSON 键路径集合（递归点路径；list 段记 ``[]``，非容器叶不产出）。"""
    paths: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{_prefix}.{key}" if _prefix else str(key)
            paths.add(path)
            paths |= json_key_paths(value, path)
    elif isinstance(obj, list):
        for item in obj:
            paths |= json_key_paths(item, f"{_prefix}[]")
    return paths


def json_key_overlap(a_body: str, b_body: str) -> float | None:
    """JSON 键集合重叠度（Jaccard = |∩|/|∪|）；任一非 JSON 或空并集 → None。"""
    try:
        a_obj = json.loads(a_body)
        b_obj = json.loads(b_body)
    except (json.JSONDecodeError, TypeError):
        return None
    a_keys = json_key_paths(a_obj)
    b_keys = json_key_paths(b_obj)
    union = a_keys | b_keys
    if not union:
        return None
    return len(a_keys & b_keys) / len(union)


def has_substance(resp: IdorResponse) -> bool:
    """B 基准成立条件：2xx 且含实质数据（非空非错误页、非空 JSON）。"""
    if status_class(resp.status) != "ok":
        return False
    stripped = resp.body.strip()
    if stripped in ("{}", "[]"):
        return False
    return len(stripped) >= MIN_SUBSTANTIVE_BYTES


def judge(baseline: IdorResponse, probe: IdorResponse) -> IdorJudgment:
    """双会话属性判定（确定性，阈值写死，判定依据全量结构化记录）。

    属性 = "身份 A 不可访问身份 B 的私有对象"；违反 = B 基准成立（2xx 实质
    数据）且 A 同 URL 请求 2xx 且（正文相似度 ≥ 0.9 或 JSON 键重叠 ≥ 0.8）。
    """
    reasons: list[str] = []
    similarity = body_similarity(baseline.body, probe.body)
    overlap = json_key_overlap(baseline.body, probe.body)

    b_ok = has_substance(baseline)
    if b_ok:
        reasons.append(
            f"B 基准成立：{baseline.status} 且含实质数据"
            f"（{len(baseline.body.strip())} 字节 ≥ {MIN_SUBSTANTIVE_BYTES}）"
        )
    else:
        reasons.append(
            f"B 基准不成立：状态 {baseline.status}（{status_class(baseline.status)}）"
            f"或无实质数据（{len(baseline.body.strip())} 字节）"
        )

    a_class = status_class(probe.status)
    reasons.append(f"A 对比响应：状态 {probe.status}（{a_class}）")
    reasons.append(
        f"正文相似度 {similarity:.3f}（阈值 {SIMILARITY_THRESHOLD}）"
    )
    if overlap is None:
        reasons.append("JSON 键重叠：—（任一响应非 JSON 或键并集为空）")
    else:
        reasons.append(
            f"JSON 键重叠 {overlap:.3f}（阈值 {JSON_KEY_OVERLAP_THRESHOLD}）"
        )

    violation = (
        b_ok
        and a_class == "ok"
        and (
            similarity >= SIMILARITY_THRESHOLD
            or (overlap is not None and overlap >= JSON_KEY_OVERLAP_THRESHOLD)
        )
    )
    if violation:
        reasons.append("属性违反成立：身份 A 获得了与身份 B 基准等价的响应")
    else:
        reasons.append("属性违反不成立")
    return IdorJudgment(
        b_status=baseline.status,
        a_status=probe.status,
        similarity=similarity,
        json_overlap=overlap,
        violation=violation,
        reasons=reasons,
    )


def judgment_dict(finding_id: str, url: str, j: IdorJudgment) -> dict:
    """判定 JSON 落盘内容（判定依据全量结构化 + 阈值快照）。"""
    return {
        "finding_id": finding_id,
        "url": url,
        "b_status": j.b_status,
        "a_status": j.a_status,
        "similarity": j.similarity,
        "json_overlap": j.json_overlap,
        "thresholds": {
            "similarity": SIMILARITY_THRESHOLD,
            "json_overlap": JSON_KEY_OVERLAP_THRESHOLD,
            "min_substantive_bytes": MIN_SUBSTANTIVE_BYTES,
        },
        "violation": j.violation,
        "reasons": j.reasons,
    }
