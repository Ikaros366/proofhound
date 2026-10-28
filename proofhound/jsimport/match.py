"""模板 × 观测 URL → 候选分级（A/B/C）与合成 URL（M24-a 匹配层）。

## 三级候选（交接单 §5）

- **A 观测实例**：JS 模板命中一条**本次爬行真实请求过且 2xx** 的 URL ⇒ 直接
  用那条 URL 重放（**参数不猜**）；
- **B 合成实例**：模板没有观测实例 ⇒ 按种子合成 URL，但**必须先过"认证基线
  2xx"门槛**（否则"参数不对"会被误读成"要登录"，见限制 53 与交接单 §10.8）；
- **C 清单**：其余（被过滤 / 同 URL 已被覆盖 / 越界 / 无会话）⇒ 只进
  ``inventory``，**不产生任何判定**。

## 候选过滤只是"收敛"，不是"判据"

:func:`exclusion_reason` 的排除表（``/health``、``/config``……）与数据接口
线索表，用途是**降低公开接口的语义误报**；它**不**参与任何判定——"这个接口
不该匿名可访问"这一半语义判断**永远只进报告分类**（交接单 §2）。

## 同 URL 只探一次

两个模板（如 ``/api/orders/1001`` 与 ``/api/orders/{param}``）可以指向同一个
URL。**探测单位是 URL**：首次出现的模板持有探测权，其余记 ``duplicate_url``
进清单——既不重复发请求，也不把后一个静默丢掉。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Iterable
from urllib.parse import parse_qsl, quote, urlparse

from proofhound.jsimport.crawl import CrawlRecord
from proofhound.jsimport.extract import EndpointTemplate

#: A 类：有 2xx 观测实例（参数不猜，原样重放）
GRADE_OBSERVED = "A"
#: B 类：无观测实例，合成 URL（须过认证基线 2xx 门槛）
GRADE_SYNTHESIZED = "B"
#: C 类：只进清单，不探测
GRADE_INVENTORY = "C"

#: 合成路径参数/查询值的缺省种子（交接单 §5.4 的 ``--param-seed 1``）
DEFAULT_PARAM_SEED = "1"

#: **公开/非数据接口**：只用来收敛候选，不构成任何证据（交接单 §4.4）
EXCLUDED_SEGMENTS = frozenset(
    {
        "health",
        "config",
        "version",
        "status",
        "login",
        "logout",
        "csrf",
        "csrf-token",
        "captcha",
        "metrics",
    }
)

#: **状态变更词**：命中即跳过、不发请求（交接单 §4.6；安全边界，不是启发式）
MUTATING_SEGMENTS = frozenset(
    {
        "logout",
        "delete",
        "remove",
        "update",
        "create",
        "save",
        "upload",
        "import",
        "reset",
        "revoke",
        "approve",
        "pay",
        "transfer",
    }
)

#: 数据接口的**段名线索**（交接单 §4.4 的关键词表，中英同名段都认）
DATA_SEGMENTS = frozenset(
    {
        "user",
        "users",
        "account",
        "accounts",
        "order",
        "orders",
        "invoice",
        "invoices",
        "admin",
        "report",
        "reports",
        "export",
        "profile",
        "record",
        "records",
    }
)

#: 数据接口的**前缀线索**
DATA_PREFIXES = ("api", "rest", "graphql")
_VERSION_SEGMENT = re.compile(r"v[0-9]+")


def segments_of(path: str) -> tuple[str, ...]:
    """URL path 的非空段（小写）。"""
    return tuple(part.lower() for part in path.split("/") if part)


def query_keys_of(url: str) -> tuple[str, ...]:
    """URL 的 query 键集（排序后；值的差异不算"不同接口"）。"""
    return tuple(
        sorted(key for key, _value in parse_qsl(urlparse(url).query, keep_blank_values=True))
    )


def template_regex(path_template: str) -> re.Pattern[str]:
    """把 ``/api/orders/{param}`` 编译成 ``^/api/orders/[^/]+$``（同段数、同字面段）。"""
    parts = [
        "[^/]+".join(re.escape(piece) for piece in segment.split("{param}"))
        for segment in path_template.split("/")
    ]
    return re.compile("^" + "/".join(parts) + "$")


def exclusion_reason(endpoint: EndpointTemplate) -> str | None:
    """候选过滤：``None`` 表示"像数据接口"，否则返回**收敛原因**（进清单）。"""
    segments = segments_of(endpoint.path_template)
    for segment in segments:
        if segment in MUTATING_SEGMENTS:
            return f"mutating_segment:{segment}"
    for key in endpoint.query_keys:
        if key.lower() in MUTATING_SEGMENTS:
            return f"mutating_query:{key}"
    for segment in segments:
        if segment in EXCLUDED_SEGMENTS:
            return f"excluded_segment:{segment}"
    if any(segment in DATA_SEGMENTS for segment in segments):
        return None
    if segments and (segments[0] in DATA_PREFIXES or _VERSION_SEGMENT.fullmatch(segments[0])):
        return None
    if "{param}" in endpoint.path_template or endpoint.query_keys:
        return None
    return "not_data_endpoint"


def synthesize_url(
    endpoint: EndpointTemplate, seed: str = DEFAULT_PARAM_SEED
) -> str:
    """把模板合成成可请求的 GET URL（路径参数与 query 值都填种子，保序）。"""
    encoded = quote(seed, safe="")
    url = f"{endpoint.origin}{endpoint.path_template.replace('{param}', encoded)}"
    if endpoint.query_keys:
        pairs = "&".join(
            f"{quote(key, safe='')}={encoded}" for key in endpoint.query_keys
        )
        url = f"{url}?{pairs}"
    return url


@dataclass
class ObservedIndex:
    """``(origin, 2xx 记录)`` 的观测索引（交接单 §5.3）。

    索引粒度是 ``(origin, path, query 键集)``——**同 path 同键集多条取包内第一条
    2xx**。之所以把"键集"放进粒度里：``/api/orders?a=1`` 与 ``/api/orders?b=1``
    是两个不同接口，若只按 path 建索引，后者的实例会被前者吞掉（静默漏测）。
    模板匹配时**优先挑键集完全一致的那条实例**，没有才退回同 path 的第一条。
    """

    by_origin: dict[str, list[CrawlRecord]] = field(default_factory=dict)

    @classmethod
    def build(cls, records: Iterable[CrawlRecord]) -> "ObservedIndex":
        index = cls()
        seen: dict[str, set[tuple[str, tuple[str, ...]]]] = {}
        for record in records:
            if not record.is_ok:
                continue
            keys = query_keys_of(record.url)
            bucket_seen = seen.setdefault(record.origin, set())
            if (record.path, keys) in bucket_seen:
                continue  # 同 path 同键集：取**包内第一条** 2xx
            bucket_seen.add((record.path, keys))
            index.by_origin.setdefault(record.origin, []).append(record)
        return index

    def match(self, endpoint: EndpointTemplate) -> list[CrawlRecord]:
        """把模板匹配到 2xx 观测实例（键集一致的优先，其余按爬行顺序）。"""
        bucket = self.by_origin.get(endpoint.origin, [])
        pattern = template_regex(endpoint.path_template)
        matched = [record for record in bucket if pattern.fullmatch(record.path)]
        if not matched:
            return []
        wanted = tuple(sorted(endpoint.query_keys))
        flags = [query_keys_of(record.url) == wanted for record in matched]
        exact = [record for record, hit in zip(matched, flags) if hit]
        rest = [record for record, hit in zip(matched, flags) if not hit]
        return exact + rest


@dataclass(frozen=True)
class Candidate:
    """一个分级后的候选（``probe_url`` 是"将会探测的 URL"，C 类可能为空）。"""

    endpoint: EndpointTemplate
    grade: str
    probe_url: str | None
    reason: str
    #: A 类命中的观测实例 URL（= ``probe_url``）及其证据锚点
    observed_url: str | None = None
    observed_ref: str | None = None
    #: 同模板的其他 2xx 观测实例（取第一条探测，其余只记录）
    additional_instances: tuple[str, ...] = ()
    #: 同 URL 已被更早的候选覆盖时，指向那个候选（**保留原等级**，只是不重复探测）
    duplicate_of: str | None = None
    #: 被同 URL 折叠 ⇒ 进清单、不探测（等级仍是 A/B，报告据此区分"漏测"与"过滤"）
    collapsed: bool = False
    #: 探测 URL 是**合成**的（报告要能区分"观测实例"与"合成实例"）
    synthetic: bool = False

    @property
    def path_template(self) -> str:
        return self.endpoint.path_template

    @property
    def display(self) -> str:
        return self.endpoint.display

    def as_dict(self) -> dict:
        data = {
            "display": self.display,
            "path_template": self.path_template,
            "query_keys": list(self.endpoint.query_keys),
            "origin": self.endpoint.origin,
            "grade": self.grade,
            "reason": self.reason,
            "probe_url": self.probe_url,
            "observed_url": self.observed_url,
            "observed_ref": self.observed_ref,
            "additional_instances": list(self.additional_instances),
            "duplicate_of": self.duplicate_of,
            "collapsed": self.collapsed,
            "synthetic": self.synthetic,
            "js_sha256": self.endpoint.js_sha256,
            "js_url": self.endpoint.js_url,
            "anchor": self.endpoint.anchor.as_dict(),
            "occurrences": self.endpoint.occurrences,
        }
        return data


def classify(
    endpoints: Iterable[EndpointTemplate],
    index: ObservedIndex,
    *,
    param_seed: str = DEFAULT_PARAM_SEED,
) -> list[Candidate]:
    """逐模板分级（A/B/C），并把重复 URL 收敛成清单项。"""
    candidates: list[Candidate] = []
    probe_owner: dict[str, str] = {}
    for endpoint in endpoints:
        filtered = exclusion_reason(endpoint)
        if filtered is not None:
            candidates.append(
                Candidate(
                    endpoint=endpoint,
                    grade=GRADE_INVENTORY,
                    probe_url=None,
                    reason=filtered,
                )
            )
            continue
        instances = index.match(endpoint)
        if instances:
            primary = instances[0]
            candidate = Candidate(
                endpoint=endpoint,
                grade=GRADE_OBSERVED,
                probe_url=primary.url,
                reason="observed_instance",
                observed_url=primary.url,
                observed_ref=primary.evidence_ref,
                additional_instances=tuple(
                    record.url for record in instances[1:]
                ),
            )
        else:
            candidate = Candidate(
                endpoint=endpoint,
                grade=GRADE_SYNTHESIZED,
                probe_url=synthesize_url(endpoint, param_seed),
                reason="synthesized_instance",
                synthetic=True,
            )
        owner = probe_owner.get(candidate.probe_url or "")
        if owner is not None:
            # 同 URL 只探一次：**等级不变**（它确实是 A/B），只是折叠进清单
            candidate = replace(
                candidate,
                reason="duplicate_url",
                duplicate_of=owner,
                collapsed=True,
            )
        else:
            probe_owner[candidate.probe_url or ""] = endpoint.display
        candidates.append(candidate)
    return candidates


__all__ = [
    "Candidate",
    "DATA_SEGMENTS",
    "DEFAULT_PARAM_SEED",
    "EXCLUDED_SEGMENTS",
    "GRADE_INVENTORY",
    "GRADE_OBSERVED",
    "GRADE_SYNTHESIZED",
    "MUTATING_SEGMENTS",
    "ObservedIndex",
    "classify",
    "exclusion_reason",
    "query_keys_of",
    "segments_of",
    "synthesize_url",
    "template_regex",
]
