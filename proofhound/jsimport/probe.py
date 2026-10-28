"""重放 + 判定 + 证据落盘（M24-a 探测层）。

```
会话自检 ──失效──> 整批只出清单（退出码 2，零确认）
   │ ok
   ├─ 认证基线（带 scope 预置会话）── 非 2xx ──> A 类 blocked / B 类清单（不驳回）
   │ 2xx
   └─ 匿名对照（**零凭据**）──> judge_unauth ──> exposed / requires_auth / blocked
                                                  confirmed / rejected / blocked
```

## 判据只有一处

三态由 :func:`proofhound.verify.unauth_control.judge_unauth` **确定性**给出，
本模块**不做任何语义判断**——"这个接口不该匿名可访问"只进报告分类，不进判定
链（交接单 §2；M16-c 裁定：敏感度判定器不产证据）。

## 安全边界（交接单 §4.6 / §8，全是结构性的）

- 只发 **GET**（客户端代码里没有别的 method 分支）；
- 路径/查询键命中状态变更词表的候选**在匹配层就被收敛成清单**，根本不进
  探测循环（:func:`proofhound.jsimport.match.exclusion_reason`）；
- **不发请求体**（:func:`~proofhound.verify.idor.fetch` 的签名里没有 body）；
- 匿名对照用**空** ``SessionConfig()``，一个字节的凭据都不带；
- 不跟随重定向（``_NoRedirect``），3xx 以状态码暴露；
- 每个 URL 发请求**前**必过 ``check_scope``（红线 5）；越界记
  ``js_scope_rejected`` 并进清单，不重试。

## 证据（交接单 §7）

``crawl.jsonl`` / ``js/<sha8>.js``（0600）/ ``endpoints.jsonl`` /
``probe/<id>.json`` / ``inventory.jsonl`` / ``summary.json`` / ``summary.md``
＋ ``audit.jsonl``。**响应正文不落盘**（只落状态码 / sha256 / 字节数），故
Cookie 不会被顺手写进证据；``summary.json`` **不含时间戳与输出路径**，连跑
两次逐字节一致（交接单 §9 的验收项）。
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Callable, Iterable, Sequence

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope, check_scope
from proofhound.compliance.session import SessionConfig, redact_bytes, secret_marker
from proofhound.jsimport.crawl import (
    DEFAULT_MAX_JS_BYTES,
    DEFAULT_MAX_JS_FILES,
    CrawlBundle,
    CrawlRecord,
    JsDocument,
    load_katana_jsonl,
)
from proofhound.jsimport.extract import (
    EndpointTemplate,
    ExtractStats,
    dedupe_endpoints,
    extract_endpoints,
)
from proofhound.jsimport.match import (
    DEFAULT_PARAM_SEED,
    GRADE_OBSERVED,
    Candidate,
    ObservedIndex,
    classify,
)
from proofhound.verify.idor import IdorResponse, status_class
from proofhound.verify.idor import fetch as fetch_response
from proofhound.verify.unauth_control import (
    VERDICT_EXPOSED,
    VERDICT_REQUIRES_AUTH,
    UnauthJudgment,
    judge_unauth,
)

#: 单次导入最多探测的候选数（交接单 §4.7；超限进清单，不静默丢）
DEFAULT_MAX_PROBES = 100
#: 缺省请求速率（QPS；交接单 §4.7 建议 1~2，并发固定 1）
DEFAULT_QPS = 2.0
#: 单请求超时（秒；交接单 §4.7）
DEFAULT_TIMEOUT = 10.0

#: 判定三态 → 报告结论（``blocked`` 兜底，fail-closed）
_VERDICT_TO_STATUS = {
    VERDICT_EXPOSED: "confirmed",
    VERDICT_REQUIRES_AUTH: "rejected",
}


@dataclass
class ImportConfig:
    """一次导入的全部输入与上限（CLI 只是它的解析器）。"""

    jsonl_paths: tuple[Path, ...]
    scope: Scope
    out_dir: Path
    param_seed: str = DEFAULT_PARAM_SEED
    fetch_missing: bool = False
    max_js_files: int = DEFAULT_MAX_JS_FILES
    max_js_bytes: int = DEFAULT_MAX_JS_BYTES
    max_probes: int = DEFAULT_MAX_PROBES
    qps: float = DEFAULT_QPS
    timeout: float = DEFAULT_TIMEOUT


@dataclass
class ImportReport:
    """一次导入的结论（``summary`` 就是落盘的 ``summary.json`` 内容）。"""

    out_dir: Path
    exit_code: int
    summary: dict
    reasons: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> int:
        return int(self.summary.get("counts", {}).get("confirmed", 0))

    @property
    def inventory(self) -> int:
        return int(self.summary.get("counts", {}).get("inventory", 0))

    def render_lines(self) -> list[str]:
        counts = self.summary.get("counts", {})
        crawl = self.summary.get("crawl", {})
        lines = [
            f"[*] 爬行记录 {crawl.get('records', 0)} 条 / "
            f"JS {crawl.get('js_documents', 0)} 份 / "
            f"接口模板 {counts.get('endpoints', 0)} 条",
            f"[*] 候选：A(观测) {counts.get('A', 0)} / B(合成) {counts.get('B', 0)} / "
            f"C(清单) {counts.get('C', 0)}；实际探测 {counts.get('probed', 0)} 条",
            f"[*] 结论：confirmed {counts.get('confirmed', 0)} / "
            f"rejected {counts.get('rejected', 0)} / "
            f"blocked {counts.get('blocked', 0)} / 清单 {counts.get('inventory', 0)}",
        ]
        lines.extend(f"    - {reason}" for reason in self.reasons)
        lines.append(f"[*] 证据: {self.out_dir}")
        return lines


# --------------------------------------------------------------- 小工具


def _sha8(value: str) -> str:
    """脱敏标记：``sha256:<hex8>``（与 ``compliance/session.py`` 同一形态）。"""
    return secret_marker(value)


def _is_2xx(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def _mkdir_private(path: Path) -> None:
    """建目录并收紧权限（``js/`` 里是 JS 原件，可能含敏感信息）。"""
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:  # pragma: no cover - 非 POSIX 文件系统
        pass


def _write_private(path: Path, data: bytes) -> None:
    """写文件并收紧到 0600（JS 原件/证据同一纪律）。"""
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - 非 POSIX 文件系统
        pass


def _jsonl(rows: Iterable[dict]) -> str:
    return "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
    )


def _slug(text: str, *, limit: int = 48) -> str:
    """URL 路径 → 文件名片段（确定性、只留安全字符）。"""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return (cleaned or "root")[:limit]


def _probe_id(order: int, candidate: Candidate) -> str:
    return f"{order:03d}_{_slug(candidate.path_template)}"


def _resp_summary(response: IdorResponse) -> dict:
    """一次请求的结构化摘要（**不含正文**，故不含 Cookie）。"""
    body = response.body or ""
    return {
        "status": response.status,
        "error": response.error,
        "body_sha256": sha256(body.encode("utf-8")).hexdigest() if body else "",
        "bytes": len(body.encode("utf-8")),
    }


def _session_configured(session: SessionConfig | None) -> bool:
    """scope 里是否配了**真凭据**（空 Cookie 与空头不算"有会话"）。"""
    if session is None:
        return False
    return bool(session.cookie_header() or session.headers)


def _session_marker(session: SessionConfig) -> dict:
    """会话的脱敏标记：只出 Cookie **名** + 值 sha256 前 8 位（交接单 §7）。"""
    return {
        "cookies": [
            {"name": name, "value": _sha8(value)}
            for name, value in session.cookies.items()
        ],
        "headers": sorted(session.headers),
    }


class _Pacer:
    """串行限速（并发固定 1；``qps <= 0`` 表示不限速，供单测用）。"""

    def __init__(
        self,
        qps: float,
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.interval = 0.0 if qps <= 0 else 1.0 / qps
        self._sleep = sleep
        self._monotonic = monotonic
        self._last: float | None = None

    def wait(self) -> None:
        if self.interval <= 0:
            return
        now = self._monotonic()
        if self._last is not None and now - self._last < self.interval:
            self._sleep(self.interval - (now - self._last))
        self._last = self._monotonic()


def select_session_check_url(
    records: Sequence[CrawlRecord], scope: Scope
) -> str | None:
    """挑一条**已知 2xx** 的页面做会话自检（优先 HTML 页面，其次任意 2xx）。

    已知 2xx 是自检成立的前提：拿一条本来就 404 的 URL 去自检，会把"页面不存在"
    误读成"会话失效"（交接单 §10.9）。
    """
    pages = [
        record
        for record in records
        if record.is_ok and record.content_type.lower().startswith("text/html")
    ]
    others = [record for record in records if record.is_ok and record not in pages]
    for record in pages + others:
        if check_scope(scope, [record.url]).allowed:
            return record.url
    return None


def _session_check_failure(response: IdorResponse) -> str | None:
    """会话自检失败原因（``None`` = 会话有效）。"""
    if response.error is not None:
        return f"会话自检请求失败（覆盖不全）：{response.error}"
    if response.status in (401, 403):
        return f"会话已失效（自检返回 {response.status}）"
    if response.status is not None and 300 <= response.status < 400:
        return f"会话已失效（自检被重定向 {response.status}，未跟随）"
    if not _is_2xx(response.status):
        return f"会话自检状态异常（{response.status}）"
    return None


# --------------------------------------------------------------- 提取


@dataclass
class _ExtractOutcome:
    endpoints: list[EndpointTemplate]
    stats: ExtractStats
    per_document: list[tuple[JsDocument, ExtractStats]]
    #: 各 JS 自身的相对路径基准（``baseURL`` 常量或 JS 所在目录），进 summary
    bases: list[str]


def _collect_js_documents(
    bundle: CrawlBundle,
    config: ImportConfig,
    audit: AuditLog,
    fetch: Callable[[str, SessionConfig], IdorResponse],
    pacer: _Pacer,
) -> list[JsDocument]:
    """``--fetch-missing``：正文缺失的 JS 按 scope 校验后**匿名**补抓一次。"""
    documents: list[JsDocument] = []
    known = {document.sha256 for document in bundle.js_documents}
    for url in list(bundle.js_body_missing):
        if len(bundle.js_documents) + len(documents) >= config.max_js_files:
            audit.record("js_skipped", url=url, reason="js_cap")
            continue
        decision = check_scope(config.scope, [url])
        if not decision.allowed:
            audit.record("js_scope_rejected", url=url, violations=decision.violations)
            continue
        pacer.wait()
        response = fetch(url, SessionConfig())
        if response.error is not None or not _is_2xx(response.status):
            audit.record(
                "js_skipped",
                url=url,
                reason="fetch_missing_failed",
                status=response.status,
                error=response.error,
            )
            continue
        body = response.body or ""
        if not body.strip():
            audit.record("js_skipped", url=url, reason="fetch_missing_empty")
            continue
        size = len(body.encode("utf-8"))
        if size > config.max_js_bytes:
            audit.record(
                "js_skipped", url=url, reason="fetch_missing_oversized", bytes=size
            )
            continue
        digest = sha256(body.encode("utf-8")).hexdigest()
        if digest in known:
            audit.record("js_skipped", url=url, reason="fetch_missing_duplicate")
            continue
        known.add(digest)
        documents.append(
            JsDocument(sha256=digest, body=body, urls=(url,), order=0, content_type="")
        )
        audit.record(
            "js_file_collected", url=url, sha256=digest, bytes=size, fetched=True
        )
    return documents


def _extract_all(documents: Sequence[JsDocument], audit: AuditLog) -> _ExtractOutcome:
    per_document: list[tuple[JsDocument, ExtractStats]] = []
    collected: list[EndpointTemplate] = []
    for document in documents:
        templates, stats = extract_endpoints(document)
        per_document.append((document, stats))
        for template in templates:
            audit.record(
                "js_endpoint_extracted",
                js_sha256=template.js_sha256,
                js_url=template.js_url,
                path_template=template.path_template,
                query_keys=list(template.query_keys),
                offset=template.anchor.offset,
                line=template.anchor.line,
            )
        collected.extend(templates)
    merged = dedupe_endpoints(collected)
    totals = ExtractStats()
    bases: set[str] = set()
    for _document, stats in per_document:
        totals.literals += stats.literals
        totals.filtered_length += stats.filtered_length
        totals.fragment_dropped += stats.fragment_dropped
        totals.filtered_not_path += stats.filtered_not_path
        totals.filtered_static += stats.filtered_static
        totals.out_of_scope += stats.out_of_scope
        totals.duplicates += stats.duplicates
        if stats.base:
            bases.add(stats.base)
    return _ExtractOutcome(
        endpoints=merged,
        stats=totals,
        per_document=per_document,
        bases=sorted(bases),
    )


# --------------------------------------------------------------- 探测


@dataclass
class _Attempt:
    """一次候选探测的结果（``kind`` 决定它进结论还是进清单）。"""

    row: dict | None
    kind: str  # "ok" | "scope_rejected" | "baseline_not_2xx"


@dataclass
class _ProbeOutcome:
    results: list[dict]
    inventory: list[dict]
    check: dict
    counts: dict
    entry_error: bool = False
    reasons: list[str] = field(default_factory=list)


def _endpoint_dict(candidate: Candidate) -> dict:
    endpoint = candidate.endpoint
    return {
        "path_template": endpoint.path_template,
        "query_keys": list(endpoint.query_keys),
        "js_sha256": endpoint.js_sha256,
        "js_url": endpoint.js_url,
        "anchor": endpoint.anchor.as_dict(),
        "occurrences": endpoint.occurrences,
    }


def _inventory_row(candidate: Candidate, reason: str, *, order: int) -> dict:
    """清单行：**不写 verdict**（交接单 §5.6），只记路径/锚点/实例/合成 URL。"""
    return {
        "order": order,
        "display": candidate.display,
        "path_template": candidate.path_template,
        "query_keys": list(candidate.endpoint.query_keys),
        "grade": candidate.grade,
        "reason": reason,
        "js_sha256": candidate.endpoint.js_sha256,
        "js_url": candidate.endpoint.js_url,
        "anchor": candidate.endpoint.anchor.as_dict(),
        "observed_url": candidate.observed_url,
        "observed_ref": candidate.observed_ref,
        "additional_instances": list(candidate.additional_instances),
        "synthetic_url": candidate.probe_url if candidate.synthetic else None,
        "duplicate_of": candidate.duplicate_of,
    }


def _judgment_dict(judgment: UnauthJudgment) -> dict:
    return judgment.as_summary()


def _conclusion(
    candidate: Candidate,
    *,
    probe_id: str,
    authenticated: IdorResponse,
    anonymous: IdorResponse | None,
    judgment: UnauthJudgment | None,
    verdict: str,
    reasons: list[str],
) -> dict:
    return {
        "probe": probe_id,
        "url": candidate.probe_url,
        "grade": candidate.grade,
        "synthetic": candidate.synthetic,
        "observed_ref": candidate.observed_ref,
        "endpoint": _endpoint_dict(candidate),
        "authenticated": _resp_summary(authenticated),
        "anonymous": None if anonymous is None else _resp_summary(anonymous),
        "judgment": None if judgment is None else _judgment_dict(judgment),
        "verdict": verdict,
        "reasons": reasons,
    }


def _probe_one(
    candidate: Candidate,
    *,
    order: int,
    session: SessionConfig,
    scope: Scope,
    fetch: Callable[[str, SessionConfig], IdorResponse],
    pacer: _Pacer,
    audit: AuditLog,
) -> _Attempt:
    """探测一个候选：scope → 认证基线 → 匿名对照 → 判定。

    A 类与 B 类的**基线失败语义刻意不同**（交接单 §5.5 / §10.8）：A 类是
    "观测实例在认证视图下异常" ⇒ ``blocked``（覆盖不全，不驳回）；B 类是
    "合成参数不对 ⇒ 端点可能根本不存在" ⇒ 清单（不产生任何判定）。
    """
    url = candidate.probe_url or ""
    decision = check_scope(scope, [url])  # 红线 5：发请求前必过 scope
    if not decision.allowed:
        audit.record("js_scope_rejected", url=url, violations=decision.violations)
        return _Attempt(row=None, kind="scope_rejected")

    probe_id = _probe_id(order, candidate)
    pacer.wait()
    baseline = fetch(url, session)
    audit.record(
        "js_probe_attempt",
        role="authenticated",
        url=url,
        status=baseline.status,
        error=baseline.error,
    )
    if baseline.error is not None:
        return _Attempt(
            row=_conclusion(
                candidate,
                probe_id=probe_id,
                authenticated=baseline,
                anonymous=None,
                judgment=None,
                verdict="blocked",
                reasons=[f"认证基线请求失败（覆盖不全，不驳回）：{baseline.error}"],
            ),
            kind="ok",
        )
    if not _is_2xx(baseline.status):
        if candidate.grade != GRADE_OBSERVED:
            return _Attempt(row=None, kind="baseline_not_2xx")
        return _Attempt(
            row=_conclusion(
                candidate,
                probe_id=probe_id,
                authenticated=baseline,
                anonymous=None,
                judgment=None,
                verdict="blocked",
                reasons=[
                    f"认证基线非 2xx（{baseline.status}，"
                    f"{status_class(baseline.status)}）→ 覆盖不全，不驳回"
                    "（A 类观测实例）"
                ],
            ),
            kind="ok",
        )

    pacer.wait()
    anonymous = fetch(url, SessionConfig())  # 匿名：**一个字节凭据都不带**
    audit.record(
        "js_probe_attempt",
        role="anonymous",
        url=url,
        status=anonymous.status,
        error=anonymous.error,
    )
    judgment = judge_unauth(baseline, anonymous)
    audit.record(
        "js_judged",
        probe=probe_id,
        url=url,
        verdict=judgment.verdict,
        anon_status=judgment.anon_status,
        byte_identical=judgment.byte_identical,
        similarity=round(judgment.similarity, 3),
    )
    return _Attempt(
        row=_conclusion(
            candidate,
            probe_id=probe_id,
            authenticated=baseline,
            anonymous=anonymous,
            judgment=judgment,
            verdict=_VERDICT_TO_STATUS.get(judgment.verdict, "blocked"),
            reasons=list(judgment.reasons),
        ),
        kind="ok",
    )


def _blocked_reason(candidate: Candidate, reason: str) -> str:
    """结构性命中（无会话/会话失效）时，**不要覆盖**候选自己的过滤原因。

    ``/api/config`` 被候选过滤挡掉这一事实，比"这次没会话"更有信息量；把两者
    混成一个 ``session_invalid`` 会让公开接口看起来像"因为没会话才没测"。
    """
    if candidate.grade in ("A", "B") and not candidate.collapsed:
        return reason
    return candidate.reason


def _run_probes(
    candidates: Sequence[Candidate],
    records: Sequence[CrawlRecord],
    *,
    session: SessionConfig | None,
    config: ImportConfig,
    max_probes: int,
    fetch: Callable[[str, SessionConfig], IdorResponse],
    pacer: _Pacer,
    audit: AuditLog,
) -> _ProbeOutcome:
    results: list[dict] = []
    inventory: list[dict] = []
    reasons: list[str] = []
    check: dict = {"url": None, "status": None, "ok": False, "reason": None}

    if not _session_configured(session):
        for order, candidate in enumerate(candidates, start=1):
            inventory.append(
                _inventory_row(
                    candidate, _blocked_reason(candidate, "session_not_configured"), order=order
                )
            )
        reason = (
            "scope 未配置预置会话 → 只能出接口清单，不能确认（交接单 §3）"
        )
        audit.record("jsimport_blocked", reason=reason)
        reasons.append(f"{reason}；退出码 2")
        return _ProbeOutcome(
            results=results,
            inventory=inventory,
            check=check,
            counts={},
            entry_error=True,
            reasons=reasons,
        )

    # 1. 会话有效性自检（交接单 §5.5 第 1 步）：不做它会把 401 vs 401 判成
    #    requires_auth（假阴性，§10.9）
    check_url = select_session_check_url(records, config.scope)
    if check_url is None:
        for order, candidate in enumerate(candidates, start=1):
            inventory.append(
                _inventory_row(
                    candidate,
                    _blocked_reason(candidate, "session_check_unavailable"),
                    order=order,
                )
            )
        reason = "找不到可用于会话自检的已知 2xx 页面"
        audit.record("jsimport_blocked", reason=reason)
        reasons.append(f"{reason}；退出码 2")
        return _ProbeOutcome(
            results=results,
            inventory=inventory,
            check=check,
            counts={},
            entry_error=True,
            reasons=reasons,
        )
    pacer.wait()
    check_response = fetch(check_url, session)
    failure = _session_check_failure(check_response)
    check = {
        "url": check_url,
        "status": check_response.status,
        "ok": failure is None,
        "reason": failure,
    }
    audit.record(
        "js_session_check",
        url=check_url,
        status=check_response.status,
        ok=failure is None,
        reason=failure,
    )
    if failure is not None:
        for order, candidate in enumerate(candidates, start=1):
            inventory.append(
                _inventory_row(candidate, _blocked_reason(candidate, "session_invalid"), order=order)
            )
        audit.record("jsimport_blocked", reason=failure, url=check_url)
        reasons.append(f"{failure}；退出码 2")
        return _ProbeOutcome(
            results=results,
            inventory=inventory,
            check=check,
            counts={},
            entry_error=True,
            reasons=reasons,
        )

    # 2. 逐候选探测（每个候选 2 次请求；超上限进清单，不静默丢）
    attempted = 0
    scope_rejected = 0
    probed = 0
    for order, candidate in enumerate(candidates, start=1):
        if candidate.grade not in ("A", "B") or candidate.collapsed:
            inventory.append(_inventory_row(candidate, candidate.reason, order=order))
            continue
        attempted += 1
        if probed >= max_probes:
            inventory.append(_inventory_row(candidate, "budget_capped", order=order))
            audit.record("js_skipped", display=candidate.display, reason="budget_capped")
            continue
        attempt = _probe_one(
            candidate,
            order=order,
            session=session,
            scope=config.scope,
            fetch=fetch,
            pacer=pacer,
            audit=audit,
        )
        if attempt.kind == "scope_rejected":
            scope_rejected += 1
            inventory.append(_inventory_row(candidate, "scope_rejected", order=order))
            continue
        probed += 1
        if attempt.row is None:
            inventory.append(_inventory_row(candidate, "baseline_not_2xx", order=order))
            continue
        results.append(attempt.row)

    counts = {
        "probed": probed,
        "confirmed": sum(1 for row in results if row["verdict"] == "confirmed"),
        "rejected": sum(1 for row in results if row["verdict"] == "rejected"),
        "blocked": sum(1 for row in results if row["verdict"] == "blocked"),
        "inventory": len(inventory),
    }
    entry_error = False
    if attempted > 0 and scope_rejected == attempted:
        entry_error = True
        reasons.append(f"候选全部越界（{scope_rejected} 条被 check_scope 拒绝）；退出码 2")
    return _ProbeOutcome(
        results=results,
        inventory=inventory,
        check=check,
        counts=counts,
        entry_error=entry_error,
        reasons=reasons,
    )


# --------------------------------------------------------------- 证据落盘


def _write_js_documents(
    js_dir: Path, documents: Sequence[JsDocument], secrets: list[str]
) -> None:
    for document in documents:
        _write_private(
            js_dir / document.name,
            redact_bytes(document.body.encode("utf-8"), secrets),
        )


def _write_probe_files(
    probe_dir: Path, results: Sequence[dict], secrets: list[str]
) -> None:
    for row in results:
        payload = json.dumps(row, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        _write_private(
            probe_dir / f"{row['probe']}.json",
            redact_bytes(payload.encode("utf-8"), secrets),
        )


def _render_summary_md(summary: dict, generated_at: str) -> str:
    counts = summary["counts"]
    crawl = summary["crawl"]
    check = summary["session"]["check"]
    lines = [
        "# JS 接口发现 → 未授权确认（M24-a）",
        "",
        f"- 生成时间：{generated_at}",
        f"- 输入：{', '.join(summary['sources']['katana_jsonl'])}",
        f"- 爬行记录 {crawl['records']} 条"
        f"（坏行 {crawl['skipped_lines']} / 结构缺项 {crawl['skipped_records']} /"
        f" 非 GET {crawl['non_get_records']}）",
        f"- JS 文件 {crawl['js_documents']} 份"
        f"（正文缺失 {len(crawl['js_body_missing'])} / 超限 {len(crawl['oversized_js'])} /"
        f" 文件数上限挡掉 {crawl['capped_js']}）",
        f"- 会话自检：{'通过' if check['ok'] else check['reason'] or '未做'}"
        f"（{check['url']} → {check['status']}）",
        "",
        "## 结论",
        "",
        "| 结论 | 条数 |",
        "|---|---|",
        f"| confirmed | {counts['confirmed']} |",
        f"| rejected | {counts['rejected']} |",
        f"| blocked | {counts['blocked']} |",
        f"| 清单（inventory） | {counts['inventory']} |",
        "",
        "> 判定口径：同一 URL，匿名客户端响应 ≡ 已认证客户端响应（逐字节相同或"
        "相似度 ≥ 阈值）才是 confirmed；语义上的「本该要登录」不进判定链。",
        "",
    ]
    for label, key in (
        ("Confirmed（匿名等价于已认证）", "confirmed"),
        ("Rejected（匿名被拒：本就要求认证）", "rejected"),
        ("Blocked（判不了：覆盖不全 / 匿名视图不同）", "blocked"),
    ):
        rows = summary[key]
        if not rows:
            continue
        lines.extend([f"## {label}", "", "| URL | 等级 | 认证 | 匿名 | 相似度 | 判定 |", "|---|---|---|---|---|---|"])
        for row in rows:
            judgment = row.get("judgment") or {}
            lines.append(
                f"| `{row['url']}` | {row['grade']} | "
                f"{row['authenticated']['status']} | "
                f"{(row['anonymous'] or {}).get('status')} | "
                f"{judgment.get('similarity_to_authenticated', '—')} | "
                f"{judgment.get('unauth_verdict', row['verdict'])} |"
            )
        lines.append("")
    inventory = summary["inventory"]
    if inventory:
        lines.extend(
            [
                "## 清单（未判定，供人工复核）",
                "",
                "| 路径模板 | 等级 | 原因 | 观测实例 / 合成 URL |",
                "|---|---|---|---|",
            ]
        )
        for row in inventory:
            target = row.get("observed_url") or row.get("synthetic_url") or "—"
            lines.append(
                f"| `{row['path_template']}` | {row['grade']} | {row['reason']} | {target} |"
            )
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------- 主流程


def run_jsimport(
    config: ImportConfig,
    *,
    fetch: Callable[[str, SessionConfig], IdorResponse] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> ImportReport:
    """跑完一次"JS 接口发现 → 未授权确认"（确定性；无 LLM 参与）。"""
    fetch_fn = fetch or (
        lambda url, session: fetch_response(url, session, timeout=config.timeout)
    )
    out_dir = Path(config.out_dir)
    js_dir = out_dir / "js"
    probe_dir = out_dir / "probe"
    for directory in (out_dir, js_dir, probe_dir):
        _mkdir_private(directory)
    audit = AuditLog(out_dir / "audit.jsonl")

    session = config.scope.session
    secrets = session.secret_values() if session is not None else []
    budget = config.scope.resolved_request_budget()
    effective_probes = min(config.max_probes, max(1, budget.max_requests // 2))
    effective_qps = min(config.qps, float(budget.rate_rps)) if config.qps > 0 else 0.0
    pacer = _Pacer(effective_qps, sleep=sleep, monotonic=monotonic)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    audit.record(
        "jsimport_started",
        sources=[str(path) for path in config.jsonl_paths],
        scopes=[str(item) for item in config.scope.domains]
        + [str(item) for item in config.scope.networks],
        ports=list(config.scope.ports),
        session=_session_marker(session) if session is not None else None,
        max_js_files=config.max_js_files,
        max_js_bytes=config.max_js_bytes,
        max_probes=effective_probes,
        qps=effective_qps,
        timeout=config.timeout,
        param_seed=config.param_seed,
        fetch_missing=config.fetch_missing,
    )

    bundle = load_katana_jsonl(
        config.jsonl_paths,
        max_js_files=config.max_js_files,
        max_js_bytes=config.max_js_bytes,
    )
    for document in bundle.js_documents:
        audit.record(
            "js_file_collected",
            sha256=document.sha256,
            urls=list(document.urls),
            bytes=document.size,
        )
    for url in bundle.js_body_missing:
        audit.record("js_skipped", url=url, reason="js_body_missing")
    for url in bundle.oversized_js:
        audit.record("js_skipped", url=url, reason="js_oversized")

    if config.fetch_missing and bundle.js_body_missing:
        fetched = _collect_js_documents(bundle, config, audit, fetch_fn, pacer)
        bundle.js_documents.extend(fetched)
        bundle.js_body_missing = [
            url for url in bundle.js_body_missing if url not in {d.urls[0] for d in fetched}
        ]

    _write_js_documents(js_dir, bundle.js_documents, secrets)
    _write_private(
        out_dir / "crawl.jsonl",
        redact_bytes(
            _jsonl(record.as_dict() for record in bundle.records).encode("utf-8"),
            secrets,
        ),
    )

    extracted = _extract_all(bundle.js_documents, audit)
    candidates = classify(
        extracted.endpoints,
        ObservedIndex.build(bundle.records),
        param_seed=config.param_seed,
    )
    for candidate in candidates:
        audit.record(
            "js_candidate_classified",
            display=candidate.display,
            grade=candidate.grade,
            reason=candidate.reason,
            probe_url=candidate.probe_url,
        )

    outcome = _run_probes(
        candidates,
        bundle.records,
        session=session,
        config=config,
        max_probes=effective_probes,
        fetch=fetch_fn,
        pacer=pacer,
        audit=audit,
    )

    inventory_orders = {row["order"] for row in outcome.inventory}
    endpoints_text = _jsonl(
        _endpoint_row(candidate, order in inventory_orders)
        for order, candidate in enumerate(candidates, start=1)
    )
    _write_private(
        out_dir / "endpoints.jsonl",
        redact_bytes(endpoints_text.encode("utf-8"), secrets),
    )
    _write_private(
        out_dir / "inventory.jsonl",
        redact_bytes(_jsonl(outcome.inventory).encode("utf-8"), secrets),
    )
    _write_probe_files(probe_dir, outcome.results, secrets)

    counts = {
        "endpoints": len(extracted.endpoints),
        "A": sum(1 for candidate in candidates if candidate.grade == "A"),
        "B": sum(1 for candidate in candidates if candidate.grade == "B"),
        "C": sum(1 for candidate in candidates if candidate.grade == "C"),
        "probed": int(outcome.counts.get("probed", 0)),
        "confirmed": int(outcome.counts.get("confirmed", 0)),
        "rejected": int(outcome.counts.get("rejected", 0)),
        "blocked": int(outcome.counts.get("blocked", 0)),
        "inventory": len(outcome.inventory),
    }
    no_records = not bundle.records
    if no_records:
        outcome.reasons.append("输入里没有任何可用爬行记录（GET ∧ 有状态码）；退出码 2")
        outcome.entry_error = True
    summary = {
        "tool": "proofhound.jsimport",
        "milestone": "M24-a",
        "sources": {"katana_jsonl": [str(path) for path in config.jsonl_paths]},
        "budget": {
            "param_seed": config.param_seed,
            "max_js_files": config.max_js_files,
            "max_js_bytes": config.max_js_bytes,
            "max_probes": effective_probes,
            "qps": effective_qps,
            "timeout": config.timeout,
            "scope_rate_rps": budget.rate_rps,
            "scope_max_requests": budget.max_requests,
        },
        "crawl": bundle.as_dict(),
        "extract": {
            **extracted.stats.as_dict(),
            "endpoints": len(extracted.endpoints),
            "bases": extracted.bases,
        },
        "session": {
            "configured": _session_configured(session),
            "marker": _session_marker(session) if session is not None else None,
            "check": outcome.check,
        },
        "counts": counts,
        "confirmed": [
            row for row in outcome.results if row["verdict"] == "confirmed"
        ],
        "rejected": [
            row for row in outcome.results if row["verdict"] == "rejected"
        ],
        "blocked": [
            row for row in outcome.results if row["verdict"] == "blocked"
        ],
        "inventory": outcome.inventory,
    }
    summary["reasons"] = list(outcome.reasons)
    exit_code = 2 if outcome.entry_error else (0 if counts["confirmed"] > 0 else 1)
    _write_private(
        out_dir / "summary.json",
        redact_bytes(
            (json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            .encode("utf-8"),
            secrets,
        ),
    )
    _write_private(
        out_dir / "summary.md",
        redact_bytes(_render_summary_md(summary, generated_at).encode("utf-8"), secrets),
    )
    audit.record(
        "jsimport_completed",
        exit_code=exit_code,
        counts=counts,
        entry_error=outcome.entry_error,
        reasons=list(outcome.reasons),
    )
    return ImportReport(
        out_dir=out_dir,
        exit_code=exit_code,
        summary=summary,
        reasons=list(outcome.reasons),
    )


def _endpoint_row(candidate: Candidate, in_inventory: bool) -> dict:
    row = candidate.as_dict()
    row["in_inventory"] = in_inventory
    return row


__all__ = [
    "DEFAULT_MAX_PROBES",
    "DEFAULT_QPS",
    "DEFAULT_TIMEOUT",
    "ImportConfig",
    "ImportReport",
    "run_jsimport",
    "select_session_check_url",
]
