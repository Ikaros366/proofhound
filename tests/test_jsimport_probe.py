"""M24-a 探测层：会话自检 → 认证基线 → 匿名对照 → 三态 → 证据落盘。

用**罐头 fetch**（零真实网络）复刻交接单 §9 的五种形态，并锁住几条容易翻车的
纪律：

- **无会话 / 会话失效 / scope 全拒 ⇒ 退出码 2 且零 confirmed**（§3、§5.5）；
- **A 类基线异常记 blocked、B 类基线非 2xx 记清单**——"参数不对"绝不能被写成
  "要登录"（§10.8）；
- **匿名重放零凭据**（靶侧断言只收到不带 Cookie 的请求）；
- **证据里没有 Cookie 值**，``summary.json`` 连跑两次逐字节一致（§9）。
"""

from __future__ import annotations

import json
import os
import stat
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse

from proofhound.compliance.scope import Scope
from proofhound.jsimport.probe import ImportConfig, run_jsimport
from proofhound.verify.idor import IdorResponse

BASE = "http://127.0.0.1:8000"
COOKIE = "s3cr3t-cookie-value"  # ≥8 字符才会进 secret_values() 的裸值清单

ORDER_JSON = '{"id": 1001, "total": 42, "items": ["a", "b"], "owner": "alice"}'
PROFILE_JSON = '{"username": "alice", "email": "alice@example.com", "role": "admin"}'
NOTE_FULL = '{"note": "confidential: merger closes 2026-12-01", "body": "' + "x" * 200 + '"}'
NOTE_TITLE = '{"title": "hello"}'

APP_JS = """fetch("/api/orders/1001");
fetch(`/api/orders/${id}`);
fetch("/api/profile");
fetch("/api/config");
fetch("/api/notes/7");
"""

DEFAULT_ROUTES = {
    "/": (200, "<html><body>spa</body></html>", 200, "<html><body>spa</body></html>"),
    "/api/orders/1001": (200, ORDER_JSON, 200, ORDER_JSON),
    "/api/profile": (200, PROFILE_JSON, 401, "unauthorized"),
    "/api/notes/7": (200, NOTE_FULL, 200, NOTE_TITLE),
}

#: 交接单 §9 要求的审计事件（缺失即证据链不完整）
REQUIRED_AUDIT_EVENTS = {
    "jsimport_started",
    "js_file_collected",
    "js_endpoint_extracted",
    "js_candidate_classified",
    "js_probe_attempt",
    "js_judged",
    "jsimport_completed",
}


class FakeSpa:
    """按 (path, 是否带会话) 返回罐头响应；``calls`` 记下靶侧收到的请求。"""

    def __init__(self, routes: dict[str, tuple[int, str, int, str]]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, bool, str]] = []

    def __call__(self, url: str, session) -> IdorResponse:
        authed = bool(session.cookie_header())
        path = urlparse(url).path
        self.calls.append((path, authed, url))
        entry = self.routes.get(path)
        if entry is None:
            return IdorResponse(url=url, status=404, body="not found")
        status, body = (entry[0], entry[1]) if authed else (entry[2], entry[3])
        return IdorResponse(url=url, status=status, body=body)


def _record(
    url: str,
    *,
    status: int = 200,
    body: str = "",
    content_type: str = "text/html; charset=utf-8",
    method: str = "GET",
) -> dict:
    return {
        "timestamp": "2026-10-28T00:00:00.000000Z",
        "request": {"method": method, "endpoint": url, "raw": "GET / HTTP/1.1\r\n\r\n"},
        "response": {
            "status_code": status,
            "headers": {"Content-Type": content_type},
            "body": body,
            "content_length": len(body.encode("utf-8")),
            "raw": f"HTTP/1.1 {status} X\r\n\r\n{body}",
        },
    }


def _write_jsonl(tmp_path: Path, records: list[dict]) -> Path:
    path = tmp_path / "katana.stdout.log"
    path.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in records) + "\n",
        encoding="utf-8",
    )
    return path


def _default_records(app_js: str = APP_JS, origin: str = BASE) -> list[dict]:
    return [
        _record(f"{origin}/", body="<html><body>spa</body></html>"),
        _record(
            f"{origin}/static/app.js",
            body=app_js,
            content_type="application/javascript; charset=utf-8",
        ),
        _record(
            f"{origin}/api/orders/1001",
            body=ORDER_JSON,
            content_type="application/json",
        ),
    ]


def _scope(
    *,
    session: bool = True,
    ports: list[int] | None = None,
    domains: list[str] | None = None,
) -> Scope:
    data: dict = {
        "networks": [] if domains else ["127.0.0.0/8"],
        "ports": ports or [],
    }
    if domains:
        data["domains"] = domains
    if session:
        data["session"] = {"cookies": {"sid": COOKIE}}
    return Scope(**data)


def _run(
    tmp_path: Path,
    *,
    records: list[dict] | None = None,
    routes: dict[str, tuple[int, str, int, str]] | None = None,
    scope: Scope | None = None,
    out_name: str = "out",
    fetch=None,
    **config_kwargs,
):
    path = _write_jsonl(tmp_path, records if records is not None else _default_records())
    spa = FakeSpa(routes if routes is not None else DEFAULT_ROUTES)
    fetch_fn = fetch if fetch is not None else spa
    config = ImportConfig(
        jsonl_paths=(path,),
        scope=scope if scope is not None else _scope(),
        out_dir=tmp_path / out_name,
        qps=0.0,
        **config_kwargs,
    )
    report = run_jsimport(config, fetch=fetch_fn)
    return report, fetch_fn


def _all_evidence_text(out_dir: Path) -> str:
    return "\n".join(
        item.read_text(encoding="utf-8", errors="replace")
        for item in sorted(out_dir.rglob("*"))
        if item.is_file()
    )


# --------------------------------------------------------------- 五种形态


def test_five_shapes_of_the_acceptance_fixture(tmp_path):
    """1 confirmed / 1 rejected / 1 blocked / 清单 2（交接单 §9 的算术）。"""
    report, _spa = _run(tmp_path)
    counts = report.summary["counts"]
    assert report.exit_code == 0
    assert counts == {
        "endpoints": 5,
        "A": 2,
        "B": 2,
        "C": 1,
        "probed": 3,
        "confirmed": 1,
        "rejected": 1,
        "blocked": 1,
        "inventory": 2,
    }
    confirmed = report.summary["confirmed"][0]
    assert confirmed["url"] == f"{BASE}/api/orders/1001"
    assert confirmed["grade"] == "A"
    assert confirmed["judgment"]["unauth_verdict"] == "exposed"
    assert confirmed["judgment"]["byte_identical"] is True


def test_rejected_is_anonymous_denied(tmp_path):
    report, _spa = _run(tmp_path)
    rejected = report.summary["rejected"][0]
    assert rejected["url"] == f"{BASE}/api/profile"
    assert rejected["grade"] == "B" and rejected["synthetic"] is True
    assert rejected["judgment"]["unauth_verdict"] == "requires_auth"
    assert rejected["anonymous"]["status"] == 401


def test_blocked_is_anonymous_different_view(tmp_path):
    """匿名 2xx 但内容不同也不像 ⇒ 判不了（宁可 blocked，也不猜）。"""
    report, _spa = _run(tmp_path)
    blocked = report.summary["blocked"][0]
    assert blocked["url"] == f"{BASE}/api/notes/7"
    assert blocked["judgment"]["unauth_verdict"] == "blocked"
    assert blocked["judgment"]["similarity_to_authenticated"] < 0.9


def test_inventory_records_duplicate_and_excluded_without_verdict(tmp_path):
    report, _spa = _run(tmp_path)
    rows = {row["path_template"]: row for row in report.summary["inventory"]}
    assert set(rows) == {"/api/orders/{param}", "/api/config"}
    assert rows["/api/orders/{param}"]["reason"] == "duplicate_url"
    assert rows["/api/orders/{param}"]["observed_url"] == f"{BASE}/api/orders/1001"
    assert rows["/api/config"]["reason"] == "excluded_segment:config"
    for row in rows.values():
        assert "verdict" not in row  # 清单**不写 verdict**


def test_anonymous_requests_carry_no_credentials(tmp_path):
    """匿名重放**零凭据**：靶侧只收到不带 Cookie 的请求（§4.6）。"""
    _report, spa = _run(tmp_path)
    authed = [call for call in spa.calls if call[1]]
    anonymous = [call for call in spa.calls if not call[1]]
    assert len(authed) == len(anonymous) + 1  # +1 是会话自检（带会话）
    assert [call[0] for call in anonymous] == [call[0] for call in authed[1:]]


def test_each_candidate_costs_exactly_two_requests(tmp_path):
    """每条候选 2 次请求 + 1 次会话自检（§5.5 / §4.7）。"""
    _report, spa = _run(tmp_path)
    assert len(spa.calls) == 3 * 2 + 1
    assert spa.calls[0] == ("/", True, f"{BASE}/")


# --------------------------------------------------------------- 结构性失败


def test_no_session_exits_2_with_zero_confirmed(tmp_path):
    report, spa = _run(tmp_path, scope=_scope(session=False))
    assert report.exit_code == 2
    assert report.summary["counts"]["confirmed"] == 0
    assert report.summary["counts"]["inventory"] == 5
    assert spa.calls == []  # 无会话 ⇒ 一个请求都不发
    assert report.summary["session"]["configured"] is False


def test_no_session_does_not_overwrite_the_filter_reason(tmp_path):
    """无会话时，被过滤掉的候选仍记自己的原因（``/config`` 不是"因为没会话才没测"）。"""
    report, _spa = _run(tmp_path, scope=_scope(session=False))
    rows = {row["path_template"]: row for row in report.summary["inventory"]}
    assert rows["/api/config"]["reason"] == "excluded_segment:config"
    assert rows["/api/profile"]["reason"] == "session_not_configured"


def test_invalid_session_exits_2_before_any_probe(tmp_path):
    routes = dict(DEFAULT_ROUTES)
    routes["/"] = (401, "login", 401, "login")
    report, spa = _run(tmp_path, routes=routes)
    assert report.exit_code == 2
    assert report.summary["counts"]["confirmed"] == 0
    assert report.summary["session"]["check"]["ok"] is False
    assert "会话已失效" in report.summary["session"]["check"]["reason"]
    assert len(spa.calls) == 1  # 只有自检那一次请求


def test_session_check_redirect_is_treated_as_expired(tmp_path):
    routes = dict(DEFAULT_ROUTES)
    routes["/"] = (302, "", 302, "")
    report, _spa = _run(tmp_path, routes=routes)
    assert report.exit_code == 2
    assert "重定向" in report.summary["session"]["check"]["reason"]


def test_scope_rejection_leaves_only_inventory(tmp_path):
    """页面在 8000（在 scope 内）、JS 在 8001（越界）⇒ 候选全部 scope_rejected。"""
    other = "http://127.0.0.1:8001"
    records = [
        _record(f"{BASE}/", body="<html></html>"),
        _record(
            f"{other}/static/app.js",
            body=APP_JS,
            content_type="application/javascript; charset=utf-8",
        ),
        _record(f"{other}/api/orders/1001", body=ORDER_JSON),
    ]
    report, spa = _run(
        tmp_path, records=records, scope=_scope(ports=[8000])
    )
    assert report.exit_code == 2
    assert report.summary["counts"]["probed"] == 0
    reasons = {row["reason"] for row in report.summary["inventory"]}
    assert "scope_rejected" in reasons
    assert len(spa.calls) == 1  # 只有自检那一次（页面在 8000，在 scope 内）


# --------------------------------------------------------------- 基线语义（§10.8）


def test_a_class_baseline_error_is_blocked_not_rejected(tmp_path):
    routes = dict(DEFAULT_ROUTES)
    routes["/api/orders/1001"] = (500, "boom", 200, ORDER_JSON)
    report, _spa = _run(tmp_path, records=[
        _record(f"{BASE}/", body="<html></html>"),
        _record(f"{BASE}/static/app.js", body='fetch("/api/orders/1001");',
                content_type="application/javascript"),
        _record(f"{BASE}/api/orders/1001", body=ORDER_JSON),
    ], routes=routes)
    assert report.summary["counts"]["blocked"] == 1
    assert report.summary["counts"]["rejected"] == 0
    assert report.exit_code == 1


def test_b_class_baseline_404_is_inventory_not_rejected(tmp_path):
    """合成参数不对 ⇒ 清单；绝不能被判成 requires_auth（否则等于"要登录"的假信号）。"""
    routes = dict(DEFAULT_ROUTES)
    routes["/api/profile"] = (404, "no such", 200, PROFILE_JSON)
    report, _spa = _run(tmp_path, records=[
        _record(f"{BASE}/", body="<html></html>"),
        _record(f"{BASE}/static/app.js", body='fetch("/api/profile");',
                content_type="application/javascript"),
    ], routes=routes)
    assert report.summary["counts"]["rejected"] == 0
    assert report.summary["counts"]["blocked"] == 0
    reasons = {row["reason"] for row in report.summary["inventory"]}
    assert reasons == {"baseline_not_2xx"}
    assert report.exit_code == 1


def test_budget_cap_sends_overflow_to_inventory(tmp_path):
    report, _spa = _run(tmp_path, max_probes=1)
    counts = report.summary["counts"]
    assert counts["probed"] == 1
    assert counts["inventory"] == 4
    assert "budget_capped" in {row["reason"] for row in report.summary["inventory"]}


def test_session_check_unavailable_is_structural_failure(tmp_path):
    """连一条**在 scope 内**的 2xx 页面都找不到 ⇒ 自检做不了 ⇒ 退出码 2、零请求。"""
    report, spa = _run(
        tmp_path,
        records=[
            _record(
                f"{BASE}/static/app.js",
                body=APP_JS,
                content_type="application/javascript",
            )
        ],
        scope=_scope(domains=["example.com"]),
    )
    assert report.exit_code == 2
    assert report.summary["counts"]["confirmed"] == 0
    assert spa.calls == []


# --------------------------------------------------------------- 证据与脱敏


def test_evidence_files_are_complete(tmp_path):
    report, _spa = _run(tmp_path)
    out = report.out_dir
    for name in (
        "crawl.jsonl",
        "endpoints.jsonl",
        "inventory.jsonl",
        "summary.json",
        "summary.md",
        "audit.jsonl",
    ):
        assert (out / name).is_file(), name
    probes = sorted((out / "probe").glob("*.json"))
    assert len(probes) == 3
    js_files = sorted((out / "js").glob("*.js"))
    assert len(js_files) == 1
    assert js_files[0].read_text(encoding="utf-8") == APP_JS


def test_js_originals_are_private(tmp_path):
    report, _spa = _run(tmp_path)
    js_dir = report.out_dir / "js"
    js_file = next(js_dir.glob("*.js"))
    assert stat.S_IMODE(os.stat(js_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(js_file).st_mode) == 0o600


def test_no_cookie_value_leaks_into_evidence(tmp_path):
    """证据、审计、摘要里都不得出现 Cookie 原文（只允许 Cookie 名 + sha256 前 8 位）。"""
    report, _spa = _run(tmp_path)
    text = _all_evidence_text(report.out_dir)
    assert COOKIE not in text
    assert COOKIE[:6] not in text
    assert "sid" in text  # 名字可以出现


def test_session_marker_uses_sha8_only(tmp_path):
    report, _spa = _run(tmp_path)
    cookie = report.summary["session"]["marker"]["cookies"][0]
    assert cookie["name"] == "sid"
    assert cookie["value"].startswith("sha256:")
    assert len(cookie["value"]) == len("sha256:") + 8


def test_response_bodies_are_not_written_to_probe_evidence(tmp_path):
    """``probe/*.json`` 只落状态码 / sha256 / 相似度——正文不落盘，故 Cookie 无从顺带外泄。"""
    report, _spa = _run(tmp_path)
    text = "\n".join(
        item.read_text(encoding="utf-8") for item in (report.out_dir / "probe").glob("*.json")
    )
    assert "alice@example.com" not in text
    assert "merger closes" not in text
    assert sha256(ORDER_JSON.encode("utf-8")).hexdigest() in text


def test_audit_records_the_documented_events(tmp_path):
    report, _spa = _run(tmp_path)
    events = {
        json.loads(line)["event"]
        for line in (report.out_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert REQUIRED_AUDIT_EVENTS <= events
    assert "js_session_check" in events


def test_summary_json_is_byte_identical_across_runs(tmp_path):
    """连跑两次 ``summary.json`` 逐字节一致（§9 的确定性验收项）。"""
    first, _ = _run(tmp_path, out_name="run1")
    second, _ = _run(tmp_path, out_name="run2")
    assert (first.out_dir / "summary.json").read_bytes() == (
        second.out_dir / "summary.json"
    ).read_bytes()


def test_summary_md_reports_the_five_shapes(tmp_path):
    report, _spa = _run(tmp_path)
    text = (report.out_dir / "summary.md").read_text(encoding="utf-8")
    assert "confirmed" in text and "清单" in text
    assert "/api/orders/1001" in text
    assert "判定口径" in text


# --------------------------------------------------------------- --fetch-missing


def test_fetch_missing_collects_js_body(tmp_path):
    body = 'fetch("/api/profile");'
    records = [
        _record(f"{BASE}/", body="<html></html>"),
        _record(f"{BASE}/static/lazy.js", body="", content_type="application/javascript"),
    ]

    class Lazy(FakeSpa):
        def __call__(self, url, session):
            if url.endswith("/static/lazy.js"):
                self.calls.append(("/static/lazy.js", bool(session.cookie_header()), url))
                return IdorResponse(url=url, status=200, body=body)
            return super().__call__(url, session)

    routes = {
        "/": (200, "<html></html>", 200, "<html></html>"),
        "/api/profile": (200, PROFILE_JSON, 401, "no"),
    }
    lazy = Lazy(routes)
    report, spa = _run(
        tmp_path,
        records=records,
        routes=routes,
        fetch=lazy,
        fetch_missing=True,
    )
    assert report.summary["crawl"]["js_documents"] == 1
    assert report.summary["counts"]["endpoints"] == 1
    assert spa is lazy
    assert any(url.endswith("/static/lazy.js") for _p, _a, url in spa.calls)


def test_fetch_missing_off_leaves_body_missing(tmp_path):
    records = [
        _record(f"{BASE}/", body="<html></html>"),
        _record(f"{BASE}/static/lazy.js", body="", content_type="application/javascript"),
    ]
    report, _spa = _run(tmp_path, records=records)
    assert report.summary["crawl"]["js_documents"] == 0
    assert report.summary["crawl"]["js_body_missing"] == [f"{BASE}/static/lazy.js"]
    assert report.summary["counts"]["endpoints"] == 0


# --------------------------------------------------------------- 无候选


def test_no_js_endpoints_exits_1(tmp_path):
    report, _spa = _run(
        tmp_path,
        records=[_record(f"{BASE}/", body="<html>no js here</html>")],
    )
    assert report.exit_code == 1
    assert report.summary["counts"]["endpoints"] == 0
    assert report.summary["crawl"]["js_documents"] == 0


def test_empty_crawl_is_entry_error(tmp_path):
    path = tmp_path / "katana.stdout.log"
    path.write_text("", encoding="utf-8")
    config = ImportConfig(jsonl_paths=(path,), scope=_scope(), out_dir=tmp_path / "out", qps=0.0)
    report = run_jsimport(config, fetch=FakeSpa(DEFAULT_ROUTES))
    assert report.exit_code == 2
    assert any("没有任何可用爬行记录" in reason for reason in report.reasons)


def test_excluded_endpoint_is_never_probed(tmp_path):
    """``/api/config`` 在 JS 里、但被候选过滤挡掉 ⇒ 靶侧一次请求都收不到。"""
    _report, spa = _run(tmp_path)
    probed_paths = {urlparse(url).path for _path, _authed, url in spa.calls}
    assert "/api/config" not in probed_paths
