#!/usr/bin/env python3
"""M24-a 实弹验收：从爬行产出的 JS 里找接口 → 未授权访问确认。

**五种形态一次跑齐**（交接单 §9）：

| 端点 | 服务端行为 | 期望 |
|---|---|---|
| `/api/orders/1001` | 带会话 200 JSON；匿名 **同一 JSON** | **confirmed**（A 类观测实例） |
| `/api/profile` | 带会话 200；匿名 401 | **rejected**（本来就要求认证） |
| `/api/notes/7` | 带会话 200 全文；匿名 200 标题 | **blocked**（匿名精简版，判不了） |
| `/api/config` | 公开配置；JS 里有、无观测实例 | **清单**（被候选过滤挡掉） |
| `/api/health` | 匿名/认证同体；**JS 里没有** | **不进候选**（只在爬行记录里） |

外加 `/api/orders/{id}` 模板：它与观测实例 `/api/orders/1001` 指向同一 URL ⇒
折叠进清单（**同一 URL 只探一次**，否则会被确认两次）。

## 起爬行产物的两种方式

1. **真 katana**（缺省）：仓库自带 `tools.d/katana/katana`（1.7.0）对本地 SPA
   跑 `-jsonl -jc`，stdout 直接就是本工具的输入——这是交接单 §1 实测的原始形态；
2. **回退**（二进制缺失时）：用 urllib 把 `/`、JS 与两个链接**真实抓一遍**，按
   katana JSONL 的字段形态序列化。**这是接缝，如实标注**：回退路径没有真爬虫，
   只有真 HTTP 响应。

## 验收项（任一失败 ⇒ 退出码 1）

1. 1 confirmed / 1 rejected / 1 blocked / 清单 2；
2. **模板匹配正确**：`/api/orders/{id}` 折叠到观测实例而不是另发一次请求；
3. **锚点可调出**：证据里的 `js_sha256` + byte offset 能在 `js/<sha8>.js` 里
   重新定位到原字面量；
4. **匿名零凭据**：靶侧日志里匿名请求一条 Cookie 都没有；
5. **无凭据泄漏**：证据目录 grep 不到会话 Cookie 的值；
6. **确定性**：连跑两次 `summary.json` 逐字节一致；
7. **无会话 ⇒ 退出码 2 且零 confirmed**；
8. **`/api/health` 不进候选**（候选只来自 JS）。

用法：
    .venv/bin/python scripts/demo_js_endpoints.py
    .venv/bin/python scripts/demo_js_endpoints.py --no-katana   # 强制回退路径
    .venv/bin/python scripts/demo_js_endpoints.py --tmp         # 跑完即弃
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from proofhound.compliance.scope import Scope  # noqa: E402
from proofhound.jsimport.extract import extract_endpoints  # noqa: E402
from proofhound.jsimport.crawl import load_katana_jsonl  # noqa: E402
from proofhound.jsimport.probe import (  # noqa: E402
    ImportConfig,
    run_jsimport,
)

KATANA = REPO / "tools.d" / "katana" / "katana"
SESSION_COOKIE = "sid"
SESSION_VALUE = "demo-session-value-2026"
ANON_ORDERS = {"id": 1001, "owner": "alice", "total": 42, "items": ["a", "b"]}
PROFILE = {"username": "alice", "email": "alice@example.com", "role": "admin"}
NOTE_FULL = {
    "id": 7,
    "title": "Quarterly plan",
    "body": "confidential: the merger closes on 2026-12-01; do not share.",
    "owner": "alice",
}
NOTE_TITLE = {"id": 7, "title": "Quarterly plan"}
PUBLIC_CONFIG = {"theme": "dark", "locale": "zh-CN"}
HEALTH = {"status": "ok"}

SPA_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>SPA</title></head>
<body>
<h1>ProofHound M24-a fixture</h1>
<script src="/static/app.js"></script>
<a href="/api/orders/1001">order 1001</a>
<a href="/api/health">health</a>
</body></html>
"""

#: 靶面 JS：普通字面量 + 模板串 + 公开接口（`/api/config`）+ 不该出现的 `/api/health`
APP_JS = """// SPA bundle（M24-a fixture）
const api = {
  order: "/api/orders/1001",
  profile: "/api/profile",
  config: "/api/config",
  notes: "/api/notes/7",
};
const orderDetail = (id) => fetch(`/api/orders/${id}`);
const profile = () => fetch("/api/profile");
const config = () => fetch("/api/config");
const note = () => fetch("/api/notes/7");
"""


class SpaHandler(BaseHTTPRequestHandler):
    """一个"看起来正常"的 SPA：静态资源 + 三个 API + 一个公开配置接口。"""

    #: [(path, 是否带会话 Cookie)]，靶侧日志（验收"匿名零凭据"用）
    hits: list[tuple[str, bool]] = []

    def do_GET(self):  # noqa: N802
        authenticated = f"{SESSION_COOKIE}={SESSION_VALUE}" in (self.headers.get("Cookie") or "")
        type(self).hits.append((self.path, authenticated))
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self._send(200, SPA_HTML, "text/html; charset=utf-8")
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript; charset=utf-8")
        if path == "/api/orders/1001":
            # 漏洞形态：匿名与已认证拿到**同一份**数据
            return self._send_json(200, ANON_ORDERS)
        if path == "/api/profile":
            if not authenticated:
                return self._send(401, "unauthorized", "text/plain; charset=utf-8")
            return self._send_json(200, PROFILE)
        if path == "/api/notes/7":
            # 匿名拿到**精简版**（标题），已认证拿到全文 ⇒ 判不了（blocked）
            return self._send_json(200, NOTE_FULL if authenticated else NOTE_TITLE)
        if path == "/api/config":
            return self._send_json(200, PUBLIC_CONFIG)
        if path == "/api/health":
            return self._send_json(200, HEALTH)
        return self._send(404, "not found", "text/plain; charset=utf-8")

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        self._send(status, body, "application/json; charset=utf-8")

    def _send(self, status: int, body: str, content_type: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # 静默（靶侧日志由 ``hits`` 记录）
        pass


def _start_fixture() -> ThreadingHTTPServer:
    SpaHandler.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), SpaHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _katana_available() -> bool:
    return KATANA.is_file() and KATANA.stat().st_mode & 0o111 != 0


def _run_katana(base_url: str, out_path: Path) -> tuple[bool, str]:
    """真 katana 1.7.0：``-jsonl -jc`` 的 stdout 就是本工具的输入。"""
    command = [
        str(KATANA),
        "-u",
        f"{base_url}/",
        "-jsonl",
        "-jc",
        "-silent",
        "-d",
        "2",
        "-c",
        "1",
        "-timeout",
        "10",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=300, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - 环境相关
        return False, f"katana 调用失败: {exc}"
    if result.returncode != 0 or not result.stdout.strip():
        return False, f"katana 返回码 {result.returncode}，stdout 为空"
    out_path.write_text(result.stdout, encoding="utf-8")
    return True, f"真 katana（{len(result.stdout.splitlines())} 条记录）"


def _fallback_crawl(base_url: str, out_path: Path) -> tuple[bool, str]:
    """回退：真 HTTP 抓一遍，按 katana JSONL 字段形态序列化（**无真爬虫**）。"""
    targets = ["/", "/static/app.js", "/api/orders/1001", "/api/health"]
    rows: list[dict] = []
    for target in targets:
        url = f"{base_url}{target}"
        try:
            with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - 本机 fixture
                body = response.read().decode("utf-8", errors="replace")
                status = response.status
                content_type = response.headers.get("Content-Type", "")
        except OSError as exc:  # pragma: no cover - 环境相关
            return False, f"回退抓取失败: {exc}"
        rows.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request": {"method": "GET", "endpoint": url, "raw": f"GET {target} HTTP/1.1\r\n\r\n"},
                "response": {
                    "status_code": status,
                    "headers": {"Content-Type": content_type},
                    "body": body,
                    "content_length": len(body.encode("utf-8")),
                    "raw": f"HTTP/1.1 {status} X\r\n\r\n{body}",
                },
            }
        )
    out_path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )
    return True, f"回退路径（真 HTTP + 罐头爬虫记录，{len(rows)} 条）"


def _write_scope(path: Path, *, with_session: bool) -> Path:
    lines = ["networks: [127.0.0.0/8]", "ports: []"]
    if with_session:
        lines += ["session:", "  cookies:", f"    {SESSION_COOKIE}: {SESSION_VALUE}"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _evidence_text(root: Path) -> str:
    return "\n".join(
        item.read_text(encoding="utf-8", errors="replace")
        for item in sorted(root.rglob("*"))
        if item.is_file()
    )


class Checker:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.rows.append({"check": name, "ok": bool(ok), "detail": detail})
        mark = "✅" if ok else "❌"
        print(f"  {mark} {name}" + (f" — {detail}" if detail else ""))

    @property
    def failed(self) -> list[dict]:
        return [row for row in self.rows if not row["ok"]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M24-a 实弹验收：JS 接口 → 未授权确认")
    parser.add_argument("--tmp", action="store_true", help="产物落临时目录，跑完即弃")
    parser.add_argument("--no-katana", action="store_true", help="强制走回退路径（不跑 katana 二进制）")
    args = parser.parse_args(argv)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.tmp:
        out_root = Path(tempfile.mkdtemp(prefix="m24a-jsimport-"))
    else:
        out_root = REPO / "evidence" / "demo_js_endpoints" / stamp
    out_root.mkdir(parents=True, exist_ok=True)

    server = _start_fixture()
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    print(f"[*] 靶: {base_url}（SPA + 三类 API + 公开配置 + health）")

    jsonl = out_root / "katana.stdout.log"
    crawl_ok, crawl_note = False, ""
    if not args.no_katana and _katana_available():
        crawl_ok, crawl_note = _run_katana(base_url, jsonl)
    if not crawl_ok:
        crawl_ok, crawl_note = _fallback_crawl(base_url, jsonl)
    print(f"[*] 爬行产物: {crawl_note} → {jsonl}")
    # 靶侧日志从"本工具的请求"开始记：katana 自身的抓取不算进匿名/已认证对照
    SpaHandler.hits = []

    scope_path = _write_scope(out_root / "scope-lab.yaml", with_session=True)
    scope = Scope.from_file(scope_path)

    checker = Checker()
    print("\n[*] 第一次运行（带会话）")
    first = run_jsimport(
        ImportConfig(
            jsonl_paths=(jsonl,),
            scope=scope,
            out_dir=out_root / "run1",
            qps=0,
        )
    )
    for line in first.render_lines():
        print(f"    {line}")
    counts = first.summary["counts"]

    print("\n[*] 第二次运行（同一份输入，验确定性）")
    second = run_jsimport(
        ImportConfig(
            jsonl_paths=(jsonl,),
            scope=scope,
            out_dir=out_root / "run2",
            qps=0,
        )
    )

    print("\n[*] 第三次运行（无会话，验结构性失败）")
    no_session_scope = Scope.from_file(_write_scope(out_root / "scope-lab-anon.yaml", with_session=False))
    third = run_jsimport(
        ImportConfig(
            jsonl_paths=(jsonl,),
            scope=no_session_scope,
            out_dir=out_root / "run3-no-session",
            qps=0,
        )
    )

    print("\n[*] 验收")
    checker.check(
        "1 confirmed / 1 rejected / 1 blocked / 清单 2",
        (counts["confirmed"], counts["rejected"], counts["blocked"], counts["inventory"])
        == (1, 1, 1, 2),
        f"实际 {counts['confirmed']}/{counts['rejected']}/{counts['blocked']}/{counts['inventory']}",
    )
    confirmed_urls = [row["url"] for row in first.summary["confirmed"]]
    checker.check(
        "confirmed 就是 /api/orders/1001（匿名拿到同一份 JSON）",
        confirmed_urls == [f"{base_url}/api/orders/1001"],
        str(confirmed_urls),
    )
    checker.check(
        "rejected 是 /api/profile（匿名 401）",
        [row["url"] for row in first.summary["rejected"]] == [f"{base_url}/api/profile"],
        str([row["url"] for row in first.summary["rejected"]]),
    )
    blocked = first.summary["blocked"]
    checker.check(
        "blocked 是 /api/notes/7（匿名精简版，判不了）",
        [row["url"] for row in blocked] == [f"{base_url}/api/notes/7"],
        str([row["url"] for row in blocked]),
    )
    inventory = {row["path_template"]: row for row in first.summary["inventory"]}
    checker.check(
        "清单含 /api/config（公开接口，被候选过滤挡掉）",
        inventory.get("/api/config", {}).get("reason") == "excluded_segment:config",
        str(inventory.get("/api/config", {}).get("reason")),
    )
    checker.check(
        "模板 /api/orders/{param} 折叠到观测实例（同一 URL 只探一次）",
        inventory.get("/api/orders/{param}", {}).get("reason") == "duplicate_url",
        str(inventory.get("/api/orders/{param}", {}).get("reason")),
    )
    checker.check(
        "/api/health 不进候选（候选只来自 JS）",
        "/api/health" not in {row["path_template"] for row in first.summary["inventory"]}
        and "health" not in (first.out_dir / "endpoints.jsonl").read_text(encoding="utf-8"),
        "health 只在爬行记录里",
    )

    # 锚点可调出：证据里的 js_sha256 + offset 能在 js/<sha8>.js 里重新定位字面量
    bundle = load_katana_jsonl([jsonl])
    document = bundle.js_documents[0]
    templates, _stats = extract_endpoints(document)
    order_template = next(
        item for item in templates if item.path_template == "/api/orders/{param}"
    )
    saved = first.out_dir / "js" / document.name
    saved_bytes = saved.read_bytes()
    anchor = order_template.anchor
    checker.check(
        "锚点（js_sha256 + byte offset）可从证据调出原字面量",
        saved.is_file()
        and saved_bytes[anchor.offset : anchor.offset + len("/api/orders/")]
        == b"/api/orders/"
        and saved_bytes == document.body.encode("utf-8"),
        f"{document.name}@{anchor.offset} line={anchor.line}",
    )

    # 匿名零凭据：靶侧日志里带 Cookie 的请求必然是自检/基线，重放请求一条都不带
    replay_paths = {
        "/api/orders/1001",
        "/api/profile",
        "/api/notes/7",
    }
    anonymous_replay = [
        path for path, authenticated in SpaHandler.hits if path in replay_paths and not authenticated
    ]
    checker.check(
        "匿名重放零凭据（靶侧日志逐条核对）",
        len(anonymous_replay) >= 3 and len(anonymous_replay) == len(
            [1 for path, authenticated in SpaHandler.hits if path in replay_paths and authenticated]
        ),
        f"匿名 {len(anonymous_replay)} 条 / 带会话 "
        f"{len([1 for p, a in SpaHandler.hits if p in replay_paths and a])} 条",
    )

    evidence_text = _evidence_text(first.out_dir)
    checker.check(
        "证据里 grep 不到会话 Cookie 的值",
        SESSION_VALUE not in evidence_text,
        f"{len(evidence_text)} 字符已检查",
    )
    checker.check(
        "summary.json 连跑两次逐字节一致",
        (first.out_dir / "summary.json").read_bytes()
        == (second.out_dir / "summary.json").read_bytes(),
        "确定性",
    )
    checker.check(
        "无会话 ⇒ 退出码 2 且零 confirmed",
        third.exit_code == 2 and third.summary["counts"]["confirmed"] == 0,
        f"exit={third.exit_code} confirmed={third.summary['counts']['confirmed']}",
    )

    server.shutdown()
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "base_url": base_url,
        "crawl": crawl_note,
        "counts": counts,
        "checks": checker.rows,
        "failed": len(checker.failed),
        "evidence": str(out_root),
    }
    (out_root / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    counts_json = json.dumps(dict(counts), ensure_ascii=False)
    print(f"\n[*] 计数: {counts_json}")
    print(f"[*] 产物: {out_root}")
    if checker.failed:
        print(f"[!] {len(checker.failed)}/{len(checker.rows)} 条验收失败", file=sys.stderr)
        if args.tmp:
            shutil.rmtree(out_root, ignore_errors=True)
        return 1
    print(f"[*] 验收 {len(checker.rows)}/{len(checker.rows)} 全绿")
    if args.tmp:
        shutil.rmtree(out_root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
