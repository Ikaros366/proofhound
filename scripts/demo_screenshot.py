#!/usr/bin/env python3
"""M20 实弹验收：证据截图对**真实** Chromium 与**真实** HTTP 靶跑通（零替身）。

## 验什么

1. **真浏览器真截图**：PNG 签名 / IHDR 尺寸 / 字节数 / sha256 自洽，文件真的
   落在证据目录；
2. **会话注入**：靶侧访问日志能看到预置 Cookie——截的是「登录后」页面，而不是
   一个匿名 302 登录页；
3. **route 防线**：页面里引用的**跨源**图片被 ``route.abort()``（计入
   ``blocked_requests``）；靶侧从未收到该跨源请求；
4. **scope 兜底**：scope 外 URL 在**一次导航都没发生**的前提下被拒（靶侧请求数
   不变）——截图能力不得成为绕过 scope 的新口子。

## 产物

``evidence/demo_screenshot/<时间戳>/``：``shot.png`` + ``server.log.json`` +
``summary.json``（gitignored）。``--tmp`` 走临时目录、跑完即弃。

用法：
    .venv/bin/python scripts/demo_screenshot.py
    .venv/bin/python scripts/demo_screenshot.py --tmp
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.verify.screenshot import (
    PNG_SIGNATURE,
    ScreenshotCapturer,
    png_size,
)

REPO = Path(__file__).resolve().parent.parent
COOKIE_NAME = "demo_session"
COOKIE_VALUE = "s3cr3t-demo-cookie"

#: 页面里故意引用一个**跨源**资源：route 防线必须 abort 它。
CROSS_ORIGIN = "http://192.0.2.10:9/beacon.png"

PAGE = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>ProofHound screenshot fixture</title></head>
<body>
  <h1>证据截图靶</h1>
  <p id="marker">this page is captured by ProofHound</p>
  <img src="{CROSS_ORIGIN}" alt="cross-origin beacon">
</body></html>
""".encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    """记录每次请求的 path 与 Cookie（会话注入的可观测证据）。"""

    hits: list[dict] = []

    def do_GET(self):  # noqa: N802 - stdlib 接口
        type(self).hits.append(
            {"path": self.path, "cookie": self.headers.get("Cookie", "")}
        )
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):  # 静默：请求记录走 hits
        pass


def _serve() -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _check(name: str, ok: bool, detail: str, checks: list[dict]) -> bool:
    checks.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}：{detail}")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tmp",
        action="store_true",
        help="产物落临时目录、跑完即弃（缺省落 evidence/demo_screenshot/<时间戳>/）",
    )
    args = parser.parse_args()

    if args.tmp:
        run_dir = Path(tempfile.mkdtemp(prefix="proofhound_screenshot_"))
        cleanup = True
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = REPO / "evidence" / "demo_screenshot" / stamp
        cleanup = False
    run_dir.mkdir(parents=True, exist_ok=True)

    print("[*] 启动本机 HTTP 靶（真实 ThreadingHTTPServer，回环随机端口）")
    server, port = _serve()
    base = f"http://127.0.0.1:{port}"
    scope = Scope(networks=["127.0.0.0/8"], ports=[port])
    checks: list[dict] = []
    summary: dict = {
        "base": base,
        "run_dir": str(run_dir),
        "started_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
    }
    ok = True
    capturer = ScreenshotCapturer(
        scope=scope,
        evidence_dir=run_dir,
        session=SessionConfig(cookies={COOKIE_NAME: COOKIE_VALUE}),
    )
    try:
        print("[*] 启动真实 Chromium（playwright）")
        capturer.start()

        # 1) 真截图
        print("[*] 截图：GET /（带预置会话）")
        result = capturer.capture(f"{base}/", name="shot")
        ok &= _check(
            "真浏览器产出 PNG",
            result.ok,
            f"path={result.path} error={result.error}",
            checks,
        )
        if result.path is not None:
            data = result.path.read_bytes()
            ok &= _check(
                "PNG 签名/尺寸自洽",
                data.startswith(PNG_SIGNATURE)
                and png_size(data) == (result.width, result.height),
                f"size={png_size(data)} bytes={len(data)}",
                checks,
            )
            ok &= _check(
                "sha256 与落盘一致",
                result.sha256 == hashlib.sha256(data).hexdigest(),
                result.sha256[:16] + "…",
                checks,
            )
            ok &= _check(
                "截图非空且为 1280×800 视口",
                len(data) > 1000 and (result.width, result.height) == (1280, 800),
                f"{len(data)} B",
                checks,
            )

        # 2) 会话注入
        ok &= _check(
            "靶侧收到预置 Cookie",
            any(COOKIE_NAME in hit["cookie"] for hit in _Handler.hits),
            f"hits={len(_Handler.hits)}",
            checks,
        )

        # 3) route 防线：跨源资源被 abort
        ok &= _check(
            "跨源子请求被 route 拦截",
            result.blocked_requests >= 1,
            f"blocked_requests={result.blocked_requests}",
            checks,
        )

        # 4) scope 兜底：越界 URL 零导航
        before = len(_Handler.hits)
        denied = capturer.capture("http://192.0.2.10:8080/evil", name="shot_evil")
        ok &= _check(
            "scope 外 URL 被拒且零请求",
            denied.error is not None
            and "scope" in denied.error
            and len(_Handler.hits) == before,
            f"error={denied.error} hits={len(_Handler.hits)}",
            checks,
        )
        summary["denied_error"] = denied.error
    finally:
        capturer.close()
        server.shutdown()
        server.server_close()

    summary["checks"] = checks
    summary["ok"] = bool(ok)
    summary["hits"] = _Handler.hits
    (run_dir / "server.log.json").write_text(
        json.dumps(_Handler.hits, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (run_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print(f"[*] 产物：{run_dir}")
    if cleanup:
        import shutil

        shutil.rmtree(run_dir, ignore_errors=True)
    print("[+] 全部断言通过" if ok else "[-] 存在失败断言")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
