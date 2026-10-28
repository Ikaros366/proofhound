#!/usr/bin/env python3
"""M20 实弹验收：证据截图 + **按类型的覆盖截图**（真实 Chromium + 真实 HTTP 靶）。

## 验什么

第一阶段（M20，确认后补证）：
1. 真浏览器真截图：PNG 签名 / IHDR 尺寸 / sha256 自洽；
2. 会话注入：靶侧访问日志能看到预置 Cookie；
3. route 防线：页面里的跨源图片被 abort（``blocked_requests ≥ 1``）；
4. scope 兜底：scope 外 URL 零导航零请求。

第二阶段（M20-b，覆盖截图）：
5. **六类漏洞的固定镜头全部产出**：``coverage.COVERAGE_SHOTS`` 里每类每条镜头
   都真截到 PNG（无会话/有会话/双身份都覆盖）；
6. **匿名镜头不带凭据**：unauth-exposure 的 ``anonymous`` 镜头靶侧看不到 Cookie；
7. **第二身份镜头用 reference 会话**：idor 的 ``reference`` 镜头靶侧看到的是
   reference 的 Cookie，而不是主会话顶替；
8. 审计逐张记 ``coverage_shot_captured``。

## 产物

``evidence/demo_screenshot/<时间戳>/``：``shot.png`` + ``cover_*.png`` +
``server.log.json`` + ``summary.json``（gitignored）。``--tmp`` 走临时目录。

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
from types import SimpleNamespace

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings import Finding, FindingState, FindingStore
from proofhound.skills.registry import SkillRegistry
from proofhound.verify import coverage
from proofhound.verify.screenshot import (
    PNG_SIGNATURE,
    ScreenshotCapturer,
    png_size,
)

REPO = Path(__file__).resolve().parent.parent
COOKIE_NAME = "demo_session"
COOKIE_VALUE = "s3cr3t-demo-cookie"
REF_COOKIE_NAME = "demo_ref"
REF_COOKIE_VALUE = "reference-cookie-value"

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
    """任何 GET 都回同一页；记录 path 与 Cookie（会话选择的证据）。"""

    hits: list[dict] = []

    def do_GET(self):  # noqa: N802 - stdlib 接口
        type(self).hits.append(
            {"path": self.path, "cookie": self.headers.get("Cookie", "")}
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *args):  # 静默：请求记录走 hits
        pass


class _NoLLM:
    """覆盖截图链路不调 LLM；被调到即失败。"""

    def complete(self, messages):
        raise AssertionError("覆盖截图链路不得调用 LLM")


def _serve() -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _check(name: str, ok: bool, detail: str, checks: list[dict]) -> bool:
    checks.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}：{detail}")
    return ok


def _new_finding(vuln_type: str, asset: str, index: int) -> Finding:
    stamp = "2026-10-28T00:00:00.000+00:00"
    return Finding(
        id=f"F-2026-9{index:03d}",
        state=FindingState.HYPOTHESIS,
        vuln_type=vuln_type,
        severity="medium",
        asset=asset,
        param="q",
        evidence_kinds=["crawl-endpoint"],
        dedup_key=f"sha256:{vuln_type}",
        created_at=stamp,
        updated_at=stamp,
    )


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
    reference = SessionConfig(cookies={REF_COOKIE_NAME: REF_COOKIE_VALUE})
    session = SessionConfig(cookies={COOKIE_NAME: COOKIE_VALUE}, reference=reference)
    coverage_scope = Scope(networks=["127.0.0.0/8"], ports=[port], session=session)
    checks: list[dict] = []
    summary: dict = {
        "base": base,
        "run_dir": str(run_dir),
        "started_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
    }
    ok = True
    produced: list[str] = []
    capturer = ScreenshotCapturer(
        scope=scope,
        evidence_dir=run_dir,
        session=session,
    )
    try:
        print("[*] 启动真实 Chromium（playwright）")
        capturer.start()

        # ---------- 第一阶段：确认后补证 ----------
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

        ok &= _check(
            "靶侧收到预置 Cookie",
            any(COOKIE_NAME in hit["cookie"] for hit in _Handler.hits),
            f"hits={len(_Handler.hits)}",
            checks,
        )
        ok &= _check(
            "跨源子请求被 route 拦截",
            result.blocked_requests >= 1,
            f"blocked_requests={result.blocked_requests}",
            checks,
        )

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

        # ---------- 第二阶段：按类型的覆盖截图 ----------
        print("[*] 覆盖截图：六类漏洞的固定镜头")
        audit = AuditLog(run_dir / "audit.jsonl")
        store = FindingStore(run_dir / "findings.jsonl")
        orch = Orchestrator(
            SkillRegistry(REPO / "skills").discover(),
            runner=SimpleNamespace(scope=coverage_scope),
            llm=_NoLLM(),
            audit=audit,
            evidence_dir=run_dir,
        )
        orch.screenshots = True
        orch.screenshot_factory = lambda: capturer

        produced: list[str] = []
        for index, vuln_type in enumerate(sorted(coverage.COVERAGE_SHOTS), start=1):
            finding = _new_finding(vuln_type, f"{base}/app?q=1", index)
            finding.audit = audit
            store.append(finding)
            orch._capture_coverage(finding, store)
            plan = coverage.plan_for(vuln_type) or ()
            shots = [
                run_dir / f"cover_{finding.id}_{shot.label}.png"
                for shot in plan
            ]
            ok &= _check(
                f"{vuln_type} 固定镜头齐备",
                all(path.is_file() and path.read_bytes().startswith(PNG_SIGNATURE) for path in shots),
                f"{len(shots)} 张：{[p.name for p in shots]}",
                checks,
            )
            produced.extend(str(path) for path in shots)

        ok &= _check(
            "覆盖截图总张数 = 镜头表总数",
            len(produced) == sum(len(v) for v in coverage.COVERAGE_SHOTS.values()),
            f"{len(produced)} 张",
            checks,
        )
        captured = [e for e in audit.read_all() if e["event"] == "coverage_shot_captured"]
        ok &= _check(
            "审计逐张记录 coverage_shot_captured",
            len(captured) == len(produced),
            f"{len(captured)} 条",
            checks,
        )

        anonymous = [hit for hit in _Handler.hits if not hit["cookie"]]
        ok &= _check(
            "匿名镜头不带凭据",
            bool(anonymous),
            f"无 Cookie 请求 {len(anonymous)} 次",
            checks,
        )
        reference_hits = [
            hit for hit in _Handler.hits if REF_COOKIE_NAME in hit["cookie"]
        ]
        ok &= _check(
            "reference 镜头使用第二身份会话",
            bool(reference_hits),
            f"reference Cookie 请求 {len(reference_hits)} 次",
            checks,
        )
    finally:
        capturer.close()
        server.shutdown()
        server.server_close()

    summary["checks"] = checks
    summary["ok"] = bool(ok)
    summary["hits"] = _Handler.hits
    summary["coverage_shots"] = [Path(p).name for p in produced]
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
