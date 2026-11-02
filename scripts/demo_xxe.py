#!/usr/bin/env python3
"""M25-a 实弹验收：六个靶 + 十项断言（XXE 手工先验的端到端验收）。

## ⚠️ 形态仿真声明（必读）

靶侧那个"会解析外部实体的 XML 解析器"是**本脚本自己实现的**（正则抽
``<!ENTITY … SYSTEM "…">`` → 读文件 / 发 HTTP 请求 → 回填空），**不是**真的
libxml / .NET / Java 解析器——Python 标准库的 ``xml.etree`` / ``xml.sax``
默认就**不会**去取 ``file://``（这正是本任务必须先做仿真的原因）。故：

- 本脚本证明的是**判据代码 + 传输层 + listener + 证据链**这一侧；
- 靶侧的"漏洞"是**形态仿真**，与 M23 的罐头堆栈同一披露纪律（限制 72）；
- 判据代码**不依赖**靶的实现细节：它只看响应字节、listener 与状态码。

``/soap/file`` 与 ``/soap/fault`` 读的是**真实的** ``/etc/passwd``（靶与工具同机），
"读文件"这一段是真的，"解析器"这一段是仿真的。

## 六个靶（交接单 §7）

=================  ==============================================  ==========
靶                  行为                                            期望
=================  ==============================================  ==========
``/soap/file``      解析外部实体，把 ``file://`` 内容换进响应        confirmed(file)
``/soap/fault``     同上，但内容出现在 ``500 + <faultstring>``       confirmed(file)
``/soap/oob``       解析实体并向我们的 listener 真发请求            confirmed(callback)
``/soap/safe``      只展开内部实体、**不加载**外部实体               rejected
``/soap/echo``      把请求体原样回显（出现 DOCTYPE 与路径字样）      rejected
``/soap/error``     500 + 通用错误页，alive 也不被替换               blocked
=================  ==============================================  ==========

## 十项断言（交接单 §7）

1. 3 confirmed / 2 rejected / 1 blocked，且通道归位；
2. 阴性对照有效：不存在的文件 ⇒ 响应不含 canary 签名；
3. 回显陷阱被驳回：``/soap/echo`` 不得 confirmed；
4. ``callback-control``（同 URL、无 DOCTYPE）⇒ listener 零回调；
5. canary 白名单不可绕过：``/etc/shadow`` 构造即拒 + 审计；``--allow-file`` 才放行；
6. 不发实体膨胀：任何发出过的 body 都过 ``entity_amplification_reasons``；
7. 证据目录 grep 不到会话 Cookie；canary 片段只存在于 0600 文件；
8. 连跑两次 ``summary.json`` 逐字节一致；
9. 越界 URL ⇒ 零请求 + ``xxe_scope_rejected``；
10. 请求数：每端点 ≤4。

用法：

    .venv/bin/python scripts/demo_xxe.py                # 证据落 evidence/demo_xxe/<ts>/
    .venv/bin/python scripts/demo_xxe.py --out /tmp/xxe # 指定输出目录
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import threading
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from proofhound.verify import xxe  # noqa: E402
from proofhound import xxeprobe  # noqa: E402

#: 演示用会话秘密（**只出现在输入 scope 里**，证据里必须 grep 不到）。
DEMO_COOKIE = "demo-session-9f3c2a7b5d1e4f68"
DEMO_AUTH = "Bearer demo-auth-4c1d8e2f6a9b3d70"

#: 仿真解析器读文件/取数的字节上限。
MAX_ENTITY_BYTES = 64 * 1024

#: 回调宽限窗口（oob 靶的回调在响应前就到达，故 1 秒足够；其余靶无回调）。
CALLBACK_WAIT = 1.0

_ENTITY_DECL_RE = re.compile(
    r"<!ENTITY\s+(?P<name>[A-Za-z_][\w.-]*)\s+"
    r'(?:(?P<system>SYSTEM)\s+"(?P<sysid>[^"]*)"|"(?P<value>[^"]*)")\s*>',
    re.IGNORECASE,
)
_DOCTYPE_RE = re.compile(r"<!DOCTYPE\b.*?\]\s*>|<!DOCTYPE\b[^>\[]*>", re.DOTALL)
_ENTITY_REF_RE = re.compile(r"&([A-Za-z_][\w.-]*);")
_CHAR_REF_RE = re.compile(r"&#\d+;|&#x[0-9A-Fa-f]+;|&(?:amp|lt|gt|quot|apos);")


# =====================================================================
# 仿真解析器（形态仿真，不是真 XML 解析器）
# =====================================================================


def unescape_xml(value: str) -> str:
    """展开字符引用与 XML 预定义实体（实体**声明时**展开，与真解析器一致）。"""

    def repl(match: re.Match[str]) -> str:
        token = match.group(0)
        if token == "&amp;":
            return "&"
        if token == "&lt;":
            return "<"
        if token == "&gt;":
            return ">"
        if token == "&quot;":
            return '"'
        if token == "&apos;":
            return "'"
        if token.startswith("&#x"):
            return chr(int(token[3:-1], 16))
        return chr(int(token[2:-1]))

    return _CHAR_REF_RE.sub(repl, value)


def parse_entities(text: str) -> dict[str, tuple[str, str]]:
    """从 DOCTYPE 内部子集里抽实体：``name -> ("system"|"literal", value)``。"""
    table: dict[str, tuple[str, str]] = {}
    for match in _ENTITY_DECL_RE.finditer(text):
        name = match.group("name")
        if match.group("system"):
            table[name] = ("system", match.group("sysid") or "")
        else:
            table[name] = ("literal", unescape_xml(match.group("value") or ""))
    return table


def _read_file_url(url: str) -> str:
    path = url[len("file://") :] if url.lower().startswith("file://") else url
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_ENTITY_BYTES)
    except OSError:
        return ""
    return data.decode("utf-8", "replace")


def _fetch_url(url: str, *, timeout: float = 3.0) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read(MAX_ENTITY_BYTES).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - 仿真靶：取数失败就当空实体
        return ""


#: 外部实体解析模式（每个靶只开一路，使两条通道**各自独立**地被验收）。
EXTERNAL_ON = "on"  # 全解析（未用：会让两条通道同时命中）
EXTERNAL_OFF = "off"  # 只展开内部实体（现代解析器默认）
EXTERNAL_FILE_ONLY = "file-only"  # 只读 file://（模拟出站 HTTP 被墙）
EXTERNAL_HTTP_ONLY = "http-only"  # 只取 http(s)://（模拟文件系统不可达）


def expand_document(text: str, *, mode: str) -> str:
    """按 ``mode`` 展开实体（**形态仿真**：正则抽声明 + 单遍替换，无递归）。"""
    table = parse_entities(text)
    document = _DOCTYPE_RE.sub("", text)

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        entry = table.get(name)
        if entry is None:
            return match.group(0)
        kind, value = entry
        if kind == "literal":
            return value
        lowered = value.lower()
        if lowered.startswith("file://") and mode in (EXTERNAL_ON, EXTERNAL_FILE_ONLY):
            return _read_file_url(value)
        if lowered.startswith(("http://", "https://")) and mode in (
            EXTERNAL_ON,
            EXTERNAL_HTTP_ONLY,
        ):
            return _fetch_url(value)
        return ""

    return _ENTITY_REF_RE.sub(repl, document)


# =====================================================================
# 六个靶（一个本地 HTTP 服务）
# =====================================================================


@dataclass
class RecordedRequest:
    path: str
    body: bytes
    headers: dict[str, str]

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "bytes": len(self.body),
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
        }


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: D102 - 静默（demo 输出自己管）
        return

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler 的约定
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        owner: "XxeTargetServer" = self.server.owner  # type: ignore[attr-defined]
        owner.record(self.path, body, {k.lower(): v for k, v in self.headers.items()})
        status, payload = owner.respond(self.path, body)
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class XxeTargetServer:
    """六个靶的宿主（真 TCP、真并发服务，靶行为是形态仿真）。"""

    def __init__(self, *, host: str = "127.0.0.1"):
        self._httpd = ThreadingHTTPServer((host, 0), _Handler)
        self._httpd.daemon_threads = True
        self._httpd.owner = self  # type: ignore[attr-defined]
        self.host = host
        self.port = self._httpd.server_address[1]
        self.requests: list[RecordedRequest] = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    def url(self, path: str) -> str:
        return self.origin + path

    def record(self, path: str, body: bytes, headers: dict[str, str]) -> None:
        with self._lock:
            self.requests.append(RecordedRequest(path=path, body=body, headers=headers))

    def requests_for(self, path: str) -> list[RecordedRequest]:
        with self._lock:
            return [item for item in self.requests if item.path == path]

    def reset(self) -> None:
        with self._lock:
            self.requests.clear()

    def respond(self, path: str, body: bytes) -> tuple[int, bytes]:
        text = body.decode("utf-8", "replace")
        if path in ("/soap/file", "/soap/fault"):
            expanded = expand_document(text, mode=EXTERNAL_FILE_ONLY)
            if path == "/soap/fault":
                payload = (
                    '<?xml version="1.0"?><soap:Fault>'
                    "<faultcode>soap:Server</faultcode>"
                    f"<faultstring>{expanded}</faultstring></soap:Fault>"
                )
                return 500, payload.encode("utf-8")
            payload = (
                '<?xml version="1.0"?><soap:Envelope><soap:Body>'
                f"{expanded}</soap:Body></soap:Envelope>"
            )
            return 200, payload.encode("utf-8")
        if path == "/soap/oob":
            expanded = expand_document(text, mode=EXTERNAL_HTTP_ONLY)
            payload = (
                '<?xml version="1.0"?><soap:Envelope><soap:Body>'
                f"{expanded}</soap:Body></soap:Envelope>"
            )
            return 200, payload.encode("utf-8")
        if path == "/soap/safe":
            expanded = expand_document(text, mode=EXTERNAL_OFF)
            payload = (
                '<?xml version="1.0"?><soap:Envelope><soap:Body>'
                f"{expanded}</soap:Body></soap:Envelope>"
            )
            return 200, payload.encode("utf-8")
        if path == "/soap/echo":
            return 200, body
        if path == "/soap/error":
            return 500, b"<html><body><h1>Internal Server Error</h1></body></html>"
        return 404, b"<html><body>not found</body></html>"

    def close(self) -> None:
        try:
            self._httpd.shutdown()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._httpd.server_close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self) -> "XxeTargetServer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# =====================================================================
# demo 主体
# =====================================================================


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class DemoResult:
    checks: list[Check] = field(default_factory=list)
    runs: dict[str, dict] = field(default_factory=dict)

    @property
    def failed(self) -> list[Check]:
        return [check for check in self.checks if not check.ok]

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append(Check(name=name, ok=ok, detail=detail))

    def render_lines(self) -> list[str]:
        lines = []
        for check in self.checks:
            mark = "✓" if check.ok else "✗"
            lines.append(f"  {mark} {check.name}" + (f"  [{check.detail}]" if check.detail else ""))
        passed = len(self.checks) - len(self.failed)
        lines.append(f"\n{passed}/{len(self.checks)} 项通过")
        return lines


#: 六个靶的期望（交接单 §7 的表）。
CASES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("/soap/file", "confirmed", ("file",)),
    ("/soap/fault", "confirmed", ("file",)),
    ("/soap/oob", "confirmed", ("callback",)),
    ("/soap/safe", "rejected", ()),
    ("/soap/echo", "rejected", ()),
    ("/soap/error", "blocked", ()),
)

SHADOW_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [
  <!ENTITY alive "PROOFHOUND&#45;ALIVE">
  <!ENTITY x SYSTEM "file:///etc/shadow">
]>
<r><probe>tpl</probe><value>&x;</value><ctrl>&alive;</ctrl></r>
"""


def write_scope(path: Path, *, port: int, ports: list[int] | None = None) -> None:
    """写一份演示用 scope（含预置会话；文件本身 0600）。"""
    allowed = ports if ports is not None else [port]
    text = (
        "networks: [127.0.0.0/8]\n"
        f"ports: {json.dumps(allowed)}\n"
        "session:\n"
        "  cookies:\n"
        f"    phsess: {DEMO_COOKIE}\n"
        "    security: low\n"
        "  headers:\n"
        f"    Authorization: {DEMO_AUTH}\n"
    )
    path.write_text(text, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover
        pass


def run_once(
    *,
    url: str,
    scope_path: Path,
    out_dir: Path,
    extra: list[str] | None = None,
) -> tuple[int, dict]:
    """跑一次 CLI，返回 ``(退出码, summary.json)``。"""
    argv = [
        "--url",
        url,
        "--scope",
        str(scope_path),
        "--out",
        str(out_dir),
        "--callback-host",
        "127.0.0.1",
        "--callback-wait",
        str(CALLBACK_WAIT),
        "--timeout",
        "10",
    ]
    argv.extend(extra or [])
    code = xxeprobe.main(argv)
    summary_path = out_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}
    return code, summary


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _audit_events(run_dir: Path) -> list[dict]:
    path = run_dir / "audit.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _all_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_file()]


def run_demo(out_root: Path, *, keep_scope: bool = True) -> DemoResult:
    """跑完六个靶 + 十项断言，返回结果（**不 sys.exit**，便于单测/复用）。"""
    result = DemoResult()
    inputs = out_root / "inputs"
    runs_root = out_root / "runs"
    inputs.mkdir(parents=True, exist_ok=True)
    runs_root.mkdir(parents=True, exist_ok=True)
    scope_path = inputs / "lab.yaml"
    shadow_path = inputs / "shadow.xml"
    shadow_path.write_text(SHADOW_TEMPLATE, encoding="utf-8")

    with XxeTargetServer() as server:
        write_scope(scope_path, port=server.port)
        amplification_bad: list[tuple[str, tuple[str, ...]]] = []
        cookie_injected: list[bool] = []
        # ---- 每个靶跑两遍（第二遍只为"summary.json 逐字节一致"）----
        for path, expected, channels in CASES:
            label = path.strip("/").replace("/", "-")
            first_dir = runs_root / f"{label}-1"
            server.reset()
            code, summary = run_once(
                url=server.url(path), scope_path=scope_path, out_dir=first_dir
            )
            for item in server.requests_for(path):
                reasons = xxe.entity_amplification_reasons(item.body)
                if reasons:
                    amplification_bad.append((path, reasons))
                cookie_injected.append(DEMO_COOKIE in item.headers.get("cookie", ""))
            result.runs[label] = {
                "code": code,
                "summary": summary,
                "requests": len(server.requests_for(path)),
                "dir": str(first_dir),
                "path": path,
            }
            second_dir = runs_root / f"{label}-2"
            run_once(url=server.url(path), scope_path=scope_path, out_dir=second_dir)
            same = (first_dir / "summary.json").read_bytes() == (
                second_dir / "summary.json"
            ).read_bytes()
            verdict = summary.get("judgment", {}).get("verdict")
            got_channels = tuple(summary.get("judgment", {}).get("channels", []))
            result.check(
                f"[1] {path} → {expected}（实得 {verdict}）",
                verdict == expected and got_channels == channels,
                f"channels={list(got_channels)}",
            )
            result.check(
                f"[8] {path} 连跑两次 summary.json 逐字节一致",
                same,
            )
            # [2] 阴性对照：不存在的文件没有产出签名
            negative = [
                probe
                for probe in summary.get("probes", [])
                if probe.get("probe") == xxe.PROBE_NEGATIVE
            ]
            result.check(
                f"[2] {path} 阴性对照未命中 canary",
                bool(negative) and negative[0].get("canary_hit") is False,
            )
            # [10] 每端点 ≤4 次请求
            count = result.runs[label]["requests"]
            result.check(f"[10] {path} 请求数 ≤4（实得 {count}）", 0 < count <= 4)

        # ---- [3] 回显陷阱：/soap/echo 的响应里**有**路径字样但没被 confirmed ----
        echo = result.runs.get("soap-echo", {})
        echo_dir = Path(echo.get("dir", ""))
        echo_body = (echo_dir / "response_2.txt").read_text(encoding="utf-8", errors="replace")
        result.check(
            "[3] 回显陷阱：请求体路径字样出现在响应里，但未判 confirmed",
            "file:///etc/passwd" in echo_body
            and echo.get("summary", {}).get("judgment", {}).get("verdict") == "rejected",
        )

        # ---- [4] callback-control：oob 靶的对照零回调 ----
        oob = result.runs.get("soap-oob", {})
        oob_dir = Path(oob.get("dir", ""))
        oob_judgment = _read_json(oob_dir / "judgment.json") if oob_dir.is_dir() else {}
        facts = oob.get("summary", {}).get("facts", {})
        result.check(
            "[4] callback-control 零回调（同 URL、无 DOCTYPE）",
            facts.get("callback_control_hit") is False
            and not oob_judgment.get("callbacks", {}).get("control_hits"),
            f"probe_hits={len(oob_judgment.get('callbacks', {}).get('probe_hits', []))}",
        )

        # ---- [5] canary 白名单：构造即拒 / 默认拒绝 / --allow-file 放行 ----
        builder_refused = False
        try:
            xxe.file_body("file:///etc/shadow")
        except xxe.XxeFileTargetError:
            builder_refused = True
        result.check("[5a] 自动通道拒绝构造 /etc/shadow 实体", builder_refused)

        server.reset()
        refuse_dir = runs_root / "shadow-refused"
        code, _summary = run_once(
            url=server.url("/soap/file"),
            scope_path=scope_path,
            out_dir=refuse_dir,
            extra=["--body-template", str(shadow_path)],
        )
        events = [event["event"] for event in _audit_events(refuse_dir)]
        result.check(
            "[5b] 模板读 /etc/shadow 默认拒绝 + 审计 xxe_file_rejected",
            code == 2 and "xxe_file_rejected" in events and len(server.requests) == 0,
            f"exit={code}",
        )

        server.reset()
        allow_dir = runs_root / "shadow-allowed"
        code, _summary = run_once(
            url=server.url("/soap/file"),
            scope_path=scope_path,
            out_dir=allow_dir,
            extra=[
                "--body-template",
                str(shadow_path),
                "--allow-file",
                "/etc/shadow",
            ],
        )
        events = [event["event"] for event in _audit_events(allow_dir)]
        for item in server.requests:
            reasons = xxe.entity_amplification_reasons(item.body)
            if reasons:
                amplification_bad.append(("shadow-allowed", reasons))
        result.check(
            "[5c] 显式 --allow-file 才放行，并记 xxe_file_override",
            "xxe_file_override" in events and len(server.requests) > 0,
            f"exit={code}",
        )

        # ---- [6] 不发实体膨胀：扫过所有发出过的 body（含模板通道）----
        result.check(
            "[6] 发出过的 body 全部通过实体膨胀检查",
            not amplification_bad,
            f"offenders={amplification_bad[:2]}",
        )

        # ---- [9] 越界 URL：零请求 + xxe_scope_rejected ----
        narrow_scope = inputs / "narrow.yaml"
        write_scope(narrow_scope, port=server.port, ports=[1])
        server.reset()
        oos_dir = runs_root / "out-of-scope"
        code, _summary = run_once(
            url=server.url("/soap/file"),
            scope_path=narrow_scope,
            out_dir=oos_dir,
        )
        events = [event["event"] for event in _audit_events(oos_dir)]
        result.check(
            "[9] 越界 URL ⇒ 零请求 + xxe_scope_rejected + 退出码 2",
            code == 2 and "xxe_scope_rejected" in events and len(server.requests) == 0,
            f"exit={code} requests={len(server.requests)}",
        )

    # ---- [7] 证据卫生：Cookie 不可见、canary 只在 0600 文件里 ----
    files = _all_files(runs_root)
    cookie_leaks = [
        str(path.relative_to(out_root))
        for path in files
        if DEMO_COOKIE.encode() in path.read_bytes() or DEMO_AUTH.encode() in path.read_bytes()
    ]
    result.check("[7a] 证据目录 grep 不到会话 Cookie/Authorization", not cookie_leaks, str(cookie_leaks[:2]))
    canary_files = [path for path in files if b"root:x:0:0" in path.read_bytes()]
    loose = [
        str(path.relative_to(out_root))
        for path in canary_files
        if stat.S_IMODE(path.stat().st_mode) != 0o600
    ]
    result.check(
        "[7b] canary 片段只存在于 0600 文件",
        bool(canary_files) and not loose,
        f"files={len(canary_files)} loose={loose[:2]}",
    )
    response_modes = [
        stat.S_IMODE(path.stat().st_mode)
        for path in files
        if path.name.startswith("response_")
    ]
    result.check(
        "[7c] 全部 response_*.txt 为 0600",
        bool(response_modes) and all(mode == 0o600 for mode in response_modes),
    )
    # 会话注入确实生效（靶侧收到过 Cookie）——否则"证据里没有 Cookie"是废话
    result.check(
        "[7d] 会话头确实注入到请求里（靶侧可见、证据里不可见）",
        bool(cookie_injected) and all(cookie_injected),
        f"requests={len(cookie_injected)}",
    )
    if not keep_scope:
        scope_path.unlink(missing_ok=True)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M25-a XXE 六靶实弹验收")
    parser.add_argument(
        "--out",
        default=None,
        help="输出目录（缺省 evidence/demo_xxe/<UTC 时间戳>）",
    )
    args = parser.parse_args(argv)
    out_root = (
        Path(args.out)
        if args.out
        else Path("evidence") / "demo_xxe" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    out_root.mkdir(parents=True, exist_ok=True)
    print(f"[+] M25-a 实弹验收：六个靶，形态仿真（见脚本 docstring）")
    print(f"    证据目录：{out_root}")
    result = run_demo(out_root)
    for line in result.render_lines():
        print(line)
    if result.failed:
        print("\n[!] 存在失败项", file=sys.stderr)
        return 1
    print("\n[+] 全部通过：3 confirmed / 2 rejected / 1 blocked，十项断言齐备")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
