#!/usr/bin/env python3
"""M21-a 实弹验收：登录重放暴破探测打**真实**本机靶（真 OCR + 真 HTTP）。

五种靶形态，各自对应一种结论：

| 靶 | 行为 | 期望 |
|---|---|---|
| `/reuse` | 图形验证码**校验但可重复使用** | **confirmed**（25 次全是凭证错误） |
| `/oneshot` | 图形验证码**一次性**（用后即失效） | **rejected**（第 1 次重放就报验证码错） |
| `/uniform` | 两种失败返回**完全一样**的页面 | **blocked**（判不了，不猜） |
| `/sms-fixed` | 短信码固定接受 `0000` | **confirmed**（固定码直接登录） |
| `/sms-random` | 短信码只认服务端随机值 | **rejected**（固定码都不成立） |

产物落 ``evidence/demo_login_replay/<时间戳>/``：五份 ``probe.json`` + ``server.log.json`` +
``summary.json``。``--tmp`` 跑完即弃。

用法：
    .venv/bin/python scripts/demo_login_replay.py
    .venv/bin/python scripts/demo_login_replay.py --tmp
"""

from __future__ import annotations

import argparse
import io
import json
import random
import string
import tempfile
import threading
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from proofhound.compliance.scope import Scope
from proofhound.verify.login_probe import ProbeConfig, run_image_probe, run_sms_probe
from proofhound.verify.raw_request import parse_raw_request

REPO = Path(__file__).resolve().parent.parent
FONT_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)

#: sid -> 验证码明文（一次性靶在 POST 时 pop）
CAPTCHAS: dict[str, str] = {}

FORM_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head>
<body>
<h1>Demo Login</h1>
<form method="post" action="{action}">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  {extra}
  <input type="hidden" name="csrf" value="static-csrf-token">
  <button type="submit">Login</button>
</form>
<img src="{captcha_src}" alt="captcha">
</body></html>
"""


def _font(size: int = 34):
    for path in FONT_PATHS:
        if Path(path).is_file():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _render_captcha(code: str) -> bytes:
    image = Image.new("RGB", (120, 44), "white")
    draw = ImageDraw.Draw(image)
    for _ in range(5):
        draw.line(
            (
                random.randint(0, 120),
                random.randint(0, 44),
                random.randint(0, 120),
                random.randint(0, 44),
            ),
            fill=(random.randint(140, 200),) * 3,
        )
    font = _font()
    for index, char in enumerate(code):
        draw.text((8 + index * 26, random.randint(2, 7)), char, font=font, fill=(20, 20, 20))
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


def _new_code() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=4))


class Handler(BaseHTTPRequestHandler):
    hits: list[dict] = []

    # ---- 路由 ----
    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        mode = parsed.path.strip("/").split("/")[0]
        sid = self._sid()
        if parsed.path.endswith("/captcha"):
            code = _new_code()
            CAPTCHAS[sid] = code
            self._send(200, _render_captcha(code), "image/png", set_cookie=f"sid={sid}")
            return
        if mode == "sms-fixed" or mode == "sms-random":
            extra = (
                '<input name="phone" placeholder="phone">'
                '<input name="sms_code" placeholder="sms code">'
            )
            html = FORM_HTML.format(action=f"/{mode}/login", extra=extra, captcha_src="")
        else:
            html = FORM_HTML.format(
                action=f"/{mode}/login", extra="", captcha_src=f"/{mode}/captcha"
            )
        self._send(200, html.encode("utf-8"), "text/html", set_cookie=f"sid={sid}")

    def do_POST(self):  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        mode = parsed.path.strip("/").split("/")[0]
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        sid = self._sid()
        self.hits.append({"mode": mode, "sid": sid, "form": {k: v[0] for k, v in form.items()}})

        if mode == "sms-fixed":
            if form.get("sms_code", [""])[0] == "0000":
                self._send(302, b"", "text/html", extra_headers={"Location": "/home", "Set-Cookie": "logged=1"})
            else:
                self._send(200, "短信验证码错误".encode("utf-8"), "text/html")
            return
        if mode == "sms-random":
            self._send(200, "短信验证码错误".encode("utf-8"), "text/html")
            return

        expected = CAPTCHAS.get(sid, "")
        submitted = form.get("captcha", [""])[0]
        if mode == "uniform":
            self._send(200, "登录失败，请重试".encode("utf-8"), "text/html")
            return
        if mode == "oneshot":
            CAPTCHAS.pop(sid, None)  # 一次性：不管对错，用后即失效
        if submitted != expected:
            self._send(200, "验证码错误".encode("utf-8"), "text/html")
            return
        self._send(200, "用户名或密码错误".encode("utf-8"), "text/html")

    # ---- 工具 ----
    def _sid(self) -> str:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "sid" and value:
                return value
        return "".join(random.choices(string.hexdigits.lower(), k=12))

    def _send(self, status, body, content_type, *, set_cookie=None, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *args):  # 静默
        pass


def _raw_request(port: int, path: str, *, sms: bool = False) -> str:
    body = (
        "username=admin&password=guess&phone=13800000000&sms_code=000000&csrf=static-csrf-token"
        if sms
        else "username=admin&password=guess&captcha=0000&csrf=static-csrf-token"
    )
    return (
        f"POST {path} HTTP/1.1\n"
        f"Host: 127.0.0.1:{port}\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        f"Content-Length: {len(body)}\n"
        "\n"
        f"{body}"
    )


def _run_case(port: int, scope: Scope, *, path: str, sms: bool = False, **kwargs):
    request = parse_raw_request(_raw_request(port, path, sms=sms), scheme="http")
    config = ProbeConfig(
        request=request,
        user="admin",
        captcha_field=None if sms else "captcha",
        sms=sms,
        phone_field="phone" if sms else None,
        sms_code_field="sms_code" if sms else None,
        attempts=25,
        **kwargs,
    )
    return run_sms_probe(config) if sms else run_image_probe(config)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tmp", action="store_true", help="产物落临时目录、跑完即弃")
    args = parser.parse_args()

    if args.tmp:
        run_dir = Path(tempfile.mkdtemp(prefix="proofhound_login_"))
        cleanup = True
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = REPO / "evidence" / "demo_login_replay" / stamp
        cleanup = False
    run_dir.mkdir(parents=True, exist_ok=True)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    scope = Scope(networks=["127.0.0.0/8"], ports=[port])
    print(f"[*] 靶: http://127.0.0.1:{port}")

    cases = [
        ("reuse", False, "/reuse/login", "confirmed"),
        ("oneshot", False, "/oneshot/login", "rejected"),
        ("uniform", False, "/uniform/login", "blocked"),
        ("sms-fixed", True, "/sms-fixed/login", "confirmed"),
        ("sms-random", True, "/sms-random/login", "rejected"),
    ]
    checks: list[dict] = []
    ok = True
    try:
        for name, sms, path, expected in cases:
            print(f"[*] 场景 {name}: 期望 {expected}")
            report = _run_case(port, scope, path=path, sms=sms)
            (run_dir / f"{name}.json").write_text(
                json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            passed = report.verdict == expected
            ok &= passed
            checks.append(
                {
                    "case": name,
                    "expected": expected,
                    "actual": report.verdict,
                    "ok": passed,
                    "attempts": len(report.attempts),
                    "reasons": report.reasons,
                }
            )
            print(
                f"    -> {report.verdict}（{len(report.attempts)} 次尝试）"
                f" {'PASS' if passed else 'FAIL'}"
            )
    finally:
        server.shutdown()
        server.server_close()

    summary = {
        "port": port,
        "checks": checks,
        "ok": bool(ok),
        "hits": len(Handler.hits),
    }
    (run_dir / "server.log.json").write_text(
        json.dumps(Handler.hits, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (run_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[*] 产物: {run_dir}")
    if cleanup:
        import shutil

        shutil.rmtree(run_dir, ignore_errors=True)
    print("[+] 全部断言通过" if ok else "[-] 存在失败断言")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
