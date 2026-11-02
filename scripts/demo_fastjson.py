"""M26-a 实弹：fastjson 系不安全反序列化的七个靶 + 12 条断言（本机，零外网）。

```bash
.venv/bin/python scripts/demo_fastjson.py            # 全部断言
.venv/bin/python scripts/demo_fastjson.py --out /tmp/demo_fastjson
```

## 形态仿真声明（必须读，且会写进报告）

**靶侧的"fastjson 解析器"由本脚本自己实现**：base64 解码 → 找 ``@type`` → 按 gadget
做 DNS 登记或 TCP 连接。它**不是**真的 fastjson，与 M23 的罐头堆栈、M25 的仿真 XML
解析器同一披露纪律（AGENTS.md 限制 72/74）。

具体到两处：

1. **DNS 通道**：真解析器会由系统 resolver 发出 DNS 查询；这里由本脚本把 qname
   ``POST /register`` 给 :class:`~proofhound.verify.observe.LocalStubDnsServer`
   （模仿 DNSLog 服务"记录到了这次查询"）。**tool 侧**轮询 provider 的 API 是真的 HTTP；
   **判定代码不依赖**靶怎么登记。
2. **TCP 通道**：真 JNDI 会先匿名 bind、拿到响应后才发带 base DN 的 SearchRequest；
   MySQL 更是服务端先说话。这里让靶连上观察点后**主动发一段带 token 的 bind 字节**，
   于是同时演示了"token 归因"与"端口归因"两条路径（后者在
   ``tests/test_fastjsonprobe.py`` 用**不发言**的靶单独钉住）。

判定代码只看三样东西：观察点的记录、响应字节、状态码——**不依赖靶的实现细节**。

## 七个靶（交接单 §7）

| 靶 | 行为 | 期望 |
|---|---|---|
| ``/login/dns`` | 处理 @type，``Inet4Address`` 触发 DNS 查询登记 | **confirmed（dns）** |
| ``/login/ldap`` | 处理 @type，``JdbcRowSetImpl`` 真连观察点 | **confirmed（tcp）** |
| ``/login/safe`` | 处理 @type，明确返回 ``autoType is not support`` | **rejected** |
| ``/login/swallow`` | 处理 @type，异常被吞，200 空响应 | **blocked** |
| ``/login/echo`` | 把解码后的 JSON 原样回显，不解析 | **blocked**（回显陷阱） |
| ``/login/prefetch`` | 处理 @type，但前置代理解析 body 里任何主机名 | **blocked**（对照命中） |
| ``/login/plain`` | 任何 body 都 200（不认 JSON） | **blocked** |

## 12 条断言

1. 2 confirmed（dns + tcp）/ 1 rejected / 4 blocked，且通道字段归位；
2. 阴性对照有效：``gadget-control``（同形态、无 @type）⇒ 该请求零动作
   （prefetch 靶除外——它的对照命中正是它判 blocked 的原因）；
3. 回显陷阱被驳回：``/login/echo`` 的响应里出现域名与 ``@type`` 字样，但**不得** confirmed；
4. token 全等：stub 里混入"同前缀但不相同"的记录 ⇒ 不得算命中；
5. A 层被覆盖：请求里含 ``java.lang.Class`` 两步链与 ``L…;`` 变体；
6. base64 三变体：标准 / urlsafe / 去 padding 都能构造出可解码的 body；
7. 不投递：TCP 观察点的回包字节是 0（写死的常量），不含 class/javaCodebase；
8. 不发 DoS：所有请求 JSON 里没有 ``$ref``、没有 >32KB、没有递归嵌套；
9. 证据：目录里 grep 不到会话 Cookie；``response_*.txt`` 0600；token 只以 sha8 出现；
10. 连跑两次 ``summary.json`` 逐字节一致；
11. 越界 URL（scope 外 host/port）⇒ 零请求 + ``fastjson_scope_rejected``；
12. 请求数：每入口 ≤12，命中即停（confirmed 靶在命中后不再发同族 payload）。
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from threading import Thread
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # 允许直接 ``python scripts/demo_fastjson.py``
    sys.path.insert(0, str(REPO_ROOT))

from proofhound.compliance.scope import Scope  # noqa: E402
from proofhound.fastjsonprobe import (  # noqa: E402
    FastjsonProbeError,
    ProbeConfig,
    ProbeReport,
    run_fastjsonprobe,
)
from proofhound.verify import fastjson as fj  # noqa: E402
from proofhound.verify.observe import LocalStubDnsServer  # noqa: E402

#: 演示用的会话 Cookie（断言"证据里 grep 不到它"）。
DEMO_COOKIE = "demo-cookie-6b1d9c4e2f8a7d30"

#: 七个靶（顺序 = 报告顺序）。
TARGETS = ("dns", "ldap", "safe", "swallow", "echo", "prefetch", "plain")

#: 期望（kind → (verdict, channel)）。
EXPECTED = {
    "dns": ("confirmed", "dns"),
    "ldap": ("confirmed", "tcp-ldap"),
    "safe": ("rejected", None),
    "swallow": ("blocked", None),
    "echo": ("blocked", None),
    "prefetch": ("blocked", None),
    "plain": ("blocked", None),
}

#: 明显的"我可被加载"字样：观察点回包里绝不允许出现。
CLASS_LOADING_MARKERS = (b"class", b"javaCodebase", b"javaFactory", b"SerializedLambda")


# =====================================================================
# 靶侧：形态仿真的 fastjson 解析器
# =====================================================================


def decode_request(body: bytes, content_type: str) -> str | None:
    """按入口形态解出 JSON 文本（表单 + base64 三变体 / raw JSON body）。"""
    lowered = (content_type or "").lower()
    if "urlencoded" not in lowered and "json" in lowered:
        return body.decode("utf-8", "replace")
    parsed = urllib.parse.parse_qs(body.decode("ascii", "replace"), keep_blank_values=True)
    values = parsed.get("json") or []
    if not values:
        return None
    value = values[0]
    padding = "=" * (-len(value) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(value + padding).decode("utf-8")
        except Exception:  # noqa: BLE001 - 试下一个变体
            continue
    return None


def iter_at_types(value):
    """递归找所有带 ``@type`` 的对象（真 fastjson 也是递归解析）。"""
    if isinstance(value, dict):
        if "@type" in value:
            yield value
        for item in value.values():
            yield from iter_at_types(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_at_types(item)


def _hostnames_in_text(text: str) -> list[str]:
    """prefetch 靶：把 body 里所有"像主机名"的 token 串抓出来（不认 @type）。"""
    import re

    return re.findall(r"phfj[0-9a-f]{32}\.[A-Za-z0-9.\-]+", text, flags=re.IGNORECASE)


def _ldap_bind(token: str) -> bytes:
    """一段**形态仿真**的 LDAP BindRequest：DN 里带 token。"""
    return b"\x30\x1d\x02\x01\x03\x04\x13cn=" + token.encode() + b",dc=example\x80\x00"


@dataclass
class RecordedRequest:
    """靶侧收到的一次请求（供断言：这次请求有没有真的产生出站动作）。"""

    path: str
    body: bytes
    content_type: str
    decoded: str | None
    status: int
    response: bytes
    actions: list[dict] = field(default_factory=list)


class FastjsonTargetServer:
    """七靶本机服务（形态仿真；见模块 docstring 的披露段）。"""

    def __init__(self, *, stub_url: str | None = None):
        self.stub_url = stub_url
        self.requests: list[RecordedRequest] = []
        #: 测试用：第一次"阳性对照"请求静默（模拟"服务端不认这个编码/形态"）
        self.fail_first_parse_control = False
        self._failed_parse_control = False
        #: 测试用：TCP 动作只连不发（模拟 MySQL"服务端先说话"）
        self.silent_tcp = False
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None

    # ---------------------------------------------------------- 生命周期

    def start(self) -> "FastjsonTargetServer":
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # noqa: D102 - 静默
                return

            def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler 约定
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                content_type = self.headers.get("Content-Type") or ""
                status, response, actions, decoded = owner.handle(
                    self.path, body, content_type
                )
                owner.requests.append(
                    RecordedRequest(
                        path=self.path,
                        body=body,
                        content_type=content_type,
                        decoded=decoded,
                        status=status,
                        response=response,
                        actions=actions,
                    )
                )
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = Thread(target=self._server.serve_forever, name="ph-fj-target", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def __enter__(self) -> "FastjsonTargetServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("靶服务未启动")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def clear(self) -> None:
        """清空已记录请求（demo 的"连跑两次"断言要一个干净的靶）。"""
        self.requests.clear()
        self._failed_parse_control = False

    # ---------------------------------------------------------- 各靶行为

    def handle(
        self, path: str, body: bytes, content_type: str
    ) -> tuple[int, bytes, list[dict], str | None]:
        kind = path.rstrip("/").rsplit("/", 1)[-1]
        text = decode_request(body, content_type)
        if text is None:
            return 200, b"login failed", [], None
        if kind == "plain":
            return 200, b"ok", [], text
        if kind == "echo":
            # 不解析，原样把解码后的 JSON 吐回去（回显陷阱）
            return 200, text.encode("utf-8"), [], text
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return 200, b"login failed", [], text

        if kind == "prefetch":
            # 前置代理：body 里任何主机名都要解析一次（与 @type 无关）
            actions = [
                {"type": "dns-prefetch", "qname": qname}
                for qname in _hostnames_in_text(text)
            ]
            for action in actions:
                self._register_dns(action["qname"])
            return 200, b"welcome", actions, text

        at_types = list(iter_at_types(parsed))
        if not at_types:
            return 200, b"welcome", [], text

        # 测试开关：第一次阳性对照静默一次（模拟"服务端不认这个编码/形态"）
        if (
            self.fail_first_parse_control
            and not self._failed_parse_control
            and any(
                str(item.get("@type", "")).startswith("proofhound") for item in at_types
            )
        ):
            self._failed_parse_control = True
            return 200, b"", [], text

        unknown = [
            item["@type"]
            for item in at_types
            if not isinstance(item.get("@type"), str) or not _known_gadget(item["@type"])
        ]
        if unknown:
            if kind in ("safe", "swallow"):
                if kind == "swallow":
                    return 200, b"", [], text
                return 200, ("autoType is not support. " + unknown[0]).encode("utf-8"), [], text
            # dns / ldap：真 fastjson 会抛 500，错误文本里带类名（阳性对照靠它）
            message = (
                "com.alibaba.fastjson.JSONException: ClassNotFoundException: " + unknown[0]
            ).encode("utf-8")
            return 500, message, [], text

        # `safe` / `swallow` 刻意**不执行** gadget（否则它们就不是"真阴性"了）
        if kind == "safe":
            return 200, b"autoType is not support.", [], text
        if kind == "swallow":
            return 200, b"", [], text

        actions = self._execute(at_types, kind)
        return 200, b"login failed", actions, text

    def _execute(self, at_types: list[dict], kind: str) -> list[dict]:
        """按靶的角色执行 gadget：dns 靶只查 DNS、ldap 靶只连 TCP（各司其职）。"""
        actions: list[dict] = []
        for item in at_types:
            at_type = item.get("@type")
            if at_type == "java.lang.Class":
                continue  # 两步链的第一步只填类缓存，不产生出站动作
            if at_type == "java.net.Inet4Address" and kind == "dns":
                qname = str(item.get("val") or "")
                if qname:
                    self._register_dns(qname)
                    actions.append({"type": "dns", "qname": qname})
            elif at_type == "com.sun.rowset.JdbcRowSetImpl" and kind == "ldap":
                url = str(item.get("dataSourceName") or "")
                action = self._tcp_action(url, send_bind=True)
                if action:
                    actions.append(action)
            elif (
                at_type == "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"
                and kind == "ldap"
            ):
                url = str(item.get("url") or "")
                action = self._tcp_action(url, send_bind=False)
                if action:
                    actions.append(action)
        return actions

    def _register_dns(self, qname: str) -> None:
        if not self.stub_url:
            return
        payload = json.dumps({"qname": qname, "ip": "127.0.0.1"}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.stub_url}/register",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=2):
                pass
        except OSError:  # pragma: no cover - stub 不在时静默
            pass

    def _tcp_action(self, url: str, *, send_bind: bool) -> dict | None:
        parsed = _parse_gadget_url(url)
        if parsed is None:
            return None
        host, port, token = parsed
        received = b""
        try:
            with socket.create_connection((host, port), timeout=2) as sock:
                if send_bind and not self.silent_tcp:
                    sock.sendall(_ldap_bind(token))
                sock.settimeout(1.0)
                try:
                    received = sock.recv(64)
                except socket.timeout:
                    received = b""
        except OSError as exc:
            return {"type": "tcp-error", "host": host, "port": port, "error": str(exc)}
        return {
            "type": "tcp",
            "host": host,
            "port": port,
            "token": token,
            "received": received,
        }


def _known_gadget(name: str) -> bool:
    return name in {
        "java.lang.Class",
        "java.net.Inet4Address",
        "Ljava.net.Inet4Address;",
        "com.sun.rowset.JdbcRowSetImpl",
        "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
    }


def _parse_gadget_url(url: str) -> tuple[str, int, str] | None:
    """从 ``ldap://h:p/token`` 或 ``jdbc:mysql://h:p/token`` 取 (host, port, token)。"""
    candidate = url
    if candidate.startswith("jdbc:mysql://"):
        candidate = "mysql://" + candidate[len("jdbc:mysql://") :]
    parsed = urllib.parse.urlparse(candidate)
    if not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        return None
    return parsed.hostname, port, parsed.path.lstrip("/")


# =====================================================================
# 运行一次
# =====================================================================


@dataclass
class RunResult:
    kind: str
    report: ProbeReport | None
    out_dir: Path
    requests: list[RecordedRequest]
    stub_records: list[dict]
    scope_path: Path


def write_scope(path: Path, *, port: int, ports: list[int] | None = None) -> Path:
    lines = [
        "networks: [127.0.0.0/8]",
        f"ports: {json.dumps(ports if ports is not None else [port])}",
        "session:",
        "  cookies:",
        f"    phsess: {DEMO_COOKIE}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def run_once(
    kind: str,
    *,
    out_root: Path,
    encoding: str = fj.ENCODING_B64,
    scope_ports: list[int] | None = None,
    url_override: str | None = None,
    shared: tuple[LocalStubDnsServer, FastjsonTargetServer] | None = None,
    dns_wait: float = 3.0,
    tcp_wait: float = 1.0,
) -> RunResult:
    """起一套全新 stub + 靶 + scope，跑一次 CLI（直调 ``run_fastjsonprobe``）。

    ``shared`` 给"连跑两次逐字节一致"用：复用同一个靶与 stub（**URL 里的端口因此相同**），
    每次运行前清空记录。真实 CLI 对同一 URL 跑两次本来就是逐字节一致的，这里只是把
    "同一个 URL"在演示里也造出来。
    """
    out_dir = out_root / kind / encoding
    out_dir.mkdir(parents=True, exist_ok=True)
    if shared is not None:
        stub, target = shared
        stub.clear()
        target.clear()
        return _run_against(
            kind, out_root, out_dir, stub, target, encoding, scope_ports, url_override,
            dns_wait, tcp_wait,
        )
    with LocalStubDnsServer(domain="stub.local") as stub:
        with FastjsonTargetServer(stub_url=stub.url) as target:
            return _run_against(
                kind, out_root, out_dir, stub, target, encoding, scope_ports,
                url_override, dns_wait, tcp_wait,
            )


def _run_against(
    kind: str,
    out_root: Path,
    out_dir: Path,
    stub: LocalStubDnsServer,
    target: FastjsonTargetServer,
    encoding: str,
    scope_ports: list[int] | None,
    url_override: str | None,
    dns_wait: float,
    tcp_wait: float,
) -> RunResult:
    port = int(target.url.rsplit(":", 1)[1])
    scope_path = out_root / f"scope_{kind}_{encoding}.yaml"
    write_scope(scope_path, port=port, ports=scope_ports)
    scope = Scope.from_file(scope_path)
    config = ProbeConfig(
        url=url_override or f"{target.url}/login/{kind}",
        scope=scope,
        out_dir=out_dir,
        encoding=encoding,
        dns_provider="stub",
        dns_api=stub.url,
        dns_wait=dns_wait,
        tcp_wait=tcp_wait,
        timeout=5.0,
    )
    report: ProbeReport | None = None
    try:
        report = run_fastjsonprobe(config)
    except FastjsonProbeError:
        raise
    return RunResult(
        kind=kind,
        report=report,
        out_dir=out_dir,
        requests=list(target.requests),
        stub_records=list(stub.records),
        scope_path=scope_path,
    )


# =====================================================================
# 断言
# =====================================================================


class Check:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bool, str]] = []

    def that(self, label: str, condition: bool, detail: str = "") -> bool:
        self.rows.append((label, bool(condition), detail))
        return bool(condition)

    @property
    def failures(self) -> list[tuple[str, bool, str]]:
        return [row for row in self.rows if not row[1]]


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _all_request_jsons(out_dir: Path) -> list[dict]:
    rows = []
    for path in sorted(out_dir.glob("request_*.json")):
        rows.append(_read_json(path))
    return rows


def _response_texts(out_dir: Path) -> list[bytes]:
    return [path.read_bytes() for path in sorted(out_dir.glob("response_*.txt"))]


def _audit_events(out_dir: Path) -> list[dict]:
    path = out_dir / "audit.jsonl"
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _json_depth(value) -> int:
    if isinstance(value, dict):
        return 1 + max((_json_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_json_depth(item) for item in value), default=0)
    return 1


def run_demo(out_root: Path) -> int:
    out_root.mkdir(parents=True, exist_ok=True)
    check = Check()
    runs: dict[str, RunResult] = {}

    # ---- 七靶各跑一次（默认编码）
    for kind in TARGETS:
        runs[kind] = run_once(kind, out_root=out_root)
        report = runs[kind].report
        check.that(
            f"{kind}: 有结论",
            report is not None and report.judgment.verdict == EXPECTED[kind][0],
            f"得到 {report.judgment.verdict if report else 'None'}，期望 {EXPECTED[kind][0]}",
        )

    # 断言 1：2 confirmed / 1 rejected / 4 blocked，且通道归位
    confirmed = [kind for kind in TARGETS if runs[kind].report.judgment.confirmed]
    rejected = [kind for kind in TARGETS if runs[kind].report.judgment.verdict == "rejected"]
    blocked = [kind for kind in TARGETS if runs[kind].report.judgment.verdict == "blocked"]
    check.that("断言1: 2 confirmed", len(confirmed) == 2, f"confirmed={confirmed}")
    check.that("断言1: 1 rejected", len(rejected) == 1, f"rejected={rejected}")
    check.that("断言1: 4 blocked", len(blocked) == 4, f"blocked={blocked}")
    check.that(
        "断言1: 通道归位（dns）",
        runs["dns"].report.judgment.channels == ("dns",),
        str(runs["dns"].report.judgment.channels),
    )
    check.that(
        "断言1: 通道归位（tcp）",
        runs["ldap"].report.judgment.channels == ("tcp-ldap",),
        str(runs["ldap"].report.judgment.channels),
    )

    # 断言 2：阴性对照有效（prefetch 除外——它的对照命中正是它 blocked 的原因）
    for kind in TARGETS:
        if kind == "prefetch":
            continue
        negative = _control_request(runs[kind].requests)
        check.that(
            f"断言2: {kind} 阴性对照零动作",
            negative is not None and not negative.actions,
            f"actions={negative.actions if negative else 'None'}",
        )
    prefetch_negative = _control_request(runs["prefetch"].requests)
    check.that(
        "断言2: prefetch 的对照**命中**（回调不可归因）",
        prefetch_negative is not None and bool(prefetch_negative.actions),
    )

    # 断言 3：回显陷阱——响应里出现域名与 @type，但绝不得 confirmed
    echo_run = runs["echo"]
    echo_bodies = b"".join(_response_texts(echo_run.out_dir))
    check.that(
        "断言3: echo 响应里确实出现域名与 @type",
        b"stub.local" in echo_bodies and b"@type" in echo_bodies,
    )
    check.that("断言3: echo 未被 confirmed", not echo_run.report.judgment.confirmed)

    # 断言 4：token 全等（同前缀不同 token 不算命中）
    check.that("断言4: token 全等（同前缀不命中）", _lookalike_check())

    # 断言 5：A 层被覆盖（safe 靶不发拒绝就停？它会把 8 个 gadget 全发一遍）
    every_request = []
    for kind in TARGETS:
        every_request.extend(_all_request_jsons(runs[kind].out_dir))
    joined = json.dumps(every_request, ensure_ascii=False)
    check.that("断言5: 含 java.lang.Class 两步链", "java.lang.Class" in joined)
    check.that("断言5: 含 L…; 变体", "Ljava.net.Inet4Address;" in joined)

    # 断言 6：base64 三变体都能构造出可解码 body（三靶各跑一次）
    for encoding in (fj.ENCODING_B64, fj.ENCODING_B64URL, fj.ENCODING_B64NOPAD):
        variant = run_once("dns", out_root=out_root / "encodings", encoding=encoding)
        decoded_ok = any(
            item.decoded and "@type" in item.decoded for item in variant.requests
        )
        check.that(
            f"断言6: {encoding} 能打中且靶解码成功",
            variant.report is not None
            and variant.report.judgment.confirmed
            and variant.report.summary["target"]["encoding"] == encoding
            and decoded_ok,
            f"verdict={variant.report.judgment.verdict if variant.report else None}",
        )

    # 断言 7：不投递——观察点回包是 0 字节，不含任何"可被加载"字样
    for kind in ("ldap",):
        tcp_actions = [
            action
            for request in runs[kind].requests
            for action in request.actions
            if action.get("type") == "tcp"
        ]
        check.that(f"断言7: {kind} 有 TCP 动作", bool(tcp_actions))
        check.that(
            f"断言7: {kind} 观察点回包 0 字节",
            all(action.get("received", b"") == b"" for action in tcp_actions),
        )
        check.that(
            f"断言7: {kind} 回包不含类加载字样",
            all(
                not any(marker in action.get("received", b"") for marker in CLASS_LOADING_MARKERS)
                for action in tcp_actions
            ),
        )

    # 断言 8：不发 DoS
    dos_ok = True
    dos_detail = ""
    for kind in TARGETS:
        for row in _all_request_jsons(runs[kind].out_dir):
            text = row["json"]
            if "$ref" in text:
                dos_ok = False
                dos_detail = f"{kind}: 含 $ref"
            if len(text.encode("utf-8")) > fj.MAX_BODY_BYTES:
                dos_ok = False
                dos_detail = f"{kind}: body 超大"
            if _json_depth(json.loads(text)) > fj.MAX_JSON_DEPTH:
                dos_ok = False
                dos_detail = f"{kind}: 深嵌套"
    check.that("断言8: 无 $ref / 超大 / 深嵌套", dos_ok, dos_detail)

    # 断言 9：证据卫生（Cookie 不落盘、0600、token 只以 sha8 出现）
    import re as _re

    token_pattern = _re.compile(rb"phfj_?[0-9a-f]{32}", _re.IGNORECASE)
    cookie_leak = False
    token_leak = False
    private = True
    for kind in TARGETS:
        directory = runs[kind].out_dir
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            data = path.read_bytes()
            if DEMO_COOKIE.encode() in data:
                cookie_leak = True
            if token_pattern.search(data):
                token_leak = True
            if path.name.startswith(("response_", "probe_", "request_")):
                if path.stat().st_mode & 0o777 != 0o600:
                    private = False
    check.that("断言9: 证据里 grep 不到会话 Cookie", not cookie_leak)
    check.that("断言9: 证据里没有 token 原文（只有 sha8）", not token_leak)
    check.that("断言9: probe/request/response 文件都是 0600", private)

    # 断言 10：连跑两次 summary.json 逐字节一致（同一个靶 URL、干净记录）
    with LocalStubDnsServer(domain="stub.local") as stub:
        with FastjsonTargetServer(stub_url=stub.url) as target:
            first = run_once(
                "dns", out_root=out_root / "repeat1", shared=(stub, target)
            )
            second = run_once(
                "dns", out_root=out_root / "repeat2", shared=(stub, target)
            )
    check.that(
        "断言10: 两次 summary.json 逐字节一致",
        (first.out_dir / "summary.json").read_bytes()
        == (second.out_dir / "summary.json").read_bytes(),
    )

    # 断言 11：越界 URL ⇒ 零请求 + fastjson_scope_rejected
    with LocalStubDnsServer(domain="stub.local") as stub:
        with FastjsonTargetServer(stub_url=stub.url) as target:
            port = int(target.url.rsplit(":", 1)[1])
            scope_path = out_root / "scope_outside.yaml"
            write_scope(scope_path, port=port, ports=[port + 1])  # 故意不包含目标端口
            outside_dir = out_root / "outside"
            outside_dir.mkdir(parents=True, exist_ok=True)
            config = ProbeConfig(
                url=f"{target.url}/login/dns",
                scope=Scope.from_file(scope_path),
                out_dir=outside_dir,
                dns_provider="stub",
                dns_api=stub.url,
                dns_wait=1.0,
                tcp_wait=0.2,
            )
            raised = False
            try:
                run_fastjsonprobe(config)
            except FastjsonProbeError:
                raised = True
            events = [event["event"] for event in _audit_events(outside_dir)]
            check.that(
                "断言11: 越界 ⇒ 结构性失败 + 零请求",
                raised and not target.requests and "fastjson_scope_rejected" in events,
                f"raised={raised} requests={len(target.requests)} events={events}",
            )

    # 断言 12：请求数 ≤12，命中即停
    budgets_ok = True
    detail = ""
    for kind in TARGETS:
        count = len(runs[kind].requests)
        if count > fj.MAX_REQUESTS_PER_ENTRY:
            budgets_ok = False
            detail = f"{kind}: {count} 次"
    check.that("断言12: 每入口 ≤12 次请求", budgets_ok, detail)

    dns_summary = runs["dns"].report.summary
    ldap_summary = runs["ldap"].report.summary
    check.that(
        "断言12: 命中即停（dns 只发了 1 个 gadget）",
        dns_summary["counts"]["gadgets"] == 1,
        f"gadgets={dns_summary['counts']['gadgets']}",
    )
    check.that(
        "断言12: 命中即停（ldap 只发了 2 个 gadget）",
        ldap_summary["counts"]["gadgets"] == 2,
        f"gadgets={ldap_summary['counts']['gadgets']}",
    )
    check.that(
        "断言12: 命中后有复测（可复现性）",
        any(row["role"] == "retest" for row in dns_summary["probes"]),
    )

    # ---- 输出
    print(f"\nM26-a 实弹：{len(check.rows)} 条断言（{out_root}）")
    for label, ok, detail in check.rows:
        mark = "✅" if ok else "❌"
        suffix = f"  [{detail}]" if detail and not ok else ""
        print(f"  {mark} {label}{suffix}")
    failures = check.failures
    print(f"\n结果：{'全绿' if not failures else f'{len(failures)} 条失败'}")
    return 0 if not failures else 1


def _control_request(requests: list[RecordedRequest]) -> RecordedRequest | None:
    """对照请求：**没有** ``@type`` 且带回调地址字面量（DNS 或 LDAP/JDBC URL）的那次。"""
    candidates = [
        item
        for item in requests
        if item.decoded is not None
        and "@type" not in item.decoded
        and any(
            literal in item.decoded
            for literal in ("stub.local", "ldap://", "jdbc:mysql://")
        )
    ]
    return candidates[-1] if candidates else None


def _lookalike_check() -> bool:
    """stub 里混入"同前缀但不相同"的记录时，不得算命中（全等比较）。"""
    from proofhound.verify.observe import LocalStubProvider, new_token

    with LocalStubDnsServer(domain="stub.local") as stub:
        provider = LocalStubProvider(api_base=stub.url)
        token = new_token()
        allocation = provider.allocate(token)
        stub.register(allocation.qname + ".evil.local")  # 把 qname 当**前缀**
        stub.register("phfj" + "0" * 32 + ".stub.local")  # 同前缀、不同 hex
        records = provider.poll(token)
        return bool(records) and all(item.token is None for item in records)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M26-a fastjson 反序列化实弹（本机，零外网）")
    parser.add_argument(
        "--out", default=None, help="证据根目录（缺省 evidence/demo_fastjson/<UTC 时间戳>）"
    )
    args = parser.parse_args(argv)
    from datetime import datetime, timezone

    out_root = (
        Path(args.out)
        if args.out
        else Path("evidence")
        / "demo_fastjson"
        / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    return run_demo(out_root)


if __name__ == "__main__":
    raise SystemExit(main())
