"""无头 Chromium 行为验证器（M8b，§5.4.2 XSS 行落地）：canary 执行探针。

本模块是 **first-party 验证器代码**（定位同 ``verify/cvss.py``），**不走**
tools/manifests 外部二进制注册体系；浏览器是"验证器"不是"爬虫"——发现侧
仍靠 katana + 解析器，这里只负责把候选 URL + 固定 payload 集喂给真实
Chromium 内核，判定 payload 是否**执行**。

红线落点：

- 红线 1：URL 构造（:func:`payload_url`）与 payload 集（``PAYLOAD_TEMPLATES``，
  ≤6 条、三类载体）全部是代码常量/确定性函数，LLM 不参与任何浏览器参数与
  payload 构造；LLM 只出现在编排层收尾的 Verifier 终审。
- 红线 2：XSS 的 Confirmed 只能来自 **canary 执行事件**（payload 内嵌 token
  在页面上下文置位标记、或触发对话框钩子）——"响应里反射了输入"不是证据。
- 红线 3：每次 probe 的原始证据（canary 事件 JSON / 执行后 DOM 快照 /
  console 记录 / 请求响应链）100% 落盘 evidence 目录，落盘前经
  ``redact_bytes`` 字节级脱敏（对齐 M3b 纪律；请求链**不记请求头**，
  从源头杜绝 Cookie 落证据）。
- 红线 5：加载任何 URL 前编排层先做 ``check_scope``；本模块再做双保险——
  导航目标自检 + ``page.route`` 拦截全部子请求，**跨 origin 或越 scope
  一律 abort** 并记入请求链。

playwright 一律**懒导入**：未装 playwright 或未装 Chromium 二进制
（``playwright install chromium``）时其余链路不受影响，本模块抛
:class:`BrowserUnavailableError`，由编排层转 blocked（fail-closed）。
"""

from __future__ import annotations

import ipaddress
import json
import secrets as _secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from proofhound.compliance.scope import Scope, Target
from proofhound.compliance.session import SessionConfig, redact_bytes

#: canary token 前缀（每次 probe 尝试生成唯一 token：``phxss_<12hex>``）
TOKEN_PREFIX = "phxss_"

#: 固定 payload 模板集（代码常量，LLM 永不接触）：三类载体 × 两种信道。
#: marker 信道——payload 直接置位 ``window[token]``；dialog 信道——payload
#: 调用 alert()，由探针钩子捕获。``{token}`` 由编排层以 fresh token 替换。
PAYLOAD_TEMPLATES: tuple[str, ...] = (
    '<script>window["{token}"]=1</script>',
    '<script>alert("{token}")</script>',
    '<img src=x onerror="window[\'{token}\']=1">',
    '<img src=x onerror="alert(\'{token}\')">',
    '<svg onload="window[\'{token}\']=1">',
    '<svg onload="alert(\'{token}\')">',
)

#: add_init_script 注入的探针（先于页面脚本执行）：hook 三类对话框，
#: 事件推入 ``window.__phxss_events``；marker 信道由 payload 置位、
#: 加载后经 evaluate 读取（双信道：脚本置标 + 对话框钩子）。
_PROBE_JS = """\
(() => {
  window.__phxss_events = [];
  const rec = (t, a) => {
    try { window.__phxss_events.push({type: t, args: Array.from(a).map(String), ts: Date.now()}); } catch (e) {}
  };
  window.alert = function(){ rec("alert", arguments); };
  window.confirm = function(){ rec("confirm", arguments); return true; };
  window.prompt = function(){ rec("prompt", arguments); return null; };
})();
"""

#: 证据有界：console / 请求链各保留的最多条数（超出丢弃，防失控页面撑爆证据）
_CONSOLE_CAP = 200
_REQUESTS_CAP = 200

DEFAULT_TIMEOUT_MS = 15_000  # 单 payload 导航超时（可配）
DEFAULT_SETTLE_MS = 500  # 加载后驻留（等 img onerror 等异步执行）


class BrowserUnavailableError(RuntimeError):
    """playwright 或 Chromium 二进制不可用（编排层转 blocked，fail-closed）。"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_token() -> str:
    """生成唯一 canary token：``phxss_<12hex>``（每次 probe 尝试一个新 token）。"""
    return f"{TOKEN_PREFIX}{_secrets.token_hex(6)}"


def payload_url(asset: str, param: str, payload: str) -> str:
    """把 asset query 中 ``param`` 的值替换为 payload（确定性，LLM 不碰）。

    参数键大小写不敏感、只替换首个命中；**param 不在 query 中 → ValueError**
    （fail-closed：宁可 blocked 也不凭空构造）。
    """
    parts = urlparse(asset)
    target = param.strip().lower()
    pairs: list[tuple[str, str]] = []
    hit = False
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if not hit and key.strip().lower() == target:
            pairs.append((key, payload))
            hit = True
        else:
            pairs.append((key, value))
    if not hit:
        raise ValueError(f"参数 {param} 不在 URL query 中（fail-closed）: {asset}")
    return urlunparse(
        (parts.scheme, parts.netloc, parts.path, parts.params,
         urlencode(pairs), parts.fragment)
    )


def _effective_port(parsed) -> int | None:
    if parsed.port is not None:
        return parsed.port
    return {"http": 80, "https": 443}.get((parsed.scheme or "").lower())


def same_origin(url_a: str, url_b: str) -> bool:
    """同源判定：scheme/host/有效端口归一化（http:80/https:443 默认端口抹平）。"""
    pa, pb = urlparse(url_a), urlparse(url_b)
    return (
        (pa.scheme or "").lower(),
        (pa.hostname or "").lower(),
        _effective_port(pa),
    ) == (
        (pb.scheme or "").lower(),
        (pb.hostname or "").lower(),
        _effective_port(pb),
    )


def allow_request(request_url: str, page_url: str, scope: Scope) -> bool:
    """请求放行判定（route abort 防线）：同源 ∧ scope 通过；其余一律 abort。"""
    if not same_origin(request_url, page_url):
        return False
    parsed = urlparse(request_url)
    host = parsed.hostname
    if not host:
        return False
    try:
        port = parsed.port
    except ValueError:
        return False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    return scope.check_target(Target(host=host, port=port, is_ip=is_ip)) is None


def canary_events(
    raw_events: list | None,
    marker_hit: bool,
    token: str,
    *,
    url: str = "",
    payload: str = "",
) -> list[dict]:
    """从探针原始事件 + marker 信道过滤出**与本 token 相关**的执行事件。

    判定铁律：对话框事件的参数文本须含本 token；marker 命中合成
    ``{"type": "marker"}`` 事件。他 token（其他尝试/页面自身）的事件一律不计。
    """
    matched: list[dict] = []
    for event in raw_events or []:
        if not isinstance(event, dict):
            continue
        args = " ".join(str(a) for a in event.get("args", []))
        if token in args:
            matched.append(
                {
                    "type": str(event.get("type") or "unknown"),
                    "token": token,
                    "detail": args,
                    "url": url,
                    "payload": payload,
                    "ts": event.get("ts"),
                }
            )
    if marker_hit:
        matched.append(
            {
                "type": "marker",
                "token": token,
                "detail": f"window[{token}] 被置位",
                "url": url,
                "payload": payload,
                "ts": None,
            }
        )
    return matched


@dataclass
class BrowserProbeResult:
    """单 payload probe 结论 + 证据文件路径（供 evidence_refs 引用）。"""

    url: str
    payload: str
    token: str
    events: list[dict] = field(default_factory=list)  # token 匹配的执行事件
    canary: bool = False  # True = payload 在页面上下文执行（铁证）
    error: str | None = None  # 非 None = 本次尝试未完成（超时/异常，fail-closed）
    canary_path: Path | None = None
    dom_path: Path | None = None
    console_path: Path | None = None
    requests_path: Path | None = None


class BrowserVerifier:
    """无头 Chromium 验证器：逐 payload probe + 证据落盘（每次 probe 一个干净 context）。

    ``context_factory`` 是测试注入口子（FakeContext/FakePage，零真实浏览器）；
    None 时使用真实 playwright Chromium（懒导入 + 懒启动）。
    """

    def __init__(
        self,
        *,
        scope: Scope,
        evidence_dir: str | Path,
        session: SessionConfig | None = None,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        settle_ms: int = DEFAULT_SETTLE_MS,
        context_factory=None,
    ):
        self._scope = scope
        self._evidence_dir = Path(evidence_dir)
        self._session = session
        self._timeout_ms = timeout_ms
        self._settle_ms = settle_ms
        self._context_factory = context_factory
        self._playwright = None
        self._browser = None

    # ---- 生命周期 ----

    def start(self) -> None:
        """懒启动真实 Chromium；测试注入模式（context_factory）为无操作。"""
        if self._context_factory is not None or self._browser is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise BrowserUnavailableError(
                "playwright 未安装（pip install playwright）"
            ) from exc
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=True)
        except Exception as exc:
            self.close()
            raise BrowserUnavailableError(
                f"Chromium 不可用（需 playwright install chromium）: {exc}"
            ) from exc

    def close(self) -> None:
        if self._browser is not None:
            self._browser.close()
            self._browser = None
        if self._playwright is not None:
            self._playwright.stop()
            self._playwright = None

    def _new_context(self):
        if self._context_factory is not None:
            return self._context_factory()
        if self._browser is None:
            raise BrowserUnavailableError("浏览器未启动（先调用 start()）")
        return self._browser.new_context()

    # ---- 单 payload probe ----

    def probe(
        self, *, finding_id: str, seq: int, url: str, payload: str, token: str
    ) -> BrowserProbeResult:
        """加载 url（payload 已内嵌）并判定 canary 执行；证据 100% 落盘脱敏。

        失败语义：任何异常/超时只置 ``error`` 字段不抛出（编排层据此转
        blocked，fail-closed）；已捕获的局部证据照常落盘。
        """
        base = {"url": url, "payload": payload, "token": token}
        if not allow_request(url, url, self._scope):
            return BrowserProbeResult(
                **base, error="导航目标未过 scope/origin 自检（fail-closed）"
            )
        try:
            context = self._new_context()
        except BrowserUnavailableError as exc:
            return BrowserProbeResult(**base, error=str(exc))

        console: list[dict] = []
        requests: list[dict] = []
        raw_events: list[dict] = []
        marker_hit = False
        dom = ""
        error: str | None = None
        try:
            self._inject_session(context, url)
            page = context.new_page()
            page.route("**/*", lambda route: self._on_route(route, url, requests))
            page.add_init_script(_PROBE_JS)
            page.on("console", lambda msg: self._on_console(msg, console))
            page.on("response", lambda resp: self._on_response(resp, requests))
            page.goto(url, timeout=self._timeout_ms)
            page.wait_for_timeout(self._settle_ms)
            marker = page.evaluate(
                "(k) => (window[k] === undefined || window[k] === null)"
                " ? null : String(window[k])",
                token,
            )
            marker_hit = marker is not None
            raw = page.evaluate("() => window.__phxss_events || []")
            if isinstance(raw, list):
                raw_events = raw
            dom = page.content()
        except Exception as exc:  # playwright TimeoutError 按类名归一档
            kind = "导航/驻留超时" if type(exc).__name__ == "TimeoutError" else "浏览器执行异常"
            error = f"{kind}: {exc}"
        finally:
            try:
                context.close()
            except Exception:
                pass

        events = canary_events(raw_events, marker_hit, token, url=url, payload=payload)
        paths = self._write_evidence(
            finding_id,
            seq,
            canary_doc={
                "finding_id": finding_id,
                "seq": seq,
                "url": url,
                "payload": payload,
                "token": token,
                "canary": bool(events) and error is None,
                "marker_hit": marker_hit,
                "events": raw_events,
                "matched_events": events,
                "error": error,
                "captured_at": _utc_now(),
            },
            dom=dom,
            console=console,
            requests=requests,
        )
        return BrowserProbeResult(
            **base,
            events=events,
            canary=bool(events) and error is None,
            error=error,
            **paths,
        )

    # ---- 内部：会话注入 / 监听器 / 证据落盘 ----

    def _inject_session(self, context, url: str) -> None:
        """把预置会话挂进浏览器 context（Cookie 按 origin 绑定；额外请求头全量）。"""
        if self._session is None:
            return
        if self._session.cookies:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            context.add_cookies(
                [
                    {"name": k, "value": v, "url": origin}
                    for k, v in self._session.cookies.items()
                ]
            )
        if self._session.headers:
            context.set_extra_http_headers(dict(self._session.headers))

    def _on_route(self, route, page_url: str, requests: list[dict]) -> None:
        """route 拦截（红线 5）：跨 origin / 越 scope 一律 abort 并记链。"""
        request = route.request
        allowed = allow_request(request.url, page_url, self._scope)
        if len(requests) < _REQUESTS_CAP:
            requests.append(
                {
                    "method": request.method,
                    "url": request.url,
                    "resource_type": getattr(request, "resource_type", ""),
                    "status": None,
                    "aborted": not allowed,
                }
            )
        if allowed:
            route.continue_()
        else:
            route.abort()

    @staticmethod
    def _on_console(msg, console: list[dict]) -> None:
        if len(console) < _CONSOLE_CAP:
            console.append({"type": str(msg.type), "text": str(msg.text)})

    @staticmethod
    def _on_response(response, requests: list[dict]) -> None:
        for entry in reversed(requests):
            if (
                entry["url"] == response.url
                and entry["status"] is None
                and not entry["aborted"]
            ):
                entry["status"] = response.status
                break

    def _write_evidence(
        self,
        finding_id: str,
        seq: int,
        *,
        canary_doc: dict,
        dom: str,
        console: list[dict],
        requests: list[dict],
    ) -> dict:
        """四份证据落盘（落盘前字节级脱敏；请求链本就不含请求头）。"""
        secrets = self._session.secret_values() if self._session else []
        stem = f"xss_{finding_id}_{seq:02d}"
        payloads = {
            "canary_path": (
                f"{stem}_canary.json",
                json.dumps(canary_doc, ensure_ascii=False, indent=2) + "\n",
            ),
            "dom_path": (f"{stem}_dom.html", dom),
            "console_path": (
                f"{stem}_console.json",
                json.dumps(console, ensure_ascii=False, indent=2) + "\n",
            ),
            "requests_path": (
                f"{stem}_requests.json",
                json.dumps(requests, ensure_ascii=False, indent=2) + "\n",
            ),
        }
        paths: dict[str, Path] = {}
        for key, (name, text) in payloads.items():
            path = self._evidence_dir / name
            path.write_bytes(redact_bytes(text.encode("utf-8"), secrets))
            paths[key] = path
        return paths
