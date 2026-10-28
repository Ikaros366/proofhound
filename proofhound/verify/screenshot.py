"""证据截图（M20）：把「已确认漏洞的复现页面」截成 PNG，作为补充证据入包。

定位同 :mod:`proofhound.verify.browser`——first-party 浏览器代码，不走
``tools/manifests`` 外部二进制体系。截图**不是判定手段**：它不参与任何
Confirmed / Rejected 判定，只给报告与人工复核补一份"当时页面长什么样"的
视觉证据。

## 纪律

- **红线 5（授权前置）**：``capture`` 前对目标 URL 做 scope 自检，页面
  ``route`` 再按「同源 ∧ scope」拦截全部子请求——复用
  :func:`proofhound.verify.browser.allow_request`，与 XSS 验证器同一套防线；
- **红线 3（上下文边界）**：图片**不进** Verifier prompt——模型看不到图，
  截图只落证据目录；
- **不阻断判定**：浏览器缺失 / 超时 / 导航失败一律返回 ``error``，由编排层
  记 ``screenshot_skipped``。一条已确认的 Finding **不得**因为截图失败改判
  （fail-open：截图是补充证据，不是判定前提）；
- **失败可见**：出错、超限、非 PNG 各有明确 ``error`` 文案，不静默吞；
- **二进制不适用文本脱敏**：``redact_bytes`` 只能处理文本，PNG 里若含敏感
  信息无法按值替换 ⇒ 截图与已落盘的 DOM / 响应正文同源，证据目录整体按
  敏感数据对待（见 AGENTS.md 已知限制）。

playwright 一律**懒导入**：未装 playwright / Chromium 时其余链路零影响，本模块
抛 :class:`~proofhound.verify.browser.BrowserUnavailableError`，由编排层转
``screenshot_skipped``。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.verify.browser import (
    BrowserUnavailableError,
    allow_request,
    apply_session,
)

#: PNG 文件签名（8 字节）
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

DEFAULT_TIMEOUT_MS = 15_000  # 单次导航超时
DEFAULT_SETTLE_MS = 500  # 加载后驻留（等异步渲染落定）
DEFAULT_VIEWPORT = (1280, 800)

#: ``capture(session=...)`` 的"未传"哨兵：与显式 ``None``（匿名）区分开。
_SESSION_UNSET = object()

#: 单张截图体积上限（8 MiB）：超出即记 error 不落盘——证据目录不该被一张
#: 无限高的整页截图撑爆（``full_page=True`` 时尤其容易）。
MAX_BYTES = 8 * 1024 * 1024


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def png_size(data: bytes) -> tuple[int, int] | None:
    """从 PNG 的 IHDR 读 ``(宽, 高)``；非 PNG / 截断返回 None（纯函数）。

    只读文件头的前 24 字节（签名 8 + 长度 4 + 类型 4 + 宽 4 + 高 4），
    不依赖任何图像库——截图元数据要能进审计，就不能为此再拉一个依赖。
    """
    if len(data) < 24 or not data.startswith(PNG_SIGNATURE):
        return None
    if data[12:16] != b"IHDR":
        return None
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


@dataclass
class ScreenshotResult:
    """一次截图的结论 + 落盘信息（失败时 ``path`` 为 None）。"""

    url: str
    path: Path | None = None
    status: int | None = None
    error: str | None = None
    width: int = 0
    height: int = 0
    bytes: int = 0
    sha256: str = ""
    #: 被 route 防线 abort 的子请求数（scope 兜底的可观测证据）
    blocked_requests: int = 0
    captured_at: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None and self.path is not None


class ScreenshotCapturer:
    """无头 Chromium 截图器：一次 capture 一个干净 context，PNG 落证据目录。

    ``context_factory`` 是测试注入口子（FakeContext / FakePage，零真实浏览器）；
    None 时使用真实 playwright Chromium（懒启动，需先调 :meth:`start`）。
    """

    def __init__(
        self,
        *,
        scope: Scope,
        evidence_dir: str | Path,
        session: SessionConfig | None = None,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        settle_ms: int = DEFAULT_SETTLE_MS,
        viewport: tuple[int, int] = DEFAULT_VIEWPORT,
        full_page: bool = False,
        max_bytes: int = MAX_BYTES,
        context_factory=None,
    ):
        self._scope = scope
        self._evidence_dir = Path(evidence_dir)
        self._session = session
        self._timeout_ms = timeout_ms
        self._settle_ms = settle_ms
        self._viewport = viewport
        self._full_page = full_page
        self._max_bytes = max_bytes
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
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

    def _new_context(self):
        if self._context_factory is not None:
            return self._context_factory()
        if self._browser is None:
            raise BrowserUnavailableError("浏览器未启动（先调用 start()）")
        return self._browser.new_context(
            viewport={"width": self._viewport[0], "height": self._viewport[1]}
        )

    # ---- 单次截图 ----

    def capture(self, url: str, *, name: str, session=_SESSION_UNSET) -> ScreenshotResult:
        """加载 ``url`` 并截图，PNG 写到 ``<evidence_dir>/<name>.png``。

        ``session`` 可按次覆盖（M20-b 覆盖截图用）：传 ``None`` = **匿名**
        （不带任何凭据），传第二身份会话 = 以 reference 视角取证；不传则用
        构造时的主会话。

        失败语义：**任何**异常/超时只置 ``error`` 字段，不抛出（编排层据此
        记 ``screenshot_skipped``，已确认的 Finding 不受影响）。
        """
        if not allow_request(url, url, self._scope):
            return ScreenshotResult(
                url=url, error="导航目标未过 scope/同源自检（fail-closed）"
            )
        try:
            context = self._new_context()
        except BrowserUnavailableError as exc:
            return ScreenshotResult(url=url, error=str(exc))

        png: bytes | None = None
        status: int | None = None
        blocked = [0]
        error: str | None = None

        def on_route(route) -> None:
            """route 拦截（红线 5）：跨 origin / 越 scope 一律 abort 并计数。"""
            if allow_request(route.request.url, url, self._scope):
                route.continue_()
            else:
                blocked[0] += 1
                route.abort()

        try:
            apply_session(
                context,
                self._session if session is _SESSION_UNSET else session,
                url,
            )
            page = context.new_page()
            page.set_viewport_size(
                {"width": self._viewport[0], "height": self._viewport[1]}
            )
            page.route("**/*", on_route)
            response = page.goto(url, timeout=self._timeout_ms)
            status = getattr(response, "status", None)
            page.wait_for_timeout(self._settle_ms)
            raw = page.screenshot(full_page=self._full_page)
            png = bytes(raw) if isinstance(raw, (bytes, bytearray)) else None
        except Exception as exc:  # playwright TimeoutError 按类名归一档
            kind = (
                "导航/驻留超时"
                if type(exc).__name__ == "TimeoutError"
                else "浏览器执行异常"
            )
            error = f"{kind}: {exc}"
        finally:
            try:
                context.close()
            except Exception:
                pass

        if error is not None:
            return ScreenshotResult(
                url=url, status=status, error=error, blocked_requests=blocked[0]
            )
        if not png:
            return ScreenshotResult(
                url=url,
                status=status,
                error="截图未返回字节（页面可能未渲染）",
                blocked_requests=blocked[0],
            )
        if len(png) > self._max_bytes:
            return ScreenshotResult(
                url=url,
                status=status,
                error=(
                    f"截图体积 {len(png)} B 超过上限 {self._max_bytes} B"
                    "（整页截图请显式开启 full_page 并评估体积）"
                ),
                blocked_requests=blocked[0],
            )
        size = png_size(png)
        if size is None:
            return ScreenshotResult(
                url=url,
                status=status,
                error="截图内容不是合法 PNG（缺签名/IHDR）",
                blocked_requests=blocked[0],
            )
        path = self._evidence_dir / f"{name}.png"
        path.write_bytes(png)
        return ScreenshotResult(
            url=url,
            path=path,
            status=status,
            width=size[0],
            height=size[1],
            bytes=len(png),
            sha256=hashlib.sha256(png).hexdigest(),
            blocked_requests=blocked[0],
            captured_at=_utc_now(),
        )


__all__ = [
    "DEFAULT_SETTLE_MS",
    "DEFAULT_TIMEOUT_MS",
    "DEFAULT_VIEWPORT",
    "MAX_BYTES",
    "PNG_SIGNATURE",
    "ScreenshotCapturer",
    "ScreenshotResult",
    "png_size",
]
