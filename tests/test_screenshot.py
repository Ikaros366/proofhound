"""M20 证据截图测试：png_size 纯函数、capture 全序（scope 自检 / 会话注入 /
route 拦截 / 落盘 / 元数据）、失败路径（越界 / 超时 / 非 PNG / 超限），以及
编排层「确认后补截图 + 进 evidence_refs + 审计、失败不阻断确认」。

零真实浏览器：截图器走 ``context_factory`` 注入的 FakePage / FakeContext；
编排层走 ``screenshot_factory`` 注入的 FakeCapturer。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core import orchestrator as orch_mod
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings import Finding, FindingState, FindingStore
from proofhound.skills.registry import SkillRegistry
from proofhound.verify.screenshot import (
    PNG_SIGNATURE,
    ScreenshotCapturer,
    ScreenshotResult,
    png_size,
)

BASE = "http://127.0.0.1:8080"


class FakeLLM:
    """编排器只要求 llm 可被 ensure_router 包装；本文件不触发任何 LLM 调用。"""

    def complete(self, messages):
        raise AssertionError("截图链路不得调用 LLM")


SCOPE = Scope(networks=["127.0.0.0/8"], ports=[8080])
PHPSESSID = "df6a4b9c0e1f2a3b4c5d6e7f890abcde"
SESSION = SessionConfig(cookies={"PHPSESSID": PHPSESSID}, headers={"X-Test": "1"})
CVSS_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"


# ---- 罐头 ----


def make_png(width: int = 1280, height: int = 800, payload: bytes = b"\x00" * 16) -> bytes:
    """构造一个**只有文件头合法**的 PNG（够 png_size 解析，不是可渲染图片）。"""
    return (
        PNG_SIGNATURE
        + (13).to_bytes(4, "big")
        + b"IHDR"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + payload
    )


class FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status


class FakeRequest:
    def __init__(self, url: str):
        self.url = url


class FakeRoute:
    def __init__(self, url: str):
        self.request = FakeRequest(url)
        self.action: str | None = None

    def continue_(self) -> None:
        self.action = "continue"

    def abort(self) -> None:
        self.action = "abort"


class FakePage:
    def __init__(
        self,
        *,
        png: bytes | Exception = b"",
        routes=(),
        goto_error: Exception | None = None,
        status: int = 200,
    ):
        self.png = png
        self.routes = list(routes)
        self.goto_error = goto_error
        self.status = status
        self.viewport: dict | None = None
        self.goto_calls: list[tuple] = []
        self.settle_ms: int | None = None
        self.screenshot_calls: list[bool] = []

    def set_viewport_size(self, size) -> None:
        self.viewport = size

    def route(self, pattern: str, handler) -> None:
        assert pattern == "**/*"
        for route in self.routes:
            handler(route)

    def goto(self, url: str, timeout=None):
        self.goto_calls.append((url, timeout))
        if self.goto_error is not None:
            raise self.goto_error
        return FakeResponse(self.status)

    def wait_for_timeout(self, ms: int) -> None:
        self.settle_ms = ms

    def screenshot(self, full_page: bool = False) -> bytes:
        self.screenshot_calls.append(full_page)
        if isinstance(self.png, Exception):
            raise self.png
        return self.png


class FakeContext:
    def __init__(self, page: FakePage):
        self._page = page
        self.cookies = None
        self.headers = None
        self.closed = False

    def add_cookies(self, cookies) -> None:
        self.cookies = cookies

    def set_extra_http_headers(self, headers) -> None:
        self.headers = headers

    def new_page(self) -> FakePage:
        return self._page

    def close(self) -> None:
        self.closed = True


def _capturer(tmp_path: Path, page: FakePage, **kwargs):
    context = FakeContext(page)
    capturer = ScreenshotCapturer(
        scope=kwargs.pop("scope", SCOPE),
        evidence_dir=tmp_path,
        session=kwargs.pop("session", SESSION),
        context_factory=lambda: context,
        **kwargs,
    )
    return capturer, context


# ---- png_size 纯函数 ----


def test_png_size_parses_ihdr():
    assert png_size(make_png(640, 480)) == (640, 480)


@pytest.mark.parametrize(
    "data",
    [b"", b"not a png at all", PNG_SIGNATURE, make_png()[:20], b"\x89PNG\r\n\x1a\n" + b"\x00" * 30],
)
def test_png_size_rejects_malformed(data):
    assert png_size(data) is None


# ---- capture：全序 / 失败路径 ----


def test_capture_writes_png_and_reports_metadata(tmp_path):
    url = f"{BASE}/vulnerabilities/xss_r/?name=%3Cscript%3E"
    cross = FakeRoute("http://127.0.0.2:9/beacon.png")
    same = FakeRoute(f"{BASE}/static/app.js")
    page = FakePage(png=make_png(1280, 800), routes=[cross, same])
    capturer, context = _capturer(tmp_path, page)

    result = capturer.capture(url, name="shot_F-2026-0001")

    assert result.ok and result.error is None
    assert result.path == tmp_path / "shot_F-2026-0001.png"
    data = result.path.read_bytes()
    assert data.startswith(PNG_SIGNATURE)
    assert result.bytes == len(data)
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert (result.width, result.height) == (1280, 800)
    assert result.status == 200 and result.blocked_requests == 1
    assert result.captured_at  # 时间戳进审计
    # 导航参数：目标 URL + 默认超时；驻留默认 500ms；默认非整页
    assert page.goto_calls == [(url, 15_000)]
    assert page.settle_ms == 500
    assert page.screenshot_calls == [False]
    assert page.viewport == {"width": 1280, "height": 800}
    # route 防线：跨 origin abort、同源 continue
    assert cross.action == "abort" and same.action == "continue"
    # 会话注入：Cookie 按 origin 绑定 + 额外请求头
    assert context.cookies[0]["name"] == "PHPSESSID"
    assert context.cookies[0]["url"] == BASE
    assert context.headers == {"X-Test": "1"}
    assert context.closed


def test_capture_rejects_out_of_scope_url(tmp_path):
    page = FakePage(png=make_png())
    capturer, context = _capturer(tmp_path, page)

    result = capturer.capture("http://192.0.2.10:8080/evil", name="shot_x")

    assert result.error is not None and "scope" in result.error
    assert result.path is None
    assert page.goto_calls == []  # 一次导航都没发生
    assert not context.closed  # 连 context 都没建


def test_capture_reports_timeout_without_writing_file(tmp_path):
    page = FakePage(goto_error=TimeoutError("Timeout 15000ms exceeded"))
    capturer, _context = _capturer(tmp_path, page)

    result = capturer.capture(f"{BASE}/slow", name="shot_slow")

    assert result.error is not None and result.error.startswith("导航/驻留超时")
    assert result.path is None
    assert list(tmp_path.glob("*.png")) == []


def test_capture_rejects_non_png_body(tmp_path):
    capturer, _context = _capturer(tmp_path, FakePage(png=b"<html>not an image</html>"))

    result = capturer.capture(f"{BASE}/x", name="shot_x")

    assert result.error is not None and "不是合法 PNG" in result.error
    assert result.path is None


def test_capture_enforces_size_cap(tmp_path):
    capturer, _context = _capturer(
        tmp_path, FakePage(png=make_png()), max_bytes=32
    )

    result = capturer.capture(f"{BASE}/x", name="shot_x")

    assert result.error is not None and "超过上限" in result.error
    assert result.path is None


def test_capture_reports_screenshot_exception(tmp_path):
    capturer, _context = _capturer(
        tmp_path, FakePage(png=RuntimeError("Target closed"))
    )

    result = capturer.capture(f"{BASE}/x", name="shot_x")

    assert result.error is not None and result.error.startswith("浏览器执行异常")
    assert result.path is None


# ---- 编排层：确认后补截图 + 引用入包；失败不阻断 ----


class FakeVerifier:
    def __init__(self, *args, **kwargs):
        pass

    def review(self, finding, *, evidence_index, diff_summary, extra_summary=None):
        return SimpleNamespace(
            verdict="confirm",
            reason="截图证据复核通过",
            cvss_vector=CVSS_XSS,
        )


class FakeCapturer:
    """编排层注入的截图器替身：可切成功/失败，记录调用。"""

    def __init__(self, out_dir: Path, *, error: str | None = None):
        self._out = Path(out_dir)
        self.error = error
        self.calls: list[tuple[str, str]] = []
        self.closed = False

    def capture(self, url: str, *, name: str) -> ScreenshotResult:
        self.calls.append((url, name))
        if self.error is not None:
            return ScreenshotResult(url=url, error=self.error)
        path = self._out / f"{name}.png"
        data = make_png()
        path.write_bytes(data)
        return ScreenshotResult(
            url=url,
            path=path,
            status=200,
            width=1280,
            height=800,
            bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            captured_at="2026-10-28T00:00:00.000+00:00",
        )

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def orch_env(tmp_path, make_skill_dir):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    audit = AuditLog(evidence_dir / "audit.jsonl")
    orch = Orchestrator(
        SkillRegistry(make_skill_dir()).discover(),
        runner=SimpleNamespace(scope=SCOPE),
        llm=FakeLLM(),
        audit=audit,
        evidence_dir=evidence_dir,
    )
    return orch, audit, evidence_dir


def _confirmed_setup(monkeypatch, evidence_dir, orch):
    monkeypatch.setattr(
        orch_mod, "gate_check", lambda finding: SimpleNamespace(passed=True, missing=[])
    )
    monkeypatch.setattr(orch_mod, "Verifier", FakeVerifier)
    store = FindingStore(evidence_dir / "findings.jsonl")
    finding = Finding(
        id="F-2026-0701",
        state=FindingState.REPRODUCED,
        vuln_type="xss",
        severity="medium",
        asset=f"{BASE}/vulnerabilities/xss_r/?name=1",
        param="name",
        evidence_kinds=["crawl-endpoint", "behavioral"],
        verification={
            "method": "browser-confirmed",
            "evidence_refs": ["evidence/x.log#L1"],
        },
        dedup_key="sha256:deadbeef",
        created_at="2026-10-28T00:00:00.000+00:00",
        updated_at="2026-10-28T00:00:00.000+00:00",
        audit=orch.audit,
    )
    store.append(finding)
    skill = SimpleNamespace(name="verify-xss", manifest=SimpleNamespace(version="1.0.0"))
    return store, finding, skill


def test_confirmed_finding_gets_screenshot_evidence_ref(
    monkeypatch, orch_env, tmp_path
):
    orch, audit, evidence_dir = orch_env
    capturer = FakeCapturer(evidence_dir)
    orch.screenshots = True
    orch.screenshot_factory = lambda: capturer
    store, finding, skill = _confirmed_setup(monkeypatch, evidence_dir, orch)

    outcome = orch._gate_and_review(
        finding, skill, store, screenshot_url=f"{BASE}/x?name=payload"
    )

    assert outcome == "confirmed"
    assert capturer.calls == [(f"{BASE}/x?name=payload", "shot_F-2026-0701")]
    assert str(evidence_dir / "shot_F-2026-0701.png") in finding.verification.evidence_refs
    events = [e["event"] for e in audit.read_all()]
    assert "screenshot_captured" in events
    captured = [e for e in audit.read_all() if e["event"] == "screenshot_captured"][0]
    assert captured["finding_id"] == "F-2026-0701"
    assert captured["file"] == "shot_F-2026-0701.png"
    assert captured["url"] == f"{BASE}/x?name=payload"
    assert captured["width"] == 1280 and captured["height"] == 800
    # 落盘快照里也带着这条引用（重新加载后仍在）
    reloaded = [f for f in FindingStore(evidence_dir / "findings.jsonl").load_all()]
    assert any(
        str(evidence_dir / "shot_F-2026-0701.png") in f.verification.evidence_refs
        for f in reloaded
        if f.id == "F-2026-0701"
    )
    # 证据包 manifest 里真的多了一条 PNG（assemble_evidence_pack 在收尾跑）
    manifest = json.loads(
        (evidence_dir / "findings" / "F-2026-0701" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    names = [item["file"] for item in manifest["items"]]
    assert any(name and name.endswith(".png") for name in names)


def test_screenshot_failure_does_not_block_confirmation(
    monkeypatch, orch_env
):
    orch, audit, evidence_dir = orch_env
    orch.screenshots = True
    orch.screenshot_factory = lambda: FakeCapturer(evidence_dir, error="Target closed")
    store, finding, skill = _confirmed_setup(monkeypatch, evidence_dir, orch)

    outcome = orch._gate_and_review(finding, skill, store)

    assert outcome == "confirmed"  # 截图失败不改判
    assert finding.state is FindingState.CONFIRMED
    assert finding.verification.evidence_refs == ["evidence/x.log#L1"]
    skipped = [e for e in audit.read_all() if e["event"] == "screenshot_skipped"]
    assert skipped and "Target closed" in skipped[0]["reason"]


def test_gate_review_defaults_to_finding_asset(monkeypatch, orch_env):
    """未显式给 screenshot_url 时截 finding.asset（非 XSS 链路的缺省语义）。"""
    orch, _audit, evidence_dir = orch_env
    capturer = FakeCapturer(evidence_dir)
    orch.screenshots = True
    orch.screenshot_factory = lambda: capturer
    store, finding, skill = _confirmed_setup(monkeypatch, evidence_dir, orch)

    assert orch._gate_and_review(finding, skill, store) == "confirmed"
    assert capturer.calls == [(finding.asset, "shot_F-2026-0701")]


def test_close_screenshotter_releases_and_resets(orch_env):
    orch, _audit, _evidence_dir = orch_env
    fake = FakeCapturer(Path("/tmp"))
    orch._screenshotter = fake

    orch._close_screenshotter()

    assert fake.closed is True
    assert orch._screenshotter is None


def test_screenshots_disabled_by_default(orch_env):
    orch, audit, _evidence_dir = orch_env
    def boom():
        raise AssertionError("未启用时不得建截图器")

    orch.screenshot_factory = boom
    assert orch._capture_screenshot(
        SimpleNamespace(id="F-1", asset=f"{BASE}/x"), f"{BASE}/x"
    ) is None
    assert [e["event"] for e in audit.read_all()] == []
