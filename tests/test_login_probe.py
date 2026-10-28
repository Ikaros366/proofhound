"""M21-a 登录重放探测测试：原始请求解析、表单替换、指纹分类、三态判定，
以及编排层用假会话跑通「校准 → OCR → 25 次重放」与 OCR 失败路径（零真实网络）。

真实 OCR 的端到端在 ``scripts/demo_login_replay.py``（实弹，5 种靶形态）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from proofhound.verify import captcha_ocr
from proofhound.verify import login_probe as lp
from proofhound.verify.raw_request import (
    RawRequestError,
    field_names,
    parse_raw_request,
    with_form,
)

RAW = (
    "POST /login HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Cookie: sid=abc\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "\r\n"
    "username=admin&password=guess&captcha=0000&csrf=t1"
)


def _resp(status: int, text: str) -> lp.LoginResponse:
    return lp.LoginResponse(
        status=status, headers={"content-type": "text/html"}, body=text.encode(), url="http://x"
    )


# ---- 原始请求解析 ----


def test_parse_raw_request_relative_target_uses_host_and_scheme():
    request = parse_raw_request(RAW, scheme="http")
    assert request.method == "POST"
    assert request.url == "http://example.com/login"
    assert request.header("cookie") == "sid=abc"
    assert field_names(request) == ["username", "password", "captcha", "csrf"]


def test_parse_raw_request_absolute_target_kept():
    raw = "GET https://example.com/a?b=1 HTTP/1.1\nHost: example.com\n\n"
    assert parse_raw_request(raw).url == "https://example.com/a?b=1"


def test_parse_raw_request_requires_host_for_relative_target():
    with pytest.raises(RawRequestError, match="Host"):
        parse_raw_request("GET /a HTTP/1.1\n\n")


def test_with_form_replaces_only_named_fields():
    request = parse_raw_request(RAW, scheme="http")
    updated = with_form(request, {"username": "root", "captcha": "zz99"})
    assert "username=root" in updated.body
    assert "captcha=zz99" in updated.body
    assert "csrf=t1" in updated.body


def test_with_form_missing_field_raises():
    request = parse_raw_request(RAW, scheme="http")
    with pytest.raises(RawRequestError, match="没有字段"):
        with_form(request, {"not_there": "1"})


def test_with_form_rejects_non_form_content_type():
    raw = RAW.replace(
        "application/x-www-form-urlencoded", "application/json"
    )
    request = parse_raw_request(raw, scheme="http")
    with pytest.raises(RawRequestError, match="urlencoded"):
        with_form(request, {"username": "root"})


# ---- 验证码图片发现 / 分类 ----


def test_find_captcha_image_by_src_hint():
    html = '<img src="/static/logo.png"><img src="/captcha?t=1">'
    assert lp.find_captcha_image(html, "http://example.com/login") == "http://example.com/captcha?t=1"


def test_find_captcha_image_returns_none():
    assert lp.find_captcha_image("<img src='/logo.png'>", "http://x/") is None


def test_classify_exact_fingerprints_and_regex_and_lockout():
    captcha = _resp(200, "验证码错误")
    credential = _resp(200, "用户名或密码错误")

    assert lp.classify(captcha, captcha, credential)[0] == "captcha"
    assert lp.classify(credential, captcha, credential)[0] == "credential"
    assert lp.classify(_resp(429, "slow down"), captcha, credential)[0] == "lockout"
    assert lp.classify(_resp(200, "账号已锁定"), captcha, credential)[0] == "lockout"
    # 文案与参考都不同时，操作员可用显式正则兜底
    other = _resp(200, "口令不正确")
    assert (
        lp.classify(other, captcha, credential, credential_error_regex="口令不正确")[0]
        == "credential"
    )
    assert lp.classify(other, captcha, credential)[0] == "unknown"


# ---- 判定纯函数 ----


def _attempts(labels: list[str]) -> list[lp.Attempt]:
    return [lp.Attempt(i + 1, "replay", "abcd", 200, label) for i, label in enumerate(labels)]


def test_judge_image_confirmed_when_all_credential():
    verdict, reasons = lp.judge_image(_attempts(["credential"] * 25), calibrated=True)
    assert verdict == "confirmed" and "25" in reasons[0]


def test_judge_image_rejected_on_captcha_or_lockout():
    assert lp.judge_image(_attempts(["credential", "captcha"]), calibrated=True)[0] == "rejected"
    assert lp.judge_image(_attempts(["credential", "lockout"]), calibrated=True)[0] == "rejected"


def test_judge_image_blocked_cases():
    assert lp.judge_image(_attempts(["credential"]), calibrated=False)[0] == "blocked"
    assert lp.judge_image(_attempts(["credential", "unknown"]), calibrated=True)[0] == "blocked"


def test_judge_sms_three_states():
    assert lp.judge_sms(_attempts(["success"]), baseline_ok=True)[0] == "confirmed"
    assert lp.judge_sms(_attempts(["credential"] * 4), baseline_ok=True)[0] == "rejected"
    assert lp.judge_sms(_attempts(["credential"]), baseline_ok=False)[0] == "blocked"


# ---- 编排层：假会话跑通全流程 ----


class FakeSession:
    """按 body 里的验证码返回罐头响应（复刻 reuse 靶：码对→凭证错误，码错→验证码错误）。"""

    expected = "abcd"

    def __init__(self, config, cookies=None):
        self.calls: list[tuple[str, str]] = []

    def request(self, method, url, *, headers=None, body=None):
        self.calls.append((method, url))
        if method == "GET" and "captcha" in url:
            return lp.LoginResponse(200, {"content-type": "image/png"}, b"\x89PNG", url)
        if method == "GET":
            return lp.LoginResponse(
                200,
                {"content-type": "text/html"},
                b"<html><img src='/captcha'></html>",
                url,
            )
        body = body or ""
        code = body.split("captcha=", 1)[-1].split("&", 1)[0] if "captcha=" in body else ""
        if code != self.expected:
            return _resp(200, "验证码错误")
        return _resp(200, "用户名或密码错误")


@pytest.fixture
def fake_env(monkeypatch):
    sessions: list[FakeSession] = []

    def factory(config):
        session = FakeSession(config)
        sessions.append(session)
        return session

    monkeypatch.setattr(lp, "_new_session", factory)
    monkeypatch.setattr(captcha_ocr, "available", lambda: True)
    monkeypatch.setattr(captcha_ocr, "solve", lambda image: "abcd")
    return sessions


def test_run_image_probe_confirmed_with_25_replays(fake_env):
    request = parse_raw_request(RAW, scheme="http")
    config = lp.ProbeConfig(
        request=request, user="admin", captcha_field="captcha", attempts=25
    )

    report = lp.run_image_probe(config)

    assert report.verdict == "confirmed"
    assert report.mode == "image" and report.calibrated is True
    replay = [a for a in report.attempts if a.stage == "replay"]
    assert len(replay) == 25 and all(a.label == "credential" for a in replay)


def test_run_image_probe_blocked_when_ocr_never_passes(fake_env, monkeypatch):
    monkeypatch.setattr(captcha_ocr, "solve", lambda image: "wrong")
    request = parse_raw_request(RAW, scheme="http")
    config = lp.ProbeConfig(request=request, user="admin", captcha_field="captcha")

    report = lp.run_image_probe(config)

    assert report.verdict == "blocked"
    assert any("OCR" in reason for reason in report.reasons)
