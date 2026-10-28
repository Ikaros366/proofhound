"""登录暴破可行性探测（M21-a）：原始请求重放 + 验证码复用 + 三态判定。

## 判定要证明的是什么

**「这条登录请求能不能被简单重放（Burp 连点 25 次）」**——不是"密码能不能猜中"。
故判据是**失败态的分类**，不是登录成功：

- 先建立两个校准指纹：**验证码错误**（故意发错码）与**凭证错误**（正确码 + 错密码）；
- 若两者不可区分 ⇒ ``blocked``（宁可判不了，也不猜）；
- 复用同一张验证码连打 25 次：中途出现验证码错误 ⇒ 验证码一次性生效 ⇒ ``rejected``；
- 25 次全是凭证错误、且无 429/锁定 ⇒ ``confirmed``（可重放暴破）。

## OCR 的失败必须与"验证码生效"分开

OCR 认错会表现成"验证码错误"，若直接采信就会把 OCR 失败误判成"有防护"。
故第一次 OCR 结果先单独试一次：若被判成验证码错误，**换一张重试**（≤3 次）；
三次都失败 ⇒ ``blocked``（明确写"可能是 OCR 失败"），绝不 ``rejected``。

## 边界（如实记录）

- 只支持 ``application/x-www-form-urlencoded`` 登录表单；
- CSRF token 一次性轮换的站点：本工具固定隐藏字段重放，会被判 ``blocked``；
- 25 次是**上限可配**的启发式：只证明"25 次内无锁定"，不证明无限可试；
- 短信分支只试固定测试码（0000/000000/1234/8888），结论是"是否存在固定码"，
  **不是**"短信验证码不可暴破"。
"""

from __future__ import annotations

import difflib
import hashlib
import re
import urllib.error
import urllib.request
from urllib.parse import urljoin
from dataclasses import dataclass, field
from pathlib import Path

from proofhound.verify import captcha_ocr
from proofhound.verify.raw_request import (
    RawRequest,
    RawRequestError,
    form_fields,
    with_form,
)

#: 重放用的固定错密码前缀（逐次加序号，避免"完全相同请求"被风控直接挡掉）。
WRONG_PASSWORD = "WrongPass!2026"

#: 短信分支的固定测试码（只试这几个，不做真暴破）。
SMS_TEST_CODES = ("0000", "000000", "1234", "8888")

#: 锁定/限速的确定性信号（状态码之外）。
LOCKOUT_RE = re.compile(
    r"(too many (?:login )?attempts?|account (?:is )?locked|rate limit|"
    r"尝试次数过多|账号已锁定|账户已锁定|请稍后再试)",
    re.IGNORECASE,
)

#: 验证码图片的 URL 特征（找不到时要求显式给 --captcha-image）。
CAPTCHA_IMG_RE = re.compile(
    r"(captcha|checkcode|verifycode|validatecode|imgcode|seccode|vcode)", re.IGNORECASE
)


class ProbeError(RuntimeError):
    """探测无法开始（配置错误、目标不可达等）。"""


@dataclass
class LoginResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def fingerprint(self) -> tuple[int, int, str]:
        return (self.status, len(self.body), hashlib.sha256(self.body).hexdigest())


@dataclass
class Attempt:
    index: int
    stage: str  # calibration / ocr / replay / sms
    code: str
    status: int
    label: str  # captcha / credential / lockout / success / unknown
    similarity: float = 0.0
    note: str = ""


@dataclass
class ProbeReport:
    mode: str  # image / sms / none
    verdict: str  # confirmed / rejected / blocked
    reasons: list[str] = field(default_factory=list)
    attempts: list[Attempt] = field(default_factory=list)
    target: str = ""
    calibrated: bool = False
    #: 证据附件（登录页截图 / 验证码图）；由 CLI 在判定后补充。
    artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "target": self.target,
            "calibrated": self.calibrated,
            "artifacts": list(self.artifacts),
            "attempts": [a.__dict__ for a in self.attempts],
        }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _parse_cookie_header(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in (value or "").split(";"):
        name, sep, val = part.strip().partition("=")
        if sep and name:
            cookies[name.strip()] = val.strip()
    return cookies


class LoginSession:
    """带 Cookie 的极简 HTTP 会话（不跟随重定向；3xx 原样返回）。

    Cookie 用**显式字典**而不是 ``CookieJar``：要能从抓到的原始请求里**播种**
    会话（Burp 里那份 Cookie 往往仍有效），也要能读回 Set-Cookie 做登录成功判定。
    """

    def __init__(self, timeout: float = 15.0, cookies: dict[str, str] | None = None):
        self.timeout = timeout
        self.cookies: dict[str, str] = dict(cookies or {})
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(
        self, method: str, url: str, *, headers: dict[str, str] | None = None, body: str | None = None
    ) -> LoginResponse:
        data = body.encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=data, method=method.upper())
        for name, value in (headers or {}).items():
            if name.lower() in {"cookie", "content-length", "host"}:
                continue  # Cookie 由会话管；长度按实际 body 重算
            request.add_header(name, value)
        if self.cookies:
            request.add_header(
                "Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            )
        try:
            response = self._opener.open(request, timeout=self.timeout)
            status, payload, raw_headers = response.status, response.read(), response.headers
        except urllib.error.HTTPError as exc:
            status, payload, raw_headers = exc.code, exc.read(), exc.headers
        except Exception as exc:  # noqa: BLE001 - 探测层统一转 ProbeError
            raise ProbeError(f"请求失败 {url}: {exc}") from exc
        for value in raw_headers.get_all("Set-Cookie") or []:
            self.cookies.update(_parse_cookie_header(value))
        return LoginResponse(
            status=status,
            headers={k.lower(): v for k, v in raw_headers.items()},
            body=payload,
            url=url,
        )


def _new_session(config: "ProbeConfig") -> LoginSession:
    """从原始请求的 Cookie 头播种会话（抓包里的会话通常仍有效）。"""
    return LoginSession(
        config.timeout, cookies=_parse_cookie_header(config.request.header("cookie"))
    )


@dataclass
class ProbeConfig:
    request: RawRequest
    user: str
    user_field: str = "username"
    pass_field: str = "password"
    captcha_field: str | None = None
    captcha_image: str | None = None
    login_page: str | None = None
    attempts: int = 25
    ocr_retries: int = 3
    timeout: float = 15.0
    sms: bool = False
    phone_field: str | None = None
    sms_code_field: str | None = None
    test_phone: str = "18888888888"
    wrong_password: str = WRONG_PASSWORD
    #: 证据附件目录（验证码图片落盘）；None = 不落盘。
    artifact_dir: Path | None = None
    captcha_error_regex: str | None = None
    credential_error_regex: str | None = None


# ---- 纯函数：相似度 / 分类 / 判定 ----


def similarity(left: bytes, right: bytes) -> float:
    """两份响应的文本相似度（截断 8KB，避免大页面拖慢判定）。"""
    a = left.decode("utf-8", "replace")[:8000]
    b = right.decode("utf-8", "replace")[:8000]
    return difflib.SequenceMatcher(None, a, b).ratio()


def classify(
    response: LoginResponse,
    captcha_ref: LoginResponse,
    credential_ref: LoginResponse,
    *,
    captcha_error_regex: str | None = None,
    credential_error_regex: str | None = None,
) -> tuple[str, float]:
    """把一个响应归到「验证码错误 / 凭证错误 / 锁定 / 未知」。

    优先级：显式正则（操作员知道文案时）→ 指纹精确相等 → 相似度（≥0.90 且
    两参考差距 ≥0.05）→ 429/锁定词 → unknown。
    """
    if response.status == 429 or LOCKOUT_RE.search(response.text):
        return "lockout", 1.0
    if captcha_error_regex and re.search(captcha_error_regex, response.text):
        return "captcha", 1.0
    if credential_error_regex and re.search(credential_error_regex, response.text):
        return "credential", 1.0
    if response.fingerprint == captcha_ref.fingerprint:
        return "captcha", 1.0
    if response.fingerprint == credential_ref.fingerprint:
        return "credential", 1.0
    sim_captcha = similarity(response.body, captcha_ref.body)
    sim_credential = similarity(response.body, credential_ref.body)
    best = max(sim_captcha, sim_credential)
    if best >= 0.90 and abs(sim_captcha - sim_credential) >= 0.05:
        return ("captcha" if sim_captcha > sim_credential else "credential"), best
    return "unknown", best


def find_captcha_image(html: str, base_url: str) -> str | None:
    """从登录页 HTML 里找验证码图片 URL（按 src 里的关键词启发式）。"""
    for match in re.finditer(r"<img[^>]+src=[\"']([^\"']+)[\"']", html, re.IGNORECASE):
        src = match.group(1)
        if CAPTCHA_IMG_RE.search(src):
            return urljoin(base_url, src)
    return None


def judge_image(
    attempts: list[Attempt], *, calibrated: bool, calibrated_reason: str = ""
) -> tuple[str, list[str]]:
    """图形验证码分支的三态判定（纯函数）。"""
    if not calibrated:
        return "blocked", [calibrated_reason or "校准不成立，无法区分验证码错误与凭证错误"]
    labels = [a.label for a in attempts]
    if "lockout" in labels:
        return "rejected", ["出现 429/锁定提示：存在登录频率防护"]
    if "captcha" in labels:
        first = labels.index("captcha") + 1
        return "rejected", [f"第 {first} 次重放即被判验证码错误：验证码一次性生效"]
    if "unknown" in labels:
        return "blocked", ["存在无法归类的响应，按宁漏勿滥判 blocked"]
    if labels and all(label == "credential" for label in labels):
        return "confirmed", [
            f"{len(labels)} 次重放全部落在「凭证错误」指纹，且未出现验证码错误/锁定"
        ]
    return "blocked", ["没有可判定的重放结果"]


def judge_sms(attempts: list[Attempt], *, baseline_ok: bool) -> tuple[str, list[str]]:
    """短信固定码分支的三态判定（纯函数）。"""
    if not baseline_ok:
        return "blocked", ["短信基线请求失败，无法判定"]
    labels = [a.label for a in attempts]
    if "success" in labels:
        code = attempts[labels.index("success")].code
        return "confirmed", [f"固定测试码 {code} 直接登录成功（验证码可枚举/固定）"]
    if labels and all(label == "credential" for label in labels):
        return "rejected", ["全部固定测试码均登录失败——仅证明这几个码无效，不代表短信不可暴破"]
    return "blocked", ["响应无法归类，按宁漏勿反判 blocked"]


# ---- 执行层 ----


def _send(
    session: LoginSession,
    config: ProbeConfig,
    *,
    captcha: str | None,
    password: str,
    phone: str | None = None,
    sms_code: str | None = None,
) -> LoginResponse:
    overrides: dict[str, str] = {
        config.user_field: config.user,
        config.pass_field: password,
    }
    if captcha is not None and config.captcha_field:
        overrides[config.captcha_field] = captcha
    if phone is not None and config.phone_field:
        overrides[config.phone_field] = phone
    if sms_code is not None and config.sms_code_field:
        overrides[config.sms_code_field] = sms_code
    prepared = with_form(config.request, overrides)
    headers = dict(prepared.headers)
    if prepared.body:
        headers["content-type"] = "application/x-www-form-urlencoded"
    return session.request(prepared.method, prepared.url, headers=headers, body=prepared.body)


def run_image_probe(config: ProbeConfig) -> ProbeReport:
    """图形验证码 / 无验证码分支。"""
    if not config.captcha_field:
        return run_no_captcha_probe(config)
    if not captcha_ocr.available():
        return ProbeReport(
            "image",
            "blocked",
            ["ddddocr 未安装（pip install ddddocr），无法识别图形验证码"],
            target=config.request.url,
        )

    session = _new_session(config)
    page_url = config.login_page or config.request.url
    try:
        page = session.request("GET", page_url, headers={"Accept": "text/html"})
    except ProbeError as exc:
        return ProbeReport("image", "blocked", [str(exc)], target=config.request.url)

    image_url = config.captcha_image or find_captcha_image(page.text, page.url)
    if not image_url:
        return ProbeReport(
            "image",
            "blocked",
            ["登录页里找不到验证码图片（请用 --captcha-image 显式指定）"],
            target=config.request.url,
        )

    attempts: list[Attempt] = []
    # 1) 验证码错误校准：故意发错码
    try:
        wrong = _send(session, config, captcha="0000", password=config.wrong_password)
    except ProbeError as exc:
        return ProbeReport("image", "blocked", [str(exc)], target=config.request.url)
    attempts.append(
        Attempt(0, "calibration", "0000", wrong.status, "captcha", note="故意错码")
    )

    # 2) OCR + 凭证错误校准（失败换图重试）
    code = ""
    credential_ref: LoginResponse | None = None
    for index in range(config.ocr_retries):
        image = session.request("GET", image_url, headers={"Accept": "image/*"})
        if config.artifact_dir is not None:
            config.artifact_dir.mkdir(parents=True, exist_ok=True)
            (config.artifact_dir / "captcha.png").write_bytes(image.body)
        code = captcha_ocr.solve(image.body)
        if not code:
            continue
        candidate = _send(session, config, captcha=code, password=config.wrong_password)
        if candidate.fingerprint == wrong.fingerprint:
            continue  # OCR 失败或验证码一次性：换一张再试
        credential_ref = candidate
        attempts.append(
            Attempt(1, "ocr", code, candidate.status, "credential", note=f"OCR 第 {index + 1} 次")
        )
        break
    if credential_ref is None:
        return ProbeReport(
            "image",
            "blocked",
            [f"OCR {config.ocr_retries} 次尝试仍被判验证码错误（可能是 OCR 失败或验证码一次性），"
             "不能据此判「有防护」"],
            attempts,
            config.request.url,
        )

    if wrong.fingerprint == credential_ref.fingerprint:
        return ProbeReport(
            "image",
            "blocked",
            ["验证码错误与凭证错误的响应不可区分（可能验证码未校验，也可能站点统一失败文案）"],
            attempts,
            config.request.url,
            calibrated=False,
        )

    # 3) 复用同一验证码重放
    for index in range(1, config.attempts + 1):
        try:
            response = _send(
                session,
                config,
                captcha=code,
                password=f"{config.wrong_password}#{index}",
            )
        except ProbeError as exc:
            attempts.append(Attempt(index, "replay", code, 0, "unknown", note=str(exc)))
            break
        label, score = classify(
            response,
            wrong,
            credential_ref,
            captcha_error_regex=config.captcha_error_regex,
            credential_error_regex=config.credential_error_regex,
        )
        attempts.append(Attempt(index, "replay", code, response.status, label, score))
        if label in {"captcha", "lockout"}:
            break
    verdict, reasons = judge_image(attempts[2:], calibrated=True)
    return ProbeReport("image", verdict, reasons, attempts, config.request.url, True)


def run_no_captcha_probe(config: ProbeConfig) -> ProbeReport:
    """无验证码分支：25 次不同错密码，全部同指纹且无锁定 ⇒ 可重放。"""
    session = _new_session(config)
    attempts: list[Attempt] = []
    baseline: LoginResponse | None = None
    for index in range(1, config.attempts + 1):
        try:
            response = _send(
                session, config, captcha=None, password=f"{config.wrong_password}#{index}"
            )
        except ProbeError as exc:
            attempts.append(Attempt(index, "replay", "", 0, "unknown", note=str(exc)))
            break
        if baseline is None:
            baseline = response
            attempts.append(Attempt(index, "replay", "", response.status, "credential", 1.0))
            continue
        if response.status == 429 or LOCKOUT_RE.search(response.text):
            label, score = "lockout", 1.0
        elif response.fingerprint == baseline.fingerprint:
            label, score = "credential", 1.0
        elif similarity(response.body, baseline.body) >= 0.90:
            label, score = "credential", similarity(response.body, baseline.body)
        else:
            label, score = "unknown", 0.0
        attempts.append(Attempt(index, "replay", "", response.status, label, score))
        if label == "lockout":
            break
    labels = [a.label for a in attempts]
    if "lockout" in labels:
        return ProbeReport("none", "rejected", ["出现 429/锁定提示"], attempts, config.request.url)
    if labels and all(label in {"credential", "unknown"} for label in labels):
        if "unknown" in labels:
            return ProbeReport("none", "blocked", ["响应无法归类"], attempts, config.request.url)
        return ProbeReport(
            "none",
            "confirmed",
            [f"{len(labels)} 次不同密码全部返回同一失败指纹，且无锁定/限速"],
            attempts,
            config.request.url,
            True,
        )
    return ProbeReport("none", "blocked", ["没有可判定的结果"], attempts, config.request.url)


def run_sms_probe(config: ProbeConfig) -> ProbeReport:
    """短信验证码分支：只试固定测试码，判定「是否存在固定码」。"""
    if not (config.phone_field and config.sms_code_field):
        return ProbeReport(
            "sms", "blocked", ["短信分支需要 --phone-field 与 --sms-code-field"], target=config.request.url
        )
    session = _new_session(config)
    page_url = config.login_page or config.request.url
    try:
        session.request("GET", page_url, headers={"Accept": "text/html"})
        baseline = _send(
            session,
            config,
            captcha=None,
            password=config.wrong_password,
            phone=config.test_phone,
            sms_code="999999",
        )
    except ProbeError as exc:
        return ProbeReport("sms", "blocked", [str(exc)], target=config.request.url)

    attempts: list[Attempt] = []
    for code in SMS_TEST_CODES:
        try:
            response = _send(
                session,
                config,
                captcha=None,
                password=config.wrong_password,
                phone=config.test_phone,
                sms_code=code,
            )
        except ProbeError as exc:
            attempts.append(Attempt(len(attempts) + 1, "sms", code, 0, "unknown", note=str(exc)))
            continue
        successful = _looks_like_login_success(response, baseline)
        attempts.append(
            Attempt(
                len(attempts) + 1,
                "sms",
                code,
                response.status,
                "success" if successful else "credential",
                note="不同于失败基线" if successful else "",
            )
        )
    verdict, reasons = judge_sms(attempts, baseline_ok=True)
    return ProbeReport("sms", verdict, reasons, attempts, config.request.url, True)


def _looks_like_login_success(response: LoginResponse, baseline: LoginResponse) -> bool:
    """登录成功判定（保守）：与失败基线指纹不同，且出现 3xx 或新 Cookie 或明显不同正文。"""
    if response.fingerprint == baseline.fingerprint:
        return False
    if 300 <= response.status < 400:
        location = response.headers.get("Location", "").lower()
        return "login" not in location and "error" not in location
    set_cookie = response.headers.get("set-cookie", "")
    if set_cookie and "login" not in response.text.lower()[:500]:
        return True
    return similarity(response.body, baseline.body) < 0.6


def capture_login_artifacts(
    scope,
    request: RawRequest,
    out_dir: str | Path,
    *,
    timeout: float = 15.0,
) -> list[str]:
    """证据附件：登录页截图 + 验证码图片（失败只返回已成功部分，绝不抛）。

    与判定解耦：截图证明的是「登录页长什么样（有没有图形验证码）」，**不是**
    「25 次重放成立」——后者由 ``probe.json`` 的尝试序列证明。故这里任何失败
    （浏览器缺失/超时/找不到验证码图）都不影响判定结论。
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    artifacts: list[str] = []
    session = LoginSession(
        timeout, cookies=_parse_cookie_header(request.header("cookie"))
    )
    try:
        page = session.request("GET", request.url, headers={"Accept": "text/html"})
    except ProbeError:
        return artifacts
    image_url = find_captcha_image(page.text, page.url)
    if image_url:
        try:
            image = session.request("GET", image_url)
            captcha_path = out / "captcha.png"
            captcha_path.write_bytes(image.body)
            artifacts.append(str(captcha_path))
        except ProbeError:
            pass
    try:
        from proofhound.compliance.session import SessionConfig
        from proofhound.verify.screenshot import ScreenshotCapturer

        capturer = ScreenshotCapturer(
            scope=scope,
            evidence_dir=out,
            session=SessionConfig(cookies=session.cookies),
        )
        try:
            capturer.start()
            result = capturer.capture(request.url, name="login-page")
        finally:
            capturer.close()
    except Exception:  # noqa: BLE001 - 截图是附件，失败不影响判定
        return artifacts
    if result.path is not None:
        artifacts.append(str(result.path))
    return artifacts


__all__ = [
    "Attempt",
    "LoginResponse",
    "LoginSession",
    "LOCKOUT_RE",
    "ProbeConfig",
    "ProbeError",
    "ProbeReport",
    "SMS_TEST_CODES",
    "WRONG_PASSWORD",
    "capture_login_artifacts",
    "classify",
    "find_captcha_image",
    "judge_image",
    "judge_sms",
    "run_image_probe",
    "run_no_captcha_probe",
    "run_sms_probe",
    "similarity",
]
