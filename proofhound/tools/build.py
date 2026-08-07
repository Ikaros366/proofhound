"""确定性命令构造器（§5.3 红线 1 的 M2b 落地形态）。

LLM 规划输出为结构化 JSON（action/tool/params），**不直接生成 shell 命令**；
argv 由本模块按工具名分派到确定性构造函数拼装，参数经 Pydantic 强校验。

- 产出 argv 列表（首元素为工具名），不经 shell 解释，无注入面；
- scope 校验仍在 ``SandboxRunner.run`` 内对 argv 强制执行（红线 5 不变）；
- restricted 出口模式下由调用方传入 ``egress_proxy_url``，构造函数负责
  注入显式代理参数（httpx 不读 proxy 环境变量）；
- M3b 预置会话：params 里只声明 ``with_session: true``，真实凭据由构造器
  从 ``session``（Scope 上的 SessionConfig）注入——LLM 永不接触凭据原文；
  ``with_session=True`` 而无 session 即校验失败（fail-closed）。
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator

from proofhound.compliance.session import SessionConfig


class UnknownToolError(ValueError):
    """没有命令构造器的工具。"""


class HttpxParams(BaseModel):
    """httpx 探活参数（对应 skills/web-scan SOP 的探活步骤）。"""

    target: str = Field(min_length=1)  # 单目标 URL 或 host
    rate_limit: int = Field(default=50, gt=0, le=1000)
    tech_detect: bool = True
    follow_redirects: bool = True
    with_session: bool = False  # M3b：注入预置会话（Cookie/额外请求头）

    @field_validator("target")
    @classmethod
    def _no_flag_injection(cls, value: str) -> str:
        if value.strip().startswith("-"):
            raise ValueError("target 不得以 - 开头（旗标注入防护）")
        return value.strip()


def _require_session(with_session: bool, session: SessionConfig | None) -> SessionConfig:
    """with_session=True 必须配会话，否则 fail-closed 校验失败。"""
    if not with_session:
        return SessionConfig()
    if session is None or not session.cookie_header():
        raise ValueError("with_session=True 要求 scope 配置预置会话（session.cookies）")
    return session


def _session_headers(session: SessionConfig) -> list[str]:
    """把预置会话渲染为 httpx ``-H`` 请求头列表。"""
    headers = [f"Cookie: {session.cookie_header()}"]
    headers.extend(f"{k}: {v}" for k, v in session.headers.items())
    return headers


def _build_httpx(
    params: dict,
    *,
    egress_proxy_url: str | None = None,
    session: SessionConfig | None = None,
) -> list[str]:
    p = HttpxParams.model_validate(params)
    argv = ["httpx", "-u", p.target]
    if egress_proxy_url:
        argv += ["-proxy", egress_proxy_url]
    if p.with_session:
        for header in _session_headers(_require_session(True, session)):
            argv += ["-H", header]
    argv += ["-status-code", "-title"]
    if p.tech_detect:
        argv.append("-tech-detect")
    if p.follow_redirects:
        argv.append("-follow-redirects")
    argv += ["-rate-limit", str(p.rate_limit), "-json", "-silent", "-no-color"]
    return argv


_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class SqlmapParams(BaseModel):
    """sqlmap 注入确认参数（对应 skills/verify-sqli SOP，L2 利用验证）。

    level/risk 设硬上限（3/2）：防规划或配置失误导致测试面失控；
    ``--batch``（禁交互）与 ``--flush-session``（禁陈旧缓存）恒由构造器
    强制，不接受参数覆盖。
    """

    url: str = Field(min_length=1)  # 含注入参数的完整 URL（GET）
    param: str | None = None  # 指定测试参数（-p），缺省测全部
    with_session: bool = False  # 注入预置会话（--cookie）
    level: int = Field(default=1, ge=1, le=3)
    risk: int = Field(default=1, ge=1, le=2)

    @field_validator("url")
    @classmethod
    def _valid_url(cls, value: str) -> str:
        value = value.strip()
        if value.startswith("-"):
            raise ValueError("url 不得以 - 开头（旗标注入防护）")
        if not re.match(r"^https?://[^\s/]+", value):
            raise ValueError("url 必须是 http(s) URL")
        return value

    @field_validator("param")
    @classmethod
    def _valid_param(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if value.startswith("-"):
            raise ValueError("param 不得以 - 开头（旗标注入防护）")
        if not _PARAM_NAME_RE.match(value):
            raise ValueError("param 只允许字母数字与 _ . -")
        return value


def _build_sqlmap(
    params: dict,
    *,
    egress_proxy_url: str | None = None,
    session: SessionConfig | None = None,
) -> list[str]:
    p = SqlmapParams.model_validate(params)
    argv = ["sqlmap", "-u", p.url]
    if egress_proxy_url:
        argv += ["--proxy", egress_proxy_url]
    if p.with_session:
        argv += ["--cookie", _require_session(True, session).cookie_header()]
    if p.param:
        argv += ["-p", p.param]
    argv += [
        "--level", str(p.level),
        "--risk", str(p.risk),
        "--batch",  # 禁交互（硬编码，不可覆盖）
        "--flush-session",  # 禁陈旧会话缓存
        "--disable-coloring",  # 输出进证据文件，禁 ANSI 转义
    ]
    return argv


_BUILDERS = {
    "httpx": _build_httpx,
    "sqlmap": _build_sqlmap,
}

_PARAMS_MODELS = {
    "httpx": HttpxParams,
    "sqlmap": SqlmapParams,
}


def build_command(
    tool: str,
    params: dict,
    *,
    egress_proxy_url: str | None = None,
    session: SessionConfig | None = None,
) -> list[str]:
    """按工具名构造 argv；未知工具抛 :class:`UnknownToolError`。"""
    builder = _BUILDERS.get(tool)
    if builder is None:
        raise UnknownToolError(f"工具 {tool} 没有命令构造器")
    return builder(params, egress_proxy_url=egress_proxy_url, session=session)


def known_tools() -> list[str]:
    """已有命令构造器的工具清单。"""
    return sorted(_BUILDERS)


def params_schema(tool: str) -> dict | None:
    """工具的 params JSON Schema（供规划器注入 prompt，防 LLM 瞎猜字段名）。"""
    model = _PARAMS_MODELS.get(tool)
    return model.model_json_schema() if model is not None else None
