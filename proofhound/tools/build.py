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

from pydantic import BaseModel, Field, field_validator, model_validator

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
    ``--batch``（禁交互）与 ``--flush-session``（禁陈旧会话缓存）恒由构造器
    强制，不接受参数覆盖。

    M8a：``forms=True`` 为 POST 表单页模式——sqlmap 自行解析页面内表单
    并测试其字段，**与 ``param`` 互斥**（不指定 ``-p``），且构造器永不产
    ``--data``（不手拼请求体，表单字段由目标页面自身决定）。
    """

    url: str = Field(min_length=1)  # 含注入参数的完整 URL（GET）或表单页 URL（forms）
    param: str | None = None  # 指定测试参数（-p），缺省测全部
    with_session: bool = False  # 注入预置会话（--cookie）
    level: int = Field(default=1, ge=1, le=3)
    risk: int = Field(default=1, ge=1, le=2)
    forms: bool = False  # M8a：POST 表单页模式（--forms；与 param 互斥）

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

    @model_validator(mode="after")
    def _forms_excludes_param(self) -> "SqlmapParams":
        if self.forms and self.param is not None:
            raise ValueError("forms 模式与 param 互斥（--forms 自解析表单，不指定 -p）")
        return self


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
    if p.forms:
        # M8a：POST 表单页模式——sqlmap 自解析页面内表单；永不手拼 --data
        argv.append("--forms")
    elif p.param:
        argv += ["-p", p.param]
    argv += [
        "--level", str(p.level),
        "--risk", str(p.risk),
        "--batch",  # 禁交互（硬编码，不可覆盖）
        "--flush-session",  # 禁陈旧会话缓存
        "--disable-coloring",  # 输出进证据文件，禁 ANSI 转义
    ]
    return argv


class KatanaParams(BaseModel):
    """katana 爬行参数（对应 skills/recon-crawl SOP，L1 发现类）。

    恒在项（构造器写死，不接受参数覆盖）：``-jsonl -silent -nc -fs rdn``
    （field-scope 限种子根域，三层 scope 纵深第一层）与
    ``-cos "(?i)(logout|logoff|signout|signoff|phpids)"``（爬行安全排除，
    v1.7.0 实测：katana 会把状态变更类 GET 链接当普通链接抓取——logout
    销毁服务端会话导致带认证爬行中途失效；DVWA ``security.php?phpids=on``
    会为该会话开启 PHPIDS、后续攻击载荷全被拦截。注意 -cos 值不能含
    逗号——旗标按逗号分片，``{m,n}`` 量词会被截断）；
    **永不产 ``-o``**——输出只走 stdout → 容器日志 → 证据落盘（红线 3）。
    depth/concurrency/rate_limit 设硬上限，防爬行面失控；不暴露 headless。
    """

    target: str = Field(min_length=1)  # 单种子 URL
    depth: int = Field(default=2, ge=1, le=5)
    concurrency: int = Field(default=5, ge=1, le=10)
    rate_limit: int | None = Field(default=None, gt=0, le=150)  # -rl，缺省不限
    with_session: bool = False  # 注入预置会话（-H Cookie/自定义头）

    @field_validator("target")
    @classmethod
    def _no_flag_injection(cls, value: str) -> str:
        if value.strip().startswith("-"):
            raise ValueError("target 不得以 - 开头（旗标注入防护）")
        return value.strip()


def _build_katana(
    params: dict,
    *,
    egress_proxy_url: str | None = None,
    session: SessionConfig | None = None,
) -> list[str]:
    p = KatanaParams.model_validate(params)
    argv = ["katana", "-u", p.target]
    if egress_proxy_url:
        argv += ["-proxy", egress_proxy_url]
    if p.with_session:
        for header in _session_headers(_require_session(True, session)):
            argv += ["-H", header]
    argv += ["-d", str(p.depth), "-c", str(p.concurrency)]
    if p.rate_limit is not None:
        argv += ["-rl", str(p.rate_limit)]
    # 恒在项（写死）：-fs rdn 限种子根域；-cos 排除状态变更类 GET 链接
    # （logout 自毁会话、phpids 开关为目标开启 IDS）；值不含逗号
    # （-cos 旗标按逗号分片，量词 {m,n} 会被截断失效）
    argv += [
        "-jsonl", "-silent", "-nc", "-fs", "rdn",
        "-cos", "(?i)(logout|logoff|signout|signoff|phpids)",
    ]
    return argv


_BUILDERS = {
    "httpx": _build_httpx,
    "sqlmap": _build_sqlmap,
    "katana": _build_katana,
}

_PARAMS_MODELS = {
    "httpx": HttpxParams,
    "sqlmap": SqlmapParams,
    "katana": KatanaParams,
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
