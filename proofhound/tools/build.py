"""确定性命令构造器（§5.3 红线 1 的 M2b 落地形态）。

LLM 规划输出为结构化 JSON（action/tool/params），**不直接生成 shell 命令**；
argv 由本模块按工具名分派到确定性构造函数拼装，参数经 Pydantic 强校验。

- 产出 argv 列表（首元素为工具名），不经 shell 解释，无注入面；
- scope 校验仍在 ``SandboxRunner.run`` 内对 argv 强制执行（红线 5 不变）；
- restricted 出口模式下由调用方传入 ``egress_proxy_url``，构造函数负责
  注入显式代理参数（httpx 不读 proxy 环境变量）。
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class UnknownToolError(ValueError):
    """没有命令构造器的工具。"""


class HttpxParams(BaseModel):
    """httpx 探活参数（对应 skills/web-scan SOP 的探活步骤）。"""

    target: str = Field(min_length=1)  # 单目标 URL 或 host
    rate_limit: int = Field(default=50, gt=0, le=1000)
    tech_detect: bool = True
    follow_redirects: bool = True

    @field_validator("target")
    @classmethod
    def _no_flag_injection(cls, value: str) -> str:
        if value.strip().startswith("-"):
            raise ValueError("target 不得以 - 开头（旗标注入防护）")
        return value.strip()


def _build_httpx(params: dict, *, egress_proxy_url: str | None = None) -> list[str]:
    p = HttpxParams.model_validate(params)
    argv = ["httpx", "-u", p.target]
    if egress_proxy_url:
        argv += ["-proxy", egress_proxy_url]
    argv += ["-status-code", "-title"]
    if p.tech_detect:
        argv.append("-tech-detect")
    if p.follow_redirects:
        argv.append("-follow-redirects")
    argv += ["-rate-limit", str(p.rate_limit), "-json", "-silent", "-no-color"]
    return argv


_BUILDERS = {
    "httpx": _build_httpx,
}


def build_command(
    tool: str, params: dict, *, egress_proxy_url: str | None = None
) -> list[str]:
    """按工具名构造 argv；未知工具抛 :class:`UnknownToolError`。"""
    builder = _BUILDERS.get(tool)
    if builder is None:
        raise UnknownToolError(f"工具 {tool} 没有命令构造器")
    return builder(params, egress_proxy_url=egress_proxy_url)


def known_tools() -> list[str]:
    """已有命令构造器的工具清单。"""
    return sorted(_BUILDERS)
