"""API 请求/响应模型（M5a，§5.9.1）：FastAPI 层的 Pydantic 契约。

- 请求模型在此强校验：非法自治模式名由 ``AutonomyMode`` 枚举直接 422；
  cookie 字符串解析失败（缺 ``=`` 的段）同样 422；
- 响应统一走 dict（FastAPI 序列化），错误响应统一
  ``{"detail": {"error": <code>, "message": <msg>}}``；
- **cookie 值永不进任何响应体**：写盘后经 :func:`parse_cookie` 只进
  ``session.json``（0600），接口只回显 ``with_session: true``。
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from proofhound.autonomy import AutonomyMode


def parse_cookie(cookie: str) -> dict[str, str]:
    """解析 ``k1=v1; k2=v2`` 形式的 Cookie 头为 dict；空段忽略。

    任一段缺 ``=`` 或键为空即抛 :class:`ValueError`（fail-closed：
    畸形 cookie 不猜测、不截断）。
    """
    cookies: dict[str, str] = {}
    for segment in cookie.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        name, sep, value = segment.partition("=")
        if not sep or not name.strip():
            raise ValueError(f"cookie 段无法解析（缺 '='）: {segment!r}")
        cookies[name.strip()] = value.strip()
    if not cookies:
        raise ValueError("cookie 为空或不含任何 k=v 段")
    return cookies


class CreateEngagementRequest(BaseModel):
    """创建 engagement：目标 + scope 授权文件 + 可选会话/模式/预算。"""

    target: str = Field(min_length=1)  # 单目标 URL/IP/域名（构造器仅支持单目标）
    scope_paths: list[str] = Field(min_length=1)  # scope YAML，相对 workspace 或绝对路径
    cookie: str | None = None  # 可选预置会话 Cookie 头（k=v; k=v 形式）
    autonomy_mode: AutonomyMode = AutonomyMode.SEMI_AUTO  # 默认半自动（§5.9.2）
    budget: int | None = Field(default=None, ge=0)  # Run 级 token 预算；0 = 拒绝一切 LLM 调用
    extras: dict[str, str] | None = None  # 报告元信息额外键（M4.5 extras 透传：company_name 等）

    @field_validator("cookie")
    @classmethod
    def _cookie_parseable(cls, value: str | None) -> str | None:
        if value is not None:
            parse_cookie(value)  # 畸形即 422（不创建任何资源）
        return value

    @field_validator("extras")
    @classmethod
    def _extras_valid(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        """extras 键约束：非空、不得占用系统保留键（报告元信息由系统生成）。"""
        if value is None:
            return value
        reserved = {"target", "scope", "started_at", "finished_at"}
        collision = reserved.intersection(value)
        if collision:
            raise ValueError(f"extras 含系统保留键 {sorted(collision)}（由系统自动生成）")
        for key in value:
            if not key.strip():
                raise ValueError("extras 含空白键")
        return value


class AutonomySwitchRequest(BaseModel):
    """切换自治模式：向宽松切换必须携带 operator（显式确认）。"""

    mode: AutonomyMode  # 非法模式名 → 422
    operator: str | None = None
    note: str = ""


class ConfirmationDecisionRequest(BaseModel):
    """批准/拒绝一个待确认动作：operator 必填（审计落款）。"""

    operator: str = Field(min_length=1)
    note: str = ""


class ReportBuildRequest(BaseModel):
    """触发报告构建：模板限 workspace templates/ 内；narrative=True 走 T1 叙述。"""

    template: str | None = None  # 模板文件名/相对路径，缺省 default_template.docx
    narrative: bool = False


class SkillUpdateRequest(BaseModel):
    """编辑 skill（M6a）：SKILL.md 全文，保存即校验（非法 422 零写入）。"""

    content: str = Field(min_length=1)


class ScopeCreateRequest(BaseModel):
    """新建 scope（M6a）：文件名（白名单字符）+ YAML 全文。"""

    name: str = Field(min_length=1)
    content: str = Field(min_length=1)


class ScopeUpdateRequest(BaseModel):
    """编辑 scope（M6a）：YAML 全文，保存即校验（非法 422 零写入）。"""

    content: str = Field(min_length=1)
