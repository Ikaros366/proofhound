"""API 认证（M14，§5.9.1）：HTTP Basic 单账户口令，**deny-by-default**。

维护者裁定的取舍是**简单优先**：不做密码复杂度、不做用户表、不做 RBAC、不做会话/
登出。默认凭据 ``shangyun`` / ``123456``，可用环境变量或 ``.env`` 覆盖（**同名环境
变量优先**，与 ``.env.example`` 的既有声明一致）：

    PROOFHOUND_API_USER / PROOFHOUND_API_PASSWORD

因为默认口令是**公开写在仓库里的固定值**，安全性不能建立在它之上，只能靠边界补强，
故一并落地四条护栏：

1. **默认口令 + 非回环绑定 = 拒绝启动**（:func:`startup_blocker`）——想绑局域网/公网，
   必须先换成自己的口令。这把"忘了改默认口令还 ``--host 0.0.0.0``"变成不可能，
   而不是只打印一条没人看的告警。
2. 启动横幅显式标注凭据来源（``default`` / ``env`` / ``dotenv`` / ``mixed``），
   用默认口令时给醒目告警。
3. 凭据比较走 :func:`hmac.compare_digest`（常量时间），避免逐字节比较的时序侧信道。
4. ``Authorization`` 头**永不**进审计/日志；401 响应体不回显任何提交内容。

诚实边界（同时记 AGENTS.md 已知限制）：**无 TLS**——Basic 口令是 Base64（非加密），
故默认只允许回环；无登录失败次数限制/锁定；无多用户与权限分级（单账户即全部权限，
包括 scope 写与 L2 批准）。
"""

from __future__ import annotations

import base64
import binascii
import hmac
import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from proofhound.llm.client import load_dotenv

#: 仓库内置默认凭据（维护者裁定：简单优先，不做密码复杂度）
DEFAULT_API_USER = "shangyun"
DEFAULT_API_PASSWORD = "123456"

#: 浏览器原生登录框的 realm
REALM = "ProofHound"

USER_KEY = "PROOFHOUND_API_USER"
PASSWORD_KEY = "PROOFHOUND_API_PASSWORD"

_SOURCE_CN = {
    "default": "仓库默认值（公开，务必仅本机使用）",
    "env": "环境变量",
    "dotenv": ".env 文件",
    "mixed": "环境变量 / .env 混合",
    "explicit": "调用方显式传入",
}


@dataclass(frozen=True)
class ApiAuth:
    """单账户口令认证配置（不可变）。"""

    username: str = DEFAULT_API_USER
    password: str = DEFAULT_API_PASSWORD
    source: str = "default"

    @property
    def is_default(self) -> bool:
        """是否仍在用仓库内置的**公开**默认口令（用户名与口令都命中才算）。"""
        return self.username == DEFAULT_API_USER and self.password == DEFAULT_API_PASSWORD

    def accepts(self, header: str | None) -> bool:
        """常量时间校验 ``Authorization: Basic <base64>`` 头。"""
        if not header or not header.lower().startswith("basic "):
            return False
        token = header.split(" ", 1)[1].strip()
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return False
        return hmac.compare_digest(decoded, f"{self.username}:{self.password}")

    def basic_header(self) -> dict[str, str]:
        """客户端侧用：本凭据对应的 ``Authorization`` 头。

        供 ``scripts/`` 的验收脚本与测试构造客户端（它们与 API 同机同权限，认证照走、
        不绕过）；生产端只读自己的凭据，不消费本方法。
        """
        return {"Authorization": basic_token(self.username, self.password)}

    def status_line(self) -> str:
        """启动横幅用的一行状态（**永不**包含口令本身）。"""
        return f"认证：已启用（账户 {self.username}，口令来源：{_SOURCE_CN.get(self.source, self.source)}）"


def basic_token(username: str, password: str) -> str:
    """``user:password`` 的 Basic 头值（Base64，**非加密**——故只适合回环/TLS 之内）。"""
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def resolve_auth(
    workspace_root: str | Path,
    env_file: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> ApiAuth:
    """统一的凭据解析入口（``create_app`` 与 ``__main__`` 共用，避免两套口径）。

    ``env_file`` 缺省取 ``<workspace>/.env``，与 ``EngagementManager`` 的约定一致。
    """
    path = Path(env_file) if env_file is not None else Path(workspace_root) / ".env"
    env: Mapping[str, str] = os.environ if environ is None else environ
    dotenv = load_dotenv(path)

    def pick(key: str) -> tuple[str | None, str | None]:
        value = (env.get(key) or "").strip()
        if value:
            return value, "env"
        value = (dotenv.get(key) or "").strip()
        if value:
            return value, "dotenv"
        return None, None

    username, user_source = pick(USER_KEY)
    password, password_source = pick(PASSWORD_KEY)
    sources = {s for s in (user_source, password_source) if s}
    if not sources:
        return ApiAuth()
    source = sources.pop() if len(sources) == 1 else "mixed"
    return ApiAuth(username or DEFAULT_API_USER, password or DEFAULT_API_PASSWORD, source)


def is_loopback(host: str) -> bool:
    """回环判定；无法解析为主机名/IP 的一律按非回环处理（fail-closed）。"""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def startup_blocker(host: str, auth: ApiAuth) -> str | None:
    """拒绝启动的原因（None 表示放行）。

    唯一硬拦：**默认口令 + 非回环绑定**。换成自己的口令即可解除——这不是"禁止对外
    提供服务"，而是"禁止拿公开口令对外提供服务"。
    """
    if is_loopback(host) or not auth.is_default:
        return None
    # 注意：提示里只给用户名与变量名，**不复述口令原文**——即便它已公开，也没有必要
    # 让口令值出现在终端记录/日志里（本项目对"密钥落地"一贯保守）。
    return (
        "=" * 72 + "\n"
        f"✗ 拒绝启动：绑定到非回环地址 {host} 却仍在使用**仓库公开的默认口令**。\n"
        f"  默认账户 {DEFAULT_API_USER} 的口令是开源仓库里写死的固定值，等同于无认证；\n"
        "  再加上 Basic 口令不经 TLS 加密，暴露到局域网/公网就是公开一个攻击工具的遥控面板。\n"
        "  三种出路，任选其一：\n"
        "    1) 改回本机使用：--host 127.0.0.1（推荐）\n"
        f"    2) 换掉默认口令：在 .env 里设 {USER_KEY} / {PASSWORD_KEY}\n"
        "    3) 仍要对外：前置反向代理做 TLS + 登录认证，并同时做第 2 条\n"
        + "=" * 72
    )
