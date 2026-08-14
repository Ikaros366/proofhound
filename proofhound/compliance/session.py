"""预置会话与凭据脱敏（M3b，§5.3 认证旁路 SOP 第①条落地）。

- :class:`SessionConfig`：engagement 预置会话（Cookie / 额外请求头），挂在
  :class:`~proofhound.compliance.scope.Scope` 上（design §5.3"scope 配置中的
  预置会话"）；构造器据此为工具注入参数（httpx ``-H``、sqlmap ``--cookie``），
  LLM 只声明 ``with_session``，永不接触凭据原文；
- 脱敏纪律：Cookie/会话值在审计、state、任何日志中**只记 sha256 前 8 位**
  （``sha256:<hex8>`` 标记）。:func:`redact_argv` / :func:`redact_text` 在
  沙箱 runner 写审计与返回命令前做精确子串替换；Finding 字段（如
  reproduction_steps）只写脱敏形态；
- 证据落盘同样脱敏（:func:`redact_bytes`，字节级）：实靶验证 sqlmap 会在
  stdout 回显 ``Cookie:`` 请求头，凭据原文随证据包外发不可接受；脱敏在
  落盘前完成，审计中的输出哈希与落盘内容一致（证据链不断裂）。非会话类
  秘密（工具自行打印的 token 等）不在其列，属已知限制。
- M8c 双会话：``SessionConfig.reference`` 可选第二身份会话
  （reference/victim），``secret_values()`` 递归覆盖两个会话的全部秘密
  值——脱敏口子不变，verify-idor 双会话属性验证的两份凭据同纪律脱敏。
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, Field

#: 裸凭据值参与脱敏的最小长度（短值只以 k=v 对形态脱敏）
MIN_SECRET_LEN = 8


class SessionConfig(BaseModel):
    """预置会话：Cookie 键值对 + 额外请求头（如 Authorization）。

    M8c 起支持可选第二身份会话 ``reference``（reference/victim 身份，
    字段与主会话同构），供 verify-idor 双会话属性验证使用；缺省 None
    时与单会话模型逐字节等价，现有全部链路零影响。
    """

    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    reference: SessionConfig | None = None

    def cookie_header(self) -> str:
        """渲染 Cookie 请求头值：``k1=v1; k2=v2``（无 cookie 时为空串）。"""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def secret_values(self) -> list[str]:
        """需要脱敏的精确子串清单（空串剔除，覆盖主会话与第二身份会话）。

        收录形态：渲染后的完整 Cookie 头、每个 ``k=v`` 对、每个 ``k: v``
        请求头对——覆盖工具输出的常见回显形态；裸值仅当其长度 ≥ 8 才收录
        （实靶教训：`security=low` 的裸值 ``low`` 会把 "fol**low**ing"
        这类正常单词替换坏，短值只经 ``k=v`` 对形态脱敏，防 collateral
        damage 破坏证据文本与解析锚点）。

        脱敏是两个会话都要（红线 5）：``reference`` 存在时递归并入其全部
        秘密值——沙箱 runner、浏览器验证器、编排层证据落盘均经本方法一个
        口子取脱敏清单，双会话凭据同纪律覆盖。
        """
        values = [self.cookie_header()]
        values.extend(f"{k}={v}" for k, v in self.cookies.items())
        values.extend(v for v in self.cookies.values() if len(v) >= MIN_SECRET_LEN)
        values.extend(f"{k}: {v}" for k, v in self.headers.items())
        values.extend(v for v in self.headers.values() if len(v) >= MIN_SECRET_LEN)
        if self.reference is not None:
            values.extend(self.reference.secret_values())
        return [v for v in values if v]


def secret_marker(secret: str) -> str:
    """凭据的脱敏标记：``sha256:<hex8>``（只记 sha256 前 8 位）。"""
    return f"sha256:{hashlib.sha256(secret.encode('utf-8')).hexdigest()[:8]}"


def redact_text(text: str, secrets: list[str]) -> str:
    """把 text 中出现的凭据精确子串替换为脱敏标记（长串优先防部分覆盖）。"""
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            text = text.replace(secret, secret_marker(secret))
    return text


def redact_argv(argv: list[str], secrets: list[str]) -> list[str]:
    """逐 token 脱敏，返回新列表（不修改入参）。"""
    return [redact_text(token, secrets) for token in argv]


def redact_bytes(data: bytes, secrets: list[str]) -> bytes:
    """字节级脱敏（供证据落盘）：UTF-8 编码后精确替换，非文本字节不动。

    实靶验证：sqlmap 会在 stdout 回显 ``Cookie:`` 请求头——证据原文若
    不脱敏，会话凭据会随证据包外发。脱敏在落盘前完成，审计哈希与落盘
    内容保持一致（证据链不断裂）。
    """
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            data = data.replace(
                secret.encode("utf-8"), secret_marker(secret).encode("utf-8")
            )
    return data
    return [redact_text(token, secrets) for token in argv]
