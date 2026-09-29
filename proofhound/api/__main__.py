"""``python -m proofhound.api``：本机 Web API 启动入口（M5a，§5.9.1）。

用法：
    python -m proofhound.api --workspace . [--port 8000] [--host 127.0.0.1]
        [--confirm-timeout 300]

网络暴露红线（§5.9.3）：默认只绑定 127.0.0.1；控制台自 M14 起有 HTTP Basic 认证
（单账户，默认凭据 ``shangyun`` / ``123456``，公开写在仓库里），但 **Basic 不经 TLS
加密**，故仍然只适用于本机/受信内网。绑定非回环地址时：

- 仍在使用默认口令 ⇒ **拒绝启动**（``auth.startup_blocker``，不能拿公开口令对外服务）；
- 已换自定义口令 ⇒ 打印醒目告警后启动（多人访问仍须前置反向代理 + TLS）。
"""

from __future__ import annotations

import argparse
import sys

from proofhound.api.auth import ApiAuth, is_loopback, resolve_auth, startup_blocker

__all__ = ["loopback_warning", "main"]


def loopback_warning(host: str) -> str | None:
    """绑定地址检查：非回环返回醒目警告文本（不阻断启动），回环返回 None。

    M14 起控制台有 HTTP Basic 认证，但**默认口令是公开的**且 Basic 不经 TLS 加密，
    故非回环绑定（非默认口令时）仍需告警：多人访问必须前置反向代理（nginx + TLS）
    + 登录认证，严禁直接暴露公网。主机名按非回环处理（fail-closed 告警）。
    """
    if is_loopback(host):
        return None
    return (
        "=" * 72 + "\n"
        f"⚠ 警告：ProofHound 控制台将绑定到非回环地址 {host}！\n"
        "  控制台仅有单账户 HTTP Basic 认证（M14），且 Basic 口令不经 TLS 加密；\n"
        "  默认口令公开写在仓库里，若仍在使用它将被拒绝启动（见 --host 说明）。\n"
        "  §5.9.3 红线：多人访问须反向代理（nginx + TLS）+ 登录认证；\n"
        "  严禁直接暴露公网。本机使用请改回 --host 127.0.0.1。\n"
        + "=" * 72
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m proofhound.api")
    parser.add_argument(
        "--workspace",
        default=".",
        help="工作区根目录（含 scope 文件、templates/、skills/、tools.d/、.env）",
    )
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机）")
    parser.add_argument("--port", type=int, default=8000, help="监听端口")
    parser.add_argument(
        "--confirm-timeout",
        type=float,
        default=300.0,
        help="确认队列等待超时秒数（超时默认拒绝并写审计）",
    )
    args = parser.parse_args(argv)

    auth: ApiAuth = resolve_auth(args.workspace)

    blocker = startup_blocker(args.host, auth)
    if blocker is not None:
        print(blocker, file=sys.stderr, flush=True)
        return 2

    warning = loopback_warning(args.host)
    if warning is not None:
        print(warning, file=sys.stderr, flush=True)

    import uvicorn

    from proofhound.api import create_app

    app = create_app(args.workspace, confirm_timeout=args.confirm_timeout, auth=auth)
    print(auth.status_line(), flush=True)
    if auth.is_default:
        print(
            "  提示：默认口令公开写在仓库里，仅适合本机使用；"
            "换口令只需在 .env 里设 PROOFHOUND_API_USER / PROOFHOUND_API_PASSWORD。",
            flush=True,
        )
    print(f"ProofHound 控制台: http://{args.host}:{args.port}/", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
