"""``python -m proofhound.api``：本机 Web API 启动入口（M5a，§5.9.1）。

用法：
    python -m proofhound.api --workspace . [--port 8000] [--host 127.0.0.1]
        [--confirm-timeout 300]

网络暴露红线（§5.9.3）：默认只绑定 127.0.0.1；绑到非 loopback 地址前确认
有反向代理 + 认证，严禁无认证直接暴露公网。
"""

from __future__ import annotations

import argparse
import ipaddress
import sys


def loopback_warning(host: str) -> str | None:
    """绑定地址检查：非回环返回醒目警告文本（不阻断启动），回环返回 None。

    网络暴露红线（§5.9.3）：控制台无认证，默认只绑 127.0.0.1；绑非回环
    地址必须有反向代理 + 登录认证，严禁无认证暴露公网。无法解析为 IP 的
    主机名按非回环处理（fail-closed 告警）。
    """
    if host.lower() == "localhost":
        return None
    try:
        if ipaddress.ip_address(host).is_loopback:
            return None
    except ValueError:
        pass  # 非 IP 主机名：落到警告
    return (
        "=" * 72 + "\n"
        f"⚠ 警告：ProofHound 控制台将绑定到非回环地址 {host}！\n"
        "  控制台无认证（M5a 已知限制），暴露局域网/公网等于公开攻击工具的遥控面板。\n"
        "  §5.9.3 红线：多人访问须反向代理（nginx + TLS）+ 登录认证；\n"
        "  严禁无认证直接暴露公网。本机使用请改回 --host 127.0.0.1。\n"
        + "=" * 72
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m proofhound.api")
    parser.add_argument(
        "--workspace",
        default=".",
        help="工作区根目录（含 scope 文件、templates/、skills/、tools.d/）",
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

    warning = loopback_warning(args.host)
    if warning is not None:
        print(warning, file=sys.stderr, flush=True)

    import uvicorn

    from proofhound.api import create_app

    app = create_app(args.workspace, confirm_timeout=args.confirm_timeout)
    print(f"ProofHound 控制台: http://{args.host}:{args.port}/", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
