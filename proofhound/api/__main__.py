"""``python -m proofhound.api``：本机 Web API 启动入口（M5a，§5.9.1）。

用法：
    python -m proofhound.api --workspace . [--port 8000] [--host 127.0.0.1]
        [--confirm-timeout 300]

网络暴露红线（§5.9.3）：默认只绑定 127.0.0.1；绑到非 loopback 地址前确认
有反向代理 + 认证，严禁无认证直接暴露公网。
"""

from __future__ import annotations

import argparse
import sys


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

    import uvicorn

    from proofhound.api import create_app

    app = create_app(args.workspace, confirm_timeout=args.confirm_timeout)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
