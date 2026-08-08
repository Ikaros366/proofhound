"""ProofHound 本机 Web API + Web 控制台（M5a/M5b，§5.9.1）。

只绑定 localhost/内网（§5.9.3 网络暴露红线）；M5a 交付后端 API（编排器 +
自主模式闸门的 HTTP 薄壳），M5b 交付纯静态本地 Web 控制台
（``proofhound/api/static/``，零依赖零构建链，挂载于 ``/``）。
用法见 ``python -m proofhound.api --help``。
"""

from proofhound.api.server import create_app

__all__ = ["create_app"]
