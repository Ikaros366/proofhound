"""ProofHound 本机 Web API（M5a，§5.9.1）：编排器 + 自主模式闸门的 HTTP 薄壳。

只绑定 localhost/内网（§5.9.3 网络暴露红线）；本里程碑只做后端 API，
前端 UI 属 M5b。用法见 ``python -m proofhound.api --help``。
"""

from proofhound.api.server import create_app

__all__ = ["create_app"]
