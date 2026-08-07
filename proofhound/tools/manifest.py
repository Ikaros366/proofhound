"""Tool Manifest schema（§5.2）：每个工具一份 YAML，Pydantic v2 强校验。

规范要点：
- ``install`` 为按优先级排列的安装配方列表，安装器自上而下依次尝试；
- ``binary`` 配方的 ``sha256`` 在 schema 层强制必填，缺失即校验失败，
  对应"白名单源 + 强制 SHA256 校验"的工具安装纪律。
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator


class InstallRecipe(BaseModel):
    """一条安装配方。``type`` 决定其余字段的必填项。"""

    type: Literal["local", "binary", "go", "apt", "pip"]
    path: str | None = None  # local：用户预置目录或文件（离线场景）
    url: str | None = None  # binary：官方 release 地址（须白名单源）
    sha256: str | None = None  # binary：强制校验；pip（M3b）：可选，提供即强制
    package: str | None = None  # go/apt/pip：包管理器兜底

    @model_validator(mode="after")
    def _check_required_fields(self) -> "InstallRecipe":
        if self.type == "local" and not self.path:
            raise ValueError("local 配方必须提供 path")
        if self.type == "binary":
            if not self.url:
                raise ValueError("binary 配方必须提供 url")
            if not self.sha256:
                raise ValueError("binary 配方必须提供 sha256（强制校验）")
        if self.type in ("go", "apt", "pip") and not self.package:
            raise ValueError(f"{self.type} 配方必须提供 package")
        if self.type == "pip" and self.sha256 and "==" not in (self.package or ""):
            raise ValueError("pip 配方带 sha256 时 package 必须 == 固定版本")
        return self


class ToolManifest(BaseModel):
    """工具清单（§5.2 YAML 规范的 schema 化）。"""

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    version: str
    check: str  # 安装检测命令，如 "nuclei -version"
    install: list[InstallRecipe] = Field(min_length=1)
    parser: str | None = None  # 输出解析器标识（解析器属后续里程碑）
    tags: list[str] = Field(default_factory=list)
    image: str | None = None  # M3b：沙箱运行镜像覆盖（如 sqlmap 需 python 镜像）


def load_manifest(path: str | Path) -> ToolManifest:
    """加载并校验一份 manifest YAML；不合规即抛 ValidationError。"""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return ToolManifest.model_validate(data)
