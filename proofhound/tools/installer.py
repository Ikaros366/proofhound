"""工具安装器（§5.2）：本地优先、缺失才装、安装即缓存。

执行顺序：
1. 运行 manifest 的 ``check`` 命令探测现有工具（PATH + ``tools.d/<name>/``），
   版本与 manifest 匹配则直接跳过——同版本工具绝不重复安装；
2. 缺失时按 manifest 中的配方优先级依次尝试：
   local（用户预置目录）→ binary（白名单源 + 强制 SHA256 校验）→
   go/apt/pip（包管理器兜底）；
3. 安装成功且自检通过后，写入版本快照 ``tools.d/installed.json``。
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .manifest import InstallRecipe, ToolManifest

# 默认允许的下载源（可在构造时覆盖，如测试中指向 127.0.0.1）
DEFAULT_ALLOWED_HOSTS = ("github.com", "objects.githubusercontent.com")

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _version_line(detected: str, version: str) -> str:
    """从 check 命令输出中取出版本行，用于快照与结果摘要。"""
    for line in detected.splitlines():
        if version in line:
            return line.strip()
    return detected.splitlines()[0].strip() if detected else ""


class InstallError(RuntimeError):
    """所有安装配方均失败，或安装过程违反安全纪律（白名单/哈希校验）。"""


@dataclass
class InstallResult:
    status: str  # "installed" | "skipped"
    source: str | None  # 命中的配方类型；"preexisting" 表示命中现有安装
    version: str
    detail: str = ""


class ToolInstaller:
    """按 manifest 安装工具并维护版本快照。"""

    def __init__(
        self,
        tools_dir: str | Path,
        allowed_hosts: tuple[str, ...] | list[str] = DEFAULT_ALLOWED_HOSTS,
        state_file: str | Path | None = None,
    ):
        self.tools_dir = Path(tools_dir)
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        self.state_file = (
            Path(state_file) if state_file else self.tools_dir / "installed.json"
        )

    def ensure(self, manifest: ToolManifest) -> InstallResult:
        """确保工具可用；同版本已安装时跳过，否则按配方优先级安装。"""
        detected = self.detect_version(manifest)
        if detected is not None and manifest.version in detected:
            version_line = _version_line(detected, manifest.version)
            if not self._snapshot_matches(manifest):
                self._write_snapshot(
                    manifest, source="preexisting", detected=version_line
                )
            return InstallResult(
                status="skipped",
                source="preexisting",
                version=manifest.version,
                detail=f"检测到现有安装且版本匹配（{version_line}），跳过",
            )

        errors: list[str] = []
        for recipe in manifest.install:
            try:
                self._apply(recipe, manifest)
            except Exception as exc:  # 配方失败，降级到下一优先级
                errors.append(f"{recipe.type}: {exc}")
                continue
            detected = self.detect_version(manifest)
            if detected is None:
                errors.append(f"{recipe.type}: 安装后自检命令仍失败")
                continue
            version_line = _version_line(detected, manifest.version)
            self._write_snapshot(manifest, source=recipe.type, detected=version_line)
            return InstallResult(
                status="installed",
                source=recipe.type,
                version=manifest.version,
                detail=version_line,
            )
        raise InstallError(
            f"工具 {manifest.name} 所有安装配方均失败: {'; '.join(errors)}"
        )

    def detect_version(self, manifest: ToolManifest) -> str | None:
        """运行 check 命令；成功返回完整输出（剥离 ANSI 转义），失败返回 None。"""
        argv = shlex.split(manifest.check)
        env = dict(os.environ)
        tool_bin = self.tools_dir / manifest.name
        env["PATH"] = f"{tool_bin}{os.pathsep}{env.get('PATH', '')}"
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=30, env=env
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        out = (proc.stdout or proc.stderr).strip()
        return _ANSI_RE.sub("", out)

    # ---- 配方实现 ----

    def _apply(self, recipe: InstallRecipe, manifest: ToolManifest) -> None:
        handler = {
            "local": self._install_local,
            "binary": self._install_binary,
            "go": self._install_go,
            "apt": self._install_apt,
            "pip": self._install_pip,
        }[recipe.type]
        handler(recipe, manifest)

    def _install_local(self, recipe: InstallRecipe, manifest: ToolManifest) -> None:
        src = Path(recipe.path)
        if not src.exists():
            raise InstallError(f"预置路径不存在: {src}")
        binary = src / manifest.name if src.is_dir() else src
        if not binary.is_file():
            raise InstallError(f"预置目录中找不到可执行文件: {binary}")
        dst = self._tool_bin_path(manifest)
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not (dst.exists() and dst.samefile(binary)):
            shutil.copy2(binary, dst)
        self._make_executable(dst)

    def _install_binary(self, recipe: InstallRecipe, manifest: ToolManifest) -> None:
        host = (urlparse(recipe.url).hostname or "").lower()
        if host not in self.allowed_hosts:
            raise InstallError(f"下载源不在白名单内: {host or recipe.url}")
        dst = self._tool_bin_path(manifest)
        dst.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "download"
            urllib.request.urlretrieve(recipe.url, archive)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if digest.lower() != recipe.sha256.lower():
                raise InstallError(
                    f"SHA256 校验失败: 期望 {recipe.sha256}，实际 {digest}"
                )
            if zipfile.is_zipfile(archive):
                with zipfile.ZipFile(archive) as zf:
                    zf.extractall(tmp)
                candidates = [
                    p for p in Path(tmp).rglob(manifest.name) if p.is_file()
                ]
                if not candidates:
                    raise InstallError(f"压缩包中未找到可执行文件 {manifest.name}")
                shutil.copy2(candidates[0], dst)
            else:
                shutil.copy2(archive, dst)
        self._make_executable(dst)

    def _install_go(self, recipe: InstallRecipe, manifest: ToolManifest) -> None:
        if shutil.which("go") is None:
            raise InstallError("go 工具链不可用")
        subprocess.run(["go", "install", recipe.package], check=True, timeout=600)

    def _install_apt(self, recipe: InstallRecipe, manifest: ToolManifest) -> None:
        if shutil.which("apt-get") is None:
            raise InstallError("apt-get 不可用")
        subprocess.run(
            ["apt-get", "install", "-y", recipe.package], check=True, timeout=600
        )

    def _install_pip(self, recipe: InstallRecipe, manifest: ToolManifest) -> None:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", recipe.package],
            check=True,
            timeout=600,
        )

    # ---- 版本快照 ----

    def _tool_bin_path(self, manifest: ToolManifest) -> Path:
        return self.tools_dir / manifest.name / manifest.name

    def _load_state(self) -> dict:
        if self.state_file.exists():
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        return {}

    def _snapshot_matches(self, manifest: ToolManifest) -> bool:
        entry = self._load_state().get(manifest.name)
        return bool(entry and entry.get("version") == manifest.version)

    def _write_snapshot(
        self, manifest: ToolManifest, source: str, detected: str
    ) -> None:
        state = self._load_state()
        state[manifest.name] = {
            "version": manifest.version,
            "detected": detected,
            "source": source,
            "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(
            json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    @staticmethod
    def _make_executable(path: Path) -> None:
        path.chmod(
            path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )
