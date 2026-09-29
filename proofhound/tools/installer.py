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
        if not recipe.sha256:
            # 旧路径（无哈希约束，仅兜底用途）：直接装进当前环境
            subprocess.run(
                [sys.executable, "-m", "pip", "install", recipe.package],
                check=True,
                timeout=600,
            )
            return
        if recipe.closure is not None:
            # M16-b：闭包路径（本体 + 依赖链一并钉哈希安装）
            self._install_pip_with_closure(recipe, manifest)
            return
        self._install_pip_pinned(recipe, manifest)

    # ---- pip + sha256（M3b：白名单源 + 版本 pin + 强制哈希 + 隔离安装） ----

    _PIP_METADATA_HOST = "pypi.org"
    _PIP_FILE_HOSTS = ("files.pythonhosted.org",)

    # ---- M16-b：pip + sha256 + **依赖闭包** ----

    #: 闭包安装的 wheel 平台标签。**与沙箱镜像耦合**：`image: python:3.12-alpine`
    #: ⇒ musllinux。宿主是 glibc，直接 `pip install --target` **找不到** musllinux
    #: wheel（实测报 `No matching distribution found for MarkupSafe`——因为宿主
    #: `sys_tags()` 里一个 musllinux 都没有），故必须交叉选择平台。
    _CLOSURE_PLATFORM = "musllinux_1_2_x86_64"
    _CLOSURE_PY_VERSION = "3.12"

    def _find_pip_artifact_by_hash(self, package: str, sha256: str) -> dict:
        """按 sha256 在 PyPI 元数据里精确定位 **wheel** 发行件（哈希即身份）。"""
        name, _, version = package.partition("==")
        meta_url = f"https://{self._PIP_METADATA_HOST}/pypi/{name}/{version}/json"
        try:
            with urllib.request.urlopen(meta_url, timeout=30) as resp:
                meta = json.load(resp)
        except (OSError, json.JSONDecodeError) as exc:
            raise InstallError(f"PyPI 元数据获取失败: {meta_url}（{exc}）") from exc
        wanted = sha256.lower()
        for item in meta.get("urls") or []:
            digests = item.get("digests") or {}
            if digests.get("sha256", "").lower() != wanted:
                continue
            if (item.get("filename") or "").endswith(".whl"):
                return item
        raise InstallError(
            f"PyPI 上找不到 sha256={sha256} 对应的 **wheel**（{package}）"
        )

    def _install_pip_with_closure(
        self, recipe: InstallRecipe, manifest: ToolManifest
    ) -> None:
        """装 本体 + 闭包：逐条校验哈希 → ``--require-hashes`` 安装到隔离目录。

        两道哈希纪律：① 下载后**逐条**重算 sha256 与 manifest 比对（不符即拒装）；
        ② 交给 pip 时仍写 ``--require-hashes``，由 pip 再校验一次。
        """
        entries: list[ClosureEntry] = list(recipe.closure or [])
        # 本体也纳入 --require-hashes（哈希模式下 pip 要求所有需求都带哈希）
        targets: list[tuple[str, str]] = [(recipe.package or "", recipe.sha256 or "")]
        targets += [(e.package, e.sha256) for e in entries]

        lib_dir = self.tools_dir / manifest.name / "lib"
        lib_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory() as tmp:
            wheelhouse = Path(tmp) / "wheels"
            wheelhouse.mkdir()
            lines: list[str] = []
            for package, sha in targets:
                artifact = self._find_pip_artifact_by_hash(package, sha)
                host = (urlparse(artifact["url"]).hostname or "").lower()
                if host not in self._PIP_FILE_HOSTS:
                    raise InstallError(
                        f"pip 下载源不在白名单内: {host or artifact['url']}"
                    )
                dest = wheelhouse / artifact["filename"]
                urllib.request.urlretrieve(artifact["url"], dest)
                digest = hashlib.sha256(dest.read_bytes()).hexdigest()
                if digest.lower() != sha.lower():
                    raise InstallError(
                        f"SHA256 校验失败（{package}）: 期望 {sha}，实际 {digest}"
                    )
                lines.append(f"{package} --hash=sha256:{sha.lower()}")

            requirements = Path(tmp) / "requirements.txt"
            requirements.write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
            subprocess.run(
                [
                    sys.executable, "-m", "pip", "install",
                    "--no-index",
                    f"--find-links={wheelhouse}",
                    "--require-hashes",
                    "--only-binary=:all:",
                    "--platform", self._CLOSURE_PLATFORM,
                    "--python-version", self._CLOSURE_PY_VERSION,
                    "--implementation", "cp",
                    "--abi", "cp" + self._CLOSURE_PY_VERSION.replace(".", ""),
                    "--upgrade", "--target", str(lib_dir),
                    "-r", str(requirements),
                ],
                check=True,
                timeout=900,
            )
        self._write_pip_wrapper(manifest, lib_dir)


    def _install_pip_pinned(
        self, recipe: InstallRecipe, manifest: ToolManifest
    ) -> None:
        """pip + sha256 配方：PyPI 元数据解析 → 哈希定位发行件 → 白名单源
        下载 → 二次校验 → 隔离安装到 ``tools.d/<name>/lib`` 并生成 wrapper。

        包名与版本来自 ``package`` 的 ``name==version`` pin（schema 层已强制）；
        发行件以 recipe.sha256 在 PyPI 元数据中精确匹配（wheel/sdist 均可），
        宿主限 pypi.org（元数据）与 files.pythonhosted.org（文件）。
        """
        name, _, version = (recipe.package or "").partition("==")
        meta_url = f"https://{self._PIP_METADATA_HOST}/pypi/{name}/{version}/json"
        try:
            with urllib.request.urlopen(meta_url, timeout=30) as resp:
                meta = json.load(resp)
        except (OSError, json.JSONDecodeError) as exc:
            raise InstallError(f"PyPI 元数据获取失败: {meta_url}（{exc}）") from exc
        artifact = self._match_pip_artifact(meta.get("urls") or [], recipe)
        file_host = (urlparse(artifact["url"]).hostname or "").lower()
        if file_host not in self._PIP_FILE_HOSTS:
            raise InstallError(f"pip 下载源不在白名单内: {file_host or artifact['url']}")

        lib_dir = self.tools_dir / manifest.name / "lib"
        lib_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / artifact["filename"]
            urllib.request.urlretrieve(artifact["url"], archive)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if digest.lower() != recipe.sha256.lower():
                raise InstallError(
                    f"SHA256 校验失败: 期望 {recipe.sha256}，实际 {digest}"
                )
            subprocess.run(
                [
                    sys.executable, "-m", "pip", "install",
                    "--no-deps", "--no-index", "--upgrade",
                    "--target", str(lib_dir), str(archive),
                ],
                check=True,
                timeout=600,
            )
        self._write_pip_wrapper(manifest, lib_dir)

    @staticmethod
    def _match_pip_artifact(urls: list[dict], recipe: InstallRecipe) -> dict:
        """在 PyPI 发行件列表中按 sha256 精确匹配（哈希即身份）。"""
        for item in urls:
            digests = item.get("digests") or {}
            if digests.get("sha256", "").lower() == recipe.sha256.lower():
                if not item.get("url") or not item.get("filename"):
                    break
                return item
        raise InstallError(
            f"PyPI 上找不到 sha256={recipe.sha256} 对应的发行件（{recipe.package}）"
        )

    def _write_pip_wrapper(self, manifest: ToolManifest, lib_dir: Path) -> None:
        """生成 ``tools.d/<name>/<name>`` wrapper：优先 console script
        （``lib/bin/<name>``），否则直跑 ``lib/<name>/<name>.py``；显式
        python3 + PYTHONPATH，宿主与容器（python 镜像）均可执行。"""
        console = Path("bin") / manifest.name
        module = Path(manifest.name) / f"{manifest.name}.py"
        if (lib_dir / console).is_file():
            entry = f'"$HERE/lib/{console}"'
        elif (lib_dir / module).is_file():
            entry = f'"$HERE/lib/{module}"'
        else:
            raise InstallError(
                f"pip 安装后找不到可执行入口: {lib_dir}/bin/{manifest.name} "
                f"或 {lib_dir}/{manifest.name}/{manifest.name}.py"
            )
        wrapper = lib_dir.parent / manifest.name
        wrapper.write_text(
            "#!/bin/sh\n"
            'HERE="$(cd "$(dirname "$0")" && pwd)"\n'
            f'PYTHONPATH="$HERE/lib${{PYTHONPATH:+:$PYTHONPATH}}" '
            f'exec python3 {entry} "$@"\n',
            encoding="utf-8",
        )
        self._make_executable(wrapper)

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
