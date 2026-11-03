"""工具安装器测试（§5.2：local → binary → 包管理器；安装即缓存）。"""

import json
import subprocess
from pathlib import Path

import pytest

from proofhound.tools.installer import InstallError, ToolInstaller
from proofhound.tools.manifest import ToolManifest


def make_manifest(install):
    return ToolManifest.model_validate(
        {
            "name": "demo-tool",
            "version": "1.0.0",
            "check": "demo-tool",
            "install": install,
        }
    )


class TestLocalRecipe:
    def test_install_from_preinstalled_dir(self, tmp_path, demo_tool_preinstalled):
        manifest = make_manifest(
            [{"type": "local", "path": str(demo_tool_preinstalled)}]
        )
        installer = ToolInstaller(tmp_path / "tools.d")
        result = installer.ensure(manifest)

        assert result.status == "installed"
        assert result.source == "local"
        binary = tmp_path / "tools.d" / "demo-tool" / "demo-tool"
        assert binary.is_file()
        assert binary.stat().st_mode & 0o111  # 可执行

        snapshot = json.loads(installer.state_file.read_text(encoding="utf-8"))
        assert snapshot["demo-tool"]["version"] == "1.0.0"
        assert snapshot["demo-tool"]["source"] == "local"

    def test_missing_preinstalled_path_fails(self, tmp_path):
        manifest = make_manifest([{"type": "local", "path": str(tmp_path / "nope")}])
        with pytest.raises(InstallError, match="所有安装配方均失败"):
            ToolInstaller(tmp_path / "tools.d").ensure(manifest)


class TestBinaryRecipe:
    def test_download_verify_install(self, tmp_path, demo_tool_zip, http_server):
        url, sha256 = demo_tool_zip
        _, _, handler = http_server
        manifest = make_manifest(
            [{"type": "binary", "url": url, "sha256": sha256}]
        )
        installer = ToolInstaller(tmp_path / "tools.d", allowed_hosts=["127.0.0.1"])
        result = installer.ensure(manifest)

        assert result.status == "installed"
        assert result.source == "binary"
        assert (tmp_path / "tools.d" / "demo-tool" / "demo-tool").is_file()
        assert handler.get_count == 1

    def test_same_version_reinstall_is_skipped(
        self, tmp_path, demo_tool_zip, http_server
    ):
        url, sha256 = demo_tool_zip
        _, _, handler = http_server
        manifest = make_manifest(
            [{"type": "binary", "url": url, "sha256": sha256}]
        )
        installer = ToolInstaller(tmp_path / "tools.d", allowed_hosts=["127.0.0.1"])

        first = installer.ensure(manifest)
        second = installer.ensure(manifest)

        assert first.status == "installed"
        assert second.status == "skipped"
        assert handler.get_count == 1  # 没有第二次下载

    def test_sha256_mismatch_rejected(self, tmp_path, demo_tool_zip):
        url, _ = demo_tool_zip
        manifest = make_manifest(
            [{"type": "binary", "url": url, "sha256": "0" * 64}]
        )
        installer = ToolInstaller(tmp_path / "tools.d", allowed_hosts=["127.0.0.1"])
        with pytest.raises(InstallError, match="SHA256 校验失败"):
            installer.ensure(manifest)
        assert not (tmp_path / "tools.d" / "demo-tool" / "demo-tool").exists()

    def test_non_whitelisted_host_rejected(self, tmp_path):
        manifest = make_manifest(
            [
                {
                    "type": "binary",
                    "url": "https://evil.example.com/tool.zip",
                    "sha256": "0" * 64,
                }
            ]
        )
        installer = ToolInstaller(
            tmp_path / "tools.d", allowed_hosts=["github.com"]
        )
        with pytest.raises(InstallError, match="白名单"):
            installer.ensure(manifest)

    def test_recipe_priority_local_before_binary(
        self, tmp_path, demo_tool_preinstalled, demo_tool_zip, http_server
    ):
        url, sha256 = demo_tool_zip
        _, _, handler = http_server
        manifest = make_manifest(
            [
                {"type": "local", "path": str(demo_tool_preinstalled)},
                {"type": "binary", "url": url, "sha256": sha256},
            ]
        )
        installer = ToolInstaller(tmp_path / "tools.d", allowed_hosts=["127.0.0.1"])
        result = installer.ensure(manifest)

        assert result.source == "local"
        assert handler.get_count == 0  # local 命中后不再尝试下载


class TestSkipLogic:
    def test_snapshot_matches_but_binary_missing_reinstalls(
        self, tmp_path, demo_tool_preinstalled
    ):
        manifest = make_manifest(
            [{"type": "local", "path": str(demo_tool_preinstalled)}]
        )
        installer = ToolInstaller(tmp_path / "tools.d")
        installer.ensure(manifest)

        # 快照还在，但二进制被删 → 必须重新安装而不是误跳过
        (tmp_path / "tools.d" / "demo-tool" / "demo-tool").unlink()
        result = installer.ensure(manifest)
        assert result.status == "installed"


class TestPipWrapperEchoArtifact:
    """M31-f 回归：pip wrapper 要把容器内产出 cat 回 stdout，并保住退出码。

    真实缺陷：dirsearch 的报告写进 ``/tmp/ds_report.json``（rootfs 只读，``/tmp`` 是
    tmpfs，**随容器销毁**），而 pip 配方生成的 wrapper 只有一句 ``exec python3 ...``，
    从不回显——``parsers/dirsearch_json.py`` 于是永远拿不到 JSON 报告，
    ``signals_recorded: dirsearch count=0``。离线预置 wrapper
    （``scripts/make_dirsearch_preset.py``）一直是带 cat 的，两条配方各说各话。
    """

    ECHO = "/tmp/ds_report.json"

    @pytest.fixture
    def artifact_path(self):
        """把 /tmp/ds_report.json 借给测试用，结束（或抛错）时恢复原状。"""
        path = Path(self.ECHO)
        backup = path.read_text(encoding="utf-8") if path.is_file() else None
        try:
            yield path
        finally:
            if backup is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(backup, encoding="utf-8")

    def _install_fake_tool(self, tmp_path, *, body: str):
        """在 tools.d/demo-tool/lib/bin/ 里放一个假 console script，生成 wrapper。"""
        from proofhound.tools.installer import WRAPPER_ECHO_ARTIFACT

        assert WRAPPER_ECHO_ARTIFACT == self.ECHO  # 常量与用例同步
        manifest = make_manifest(
            [{"type": "local", "path": str(tmp_path / "nonexistent")}]
        )
        lib_dir = tmp_path / "tools.d" / manifest.name / "lib"
        (lib_dir / "bin").mkdir(parents=True)
        (lib_dir / "bin" / manifest.name).write_text(body, encoding="utf-8")
        ToolInstaller(tmp_path / "tools.d")._write_pip_wrapper(manifest, lib_dir)
        return lib_dir.parent / manifest.name

    def test_wrapper_preserves_exit_code_and_stdout(self, tmp_path):
        """工具失败（exit 3）时：wrapper 的 stdout 仍完整、退出码仍是 3。

        旧实现用 ``exec``，这两条本来也成立；但去掉 exec 之后**必须**显式 ``exit``，
        否则 ``cat`` 的退出码会盖掉工具的真实退出码（128 就成了假成功/假失败）。
        """
        wrapper = self._install_fake_tool(
            tmp_path,
            body='import sys\nprint("TOOL-STDOUT")\nsys.exit(3)\n',
        )
        proc = subprocess.run(
            ["sh", str(wrapper)], capture_output=True, text=True, timeout=60
        )
        assert proc.returncode == 3, proc
        assert "TOOL-STDOUT" in proc.stdout

    def test_wrapper_echoes_artifact_after_tool_output(self, tmp_path, artifact_path):
        """产出存在时：内容追加在工具 stdout **之后**，退出码依然透传。"""
        artifact_path.write_text('{"results": [{"url": "https://h/a"}]}', encoding="utf-8")
        wrapper = self._install_fake_tool(
            tmp_path,
            body='import sys\nprint("TOOL-STDOUT")\nsys.exit(0)\n',
        )
        proc = subprocess.run(
            ["sh", str(wrapper)], capture_output=True, text=True, timeout=60
        )
        assert proc.returncode == 0, proc
        out = proc.stdout
        assert "TOOL-STDOUT" in out
        assert '{"results": [{"url": "https://h/a"}]}' in out
        # 顺序：先工具输出，后回显产出（解析器按"最后一段 JSON"定位报告）
        assert out.index("TOOL-STDOUT") < out.index('"results"')

    def test_wrapper_is_silent_when_tool_produced_nothing(self, tmp_path, artifact_path):
        """没有产出时不得凭空输出（否则解析器会把空当坏输入）。"""
        artifact_path.unlink(missing_ok=True)
        wrapper = self._install_fake_tool(
            tmp_path, body='print("ONLY-TOOL-OUTPUT")\n'
        )
        proc = subprocess.run(
            ["sh", str(wrapper)], capture_output=True, text=True, timeout=60
        )
        assert proc.returncode == 0, proc
        assert proc.stdout.strip() == "ONLY-TOOL-OUTPUT"
