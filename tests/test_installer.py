"""工具安装器测试（§5.2：local → binary → 包管理器；安装即缓存）。"""

import json

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
