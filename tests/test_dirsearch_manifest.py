"""M16-b：dirsearch manifest（含依赖闭包）与 installer 闭包纪律。

锁三件事：

1. manifest schema：``closure`` 只对 ``pip`` 有意义；闭包每条必须 ``==`` 钉版 +
   64 位 sha256（缺哈希 = 让 pip 自己挑文件，违反钉版纪律）；
2. ``dirsearch.yaml`` 的实际内容：27 个发行件全钉哈希、``image``/``parser`` 齐备，
   且 ``parser`` 真在 ``PARSER_REGISTRY`` 里（否则扫阶段不会桥接）；
3. installer 的闭包路径**强制哈希**：哈希不符即拒装（不发起安装）。
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from proofhound.tools.installer import InstallError, ToolInstaller
from proofhound.tools.manifest import load_manifest
from proofhound.tools.parsers import PARSER_REGISTRY

MANIFESTS = __import__("pathlib").Path(__file__).parent.parent / "proofhound" / "tools" / "manifests"
DIRSEARCH = MANIFESTS / "dirsearch.yaml"

FAKE_SHA = "a" * 64


# ------------------------------------------------------------- schema 纪律


def test_closure_entry_requires_pinned_version():
    from proofhound.tools.manifest import ClosureEntry

    with pytest.raises(ValidationError):
        ClosureEntry(package="requests", sha256=FAKE_SHA)  # 缺 ==
    ok = ClosureEntry(package="requests==2.33.1", sha256=FAKE_SHA)
    assert ok.package == "requests==2.33.1"


def test_closure_entry_requires_full_sha256():
    from proofhound.tools.manifest import ClosureEntry

    with pytest.raises(ValidationError):
        ClosureEntry(package="requests==2.33.1", sha256="abc")
    with pytest.raises(ValidationError):
        ClosureEntry(package="requests==2.33.1", sha256="")  # 必填


def test_closure_only_meaningful_for_pip():
    from proofhound.tools.manifest import InstallRecipe

    with pytest.raises(ValidationError, match="closure 只对 pip"):
        InstallRecipe(type="go", package="x", closure=[])


def test_binary_recipe_still_requires_sha256():
    """回归：既有 binary 强制哈希纪律不受本轮影响。"""
    from proofhound.tools.manifest import InstallRecipe

    with pytest.raises(ValidationError, match="sha256"):
        InstallRecipe(type="binary", url="https://github.com/x/y.zip")


def test_pip_without_closure_stays_backward_compatible():
    """sqlmap 形态（无 closure）必须照旧通过校验。"""
    from proofhound.tools.manifest import InstallRecipe

    r = InstallRecipe(type="pip", package="sqlmap==1.10.8", sha256=FAKE_SHA)
    assert r.closure is None


# ------------------------------------------------------- 实际 manifest 内容


def test_dirsearch_manifest_shape():
    m = load_manifest(DIRSEARCH)
    assert m.name == "dirsearch"
    assert m.version == "0.5.0"
    assert m.image == "python:3.12-alpine"   # Python 工具需 python 镜像
    assert m.parser == "dirsearch_json"
    assert m.parser in PARSER_REGISTRY, "parser 必须在注册表里，否则扫阶段不桥接"
    assert [r.type for r in m.install] == ["local", "pip"]
    assert "recon" in m.tags


def test_dirsearch_local_recipe_points_at_tools_d():
    m = load_manifest(DIRSEARCH)
    local = next(r for r in m.install if r.type == "local")
    assert local.path == "./tools.d/dirsearch"


def test_dirsearch_pip_recipe_has_pinned_artifact_and_closure():
    m = load_manifest(DIRSEARCH)
    pip = next(r for r in m.install if r.type == "pip")
    assert pip.package == "dirsearch==0.5.0"
    assert pip.sha256 == "10dc3476fdc9e71d7a0f41b2745b2261f3a1833f4f8c9db9b3b9c6dfe41c9597"
    assert pip.closure is not None
    # 26 条依赖 + 1 条本体 = 27 个发行件（实测闭包）
    assert len(pip.closure) == 26
    for e in pip.closure:
        assert "==" in e.package
        assert len(e.sha256) == 64
        int(e.sha256, 16)  # 必须是合法十六进制


def test_dirsearch_closure_pins_the_cryptography_chain():
    """cryptography 经 requests-ntlm → spnego **真被导入**，必须钉进闭包。

    实现期实测：不装 cryptography 时容器内 `import requests_ntlm` 直接
    `ModuleNotFoundError: No module named 'cryptography'`（spnego._ntlm_raw.crypto
    导 `cryptography.hazmat.backends`）。故它不是"可选依赖"。
    """
    m = load_manifest(DIRSEARCH)
    pip = next(r for r in m.install if r.type == "pip")
    pkgs = {e.package.split("==")[0].lower(): e.package for e in pip.closure}
    for required in ("cryptography", "cffi", "pyspnego", "requests-ntlm",
                     "httpx-ntlm", "beautifulsoup4", "jinja2", "defusedcsv",
                     "defusedxml", "colorama", "requests", "httpx"):
        assert required in pkgs, f"闭包缺少 {required}"


def test_all_manifests_still_load():
    """回归：四个 manifest 一起加载不炸，旧三个形态不变。"""
    names = {}
    for f in sorted(MANIFESTS.glob("*.yaml")):
        m = load_manifest(f)
        names[m.name] = m
    assert set(names) == {"dirsearch", "httpx", "katana", "sqlmap"}
    assert names["httpx"].image is None
    assert names["katana"].image is None
    assert names["sqlmap"].image == "python:3.12-alpine"
    assert names["sqlmap"].install[1].closure is None  # 旧路径不变


# ----------------------------------------------------- installer 闭包纪律


def test_closure_install_rejects_hash_mismatch(tmp_path, monkeypatch):
    """哈希不符即拒装——不得回落到"先装上再说"。"""
    m = load_manifest(DIRSEARCH)
    pip = next(r for r in m.install if r.type == "pip")

    installer = ToolInstaller(tmp_path / "tools.d")

    def fake_find(self, package, sha256):
        # 声称 PyPI 上存在，但下载下来的内容哈希对不上
        return {
            "url": "https://files.pythonhosted.org/packages/fake.whl",
            "filename": "fake.whl",
            "digests": {"sha256": sha256},
        }

    def fake_urlretrieve(url, dest):
        from pathlib import Path
        Path(dest).write_bytes(b"not the real wheel")

    monkeypatch.setattr(ToolInstaller, "_find_pip_artifact_by_hash", fake_find)
    monkeypatch.setattr("urllib.request.urlretrieve", fake_urlretrieve)

    with pytest.raises(InstallError, match="SHA256 校验失败"):
        installer._install_pip_with_closure(pip, m)


def test_closure_install_rejects_artifact_outside_whitelist(tmp_path, monkeypatch):
    """下载源不在白名单（pypi.org / files.pythonhosted.org）即拒装。"""
    m = load_manifest(DIRSEARCH)
    pip = next(r for r in m.install if r.type == "pip")

    installer = ToolInstaller(tmp_path / "tools.d")

    def fake_find(self, package, sha256):
        return {
            "url": "https://evil.example.com/packages/fake.whl",
            "filename": "fake.whl",
            "digests": {"sha256": sha256},
        }

    monkeypatch.setattr(ToolInstaller, "_find_pip_artifact_by_hash", fake_find)

    with pytest.raises(InstallError, match="不在白名单"):
        installer._install_pip_with_closure(pip, m)


def test_closure_install_requires_wheel_not_sdist(tmp_path, monkeypatch):
    """闭包只收 wheel（sdist 需要构建工具链，且哈希纪律下不该现场编译）。"""
    m = load_manifest(DIRSEARCH)
    pip = next(r for r in m.install if r.type == "pip")
    installer = ToolInstaller(tmp_path / "tools.d")

    # _find_pip_artifact_by_hash 的"只要 wheel"逻辑：喂一个只有 sdist 的元数据
    real_urlopen = __import__("urllib.request", fromlist=["urlopen"]).urlopen

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    import json as _json

    def fake_urlopen(url, timeout=None):
        payload = _json.dumps({"urls": [
            {"filename": "x.tar.gz", "digests": {"sha256": "b" * 64},
             "url": "https://files.pythonhosted.org/x.tar.gz"},
        ]}).encode()
        return _Resp(payload)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(InstallError, match="wheel"):
        installer._find_pip_artifact_by_hash("pkg==1.0", "b" * 64)
    assert real_urlopen is not None  # 保留引用，避免未使用告警
