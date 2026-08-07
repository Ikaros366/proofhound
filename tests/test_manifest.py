"""Tool Manifest schema 校验测试（§5.2）。"""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from proofhound.tools.manifest import ToolManifest, load_manifest

BUILTIN_MANIFEST = (
    Path(__file__).parent.parent / "proofhound" / "tools" / "manifests" / "httpx.yaml"
)

VALID = {
    "name": "demo-tool",
    "version": "1.0.0",
    "check": "demo-tool -version",
    "install": [{"type": "local", "path": "./tools.d/demo-tool"}],
    "parser": "demo_json",
    "tags": ["recon"],
}


def test_valid_manifest():
    manifest = ToolManifest.model_validate(VALID)
    assert manifest.name == "demo-tool"
    assert manifest.install[0].type == "local"


def test_binary_recipe_requires_sha256():
    data = {
        **VALID,
        "install": [{"type": "binary", "url": "https://github.com/x/y.zip"}],
    }
    with pytest.raises(ValidationError, match="sha256"):
        ToolManifest.model_validate(data)


def test_binary_recipe_requires_url():
    data = {**VALID, "install": [{"type": "binary", "sha256": "ab" * 32}]}
    with pytest.raises(ValidationError, match="url"):
        ToolManifest.model_validate(data)


def test_local_recipe_requires_path():
    data = {**VALID, "install": [{"type": "local"}]}
    with pytest.raises(ValidationError, match="path"):
        ToolManifest.model_validate(data)


def test_package_recipe_requires_package():
    data = {**VALID, "install": [{"type": "go"}]}
    with pytest.raises(ValidationError, match="package"):
        ToolManifest.model_validate(data)


def test_unknown_recipe_type_rejected():
    data = {**VALID, "install": [{"type": "curl-pipe-sh", "url": "https://x"}]}
    with pytest.raises(ValidationError):
        ToolManifest.model_validate(data)


def test_invalid_name_rejected():
    with pytest.raises(ValidationError):
        ToolManifest.model_validate({**VALID, "name": "Bad_Name!"})
    with pytest.raises(ValidationError):
        ToolManifest.model_validate({**VALID, "name": "-leading-dash"})


def test_install_list_must_not_be_empty():
    with pytest.raises(ValidationError):
        ToolManifest.model_validate({**VALID, "install": []})


def test_load_manifest_from_yaml(tmp_path):
    path = tmp_path / "demo.yaml"
    path.write_text(yaml.safe_dump(VALID), encoding="utf-8")
    manifest = load_manifest(path)
    assert manifest.version == "1.0.0"
    assert manifest.tags == ["recon"]


def test_builtin_httpx_manifest_is_valid():
    manifest = load_manifest(BUILTIN_MANIFEST)
    assert manifest.name == "httpx"
    binary = next(r for r in manifest.install if r.type == "binary")
    assert binary.url.startswith("https://github.com/")
    assert len(binary.sha256) == 64
