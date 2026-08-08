"""katana 命令构造器与 manifest 单元测试（M3d，红线 1：argv 唯一来源）。"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from proofhound.compliance.session import SessionConfig
from proofhound.tools.build import build_command
from proofhound.tools.manifest import load_manifest
from proofhound.tools.parsers import PARSER_REGISTRY

MANIFESTS_DIR = (
    Path(__file__).parent.parent / "proofhound" / "tools" / "manifests"
)


def test_katana_argv_golden():
    argv = build_command("katana", {"target": "http://127.0.0.1:8080"})
    assert argv == [
        "katana", "-u", "http://127.0.0.1:8080",
        "-d", "2", "-c", "5",
        "-jsonl", "-silent", "-nc", "-fs", "rdn",
        "-cos", "(?i)(logout|logoff|signout|signoff|phpids)",
    ]


def test_katana_optional_flags():
    argv = build_command(
        "katana",
        {"target": "http://h.tld", "depth": 3, "concurrency": 8, "rate_limit": 50},
        egress_proxy_url="http://127.0.0.1:18080",
    )
    assert argv[argv.index("-proxy") + 1] == "http://127.0.0.1:18080"
    assert argv[argv.index("-d") + 1] == "3"
    assert argv[argv.index("-c") + 1] == "8"
    assert argv[argv.index("-rl") + 1] == "50"
    assert "-o" not in argv  # 输出只走 stdout（红线 3），构造器永不产 -o


def test_katana_cos_constant_comma_free():
    """-cos 旗标按逗号分片：值含逗号会被截断失效（spike 实测教训）。"""
    argv = build_command("katana", {"target": "http://h.tld"})
    assert "," not in argv[argv.index("-cos") + 1]


def test_katana_flag_injection_rejected():
    with pytest.raises(ValidationError):
        build_command("katana", {"target": "-o /etc/passwd"})


def test_katana_bounds_rejected():
    with pytest.raises(ValidationError):
        build_command("katana", {"target": "h.tld", "depth": 0})
    with pytest.raises(ValidationError):
        build_command("katana", {"target": "h.tld", "depth": 6})
    with pytest.raises(ValidationError):
        build_command("katana", {"target": "h.tld", "concurrency": 0})
    with pytest.raises(ValidationError):
        build_command("katana", {"target": "h.tld", "concurrency": 11})
    with pytest.raises(ValidationError):
        build_command("katana", {"target": "h.tld", "rate_limit": 151})


def test_katana_session_injection():
    session = SessionConfig(
        cookies={"PHPSESSID": "abc123"}, headers={"X-Token": "t1"}
    )
    argv = build_command(
        "katana", {"target": "http://h.tld", "with_session": True}, session=session
    )
    headers = [argv[i + 1] for i, t in enumerate(argv) if t == "-H"]
    assert "Cookie: PHPSESSID=abc123" in headers
    assert "X-Token: t1" in headers


def test_katana_session_required_fail_closed():
    """with_session=True 而无会话配置：fail-closed 校验失败（凭据不绕行）。"""
    with pytest.raises(ValueError, match="预置会话"):
        build_command("katana", {"target": "http://h.tld", "with_session": True})


def test_katana_manifest_valid():
    manifest = load_manifest(MANIFESTS_DIR / "katana.yaml")
    assert manifest.name == "katana"
    assert manifest.parser == "katana_jsonl"
    assert manifest.parser in PARSER_REGISTRY
    binary = next(r for r in manifest.install if r.type == "binary")
    assert binary.sha256  # schema 层强制；白名单宿主由安装器校验
    assert "github.com" in binary.url
    assert "==" not in binary.url
    assert manifest.tags == ["recon", "web", "crawl"]
