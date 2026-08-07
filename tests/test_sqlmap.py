"""sqlmap 工具接入测试（M3b）：manifest、构造器强校验、stdout 解析器快照。

解析器配版本快照（tests/fixtures/sqlmap_*_1_10.txt，源自 sqlmap 1.10.8
输出格式），防工具输出格式随版本漂移。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from proofhound.compliance.session import SessionConfig
from proofhound.tools.build import build_command, params_schema
from proofhound.tools.manifest import load_manifest
from proofhound.tools.parsers import parse_sqlmap_stdout

FIXTURES = Path(__file__).parent / "fixtures"
MANIFEST = (
    Path(__file__).parent.parent / "proofhound" / "tools" / "manifests" / "sqlmap.yaml"
)
SESSION = SessionConfig(cookies={"PHPSESSID": "abc123", "security": "low"})
URL = "http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit"


# ---- manifest ----


def test_sqlmap_manifest_loads():
    manifest = load_manifest(MANIFEST)
    assert manifest.name == "sqlmap"
    assert manifest.version == "1.10.8"
    assert manifest.image == "python:3.12-alpine"  # 沙箱镜像覆盖声明
    assert manifest.parser == "sqlmap_stdout"
    pip = [r for r in manifest.install if r.type == "pip"][0]
    assert pip.package == "sqlmap==1.10.8"  # 版本 pin
    assert pip.sha256 and len(pip.sha256) == 64  # 强制 SHA256


def test_pip_recipe_with_sha256_requires_version_pin():
    with pytest.raises(ValidationError):
        load_manifest_data = {
            "name": "badtool",
            "version": "1.0",
            "check": "badtool --version",
            "install": [{"type": "pip", "package": "badtool", "sha256": "0" * 64}],
        }
        from proofhound.tools.manifest import ToolManifest

        ToolManifest.model_validate(load_manifest_data)


def test_httpx_manifest_has_no_image_override():
    manifest = load_manifest(MANIFEST.parent / "httpx.yaml")
    assert manifest.image is None


# ---- 构造器 ----


def test_sqlmap_argv_golden():
    argv = build_command("sqlmap", {"url": URL, "param": "id", "with_session": True}, session=SESSION)
    assert argv[:2] == ["sqlmap", "-u"]
    assert URL in argv
    assert argv[argv.index("--cookie") + 1] == "PHPSESSID=abc123; security=low"
    assert argv[argv.index("-p") + 1] == "id"
    # 禁交互/禁陈旧缓存/禁 ANSI 恒在，不接受参数覆盖
    for forced in ("--batch", "--flush-session", "--disable-coloring"):
        assert forced in argv
    assert argv[argv.index("--level") + 1] == "1"
    assert argv[argv.index("--risk") + 1] == "1"


def test_sqlmap_level_risk_caps():
    with pytest.raises(ValidationError):
        build_command("sqlmap", {"url": URL, "level": 4})
    with pytest.raises(ValidationError):
        build_command("sqlmap", {"url": URL, "risk": 3})
    with pytest.raises(ValidationError):
        build_command("sqlmap", {"url": URL, "level": 0})
    argv = build_command("sqlmap", {"url": URL, "level": 3, "risk": 2})
    assert argv[argv.index("--level") + 1] == "3"


def test_sqlmap_url_validation():
    with pytest.raises(ValidationError):
        build_command("sqlmap", {"url": "-o /etc/passwd"})
    with pytest.raises(ValidationError):
        build_command("sqlmap", {"url": "ftp://example.com/"})
    with pytest.raises(ValidationError):
        build_command("sqlmap", {"url": "example.com"})


def test_sqlmap_param_validation():
    with pytest.raises(ValidationError):
        build_command("sqlmap", {"url": URL, "param": "id; rm -rf /"})
    with pytest.raises(ValidationError):
        build_command("sqlmap", {"url": URL, "param": "--os-shell"})
    argv = build_command("sqlmap", {"url": URL})  # 不带 param：无 -p
    assert "-p" not in argv


def test_sqlmap_with_session_requires_session():
    with pytest.raises(ValueError, match="预置会话"):
        build_command("sqlmap", {"url": URL, "with_session": True})
    with pytest.raises(ValueError):
        build_command(
            "sqlmap",
            {"url": URL, "with_session": True},
            session=SessionConfig(),  # 空会话同样拒绝
        )


def test_sqlmap_without_session_has_no_cookie():
    argv = build_command("sqlmap", {"url": URL})
    assert "--cookie" not in argv


def test_sqlmap_proxy_injected():
    argv = build_command(
        "sqlmap", {"url": URL}, egress_proxy_url="http://127.0.0.1:18080"
    )
    assert argv[argv.index("--proxy") + 1] == "http://127.0.0.1:18080"


def test_sqlmap_params_schema_exposed():
    schema = params_schema("sqlmap")
    assert schema is not None
    assert set(schema["properties"]) >= {"url", "param", "with_session", "level", "risk"}


# ---- 解析器（版本快照） ----


def _anchor_line_of(text: str) -> int:
    for lineno, line in enumerate(text.split("\n"), start=1):  # \n 行号契约
        if "identified the following injection point(s)" in line:
            return lineno
    raise AssertionError("fixture 缺确认锚点行")


def test_parse_confirmed_fixture():
    """快照为 DVWA 实跑真实输出（sqlmap 1.10.8，cookie 已脱敏，含裸 \\r）。"""
    text = (FIXTURES / "sqlmap_confirmed_1_10.txt").read_text(encoding="utf-8")
    report = parse_sqlmap_stdout(text)
    assert report.confirmed
    assert report.parameter == "id"
    assert report.param_kind == "GET"
    assert report.anchor_line == _anchor_line_of(text)
    assert report.requests_total == 182
    types = [t.type for t in report.techniques]
    assert types == ["boolean-based blind", "error-based", "time-based blind", "UNION query"]
    boolean = report.techniques[0]
    assert "OR NOT 3041=3041" in boolean.payload
    assert "boolean-based blind" in boolean.title
    union = report.techniques[3]
    assert "UNION" in union.payload


def test_parse_negative_fixture():
    text = (FIXTURES / "sqlmap_negative_1_10.txt").read_text(encoding="utf-8")
    report = parse_sqlmap_stdout(text)
    assert not report.confirmed
    assert report.parameter is None
    assert report.techniques == []
    assert "do not appear to be injectable" in (report.note or "")


def test_parse_garbage_fail_closed():
    report = parse_sqlmap_stdout("完全的垃圾输出\n没有任何锚点\n")
    assert not report.confirmed
    assert report.note  # 有说明而非静默


def test_parse_anchor_without_details_not_confirmed():
    text = "sqlmap identified the following injection point(s) with a total of 3 HTTP(s) requests:\n---\n---\n"
    report = parse_sqlmap_stdout(text)
    assert not report.confirmed  # 锚点后无 Parameter/技术清单 → fail-closed
