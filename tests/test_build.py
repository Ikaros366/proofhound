"""命令构造器单元测试（M2b）：argv 唯一来源，LLM 不碰命令（红线 1）。"""

import pytest
from pydantic import ValidationError

from proofhound.tools.build import UnknownToolError, build_command, known_tools


def test_httpx_argv_golden():
    argv = build_command("httpx", {"target": "http://127.0.0.1:8000"})
    assert argv == [
        "httpx", "-u", "http://127.0.0.1:8000",
        "-status-code", "-title", "-tech-detect", "-follow-redirects",
        "-rate-limit", "50", "-json", "-silent", "-no-color",
    ]


def test_httpx_proxy_injected():
    argv = build_command(
        "httpx",
        {"target": "http://127.0.0.1:8000"},
        egress_proxy_url="http://127.0.0.1:18080",
    )
    assert argv[:4] == ["httpx", "-u", "http://127.0.0.1:8000", "-proxy"]
    assert "http://127.0.0.1:18080" in argv


def test_httpx_optional_flags():
    argv = build_command(
        "httpx",
        {"target": "h.tld", "tech_detect": False, "follow_redirects": False,
         "rate_limit": 10},
    )
    assert "-tech-detect" not in argv
    assert "-follow-redirects" not in argv
    assert argv[argv.index("-rate-limit") + 1] == "10"


def test_httpx_flag_injection_rejected():
    with pytest.raises(ValidationError):
        build_command("httpx", {"target": "-o /etc/passwd"})


def test_httpx_bad_params_rejected():
    with pytest.raises(ValidationError):
        build_command("httpx", {"target": "h.tld", "rate_limit": 0})
    with pytest.raises(ValidationError):
        build_command("httpx", {})


def test_unknown_tool():
    with pytest.raises(UnknownToolError):
        build_command("nmap", {"target": "h.tld"})


def test_known_tools():
    assert known_tools() == ["httpx", "sqlmap"]  # M3b：sqlmap 构造器接入
