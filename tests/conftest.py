from __future__ import annotations

import base64
import functools
import hashlib
import threading
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


class _CountingHandler(SimpleHTTPRequestHandler):
    """记录 GET 次数的静态文件服务（用于断言"不重复下载"）。"""

    get_count = 0

    def do_GET(self):
        type(self).get_count += 1
        super().do_GET()

    def log_message(self, *args):
        pass


@pytest.fixture
def http_server(tmp_path):
    """本地 HTTP 服务，根目录为 tmp_path。返回 (base_url, served_dir, handler_cls)。"""
    _CountingHandler.get_count = 0
    handler = functools.partial(_CountingHandler, directory=str(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", tmp_path, _CountingHandler
    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture
def demo_tool_preinstalled(tmp_path):
    """用户预置工具目录（local 配方）。"""
    tool_dir = tmp_path / "preinstalled"
    tool_dir.mkdir()
    script = tool_dir / "demo-tool"
    script.write_text("#!/bin/sh\necho 'demo-tool 1.0.0'\n", encoding="utf-8")
    script.chmod(0o755)
    return tool_dir


@pytest.fixture
def demo_tool_zip(http_server):
    """binary 配方 fixture：本地 HTTP 服务上的 zip 包。返回 (url, sha256)。"""
    base_url, served_dir, _ = http_server
    zpath = served_dir / "demo-tool.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("demo-tool", "#!/bin/sh\necho 'demo-tool 1.0.0'\n")
    digest = hashlib.sha256(zpath.read_bytes()).hexdigest()
    return f"{base_url}/demo-tool.zip", digest


@pytest.fixture
def docker_client():
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env()
        client.ping()
    except Exception:
        pytest.skip("Docker 守护进程不可用")
    return client


@pytest.fixture
def chromium():
    """真实 Chromium 浏览器（M8b e2e）：playwright 或浏览器二进制缺失即 skip
    （仿 docker_client 先例，无浏览器环境自动跳过）。"""
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    try:
        pw = sync_playwright().start()
    except Exception:
        pytest.skip("playwright 启动失败")
    try:
        browser = pw.chromium.launch(headless=True)
    except Exception:
        pw.stop()
        pytest.skip("Chromium 二进制不可用（playwright install chromium）")
    yield browser
    browser.close()
    pw.stop()


@pytest.fixture
def sandbox_image(docker_client):
    from docker.errors import ImageNotFound

    image = "alpine:3.20"
    try:
        docker_client.images.get(image)
    except ImageNotFound:
        try:
            docker_client.images.pull(image)
        except Exception:
            pytest.skip(f"{image} 镜像不可用且拉取失败")
    return image


@pytest.fixture
def fake_tools_dir(tmp_path):
    """沙箱测试用假工具：回显参数，并探测工具目录是否只读。"""
    tool_dir = tmp_path / "tools.d" / "echo-tool"
    tool_dir.mkdir(parents=True)
    script = tool_dir / "echo-tool"
    script.write_text(
        "#!/bin/sh\n"
        'echo "args: $@"\n'
        "touch /opt/tools/echo-tool/MUTABLE 2>/dev/null && echo MUTABLE || echo READONLY\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return tmp_path / "tools.d"


@pytest.fixture
def make_skill_dir(tmp_path):
    """M2b 测试用 skill 目录工厂：写一个最小合法 SKILL.md，返回 skills 根目录。"""

    def _make(name="web-scan", tools=("httpx",), body="SOP 正文：先探活，再解析。"):
        skill_dir = tmp_path / "skills" / name
        skill_dir.mkdir(parents=True)
        skill_dir.joinpath("SKILL.md").write_text(
            f"---\n"
            f"name: {name}\n"
            f"description: 测试用 skill\n"
            f"version: 1.0.0\n"
            f"required_tools: [{', '.join(tools)}]\n"
            f"risk_level: L1\n"
            f"inputs: [targets]\n"
            f"outputs: [signals]\n"
            f"---\n"
            f"\n{body}\n",
            encoding="utf-8",
        )
        return tmp_path / "skills"

    return _make


@pytest.fixture
def report_evidence_dir(tmp_path):
    """M4 报告测试用证据目录：四态 findings + 证据包 + audit（时间窗派生源）。

    桶分布：confirmed ×2（critical/high，供 severity 排序断言）、
    reproduced ×1、hypothesis ×1、rejected ×1（带 rejection_reason）。
    """
    from proofhound.compliance.audit import AuditLog
    from proofhound.findings.evidence import assemble_evidence_pack
    from proofhound.findings.finding import Finding, FindingStore, Verification

    directory = tmp_path / "evidence"
    directory.mkdir()
    log = directory / "run1.stdout.log"
    log.write_text("line1\nline2 inject point\nline3\n", encoding="utf-8")

    store = FindingStore(directory / "findings.jsonl")

    def _finding(fid, state, vuln_type, severity, **overrides):
        defaults = dict(
            id=fid,
            state=state,
            vuln_type=vuln_type,
            severity=severity,
            asset=f"http://127.0.0.1:9/app?q={fid[-4:]}",
            title=f"{vuln_type} 标题",
            dedup_key=f"sha256:{fid}",
            evidence_kinds=["status-code"],
            created_at="2026-08-07T00:00:00.000+00:00",
            updated_at="2026-08-07T00:00:00.000+00:00",
        )
        defaults.update(overrides)
        return Finding(**defaults)

    confirmed_high = _finding(
        "F-2026-0001", "confirmed", "sqli", "high",
        evidence_kinds=["status-code", "behavioral"],
        verification=Verification(
            method="sqlmap-confirmed",
            evidence_refs=[f"{log}#L2"],
            baseline_diff="真条件 1,203B / 假条件 217B",
            reproduction_steps=["步骤一", "步骤二"],
            verified_by="verify-sqli@1.0.0",
            verified_at="2026-08-07T01:00:00.000+00:00",
        ),
    )
    confirmed_critical = _finding("F-2026-0005", "confirmed", "rce", "critical")
    reproduced = _finding("F-2026-0002", "reproduced", "sqli", "medium")
    hypothesis = _finding("F-2026-0003", "hypothesis", "web-exposure", "info")
    rejected = _finding(
        "F-2026-0004", "rejected", "version-cve", "low",
        rejection_reason="版本匹配型 CVE 无行为验证，铁律禁止直接 Confirmed",
    )
    for finding in (
        confirmed_high, confirmed_critical, reproduced, hypothesis, rejected,
    ):
        store.append(finding)
    # 只有 confirmed_high 组装证据包（其余验证 assembled=False 路径）
    assemble_evidence_pack(confirmed_high, evidence_base=directory)

    audit = AuditLog(directory / "audit.jsonl")
    audit.record("demo_start", note="开始")
    audit.record("demo_end", note="结束")
    return directory


# ---- M14：API 认证默认开启后的测试客户端凭据 ----

DEFAULT_API_USER = "shangyun"
DEFAULT_API_PASSWORD = "123456"


def basic_auth_header(
    user: str = DEFAULT_API_USER, password: str = DEFAULT_API_PASSWORD
) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


@pytest.fixture(autouse=True)
def api_credentials(monkeypatch):
    """M14：让 API 认证在测试里**照常生效**，同时不给 9 个测试文件的 19 处 client
    构造加样板。

    - 固定 ``PROOFHOUND_API_USER/PASSWORD`` 环境变量：凭据判定不受本机 ``.env``
      影响，测试因此可判定；
    - 给 ``TestClient`` 注入默认 ``Authorization`` 头——这是**如实带上凭据**，
      不是绕过校验。想测无凭据/错凭据的用例显式传 ``headers=...`` 覆盖，
      或传 ``api_auth=False`` 关掉注入（见 ``tests/test_api_auth.py``）。
    """
    from fastapi.testclient import TestClient

    monkeypatch.setenv("PROOFHOUND_API_USER", DEFAULT_API_USER)
    monkeypatch.setenv("PROOFHOUND_API_PASSWORD", DEFAULT_API_PASSWORD)

    original_init = TestClient.__init__

    def patched_init(self, app, *args, **kwargs):
        if kwargs.pop("api_auth", True):
            headers = dict(kwargs.pop("headers", None) or {})
            headers.setdefault("Authorization", basic_auth_header())
            kwargs["headers"] = headers
        return original_init(self, app, *args, **kwargs)

    monkeypatch.setattr(TestClient, "__init__", patched_init)
