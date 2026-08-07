from __future__ import annotations

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
