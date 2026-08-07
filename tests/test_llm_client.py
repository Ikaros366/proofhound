"""最小 LLM 客户端单元测试（M2b）：零真实网络，urllib 层一律 mock。"""

import io
import json
import urllib.error

import pytest

from proofhound.llm.client import LLMClient, LLMConfig, LLMError, load_dotenv

_ENV_NAMES = (
    "PROOFHOUND_LLM_BASE_URL",
    "PROOFHOUND_LLM_API_KEY",
    "PROOFHOUND_LLM_MODEL",
)


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self) -> bytes:
        return self._body


def _config() -> LLMConfig:
    return LLMConfig(base_url="https://llm.example/v1", api_key="k", model="m")


def test_dotenv_parsing(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n"
        "A=1\n"
        'B="quoted"\n'
        "C='sq'\n"
        "export D=4\n"
        "BADLINE\n"
        "\n",
        encoding="utf-8",
    )
    assert load_dotenv(env) == {"A": "1", "B": "quoted", "C": "sq", "D": "4"}


def test_dotenv_missing_file(tmp_path):
    assert load_dotenv(tmp_path / ".env") == {}


def test_from_env_reads_dotenv(tmp_path, monkeypatch):
    for name in _ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    env = tmp_path / ".env"
    env.write_text(
        "PROOFHOUND_LLM_BASE_URL=https://file.example/v1/\n"
        "PROOFHOUND_LLM_API_KEY=filekey\n"
        "PROOFHOUND_LLM_MODEL=filemodel\n",
        encoding="utf-8",
    )
    cfg = LLMConfig.from_env(env)
    assert cfg.base_url == "https://file.example/v1"  # 尾斜杠被裁掉
    assert cfg.api_key == "filekey"
    assert cfg.model == "filemodel"


def test_from_env_environ_precedence(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        "PROOFHOUND_LLM_BASE_URL=https://file.example/v1\n"
        "PROOFHOUND_LLM_API_KEY=filekey\n"
        "PROOFHOUND_LLM_MODEL=filemodel\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PROOFHOUND_LLM_API_KEY", "envkey")
    cfg = LLMConfig.from_env(env)
    assert cfg.api_key == "envkey"  # 已有环境变量优先于 .env


def test_from_env_missing_raises(tmp_path, monkeypatch):
    for name in _ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(LLMError, match="PROOFHOUND_LLM_BASE_URL"):
        LLMConfig.from_env(tmp_path / ".env")


def test_complete_success(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["payload"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse(
            json.dumps({"choices": [{"message": {"content": "OK"}}]}).encode()
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = LLMClient(_config())
    out = client.complete([{"role": "user", "content": "hi"}])
    assert out == "OK"
    assert captured["url"] == "https://llm.example/v1/chat/completions"
    assert captured["payload"]["model"] == "m"
    assert captured["payload"]["messages"] == [{"role": "user", "content": "hi"}]
    assert captured["headers"]["Authorization"] == "Bearer k"


def test_complete_http_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 500, "server error", None, io.BytesIO(b"boom")
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(LLMError, match="HTTP 500"):
        LLMClient(_config()).complete([])


def test_complete_conn_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(LLMError, match="连接失败"):
        LLMClient(_config()).complete([])


def test_complete_bad_response(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout=None: _FakeResponse(b"not json"),
    )
    with pytest.raises(LLMError, match="格式异常"):
        LLMClient(_config()).complete([])
