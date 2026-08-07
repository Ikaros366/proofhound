"""最小 LLM 客户端（M2b，§5.3）：OpenAI 兼容协议的单端点封装。

- 模型路由（T0/T1/T2 选路）、用量计量与预算帽见 M2c 的 llm/router.py、
  llm/usage.py；本模块只做单端点 HTTP，不含选路逻辑；
- 零第三方依赖：用 stdlib ``urllib`` POST ``{base_url}/chat/completions``；
- 配置来自环境变量（``PROOFHOUND_LLM_BASE_URL`` / ``PROOFHOUND_LLM_API_KEY`` /
  ``PROOFHOUND_LLM_MODEL``），缺省从 ``.env`` 读取；已有环境变量优先于 .env
  （M2c 起分档配置走 ``PROOFHOUND_T0/T1/T2_*``，见 llm/router.py）；
- 不做内置重试：失败分类与重试预算归编排器（core/failures.py）。
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ENV_BASE_URL = "PROOFHOUND_LLM_BASE_URL"
ENV_API_KEY = "PROOFHOUND_LLM_API_KEY"
ENV_MODEL = "PROOFHOUND_LLM_MODEL"


class LLMError(RuntimeError):
    """LLM 调用失败：网络异常、HTTP 非 2xx 或响应格式不符。"""


def load_dotenv(path: str | Path) -> dict[str, str]:
    """解析 .env（``KEY=VALUE`` 行，支持 # 注释与首尾引号），文件不存在返回空。"""
    path = Path(path)
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            values[key] = value
    return values


@dataclass
class LLMConfig:
    """单模型接入配置。"""

    base_url: str  # OpenAI 兼容端点，如 https://api.moonshot.cn/v1
    api_key: str
    model: str
    timeout: float = 60.0
    temperature: float | None = None  # 非 None 才进请求 payload
    max_tokens: int | None = None  # 同上

    @classmethod
    def from_env(cls, env_file: str | Path = ".env") -> "LLMConfig":
        """从环境变量构建配置；``.env`` 作为缺省值，已有环境变量优先。"""
        dotenv = load_dotenv(env_file)

        def _get(name: str) -> str | None:
            return os.environ.get(name) or dotenv.get(name)

        missing = [
            name
            for name in (ENV_BASE_URL, ENV_API_KEY, ENV_MODEL)
            if not _get(name)
        ]
        if missing:
            raise LLMError(
                f"缺少 LLM 配置: {', '.join(missing)}（环境变量或 .env 提供）"
            )
        return cls(
            base_url=_get(ENV_BASE_URL).rstrip("/"),
            api_key=_get(ENV_API_KEY),
            model=_get(ENV_MODEL),
        )


@dataclass
class CompletionResult:
    """一次补全的完整结果：文本 + 服务商 usage（可能缺失）+ 耗时。"""

    content: str
    usage: dict | None  # 响应中的 usage 字段；无则为 None（调用方按字符估算）
    latency_ms: float


class LLMClient:
    """OpenAI 兼容 chat/completions 的最小封装。"""

    def __init__(self, config: LLMConfig):
        self.config = config

    def complete(self, messages: list[dict]) -> str:
        """发起一次对话补全，返回 assistant 消息文本。失败抛 :class:`LLMError`。"""
        return self.complete_with_usage(messages).content

    def complete_with_usage(self, messages: list[dict]) -> CompletionResult:
        """同 :meth:`complete`，但返回 content + usage + 耗时（供路由层计量）。"""
        payload_dict = {"model": self.config.model, "messages": messages}
        if self.config.temperature is not None:
            payload_dict["temperature"] = self.config.temperature
        if self.config.max_tokens is not None:
            payload_dict["max_tokens"] = self.config.max_tokens
        payload = json.dumps(payload_dict).encode("utf-8")
        request = urllib.request.Request(
            f"{self.config.base_url}/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
            },
            method="POST",
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:500].decode("utf-8", errors="replace")
            raise LLMError(f"LLM HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise LLMError(f"LLM 连接失败: {exc.reason}") from exc
        except OSError as exc:  # timeout 等
            raise LLMError(f"LLM 请求异常: {exc}") from exc
        latency_ms = (time.monotonic() - started) * 1000
        try:
            data = json.loads(body)
            content = data["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"LLM 响应格式异常: {exc}") from exc
        if not isinstance(content, str):
            raise LLMError("LLM 响应 content 非文本")
        usage = data.get("usage")
        return CompletionResult(
            content=content,
            usage=usage if isinstance(usage, dict) else None,
            latency_ms=latency_ms,
        )
