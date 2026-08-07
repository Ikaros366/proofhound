"""llm 模块（M2b）：OpenAI 兼容协议的最小单模型客户端。

模型路由（T0/T1/T2 分级）、预算帽、上下文治理属 M2c。
"""

from proofhound.llm.client import LLMClient, LLMConfig, LLMError, load_dotenv

__all__ = ["LLMClient", "LLMConfig", "LLMError", "load_dotenv"]
