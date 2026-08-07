"""工具输出解析器（§5.2）：确定性解析（regex/JSON，非 LLM）。

每个工具 manifest 的 ``parser`` 标识对应本包一个解析函数，统一登记在
:data:`PARSER_REGISTRY`；原始输出全文已落盘 ``evidence/``，解析器只把
结构化 Signal 交给编排器（红线 3）。
"""

from proofhound.tools.parsers.httpx_json import parse_httpx_jsonl

# key = ToolManifest.parser 标识
PARSER_REGISTRY = {
    "httpx_json": parse_httpx_jsonl,
}

__all__ = ["PARSER_REGISTRY", "parse_httpx_jsonl"]
