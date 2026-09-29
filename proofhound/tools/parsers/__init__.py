"""工具输出解析器（§5.2）：确定性解析（regex/JSON，非 LLM）。

每个工具 manifest 的 ``parser`` 标识对应本包一个解析函数，统一登记在
:data:`PARSER_REGISTRY`；原始输出全文已落盘 ``evidence/``，解析器只把
结构化 Signal 交给编排器（红线 3）。
"""

from proofhound.tools.parsers.dirsearch_json import parse_dirsearch_json
from proofhound.tools.parsers.httpx_json import parse_httpx_jsonl
from proofhound.tools.parsers.katana_jsonl import parse_katana_jsonl
from proofhound.tools.parsers.sqlmap_stdout import (
    SqlmapReport,
    SqlmapTechnique,
    parse_sqlmap_stdout,
)

# key = ToolManifest.parser 标识
# 注意：sqlmap_stdout 是验证结论解析器（产 SqlmapReport 而非 Signal），
# 不登记进本注册表——该表契约是 Signal 解析器，供 scan 阶段自动桥接。
PARSER_REGISTRY = {
    "dirsearch_json": parse_dirsearch_json,
    "httpx_json": parse_httpx_jsonl,
    "katana_jsonl": parse_katana_jsonl,
}

__all__ = [
    "PARSER_REGISTRY",
    "parse_dirsearch_json",
    "SqlmapReport",
    "SqlmapTechnique",
    "parse_httpx_jsonl",
    "parse_katana_jsonl",
    "parse_sqlmap_stdout",
]
