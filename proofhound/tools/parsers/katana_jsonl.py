"""katana ``-jsonl`` 输出解析器（manifest parser 标识：``katana_jsonl``）。

katana 的 JSONL 输出每行一个 ``{"request": {...}, "response": {...}}``
对象。逐行解析；坏行跳过并计数（解析容错，但计数进审计）。M3d 只覆盖
**GET 且 URL 含非空 query** 的带参端点——逐条产 ``kind="param-endpoint"``
Signal（POST、无 query 的记录丢弃不计坏行）；每条 Signal 的
``evidence_ref`` 指向原始输出文件的对应行号（``路径#L<行号>``）。

带参端点两个来源（v1.7.0 实测）：

1. katana 直接发现的带 query GET 端点（链接/重定向等）；
2. **分支 B（GET 表单合成）**：katana 默认不自动填充表单（``-aff``
   experimental 会真实提交含 logout/security 的 POST 表单，副作用不可控，
   不采用），GET 表单由本解析器从 ``response.body`` 用 html.parser 确定性
   提取，按表单 action + 字段名合成查询 URL（method 缺省按 GET 处理）。
   零副作用：不向目标提交任何表单。
   **无 value 字段统一填占位值 "1"**（有 value 取 value）：渗透爬行惯例
   ——空值参数会让下游行为验证失去 baseline 可比（DVWA 实靶实测：sqlmap
   对空 id 判 "not injectable"，填 1 即确认）。

同一合成/发现 URL 跨行去重（首见行号锚点），输出顺序确定。
"""

from __future__ import annotations

import json
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlparse

from proofhound.findings.signal import Signal

# GET 表单提交时不参与的 input 类型（其余带 name 即收，宁宽勿漏——
# 下游 triage 启发式键名与 scope 校验做过滤）
_NON_SUBMIT_INPUT_TYPES = frozenset({"button", "reset", "file", "image"})


class _GetFormExtractor(HTMLParser):
    """从 HTML 提取 GET 表单（action + 字段名/值），零依赖确定性解析。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []  # [{"action": str, "fields": [(name, value)]}]
        self._mode: str | None = None  # None | "get" | "post"
        self._action = ""
        self._fields: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            if self._mode is not None:
                return  # 嵌套表单：按坏 HTML 忽略内层
            method = (attrs.get("method") or "get").strip().lower()
            self._mode = "get" if method == "get" else "post"
            self._action = attrs.get("action") or ""
            self._fields = []
            return
        if self._mode != "get" or tag not in ("input", "select", "textarea"):
            return
        if tag == "input" and (attrs.get("type") or "text").strip().lower() in (
            _NON_SUBMIT_INPUT_TYPES
        ):
            return
        name = attrs.get("name")
        if name:
            # 无 value 字段填占位 "1"：空值会让下游行为验证失去 baseline 可比
            self._fields.append((name, attrs.get("value") or "1"))

    def handle_endtag(self, tag):
        if tag == "form" and self._mode is not None:
            if self._mode == "get" and self._fields:
                self.forms.append(
                    {"action": self._action, "fields": list(self._fields)}
                )
            self._mode = None


def _extract_get_form_urls(page_url: str, body: str) -> list[str]:
    """从页面 HTML 提取 GET 表单并合成查询 URL（保序、页内去重）。"""
    extractor = _GetFormExtractor()
    try:
        extractor.feed(body)
        extractor.close()
    except Exception:
        return []  # 坏 HTML 不致命：表单提取是 best-effort 增强
    urls: list[str] = []
    for form in extractor.forms:
        fields = list(dict.fromkeys(form["fields"]))
        if not fields:
            continue
        joined = urljoin(page_url, form["action"])  # 空 action → 页面自身
        parts = urlparse(joined)
        base = parts._replace(fragment="").geturl()
        sep = "&" if parts.query else "?"
        url = f"{base}{sep}{urlencode(fields)}"
        if url not in urls:
            urls.append(url)
    return urls


def parse_katana_jsonl(
    text: str,
    *,
    evidence_path: str,
    skill: str,
    source_tool: str = "katana",
) -> tuple[list[Signal], int]:
    """解析 katana JSONL 输出，返回 ``(signals, skipped_lines)``。"""
    signals: list[Signal] = []
    seen: set[str] = set()  # 跨行去重（首见锚点）
    skipped = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if not isinstance(data, dict):
            skipped += 1
            continue
        request = data.get("request")
        if not isinstance(request, dict):
            skipped += 1  # 无 request 段无法判型，fail-closed 计坏行
            continue
        endpoint = request.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            skipped += 1
            continue
        response = data.get("response")
        status_code = (
            response.get("status_code") if isinstance(response, dict) else None
        )
        assets: list[str] = []
        if request.get("method") == "GET" and urlparse(endpoint).query:
            assets.append(endpoint)  # 来源 1：直接发现的带 query GET 端点
        body = response.get("body") if isinstance(response, dict) else None
        if isinstance(body, str) and "<form" in body:
            assets.extend(_extract_get_form_urls(endpoint, body))  # 分支 B
        for asset in assets:
            if asset in seen:
                continue
            seen.add(asset)
            signals.append(
                Signal(
                    asset=asset,
                    status_code=(
                        status_code if isinstance(status_code, int) else None
                    ),
                    kind="param-endpoint",
                    source_tool=source_tool,
                    skill=skill,
                    evidence_ref=f"{evidence_path}#L{lineno}",
                )
            )
    return signals, skipped
