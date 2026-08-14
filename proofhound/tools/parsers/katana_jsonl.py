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

M8a（POST 表单发现）：除分支 B 外，从 ``response.body`` 识别 POST 候选
表单，产 ``kind="form_page"`` Signal——asset 为**页面 URL 本身**（不拼
参数，forms 模式验证由 sqlmap 自行解析页面内表单），字段名清单存
``form_fields``（供 triage 启发式键名匹配）。合格表单规则：

- 规则 A：method 显式为 post（大小写不敏感）且 ≥1 个有 name 的
  input|select|textarea 字段（button/reset/file/image 不收）；
- 规则 B：method **缺省**、action 非空且含有 name 的密码/文本字段
  （登录类表单常缺省 method，密码/文本字段是 POST 意图信号）；
- **同源防线（fail-closed）**：两规则均要求 action 解析后与页面同源
  （scheme/host/port 一致，空 action = 页面自身）。forms 模式 sqlmap
  实际 POST 的目标是表单 action——跨域 action 会脱离 ``-u`` 的 scope
  校验覆盖面，故跨域表单一律不产候选；同页多个合格表单字段名并集进
  一条信号。

去重键为 ``(kind, asset)``：同一 URL 的 param-endpoint 与 form_page 是
两类信号、都保留；同类同 URL 跨行去重（首见行号锚点），输出顺序确定。
"""

from __future__ import annotations

import json
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlparse

from proofhound.findings.signal import Signal

# GET 表单提交时不参与的 input 类型（其余带 name 即收，宁宽勿漏——
# 下游 triage 启发式键名与 scope 校验做过滤）
_NON_SUBMIT_INPUT_TYPES = frozenset({"button", "reset", "file", "image"})

# M8a 规则 B 判定：有 name 且为密码/文本类的 input type（type 缺省按 text）
_TEXT_PASSWORD_INPUT_TYPES = frozenset({"text", "password"})


class _FormExtractor(HTMLParser):
    """从 HTML 提取全部表单（method/action/字段名值），零依赖确定性解析。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        # [{"method": str|None（原始值小写，缺省 None）, "action": str,
        #   "fields": [(name, value)], "has_text_or_password": bool}]
        self.forms: list[dict] = []
        self._open = False  # 是否处于某个 form 内（嵌套表单按坏 HTML 忽略内层）
        self._method: str | None = None
        self._action = ""
        self._fields: list[tuple[str, str]] = []
        self._has_text_or_password = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            if self._open:
                return  # 嵌套表单：按坏 HTML 忽略内层
            method = attrs.get("method")
            self._method = method.strip().lower() if method else None
            self._action = attrs.get("action") or ""
            self._fields = []
            self._has_text_or_password = False
            self._open = True
            return
        if not self._open or tag not in ("input", "select", "textarea"):
            return
        input_type = (
            (attrs.get("type") or "text").strip().lower() if tag == "input" else ""
        )
        if tag == "input" and input_type in _NON_SUBMIT_INPUT_TYPES:
            return
        name = attrs.get("name")
        if name:
            # 无 value 字段填占位 "1"：空值会让下游行为验证失去 baseline 可比
            self._fields.append((name, attrs.get("value") or "1"))
            if input_type in _TEXT_PASSWORD_INPUT_TYPES:
                self._has_text_or_password = True

    def handle_endtag(self, tag):
        if tag == "form" and self._open:
            self.forms.append(
                {
                    "method": self._method,
                    "action": self._action,
                    "fields": list(self._fields),
                    "has_text_or_password": self._has_text_or_password,
                }
            )
            self._open = False


def _extract_forms(body: str) -> list[dict]:
    """从页面 HTML 提取全部表单；坏 HTML 不致命（表单提取是 best-effort 增强）。"""
    extractor = _FormExtractor()
    try:
        extractor.feed(body)
        extractor.close()
    except Exception:
        return []
    return extractor.forms


def _synthesize_get_form_urls(page_url: str, forms: list[dict]) -> list[str]:
    """分支 B：GET 表单（method 缺省按 GET）合成查询 URL（保序、页内去重）。"""
    urls: list[str] = []
    for form in forms:
        if form["method"] not in (None, "get"):
            continue
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


def _same_origin(page_url: str, action: str) -> bool:
    """表单 action 解析后与页面同源（scheme/host/port 一致；空 action=页面自身）。

    fail-closed 防线（M8a）：forms 模式下 sqlmap 实际 POST 的目标是表单
    action——跨域 action 会脱离 ``-u``（页面 URL）的 scope 校验覆盖面，
    故跨域表单一律不产候选。端口显式比对（``http://h`` 与 ``http://h:80``
    视为不同源，宁漏勿放）。
    """
    try:
        page = urlparse(page_url)
        dest = urlparse(urljoin(page_url, action))
        return (page.scheme.lower(), page.hostname, page.port) == (
            dest.scheme.lower(),
            dest.hostname,
            dest.port,
        )
    except ValueError:
        return False  # 非法端口等解析异常：fail-closed


def _form_page_field_names(page_url: str, forms: list[dict]) -> list[str]:
    """M8a：页面内 POST 候选表单的有 name 字段名并集（保序去重）。

    合格表单规则 A（显式 post + 有 name 字段）/ B（method 缺省 + 非空
    action + 密码/文本字段）见模块 docstring；两规则均要求 action 同源。
    """
    names: list[str] = []
    for form in forms:
        method = form["method"]
        if method == "post":
            qualified = bool(form["fields"])
        elif method is None:
            qualified = bool(form["action"].strip()) and form["has_text_or_password"]
        else:
            qualified = False
        if not qualified or not _same_origin(page_url, form["action"]):
            continue
        for name, _value in form["fields"]:
            if name not in names:
                names.append(name)
    return names


def parse_katana_jsonl(
    text: str,
    *,
    evidence_path: str,
    skill: str,
    source_tool: str = "katana",
) -> tuple[list[Signal], int]:
    """解析 katana JSONL 输出，返回 ``(signals, skipped_lines)``。"""
    signals: list[Signal] = []
    seen: set[tuple[str, str]] = set()  # (kind, asset) 跨行去重（首见锚点）
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
        form_fields: list[str] = []
        body = response.get("body") if isinstance(response, dict) else None
        if isinstance(body, str) and "<form" in body:
            forms = _extract_forms(body)
            assets.extend(_synthesize_get_form_urls(endpoint, forms))  # 分支 B
            form_fields = _form_page_field_names(endpoint, forms)  # M8a
        for asset in assets:
            key = ("param-endpoint", asset)
            if key in seen:
                continue
            seen.add(key)
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
        # M8a：POST 候选表单页信号（asset=页面 URL 本身，不拼参数）；
        # 与 param-endpoint 按 (kind, asset) 分别去重，同 URL 两 kind 共存
        if form_fields and ("form_page", endpoint) not in seen:
            seen.add(("form_page", endpoint))
            signals.append(
                Signal(
                    asset=endpoint,
                    status_code=(
                        status_code if isinstance(status_code, int) else None
                    ),
                    kind="form_page",
                    source_tool=source_tool,
                    skill=skill,
                    evidence_ref=f"{evidence_path}#L{lineno}",
                    form_fields=form_fields,
                )
            )
    return signals, skipped
