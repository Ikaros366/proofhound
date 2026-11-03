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

import hashlib
import json
import re
from dataclasses import replace
from html.parser import HTMLParser
from urllib.parse import quote, urlencode, urljoin, urlparse

from proofhound.findings.signal import Signal
from proofhound.jsimport.crawl import JsDocument
from proofhound.jsimport.extract import extract_endpoints
from proofhound.jsimport.match import (
    DATA_PREFIXES,
    DATA_SEGMENTS,
    exclusion_reason,
    segments_of,
)

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



#: JS 正文字面量抽取后**不产候选**的路径前缀（静态资源面由 dirsearch 负责）
_JS_ENDPOINT_SKIP_TEMPLATE = "{param}"

#: 版本段（``/api/v1``）：与 :mod:`proofhound.jsimport.match` 同一套词表
_JS_VERSION_SEGMENT = re.compile(r"v[0-9]+")

#: 单段路径的合法字符（M33 实测收紧）：JS 里大量以 ``/`` 开头的字符串其实是
#: **正则字面量或代码片段**（``/,end:``、``/})]},l={className:``、``/\\*``），
#: 拼上 ``/api/v1`` 之后它们全都"像接口"，会把候选池灌成噪声（实测 50 条垃圾）。
#: 只接受词形段（字母数字与 ``._~-``），最多 6 段。
_JS_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~-]{1,64}")
_MAX_API_SEGMENTS = 6


def _is_clean_api_path(path_template: str) -> bool:
    """路径是否像"人写出来的接口路径"（不是正则/代码片段）。"""
    segments = [part for part in path_template.split("/") if part]
    if not segments or len(segments) > _MAX_API_SEGMENTS:
        return False
    return all(_JS_PATH_SEGMENT.fullmatch(part) for part in segments)


def _looks_like_api_path(path_template: str) -> bool:
    """路径本身必须带**数据线索**，否则不产 api-endpoint（M33 实测收敛）。

    只用 :mod:`~proofhound.jsimport.match` 的同一套词表（``DATA_PREFIXES`` /
    ``DATA_SEGMENTS``），不另立标准。两条实测必须挡住的形态：

    - ``/api/v1`` —— 这是 ``baseURL`` 常量本身（接口的**基址**，不是端点）；
    - ``/settings/providers/new`` —— 纯 SPA 路由。它带着 query 键，故能通过
      ``exclusion_reason`` 的"有 query 就算数据接口"这条口子；但匿名与已认证
      请求它都会拿到同一个空壳，进 ``unauth-exposure`` 会被判成**误确认**。
      SPA 路由归发现侧的页面面，不归接口面。
    """
    segments = segments_of(path_template)
    if not segments:
        return False
    if segments[0] not in DATA_PREFIXES:
        # 裸的 ``/users`` / ``/settings/providers/new`` 与 SPA 页面路由同名同形，
        # 匿名与已认证都会拿到同一个空壳 ⇒ 进 unauth-exposure 会被判成**误确认**。
        # 故只认带数据前缀的路径；没有前缀的 REST 风格接口本轮不产（已知代价）。
        return False
    rest = list(segments[1:])
    if rest and _JS_VERSION_SEGMENT.fullmatch(rest[0]):
        rest = rest[1:]
    if not rest:
        return False  # "/api/v1" 剥掉前缀与版本后为空 ⇒ 只是基址
    # 剩余段全是纯版本号（``/api/v1/v4``）⇒ 那是 semver 碎片被拼上基址，不是接口
    return not all(_JS_VERSION_SEGMENT.fullmatch(segment) for segment in rest)


def _candidate_paths(path_template: str, bases: list[str]) -> list[str]:
    """一个 JS 字面量可能对应的真实地址（M33：两条语义都算）。

    - 原样：字面量本身就是完整路径（``"/api/v1/info"``、``"/users/"``）；
    - 基址拼接：``baseURL: "/api/v1"`` + 字面量 ``"/info"`` ⇒ ``/api/v1/info``
      （axios 等框架的真实行为）。**这是假设**，故只在字面量以 ``/`` 开头、
      且尚未带基址时才补一条，调用方在 Signal.note 上标 ``+base`` 以示区别。
    """
    paths = [path_template]
    # 只对**单段**字面量做基址拼接：``get("/info")`` 这类是接口调用，而
    # ``/settings/providers/new``、``/assets/rest``、``/dev/null`` 基本都是页面
    # 或资源路由——把它们拼成 ``/api/v1/...`` 只会造出 404 噪声（实测 20 条
    # unauth 候选里大半是这类）。单段里的纯版本号（``/v4``）同样排除。
    segments = [part for part in path_template.split("/") if part]
    if len(segments) != 1 or _JS_VERSION_SEGMENT.fullmatch(segments[0]):
        return paths
    for base in bases:
        if not path_template.startswith("/"):
            continue
        if path_template == base or path_template.startswith(base + "/"):
            continue  # 已带基址，不再重复拼
        candidate = base + path_template
        if candidate not in paths:
            paths.append(candidate)
    return paths


def _js_endpoint_signals(
    endpoint: str,
    body: str,
    *,
    evidence_path: str,
    lineno: int,
    skill: str,
    source_tool: str,
    seen: set[tuple[str, str]],
    bases: list[str],
) -> list[Signal]:
    """M33：JS 正文里写死的接口路径 → ``api-endpoint``（+ 带 query 的 ``param-endpoint``）。

    为什么在这里做：``katana -jc`` 的抽取是**部分的**（限制 53 实测：同一份 bundle
    里 ``/api/profile`` 抽到、``/api/orders/1001`` 没抽到），而 ``jsimport`` 自己从
    ``response.body`` 抽的那套（M24-a）一直只有手工 CLI 入口、不进生产候选池。
    本函数把 M24-a 的抽取器接成**发现层生产者**，不新增第二套正则。

    收敛口径（与 M24-a 同一把尺子，不另立标准）：

    - 只认 :func:`~proofhound.jsimport.match.exclusion_reason` 判为「像数据接口」的
      路径——状态变更词、公开端点（login/logout/config…）、没有数据线索的纯 SPA
      路由一律不产。**SPA 页面路由不能进 unauth-exposure**：匿名与已认证都会拿到
      同一个空壳，"等价"会被误判成未授权暴露。
    - **路径模板**（``/users/{param}``）不产：没有观测实例就没法合成可信 URL。
    - 带 query 键的模板另产一条 ``param-endpoint``：把 JS 里写死的查询参数接进既有
      的 sqli/xss/idor 提示表（M24-a 抽到了却一直没人消费的那部分）。

    抽取失败一律返回空（best-effort 增强，绝不弄坏解析主链路）。
    """
    parsed = urlparse(endpoint)
    if not parsed.path.lower().endswith((".js", ".mjs")):
        return []  # 只对 JS 正文做抽取（JSON/HTML 不是接口清单来源）
    document = JsDocument(
        sha256=hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
        body=body,
        urls=(endpoint,),
        order=lineno,
        content_type="",
    )
    try:
        templates, _stats = extract_endpoints(document)
    except Exception:  # noqa: BLE001 - 抽取是增强，不是主链路
        return []
    out: list[Signal] = []
    for template in templates:
        if _JS_ENDPOINT_SKIP_TEMPLATE in template.path_template:
            continue
        for path_template in _candidate_paths(template.path_template, bases):
            # 顺序重要：**先**拼基址，再按拼完的路径判"像不像接口"。否则
            # ``get("/info")`` 会在拼成 ``/api/v1/info`` **之前**被判
            # ``not_data_endpoint`` 丢掉（实测 0 候选的根因）。
            if not _is_clean_api_path(path_template):
                continue
            if not _looks_like_api_path(path_template):
                continue
            if exclusion_reason(replace(template, path_template=path_template)) is not None:
                continue
            asset = f"{template.origin}{path_template}"
            key = ("api-endpoint", asset)
            if key not in seen:
                seen.add(key)
                note = f"js:{template.js_url}"
                if path_template != template.path_template:
                    note += "+base"
                out.append(
                    Signal(
                        asset=asset,
                        kind="api-endpoint",
                        source_tool=source_tool,
                        skill=skill,
                        evidence_ref=f"{evidence_path}#L{lineno}",
                        note=note,
                    )
                )
            if template.query_keys:
                query = "&".join(f"{quote(key, safe='')}=1" for key in template.query_keys)
                url = f"{asset}?{query}"
                param_key = ("param-endpoint", url)
                if param_key not in seen:
                    seen.add(param_key)
                    out.append(
                        Signal(
                            asset=url,
                            kind="param-endpoint",
                            source_tool=source_tool,
                            skill=skill,
                            evidence_ref=f"{evidence_path}#L{lineno}",
                            note="js-query-keys",
                        )
                    )
    return out



#: 跨文件 baseURL 收集上限（3 条足够；多基址只说明站点有多套客户端）
_MAX_BASES = 3


def _collect_explicit_bases(text: str) -> list[str]:
    """预扫描：本批 JS 正文里出现过的 ``baseURL``/``API_BASE`` 常量（M33）。

    为什么需要跨文件：这份目标里 ``baseURL: "/api/v1"`` 写在 api 客户端那个
    bundle，而 ``get("/info")`` 的调用点在另一个 bundle——单文件抽取拿不到基址，
    ``/info`` 只能按"JS 文件所在目录"归并成 ``/assets/info``（假端点）。
    """
    from proofhound.jsimport.extract import explicit_bases

    bases: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        request = data.get("request")
        response = data.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        endpoint = request.get("endpoint")
        body = response.get("body")
        if not isinstance(endpoint, str) or not isinstance(body, str) or not body:
            continue
        if not urlparse(endpoint).path.lower().endswith((".js", ".mjs")):
            continue
        for base in explicit_bases(body.encode("utf-8", "replace")):
            path = base.rstrip("/")
            if path and path != "/" and path not in bases:
                bases.append(path)
                if len(bases) >= _MAX_BASES:
                    return bases
    return bases


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
    # M33：跨文件收集显式 baseURL（api 客户端的基址常写在另一个 bundle 里）
    bases = _collect_explicit_bases(text)
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
        # M33：JS 正文里写死的接口路径（M24-a 的抽取器，接进生产候选）
        if isinstance(body, str) and body:
            signals.extend(
                _js_endpoint_signals(
                    endpoint,
                    body,
                    evidence_path=evidence_path,
                    lineno=lineno,
                    skill=skill,
                    source_tool=source_tool,
                    seen=seen,
                    bases=bases,
                )
            )
    return signals, skipped
