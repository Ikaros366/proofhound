#!/usr/bin/env python3
"""M9c Step 0：中性基准（triage 发现层三臂消融）。

## 为什么需要这个基座

维护者问过："我这个跟别的自主 AI 渗透系统差好多。" 论文（XBOW 基准）
的核心教训是：**没有"裸模型打多少分"的参照线，所有架构增益都悬空**。
故 M9c 的硬前置是：先拿到【发现率 / 误报率 / 单题成本】的中性数字。

## 为什么不用 DVWA

DVWA 的参数名全是 `id` / `name`，**恰好落在 triage 提示表内**——拿它测
"关键词盲区"必然测不出来。基座因此自建 stdlib fixture，参数名可控：
A/B 两族端点唯一差别就是**参数名是否命中提示表**，其余行为完全同构。

## 三个臂（消融）

- ``rules``      ：现状（`_triage_candidates` 规则表，零 LLM）
- ``rules+model``：规则表 ∪ 模型候选（M9c① 的目标形态）
- ``model``      ：纯模型（规则表停用）——对标论文"裸模型"的参照线

## 指标

- **发现率**：真漏洞端点中，产出了正确 `vuln_type` 候选的比例
- **误报率**：安全对照端点中，被产出候选的比例（候选级，非 Confirmed 级）
- **单题成本**：wall time + LLM token（从 `llm_call` 审计取）

## 语义纪律（不许含糊）

本基座的"误报率"是**候选级**，不是 Confirmed 级——发现侧产生候选不等于
确认漏洞（红线 2）。Confirmed 级数字必须跑真实 verify 链路（Docker +
Chromium + T2），不在本脚本默认范围。

## M10a Step 1：真可确认后端

原 fixture 的"真漏洞"端点只是**模拟**特征（取值含引号 → 500），只能测发现层。
M10a Step 1 把后端换成真的：sqli 走 sqlite 拼接查询（sqlmap 可确认）、
xss 保持不转义反射（canary 可确认）、idor 引入身份归属（双会话属性违反可确认），
D 族换成**真安全**（含 `/d/safe4` 的真授权校验、`/d/safe2` 去掉模拟 SQL 错误）。

**不变式**：端点表/参数名、首页链接、表单字段、爬行状态码一律不动；D 族
"两个探测取值响应长度相同"的性质保持（粗筛只比长度）→ 离线三臂数字应逐格不变。

用法：
    .venv/bin/python scripts/bench_triage.py            # 离线确定性：三臂消融
    .venv/bin/python scripts/bench_triage.py --model    # rules+model 臂接真实 T1 档

    # M10a：端到端真实确认链路（Docker + Chromium + T2）→ Confirmed 级数字
    .venv/bin/python scripts/bench_triage.py --live
    .venv/bin/python scripts/bench_triage.py --live --arm rules+model+prefilter

产物落 evidence/bench_triage/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from proofhound.compliance.audit import AuditLog  # noqa: E402
from proofhound.core.orchestrator import (  # noqa: E402
    _IDOR_PARAM_HINTS,
    _SQLI_PARAM_HINTS,
    _XSS_PARAM_HINTS,
    Orchestrator,
)
from proofhound.findings.signal import Signal  # noqa: E402
from proofhound.llm.client import LLMError  # noqa: E402
from proofhound.llm.router import ModelRouter, Tier  # noqa: E402
from proofhound.llm.usage import UsageTracker  # noqa: E402
from proofhound.skills.registry import SkillRegistry  # noqa: E402
from proofhound.verify.prefilter import ScreenDecision  # noqa: E402
from proofhound.verify.prefilter import screen as prefilter_screen  # noqa: E402

BENCH_DIR: Path
TOKEN = "bench0session0token"  # >=16 字符，演练脱敏路径


# =====================================================================
# 一、ground truth 端点表
# =====================================================================

#: 表外参数名样本——刻意取不同语系/构词法，覆盖交接文档点名的盲区：
#: 英文复合（article_id/sku/ref）、中文站点缩写（bh=编号）、泛化短名（no）。
#: 这些名字都不在 _SQLI/_XSS/_IDOR_PARAM_HINTS 任何一张表里。
OUT_OF_TABLE = ("article_id", "sku", "ref", "bh", "no", "token", "product", "code")


@dataclass(frozen=True)
class Endpoint:
    """一条 ground truth 端点。

    ``vuln`` 为 None 表示安全对照（必须有响应差异但不构成漏洞）。
    ``param`` 为 None 表示表单端点（字段名走 ``fields``）。
    """

    path: str
    param: str | None
    vuln: str | None
    fields: tuple[str, ...] = ()
    note: str = ""

    @property
    def in_table(self) -> bool:
        """参数名/字段名是否命中现有提示表（真值来自 orchestrator 的表本身）。"""
        names = [self.param] if self.param else list(self.fields)
        if not names:
            return False
        return any(
            n in _SQLI_PARAM_HINTS or n in _XSS_PARAM_HINTS or n in _IDOR_PARAM_HINTS
            for n in names
        )


#: 端点表。设计原则：**A/B 两族行为同构，唯一变量是参数名是否在表内**。
#: 故任何"发现率差异"只可能来自 triage 的关键词匹配，不可能来自靶场难度差。
ENDPOINTS: tuple[Endpoint, ...] = (
    # ---- A 族：真漏洞 + 参数名命中提示表（现规则表应发现） ----
    Endpoint("/a/sqli", "id", "sqli", note="表内（sqli 表）"),
    Endpoint("/a/sqli2", "page", "sqli", note="表内（sqli 表）"),
    Endpoint("/a/xss", "name", "xss", note="表内（xss 表）"),
    Endpoint("/a/idor", "id", "idor", note="表内（idor 表）"),
    # ---- B 族：真漏洞 + 参数名**不在**任何提示表（盲区样本） ----
    Endpoint("/b/sqli", "article_id", "sqli", note="表外（交接文档点名）"),
    Endpoint("/b/sqli2", "bh", "sqli", note="表外（中文站编号缩写）"),
    Endpoint("/b/sqli3", "sku", "sqli", note="表外（电商）"),
    Endpoint("/b/xss", "ref", "xss", note="表外"),
    Endpoint("/b/idor", "no", "idor", note="表外"),
    Endpoint("/b/idor2", "token", "idor", note="表外"),
    # ---- C 族：真漏洞 + 表单字段名不在表内（M8a form_page 路径的盲区） ----
    Endpoint("/c/form-sqli", None, "sqli", fields=("bh",), note="表单字段表外"),
    Endpoint(
        "/c/form-sqli2", None, "sqli", fields=("article_id", "sku"),
        note="表单字段表外",
    ),
    # ---- D 族：安全对照（有响应差异，但无漏洞）→ 误报率分母 ----
    Endpoint("/d/safe", "id", None, note="对照：表内参数但无漏洞"),
    Endpoint("/d/safe2", "article_id", None, note="对照：表外参数且无漏洞"),
    Endpoint("/d/safe3", "name", None, note="对照：xss 表内但已转义"),
    Endpoint("/d/safe4", "no", None, note="对照：表外 idor 类参数但有授权判断"),
)


# =====================================================================
# 二、fixture 应用（stdlib http.server；行为与参数名解耦）
# =====================================================================


# =====================================================================
# 二·补 M10a Step 1：真可确认后端（sqlite + 身份归属）
# =====================================================================
#
# 动因：原 fixture 的"真漏洞"端点只是**模拟**特征（取值含引号 → 500），只能测
# 发现层，无法让真实确认链路（sqlmap / 无头浏览器 / 双会话属性判定）真的确认
# 或真的驳回。M10a 要拿 **Confirmed 级**误报率，后端因此必须是真的。
#
# 不变式（必须保持，否则离线 triage 口径漂移）：
#   1. 端点表与参数名不变 → rules 臂与送审摘要不变；
#   2. 首页链接与表单字段不变 → 确定性爬行产出的 Signal 不变；
#   3. 爬行取到的状态码仍为 200；
#   4. D 族（安全对照）"两个探测取值(1 / 999999)响应长度相同"的性质不变
#      → 粗筛裁定不变（粗筛只比长度，见 verify/prefilter.py::decide）；
#   5. 所有响应体 >= 64 字节（MIN_COMPARABLE_BYTES）→ 长度仍有信息量。

#: 主会话身份（越权方）——Cookie 值复用既有 ``TOKEN``。
PRIMARY_IDENTITY = "attacker"
#: 第二身份（数据所有者）——``SessionConfig.reference`` 用它做属性对照。
OWNER_IDENTITY = "owner"
#: 第二身份的 Cookie 值（>=16 字符，沿用与 TOKEN 同样的脱敏演练长度）。
REFERENCE_TOKEN = "bench0reference0token"

_DB_LOCK = threading.Lock()
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, label TEXT, body TEXT)")
_DB.executemany(
    "INSERT INTO records (id, label, body) VALUES (?, ?, ?)",
    [
        (i, f"记录 {i}", f"第 {i} 条记录的正文内容，供行为验证读取与比对。")
        for i in range(1, 6)
    ],
)
_DB.commit()

#: 对象归属表：对象 id → 所有者身份。
#: IDOR 端点（/a/idor、/b/idor、/b/idor2）**不做**授权校验 → 真漏洞；
#: ``/d/safe4`` **做**校验 → 真安全对照。
_OBJECT_OWNER = {i: OWNER_IDENTITY for i in range(1, 6)}


def _sqlite_rows(value: str, label: str, param: str) -> tuple[int, str]:
    """拼接式 SQL 查询（**刻意可注入**）→ ``(状态码, 正文)``。

    A/B/C 三族共用本函数、**形态同构**（同一后端、同一 vuln 语义、唯一变量是
    参数名），但 ``label``/``param`` 让正文**逐端点不同**——这是硬要求，不是
    装饰：正文逐字节相同的多个端点会被 katana 当作**重复响应丢弃**，端点根本
    进不了 crawler。实测（未带 label 时）：16 个端点只有 9 个被爬到，
    sqli 5→1、xss 2→1、idor 3→1。回归网见
    ``tests/test_bench_fixture.py::test_no_two_endpoints_share_a_body``。

    语法错误返回 500 + 真实 sqlite 错误文本，供 sqlmap 的 error-based 技术使用。
    """
    sql = f"SELECT label, body FROM records WHERE id = {value}"
    try:
        with _DB_LOCK:
            row = _DB.execute(sql).fetchone()
    except sqlite3.Error as exc:
        return 500, _page(f"{label} · SQL 错误", f"{param}={value} 数据库错误：{exc}")
    if row is None:
        return 200, _page(f"{label} · 无结果", f"{param}={value} 没有匹配的记录。")
    return 200, _page(
        f"{label} · 查询结果", f"{param}={value} 记录 {row[0]}：{row[1]}"
    )


def _object_page(value: str, label: str, param: str) -> str:
    """对象详情页（IDOR 端点用：**不区分身份**，故越权成立）。

    ``label``/``param`` 的理由同 :func:`_sqlite_rows`：避免多端点正文雷同
    而被 crawler 当重复响应丢弃。
    """
    try:
        oid = int(value)
    except (TypeError, ValueError):
        oid = -1
    if oid not in _OBJECT_OWNER:
        return _page(f"{label} · 不存在", f"{param}={value} 对象不存在。")
    return _page(
        f"{label} · 对象详情",
        f"{param}={value} 对象 {oid}：所有者 {_OBJECT_OWNER[oid]}，"
        "金额 800，状态已发货。",
    )


def _page(title: str, body: str, links: tuple[str, ...] = ()) -> str:
    """页面渲染。footer 带 **per-endpoint 标记**（``ep=<路径去斜杠>``）。

    M11b：原先硬编码 ``session=TOKEN``（attacker 凭据）——两个问题：
    ① 页面在"谁在看"上说谎（owner 会话的响应回显 attacker 的 token）；
    ② 它**冒充了端点差异**——三个 IDOR 端点的可见文本实际相同，仅靠这行硬编码
    标记才逐字节可区分，于是 M10a 的 Verifier 反复援引的"两份响应 sha256 完全
    相同 → 更像公开内容"**部分是该缺陷制造的伪迹**。

    改为 per-endpoint 标记后：正文差异来自**端点身份**（路径唯一），不依赖任何
    凭据、与内容语义无关，且长度稳定（标记长度随路径变化，但同端点恒定）。
    脱敏演练随之取消：凭据脱敏由生产链路自身测试覆盖，不该由基准 fixture 承担
    ——尤其是当它需要伪造正文差异时。
    """
    nav = "".join(f'<a href="{href}">{href}</a>' for href in links)
    return (
        f"<html><head><title>{title}</title></head><body>"
        f"<h1>{title}</h1><nav>{nav}</nav><div>{body}</div>"
        f"<footer>ep={_current_ep()}</footer></body></html>"
    )


#: 当前请求路径的端点标记（由 ``do_GET`` 逐请求设置）
_CURRENT_EP: list[str] = ["root"]


def _current_ep() -> str:
    return _CURRENT_EP[0]


class _FixtureHandler(BaseHTTPRequestHandler):
    """端点行为由 ``path`` 决定；参数名**完全不参与**行为分支。

    这样 A 族与 B 族的唯一差别只剩"参数名在不在提示表里"，消融结论才干净。
    """

    def _respond(self, status: int, body: str, extra: dict | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _identity(self) -> str | None:
        """Cookie ``phsess`` → 身份名（主会话 attacker / 第二会话 owner）。

        长度与形态刻意与脱敏演练保持一致；未知值原样返回（便于人工探测）。
        """
        cookie = self.headers.get("Cookie") or ""
        for segment in cookie.split(";"):
            name, _, value = segment.strip().partition("=")
            if name == "phsess" and value:
                if value == TOKEN:
                    return PRIMARY_IDENTITY
                if value == REFERENCE_TOKEN:
                    return OWNER_IDENTITY
                return value
        return None

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        # M11b：footer 标记当前端点（每个端点路径唯一 → 正文唯一）
        _CURRENT_EP[0] = path.strip("/").replace("/", "-") or "root"

        def first(key: str) -> str:
            return (query.get(key) or [""])[0]

        if path == "/":
            links = tuple(
                f"{ep.path}?{ep.param}=1" for ep in ENDPOINTS if ep.param
            ) + tuple(ep.path for ep in ENDPOINTS if not ep.param)
            self._respond(200, _page("bench fixture", "端点索引", links))
            return

        if path in ("/c/form-sqli", "/c/form-sqli2"):
            fields = ("bh",) if path == "/c/form-sqli" else ("article_id", "sku")
            inputs = "".join(f'<input name="{n}" value="1">' for n in fields)
            self._respond(
                200,
                _page(
                    "表单查询",
                    f'<form method="post" action="{path}">{inputs}'
                    '<input type="submit"></form>',
                ),
            )
            return

        # ---- A/B/C sqli 族：真 sqlite 拼接注入（A 表内 / B 表外，行为同构） ----
        if path in ("/a/sqli", "/a/sqli2", "/b/sqli", "/b/sqli2", "/b/sqli3"):
            key, label = {
                "/a/sqli": ("id", "商品详情"),
                "/a/sqli2": ("page", "分页结果"),
                "/b/sqli": ("article_id", "文章正文"),
                "/b/sqli2": ("bh", "编号查询"),
                "/b/sqli3": ("sku", "商品清单"),
            }[path]
            status, body = _sqlite_rows(first(key), label, key)
            self._respond(status, body)
            return

        # ---- A/B xss 族：**不转义**反射（真漏洞，无头浏览器 canary 可确认） ----
        if path in ("/a/xss", "/b/xss"):
            # 两族都**不转义**（真漏洞，canary 可确认），但标题逐端点不同——
            # 同正文会被 katana 当重复响应丢弃（见 _sqlite_rows 注记）。
            key, title = (
                ("name", "网络搜索结果") if path == "/a/xss" else ("ref", "来源页")
            )
            value = first(key)
            self._respond(200, _page(title, f"你好，{value}，以下是找到的内容"))
            return

        # ---- A/B idor 族：对象归属 owner，端点**不做**授权校验（真漏洞） ----
        if path in ("/a/idor", "/b/idor", "/b/idor2"):
            key, label = {
                "/a/idor": ("id", "订单详情"),
                "/b/idor": ("no", "对象详情"),
                "/b/idor2": ("token", "凭据详情"),
            }[path]
            # M11b：**未认证**请求得定长通用页——否则"公开资源"与"B 的私有对象
            # 被 A 拿到"在未认证对照下同形，判据无法区分（这正是 Verifier 索要
            # 的那个对照缺失的根因）。刻意用 200 而非 403：旧系统常见"登录页
            # 200"形态，且保持"匿名也能拿到 200"这一**最不利**情形，迫使判据
            # 必须在正文层面工作。attacker（已认证非属主）仍拿到对象页 → 漏洞
            # 语义与 ground truth 不变。
            if self._identity() is None:
                # M11c：改用 **403 拒绝**——"未认证被拒"的明确表达。原实现用
                # 200 + 登录页，会被 M11b 对照判据判 blocked（只否定不肯定），
                # 导致真 IDOR 系统性测不到判定结果；302 则会被测试/工具的
                # urllib 跟随到未注册的 /login（404），语义模糊且多端点正文相同。
                self._respond(
                    403, _page("请先登录", "未认证会话无权查看该页面内容。")
                )
                return
            self._respond(200, _object_page(first(key), label, key))
            return

        # ---- D 族：安全对照（**真安全**，但仍保留"诱出候选"的形态） ----
        if path == "/d/safe":
            # 公开资源：取值被忽略、无回显、定长 → 无注入、无反射。
            # 注意它对**两个身份返回同一份内容**，IDOR 判定器分不出"公开资源"
            # 与"B 的私有对象被 A 拿到"——这正是刻意留给 Verifier 终审的陷阱。
            self._respond(200, _page("公开页", "公开内容，任何人都可以访问。"))
            return
        if path == "/d/safe2":
            # 真安全：取值被忽略，且**不**产生 SQL 错误。
            # （原实现"引号 → 500"是模拟特征，会让 sqlmap 误判为可注入，已移除）
            self._respond(200, _page("帮助页", "静态帮助内容，取值被忽略。"))
            return
        if path == "/d/safe3":
            # 真安全：反射**已转义** → canary 不会执行（xss 不应 Confirmed）。
            value = first("name").replace("<", "&lt;").replace(">", "&gt;")
            self._respond(200, _page("搜索", f"你好 {value}"))
            return
        if path == "/d/safe4":
            # 真安全：**做**授权校验。非所有者得到**定长**通用页——刻意定长，
            # 既保持粗筛"取值不影响响应长度"的裁定不变，也不泄漏对象存在性；
            # 且与 owner 的对象页内容不同 → IDOR 属性违反不成立。
            if self._identity() != OWNER_IDENTITY:
                self._respond(200, _page("工单页", "无权查看该工单详情。"))
                return
            self._respond(200, _object_page(first("no"), "工单详情", "no"))
            return

        self._respond(404, _page("404", "not found"))

    def do_POST(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = urllib.parse.parse_qs(raw, keep_blank_values=True)
        if parsed.path in ("/c/form-sqli", "/c/form-sqli2"):
            # 真 POST 注入：字段值同样拼进 SQL（M8a form_page 路径的可确认版）
            if parsed.path == "/c/form-sqli":
                fields, label = ("bh",), "表单查询"
            else:
                fields, label = ("article_id", "sku"), "表单查询二"
            value, param = "1", fields[0]
            for name in fields:
                if form.get(name):
                    value, param = form[name][0], name
                    break
            status, body = _sqlite_rows(value, label, param)
            self._respond(status, body)
            return
        self._respond(404, _page("404", "not found"))

    def log_message(self, *args):
        pass


def start_fixture() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    return server, f"http://127.0.0.1:{port}"


# =====================================================================
# 三、确定性爬行（in-process，零 Docker）——产 Signal 语料
# =====================================================================


class _LinkFormParser(HTMLParser):
    """极简链接/表单提取：镜像 katana_jsonl 解析器的产信号语义。"""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[tuple[str, list[str]]] = []
        self._in_form = False
        self._form_fields: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == "a" and attrs_d.get("href"):
            self.links.append(attrs_d["href"])
        elif tag == "form":
            self._in_form = True
            self._form_fields = []
        elif self._in_form and tag in ("input", "select", "textarea"):
            name = (attrs_d.get("name") or "").strip()
            if name and name not in self._form_fields:
                self._form_fields.append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._in_form:
            self._in_form = False
            self.forms.append(("", self._form_fields))


def _fetch(url: str) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"Cookie": f"phsess={TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _signal(url, code, kind, ref, fields=()):
    return Signal(
        asset=url,
        status_code=code,
        kind=kind,
        source_tool="bench-crawl",
        skill="recon-crawl",
        evidence_ref=ref,
        form_fields=list(fields),
    )


def crawl(base: str):
    """确定性爬行：首页 → 带参 GET 端点 + 表单页。

    返回 (signals, 原始证据落盘文本)。信号 ``evidence_ref`` 指向落盘文件行号
    （红线 3：LLM 上下文只有结构化摘要 + 文件引用路径）。
    """
    lines: list[str] = []
    signals: list = []

    status, body = _fetch(base + "/")
    lines.append(json.dumps({"url": base + "/", "status_code": status}))
    parser = _LinkFormParser()
    parser.feed(body)

    for href in parser.links:
        url = urllib.parse.urljoin(base + "/", href)
        code, page = _fetch(url)
        lines.append(json.dumps({"url": url, "status_code": code}))
        if urllib.parse.urlparse(url).query:
            signals.append(
                _signal(url, code, "param-endpoint", f"bench.stdout.log#L{len(lines)}")
            )
        inner = _LinkFormParser()
        inner.feed(page)
        for _action, fields in inner.forms:
            if not fields:
                continue
            if urllib.parse.urlparse(url).netloc != urllib.parse.urlparse(base).netloc:
                continue  # 同源防线（fail-closed）
            lines.append(json.dumps({"url": url, "form_fields": fields}))
            signals.append(
                _signal(
                    url, 200, "form_page",
                    f"bench.stdout.log#L{len(lines)}", fields=fields,
                )
            )
    return signals, "\n".join(lines) + "\n"


# =====================================================================
# 四、三臂执行
# =====================================================================


class _SilentLLM:
    """rules 臂的占位 LLM：真被调到就说明接线错了。"""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages):
        self.calls += 1
        raise AssertionError("本臂不应调用 LLM")


class _ScriptedRouter:
    """离线替身：代表**模型能力上界**——按 ground truth 逐端点回候选。

    为什么让替身"作弊"：基座要回答的是"**发现层的门开多大**"，不是"这个
    模型有多强"。替身按真实端点回候选 = 上限；规则表的发现率与之的差值，
    就是**纯规则表把多少真实漏洞挡在门外**（本基座的核心数字）。

    真实模型表现必须用 ``--model`` 跑真 T1 档——替身数字**不可**当作模型
    实测值，报告 meta 里单列 model_mode 标注。

    替身只读 ``path`` 与参数名，与真模型收到的输入同构（不读响应体）。
    """

    def __init__(self, path_table: dict[str, tuple[str, str]]) -> None:
        # path -> (vuln_type, param)
        self.path_table = path_table
        self.calls = 0

    tracker: object | None = None  # 由 run_arm 注入 UsageTracker（成本口径）

    def complete(self, messages):
        # legacy 单参客户端接口：Orchestrator 经 ensure_router 包成
        # _LegacyClientAdapter 后按档位转发到这里（档位对本替身无意义）
        self.calls += 1
        payload = messages[-1]["content"]
        # 与真实链路同款计量：无 usage 时按 4 字符≈1 token 估算（标 estimated）
        if self.tracker is not None:
            from proofhound.llm.usage import UsageRecord, estimate_tokens

            reply = self._reply_for(payload)
            self.tracker.record(
                UsageRecord(
                    tier="t1",
                    model="scripted-upper-bound",
                    prompt_tokens=sum(
                        estimate_tokens(str(m.get("content", ""))) for m in messages
                    ),
                    completion_tokens=estimate_tokens(reply),
                    latency_ms=0.0,
                    estimated=True,
                )
            )
            return reply
        return self._reply_for(payload)

    def _reply_for(self, payload):
        found = []
        for line in payload.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            entry = self.path_table.get(row.get("path"))
            if entry is None:
                continue
            vuln, param = entry
            found.append(
                {
                    "vuln_type": vuln,
                    "param": param,
                    "reason": "替身上界：语义识别",
                    "confidence": "medium",
                }
            )
        return json.dumps({"hypotheses": found}, ensure_ascii=False)


def apply_screening(base_url: str, score: Score, findings) -> None:
    """对 findings 逐条真发只读 GET 粗筛，回填 Score 的 screened_* 字段。

    粗筛只判定「值得不值得花贵验证」，**不改 Finding 状态**（红线 2）。
    """
    path_vuln = {ep.path: ep.vuln for ep in ENDPOINTS}
    for finding in findings:
        endpoint = _endpoint_of(finding.asset)
        result = prefilter_screen(base_url + finding.asset.split(base_url, 1)[-1]
                                  if finding.asset.startswith(base_url)
                                  else base_url + endpoint + "?" +
                                  urllib.parse.urlencode({finding.param or "id": "1"}),
                                  finding.param)
        if result.decision is not ScreenDecision.UNLIKELY:
            continue
        expected = path_vuln.get(endpoint)
        entry = {
            "path": endpoint,
            "param": finding.param,
            "vuln_type": finding.vuln_type,
            "reason": result.reason,
        }
        if expected is None:
            score.screened_out_safe.append(entry)
        else:
            score.screened_out_vuln.append(entry)


def run_arm(
    arm: str,
    signals,
    raw_text: str,
    workdir: Path,
    router=None,
    real_router=None,
):
    """跑一个臂的 triage，返回 (findings, 统计)。

    三臂共用同一份 Signal 语料与同一套下游逻辑，**只有候选生成来源不同**：
    - rules      ：规则表
    - model      ：仅模型（规则表停用）
    - rules+model：两者并集
    """
    evidence_dir = workdir / arm
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "bench.stdout.log").write_text(raw_text, encoding="utf-8")
    with (evidence_dir / "bench.signals.jsonl").open("w", encoding="utf-8") as fh:
        for sig in signals:
            fh.write(sig.model_dump_json() + "\n")

    audit = AuditLog(evidence_dir / "audit.jsonl")
    # 真实 ModelRouter 必须挂本臂的审计，否则 llm_call 不落盘、token 统计为 0
    # （ModelRouter 把 llm_call 记进构造时注入的 audit；不重挂就测不出成本）
    if real_router is not None:
        real_router.audit = audit
        real_router.tracker = UsageTracker()
    orch = Orchestrator(
        SkillRegistry(REPO_ROOT / "skills").discover(),
        runner=None,
        llm=router if router is not None else _SilentLLM(),
        audit=audit,
        evidence_dir=evidence_dir,
        triage_rules=(arm != "model"),
        triage_model=(arm != "rules"),
    )
    started = time.monotonic()
    findings = orch.run_triage_phase()
    elapsed = time.monotonic() - started

    events = audit.read_all()
    tokens = sum(
        int(e.get("prompt_tokens") or 0) + int(e.get("completion_tokens") or 0)
        for e in events
        if e.get("event") == "llm_call"
    )
    summary = next((e for e in events if e.get("event") == "triage_completed"), {})
    return findings, {
        "arm": arm,
        "wall_s": round(elapsed, 3),
        "llm_calls": sum(1 for e in events if e.get("event") == "llm_call"),
        "llm_tokens": tokens,
        "findings": len(findings),
        "triage_summary": summary,
        "audit_events": len(events),
    }


# =====================================================================
# 五、评分（纯函数，可单测）
# =====================================================================


def _endpoint_of(asset: str) -> str:
    return urllib.parse.urlparse(asset).path


@dataclass
class Score:
    """一个臂的评分结果。

    ``*_screened`` 系列 = 候选再经**廉价粗筛**后的数字（只统计，不发贵验证）：
    粗筛把 UNLIKELY 的候选挡在贵验证档之外，因此"粗筛后误报率"才是
    真正决定**贵验证预算怎么花**的数字。
    """

    arm: str
    hit_vuln: int = 0
    total_vuln: int = 0
    hit_safe: int = 0
    total_safe: int = 0
    missed: list = field(default_factory=list)
    false_positives: list = field(default_factory=list)
    screened_out_vuln: list = field(default_factory=list)
    screened_out_safe: list = field(default_factory=list)

    @property
    def discovery_rate(self) -> float:
        return self.hit_vuln / self.total_vuln if self.total_vuln else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.hit_safe / self.total_safe if self.total_safe else 0.0

    @property
    def screened_discovery_rate(self) -> float:
        out = len({entry["path"] for entry in self.screened_out_vuln})
        assert out <= self.hit_vuln, (
            f"口径不自洽：被粗筛的真漏洞端点 {out} > 命中数 {self.hit_vuln}"
        )
        kept = self.hit_vuln - out
        return kept / self.total_vuln if self.total_vuln else 0.0

    @property
    def screened_false_positive_rate(self) -> float:
        out = len({entry["path"] for entry in self.screened_out_safe})
        assert out <= self.hit_safe, (
            f"口径不自洽：被粗筛的对照端点 {out} > 误报数 {self.hit_safe}"
        )
        kept = self.hit_safe - out
        return kept / self.total_safe if self.total_safe else 0.0

    def to_dict(self) -> dict:
        return {
            "arm": self.arm,
            "discovery_rate": round(self.discovery_rate, 4),
            "hit_vuln": self.hit_vuln,
            "total_vuln": self.total_vuln,
            "false_positive_rate": round(self.false_positive_rate, 4),
            "hit_safe": self.hit_safe,
            "total_safe": self.total_safe,
            "screened_discovery_rate": round(self.screened_discovery_rate, 4),
            "screened_false_positive_rate": round(
                self.screened_false_positive_rate, 4
            ),
            "screened_out_vuln": self.screened_out_vuln,
            "screened_out_safe": self.screened_out_safe,
            "missed": self.missed,
            "false_positives": self.false_positives,
        }


def score_arm(arm: str, findings) -> Score:
    """候选级评分：真漏洞端点是否产出**正确 vuln_type** 的候选。

    判定"正确"用的是 ground truth 的 vuln_type（发现层不判确认，只判方向）。
    """
    by_path: dict = {}
    for finding in findings:
        by_path.setdefault(_endpoint_of(finding.asset), set()).add(finding.vuln_type)

    result = Score(arm=arm)
    for ep in ENDPOINTS:
        produced = by_path.get(ep.path, set())
        if ep.vuln is None:
            result.total_safe += 1
            if produced:
                result.hit_safe += 1
                result.false_positives.append(f"{ep.path} -> {sorted(produced)}")
        else:
            result.total_vuln += 1
            if ep.vuln in produced:
                result.hit_vuln += 1
            else:
                result.missed.append(
                    f"{ep.path}（{ep.note}，期望 {ep.vuln}，"
                    f"实得 {sorted(produced) or '无候选'}）"
                )
    return result


# =====================================================================
# 六、报告
# =====================================================================


def render_markdown(rows, meta) -> str:
    lines = [
        "# ProofHound M9c 中性基准（triage 发现层三臂消融）",
        "",
        f"- 时间：{meta['stamp']}",
        f"- 端点总数：{meta['endpoints']}"
        f"（真漏洞 {meta['vuln_endpoints']} / 安全对照 {meta['safe_endpoints']}）",
        f"- Signal 数：param-endpoint {meta['signals_param']} / "
        f"form_page {meta['signals_form']}",
        f"- 参数名表外样本：{', '.join(meta['out_of_table'])}",
        f"- model 臂来源：{meta['model_mode']}",
        "",
        "## 指标（候选级，非 Confirmed 级）",
        "",
        "| 臂 | 发现率 | 误报率 | **粗筛后**发现率 | **粗筛后**误报率 | "
        "LLM 调用 | LLM token | wall(s) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        s = row["score"]
        lines.append(
            f"| `{row['arm']}` | {s['discovery_rate']:.1%} "
            f"({s['hit_vuln']}/{s['total_vuln']}) "
            f"| {s['false_positive_rate']:.1%} "
            f"({s['hit_safe']}/{s['total_safe']}) "
            f"| {s['screened_discovery_rate']:.1%} "
            f"| {s['screened_false_positive_rate']:.1%} "
            f"| {row['llm_calls']} | {row['llm_tokens']} | {row['wall_s']:.3f} |"
        )
    lines.append("")
    for row in rows:
        s = row["score"]
        lines.append(f"### 臂 `{row['arm']}` 明细")
        lines.append("")
        if s["missed"]:
            lines.append("**漏报**：")
            lines += [f"- {m}" for m in s["missed"]]
        else:
            lines.append("**漏报**：无")
        lines.append("")
        if s["false_positives"]:
            lines.append("**误报（对照端点产出候选）**：")
            lines += [f"- {m}" for m in s["false_positives"]]
        else:
            lines.append("**误报**：无")
        lines.append("")
        if s["screened_out_safe"]:
            lines.append("**粗筛建议不优先（对照端点）**：")
            lines += [
                f"- `{e['path']}` [{e['vuln_type']}] {e['reason']}"
                for e in s["screened_out_safe"]
            ]
            lines.append("")
        if s["screened_out_vuln"]:
            lines.append("**粗筛误建议不优先（真漏洞端点，属该层误差）**：")
            lines += [
                f"- `{e['path']}` [{e['vuln_type']}] {e['reason']}"
                for e in s["screened_out_vuln"]
            ]
            lines.append("")
    lines.append(
        "> 语义纪律：本表误报率为**候选级**——发现侧产出候选不等于确认漏洞（红线 2）。"
    )
    lines.append(
        "> Confirmed 级数字须跑真实 verify 链路（Docker + Chromium + T2），"
        "不在本脚本默认范围。"
    )
    return "\n".join(lines) + "\n"


# =====================================================================
# 六、M10a：--live 端到端确认链路 → Confirmed 级指标
# =====================================================================
#
# 离线三臂只回答"发现层的门开多大"（候选级）。本节回答另一半问题：
# **这些候选里有多少真的能被确认为漏洞、有多少误报会穿过确认链路**——
# 这是 M9c 两个开关"要不要默认开启"的事实前提。
#
# 指标口径（维护者裁定，M10a Step 2）：
#   - 粒度 = (端点路径, vuln_type)：**类型错配计误报**（如在与身份无关的
#     sqli 端点上 Confirmed 了一个 IDOR——ground truth 说那里只有 sqli）；
#   - ``verify_blocked``（T2 读超时 / 缺第二会话 / 基准不成立）**单列一行，
#     不计入 precision/recall 分母**——超时是"未能判定"，不是"确证不成立"。

#: 4 臂 = 两个生产开关（M9c）的 2x2 组合。
_LIVE_ARMS: tuple[tuple[str, bool, bool], ...] = (
    ("rules", False, False),
    ("rules+model", True, False),
    ("rules+prefilter", False, True),
    ("rules+model+prefilter", True, True),
)


def expected_pairs() -> dict[str, set[str]]:
    """ground truth：端点路径 → 该端点**真实存在**的漏洞类型集合。"""
    out: dict[str, set[str]] = {}
    for ep in ENDPOINTS:
        if ep.vuln:
            out.setdefault(ep.path, set()).add(ep.vuln)
    return out


def _live_workspace(root: Path, port: int) -> Path:
    """live 工作区：scope.yaml（仅 fixture 主机/端口）+ 符号链接复用仓库资产。"""
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=False)
    (workspace / "scope.yaml").write_text(
        f"networks: [127.0.0.0/8]\nports: [{port}]\n", encoding="utf-8"
    )
    for name in ("templates", "skills", "tools.d"):
        (workspace / name).symlink_to(REPO_ROOT / name)
    return workspace


def _audit_lines(eng_dir: Path) -> list[dict]:
    path = eng_dir / "audit.jsonl"
    if not path.is_file():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _wait_terminal(client, eng_id: str, timeout: float) -> str:
    """等 engagement 到 done/failed；超时返回当前态（由调用方如实记录）。"""
    deadline = time.monotonic() + timeout
    state = "unknown"
    while time.monotonic() < deadline:
        state = client.get(f"/api/engagements/{eng_id}").json()["state"]
        if state in ("done", "failed"):
            return state
        time.sleep(2.0)
    return state


def score_live(findings: list[dict], events: list[dict]) -> dict:
    """按 (端点, vuln_type) 粒度算 Confirmed 级指标（纯函数，可离线复核）。"""
    truth = expected_pairs()
    controls = {ep.path for ep in ENDPOINTS if ep.vuln is None}

    blocked_ids: set[str] = set()
    reasons: dict[str, int] = {}
    for event in events:
        if event.get("event") != "verify_blocked":
            continue
        fid = event.get("finding_id")
        if fid:
            blocked_ids.add(fid)
        reason = (event.get("reason") or "").strip()
        key = reason[:60] if reason else "(无原因)"
        reasons[key] = reasons.get(key, 0) + 1

    confirmed = [f for f in findings if f.get("state") == "confirmed"]
    tp: list[tuple[str, str]] = []
    fp: list[tuple[str, str]] = []
    for finding in confirmed:
        path = urllib.parse.urlparse(finding.get("asset") or "").path
        vuln_type = finding.get("vuln_type") or "?"
        (tp if vuln_type in truth.get(path, set()) else fp).append((path, vuln_type))

    # 12 条 ground truth 配对的终态漏斗（候选根本没产出 / 被驳回 / 未能判定 / 已确认）
    funnel: dict[str, str] = {}
    for path, types in sorted(truth.items()):
        for vuln_type in sorted(types):
            hit = [
                f for f in findings
                if urllib.parse.urlparse(f.get("asset") or "").path == path
                and f.get("vuln_type") == vuln_type
            ]
            if not hit:
                state = "无候选"
            else:
                finding = hit[0]
                state = finding.get("state") or "?"
                if state != "confirmed" and finding.get("id") in blocked_ids:
                    state = "未能判定"
            funnel[f"{path} [{vuln_type}]"] = state

    total = len(tp) + len(fp)
    return {
        "tp": sorted(f"{p} [{v}]" for p, v in tp),
        "fp": sorted(f"{p} [{v}]" for p, v in fp),
        "tp_n": len(tp),
        "fp_n": len(fp),
        "recall": len(tp) / sum(len(v) for v in truth.values()),
        "precision": (len(tp) / total) if total else None,
        "fp_rate": (len(fp) / total) if total else None,
        "unresolved_n": len(blocked_ids),
        "unresolved_reasons": reasons,
        "type_mismatch": sorted(
            f"{p} [{v}]" for p, v in fp if p in truth
        ),
        "controls_confirmed": sorted({p for p, _ in fp if p in controls}),
        "funnel": funnel,
    }


def _live_cost(events: list[dict]) -> dict:
    """单题成本：token 取自 ``llm_call`` 审计（M9c 同一口径）。"""
    calls = [e for e in events if e.get("event") == "llm_call"]
    by_tier: dict[str, int] = {}
    prompt = completion = 0
    for event in calls:
        tier = str(event.get("tier") or "?")
        tokens = (event.get("prompt_tokens") or 0) + (event.get("completion_tokens") or 0)
        by_tier[tier] = by_tier.get(tier, 0) + tokens
        prompt += event.get("prompt_tokens") or 0
        completion += event.get("completion_tokens") or 0
    return {
        "llm_calls": len(calls),
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt + completion,
        "by_tier": by_tier,
    }


def run_live_arm(
    name: str,
    triage_model: bool,
    prefilter: bool,
    *,
    env_file: str,
    base: str,
    port: int,
    root: Path,
    timeout: float,
) -> dict:
    """跑一个臂：真实编排栈（Docker 沙箱 + T1/T2 + Chromium），semi_auto 无人工闸。

    M9c③ 起内置三条 verify-* 均为只读，semi_auto 下闸门直接放行、不进确认队列，
    故本函数无需处理确认队列——这正是要测的"无人过滤"形态。
    """
    from fastapi.testclient import TestClient

    from proofhound.api import create_app

    os.environ["PROOFHOUND_TRIAGE_MODEL"] = "1" if triage_model else "0"
    os.environ["PROOFHOUND_VERIFY_PREFILTER"] = "1" if prefilter else "0"

    arm_dir = root / name.replace("+", "_")
    workspace = _live_workspace(arm_dir, port)
    app = create_app(workspace, env_file=env_file, confirm_timeout=900.0)
    started = time.monotonic()
    with TestClient(app, headers=app.state.auth.basic_header()) as client:
        created = client.post(
            "/api/engagements",
            json={
                "target": base,
                "scope_paths": ["scope.yaml"],
                "cookie": f"phsess={TOKEN}",
                "reference_cookie": f"phsess={REFERENCE_TOKEN}",
                # M11c：归属比对期望值——对象页展示的是 `OWNER_IDENTITY`
                # （"owner"），而 reference 凭据是随机值，两者不同源，必须显式
                # 声明，否则归属判 mismatched（真 IDOR 会被"缺归属证据"驳回）
                "reference_identity": OWNER_IDENTITY,
                "autonomy_mode": "semi_auto",
            },
        )
        if created.status_code != 201:
            raise RuntimeError(
                f"创建 engagement 失败: HTTP {created.status_code} {created.text[:300]}"
            )
        payload = created.json()
        if not payload.get("with_reference_session"):
            raise RuntimeError("engagement 未挂上第二身份会话（reference）")
        eng_id = payload["id"]
        client.post(f"/api/engagements/{eng_id}/run")
        state = _wait_terminal(client, eng_id, timeout)
        findings = client.get(f"/api/engagements/{eng_id}/findings").json()["findings"]
    wall = time.monotonic() - started

    events = _audit_lines(workspace / "engagements" / eng_id)
    score = score_live(findings, events)
    cost = _live_cost(events)
    pending = [e for e in events if e.get("event") == "action_read_only_auto"]
    print(
        f"    终态={state} findings={len(findings)} 审计={len(events)} "
        f"只读自动放行={len(pending)} 候选上限={sum(1 for e in events if e.get('event') == 'triage_capped')}",
        flush=True,
    )
    return {
        "arm": name,
        "triage_model": triage_model,
        "verify_prefilter": prefilter,
        "final_state": state,
        "wall_s": wall,
        "findings_n": len(findings),
        "read_only_auto_n": len(pending),
        "score": score,
        "cost": cost,
    }


def render_live_markdown(rows: list[dict], meta: dict) -> str:
    lines = ["# ProofHound M10a 基线：Confirmed 级误报率 / 检出率 / 单题成本", ""]
    lines.append(f"- 时间：{meta['stamp']}")
    lines.append(f"- 指标粒度：**{meta['granularity']}**（类型错配计误报）")
    lines.append(f"- 超时口径：{meta['blocked_policy']}")
    lines.append(
        f"- ground truth：{meta['ground_truth_pairs']} 条真漏洞配对 + 4 个安全对照"
    )
    lines.append("")
    lines.append(
        "| 臂 | TRIAGE_MODEL | VERIFY_PREFILTER | 检出率 | 精确率 | 误报率 | TP | FP "
        "| 未能判定 | token | wall(s) |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for row in rows:
        s = row["score"]
        precision = f"{s['precision']:.1%}" if s["precision"] is not None else "—"
        fp_rate = f"{s['fp_rate']:.1%}" if s["fp_rate"] is not None else "—"
        lines.append(
            f"| `{row['arm']}` | {int(row['triage_model'])} | "
            f"{int(row['verify_prefilter'])} | **{s['recall']:.1%}** | {precision} | "
            f"{fp_rate} | {s['tp_n']} | {s['fp_n']} | {s['unresolved_n']} | "
            f"{row['cost']['total_tokens']} | {row['wall_s']:.0f} |"
        )
    lines.append("")
    for row in rows:
        s = row["score"]
        lines.append(f"### 臂 `{row['arm']}` 明细")
        lines.append("")
        lines.append(f"- 终态：{row['final_state']}；只读自动放行 {row['read_only_auto_n']} 次")
        lines.append(
            f"- 单题成本：{row['cost']['total_tokens']} token "
            f"（{row['cost']['llm_calls']} 次调用，分档 {row['cost']['by_tier']}）"
        )
        lines.append("")
        lines.append(f"**实测 TP**（{s['tp_n']}）：{s['tp'] or '无'}")
        lines.append("")
        lines.append(f"**误报 FP**（{s['fp_n']}）：{s['fp'] or '无'}")
        lines.append("")
        if s["type_mismatch"]:
            lines.append(
                f"**类型错配**（端点确有漏洞，但 Confirmed 的类型与 ground truth 不符）："
                f"{s['type_mismatch']}"
            )
            lines.append("")
        if s["controls_confirmed"]:
            lines.append(f"**对照端点被 Confirmed**：{s['controls_confirmed']}")
            lines.append("")
        lines.append(
            f"**未能判定（verify_blocked）**：{s['unresolved_n']} 条"
            f"（{s['unresolved_reasons'] or '无'}）"
        )
        lines.append("")
        lines.append("**12 条真漏洞 + 4 对照的终态漏斗**：")
        lines.append("")
        for key, state in s["funnel"].items():
            lines.append(f"- `{key}` → {state}")
        lines.append("")
    return "\n".join(lines) + "\n"


def run_live(args, out_dir: Path) -> int:
    """M10a：4 臂 × 真实确认链路 → Confirmed 级指标。"""
    try:
        router = ModelRouter.from_env(args.env_file)
    except LLMError as exc:
        print(f"[配置错误] {exc}", file=sys.stderr)
        return 2
    for tier, label in ((Tier.T1, "T1"), (Tier.T2, "T2")):
        if tier not in router.configs:
            print(
                f"[配置错误] --live 需要 {label} 档：PROOFHOUND_{label}_*",
                file=sys.stderr,
            )
            return 2
    try:
        import docker

        docker.from_env().ping()
    except Exception as exc:  # noqa: BLE001
        print(f"[环境错误] Docker 不可用（沙箱执行是红线，不可跳过）: {exc}",
              file=sys.stderr)
        return 2

    arms = [a for a in _LIVE_ARMS if args.arm is None or a[0] in args.arm]
    if not arms:
        print(
            f"[配置错误] --arm 未匹配任何臂：{[a[0] for a in _LIVE_ARMS]}",
            file=sys.stderr,
        )
        return 2

    server, base = start_fixture()
    port = int(urllib.parse.urlparse(base).port)
    print(f"[*] --live：fixture {base}（真后端：sqlite 注入 / 未转义反射 / 身份归属）")
    print(f"[*] 臂：{[a[0] for a in arms]}；单臂超时 {args.live_timeout:.0f}s")
    rows: list[dict] = []
    try:
        for name, triage_model, prefilter in arms:
            print(
                f"\n=== 臂 {name}（PROOFHOUND_TRIAGE_MODEL={int(triage_model)} "
                f"PROOFHOUND_VERIFY_PREFILTER={int(prefilter)}）===",
                flush=True,
            )
            row = run_live_arm(
                name, triage_model, prefilter,
                env_file=args.env_file, base=base, port=port,
                root=out_dir, timeout=args.live_timeout,
            )
            rows.append(row)
            s = row["score"]
            precision = (
                f"{s['precision']:.1%}" if s["precision"] is not None else "—"
            )
            print(
                f"[*] 臂 {name}: TP={s['tp_n']} FP={s['fp_n']} "
                f"未能判定={s['unresolved_n']} 检出率={s['recall']:.1%} "
                f"精确率={precision} token={row['cost']['total_tokens']} "
                f"wall={row['wall_s']:.0f}s",
                flush=True,
            )
    finally:
        server.shutdown()

    meta = {
        "stamp": out_dir.name,
        "mode": "live-confirmed",
        "granularity": "（端点路径, vuln_type）",
        "blocked_policy": "verify_blocked 单列，不计入 precision/recall 分母",
        "arms": [a[0] for a in arms],
        "ground_truth_pairs": sum(len(v) for v in expected_pairs().values()),
        "env_switches": {
            "PROOFHOUND_TRIAGE_MODEL": "按臂设置",
            "PROOFHOUND_VERIFY_PREFILTER": "按臂设置",
        },
        "note": (
            "Confirmed 级：仅 state=confirmed 计入 TP/FP；候选级数字见离线三臂"
            "（同一 fixture，--live 为附加模式，不改变离线确定性）"
        ),
    }
    (out_dir / "live_report.json").write_text(
        json.dumps({"meta": meta, "arms": rows}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    markdown = render_live_markdown(rows, meta)
    (out_dir / "live_report.md").write_text(markdown, encoding="utf-8")
    print("\n" + markdown)
    print(f"[*] 产物：{out_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M9c triage 三臂消融基准")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument(
        "--model",
        action="store_true",
        help="rules+model 臂改用真实 T1 档（需 PROOFHOUND_T1_*）；缺省用离线替身上界",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="M10a：端到端真实确认链路（Docker + Chromium + T2）→ Confirmed 级指标",
    )
    parser.add_argument(
        "--arm",
        action="append",
        default=None,
        help=f"--live 只跑指定臂（可重复）；缺省跑全部：{[a[0] for a in _LIVE_ARMS]}",
    )
    parser.add_argument(
        "--live-timeout",
        type=float,
        default=3600.0,
        help="--live 单臂等待终态的秒数上限（缺省 3600）",
    )
    args = parser.parse_args()

    global BENCH_DIR
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    BENCH_DIR = REPO_ROOT / "evidence" / "bench_triage" / stamp
    BENCH_DIR.mkdir(parents=True, exist_ok=True)

    if args.live:
        return run_live(args, BENCH_DIR)

    # --model：rules+model 臂改用真实 T1 档（模型实测）；缺省用离线替身（上界）
    real_router = None
    if args.model:
        try:
            real_router = ModelRouter.from_env(args.env_file)
        except LLMError as exc:
            print(f"[配置错误] {exc}", file=sys.stderr)
            return 2
        if Tier.T1 not in real_router.configs:
            print(
                "[配置错误] --model 需要 T1 档（假设生成）：PROOFHOUND_T1_*",
                file=sys.stderr,
            )
            return 2
        print("[*] --model：rules+model 臂使用真实 T1 档（会产生真实 LLM 调用与费用）")

    signals: list = []
    server, base = start_fixture()
    try:
        signals, raw_text = crawl(base)
        print(f"[*] fixture 已启动 {base}；确定性爬行得 {len(signals)} 条 Signal")
        param_n = sum(1 for s in signals if s.kind == "param-endpoint")
        form_n = sum(1 for s in signals if s.kind == "form_page")
        print(f"    param-endpoint={param_n} form_page={form_n}")

        path_table: dict = {}
        for ep in ENDPOINTS:
            if not ep.vuln:
                continue
            param = ep.param if ep.param else (ep.fields[0] if ep.fields else "")
            path_table[ep.path] = (ep.vuln, param)

        rows = []
        for arm in ("rules", "model", "rules+model"):
            if arm in ("model", "rules+model"):
                if real_router is not None:
                    router = real_router
                else:
                    router = _ScriptedRouter(path_table)
                    router.tracker = UsageTracker()  # 替身也按同一口径计量
            else:
                router = None
            findings, stats = run_arm(
                arm,
                signals,
                raw_text,
                BENCH_DIR,
                router,
                real_router=(
                    real_router if (real_router is not None and router is real_router)
                    else None
                ),
            )
            scored = score_arm(arm, findings)
            apply_screening(base, scored, findings)
            rows.append({**stats, "score": scored.to_dict()})
            print(
                f"[*] 臂 {arm:<12} 发现率 {scored.discovery_rate:.1%} "
                f"({scored.hit_vuln}/{scored.total_vuln})  "
                f"误报率 {scored.false_positive_rate:.1%} "
                f"({scored.hit_safe}/{scored.total_safe})  "
                f"→ 粗筛后 {scored.screened_discovery_rate:.1%} / "
                f"{scored.screened_false_positive_rate:.1%}  "
                f"token={stats['llm_tokens']}"
            )
    finally:
        server.shutdown()

    meta = {
        "stamp": stamp,
        "endpoints": len(ENDPOINTS),
        "vuln_endpoints": sum(1 for e in ENDPOINTS if e.vuln),
        "safe_endpoints": sum(1 for e in ENDPOINTS if e.vuln is None),
        "signals_param": sum(1 for s in signals if s.kind == "param-endpoint"),
        "signals_form": sum(1 for s in signals if s.kind == "form_page"),
        "out_of_table": list(OUT_OF_TABLE),
        "model_mode": "real-t1" if args.model else "scripted-upper-bound",
        "note": (
            "真实 T1 档实测（--model）"
            if args.model
            else (
                "包含模型的臂使用离线替身（模型能力上界），数字不代表真实模型表现；"
                "真实模型须以 --model 跑 T1 档"
            )
        ),
    }
    (BENCH_DIR / "bench_report.json").write_text(
        json.dumps({"meta": meta, "arms": rows}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    markdown = render_markdown(rows, meta)
    (BENCH_DIR / "bench_report.md").write_text(markdown, encoding="utf-8")
    print("\n" + markdown)
    print(f"[*] 产物：{BENCH_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())