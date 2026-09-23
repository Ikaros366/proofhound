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

用法：
    .venv/bin/python scripts/bench_triage.py            # 离线确定性：三臂消融
    .venv/bin/python scripts/bench_triage.py --model    # rules+model 臂接真实 T1 档

产物落 evidence/bench_triage/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import argparse
import json
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


def _quote_hits(value: str) -> bool:
    """注入特征：引号未转义（模拟拼接式 SQL）。纯字符串判定，不连数据库。"""
    return "'" in value or '"' in value


def _page(title: str, body: str, links: tuple[str, ...] = ()) -> str:
    nav = "".join(f'<a href="{href}">{href}</a>' for href in links)
    return (
        f"<html><head><title>{title}</title></head><body>"
        f"<h1>{title}</h1><nav>{nav}</nav><div>{body}</div>"
        f"<footer>session={TOKEN}</footer></body></html>"
    )


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
        cookie = self.headers.get("Cookie") or ""
        for segment in cookie.split(";"):
            name, _, value = segment.strip().partition("=")
            if name == "phsess" and value:
                return value
        return None

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

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

        # ---- A 族：表内参数名 ----
        if path == "/a/sqli":
            value = first("id")
            if _quote_hits(value):
                self._respond(
                    500, _page("SQL error", "You have an error in your SQL syntax")
                )
                return
            # 真漏洞端点的真实行为：取值被反射进响应（长度随取值变化）
            self._respond(
                200,
                _page(
                    f"商品详情 {value}",
                    f"商品编号 id={value}，库存充足，可立即下单，支持七天无理由退换。",
                ),
            )
            return
        if path == "/a/sqli2":
            value = first("page")
            if _quote_hits(value):
                self._respond(500, _page("SQL error", "SQL syntax error near"))
                return
            self._respond(200, _page(f"第 {value} 页", f"当前页码 page={value}，共 42 条记录"))
            return
        if path == "/a/xss":
            value = first("name")
            self._respond(200, _page("搜索结果", f"你好，{value}，以下是找到的内容"))
            return
        if path == "/a/idor":
            value = first("id")
            self._respond(
                200,
                _page(f"订单 {value}", f"订单明细 id={value} 金额 800 状态已发货"),
            )
            return

        # ---- B 族：表外参数名（行为与 A 族同构） ----
        if path in ("/b/sqli", "/b/sqli2", "/b/sqli3"):
            key = {"/b/sqli": "article_id", "/b/sqli2": "bh", "/b/sqli3": "sku"}[path]
            value = first(key)
            if _quote_hits(value):
                self._respond(500, _page("SQL error", "SQL syntax error near"))
                return
            self._respond(
                200,
                _page(
                    f"文章 {value}",
                    f"正文内容 {key}={value}，共 3 页，预计阅读 5 分钟。",
                ),
            )
            return
        if path == "/b/xss":
            value = first("ref")
            self._respond(200, _page("来源页", f"你来自 {value}，即将为你跳转"))
            return
        if path in ("/b/idor", "/b/idor2"):
            key = "no" if path == "/b/idor" else "token"
            value = first(key)
            self._respond(
                200,
                _page(f"对象 {value}", f"明细 {key}={value} 客户张三 联系方式已隐藏"),
            )
            return

        # ---- D 族：安全对照（有响应差异，但无漏洞） ----
        if path == "/d/safe":
            value = first("id")
            # 安全对照：取值被忽略（定长模板），无回显
            self._respond(200, _page("公开页", "公开内容，任何人都可以访问。"))
            return
        if path == "/d/safe2":
            value = first("article_id")
            if _quote_hits(value):
                self._respond(500, _page("SQL error", "SQL syntax error near"))
                return
            self._respond(200, _page("帮助页", "静态帮助内容，取值被忽略。"))
            return
        if path == "/d/safe3":
            value = first("name").replace("<", "&lt;").replace(">", "&gt;")
            self._respond(200, _page("搜索", f"你好 {value}"))
            return
        if path == "/d/safe4":
            value = first("no")
            if self._identity() != "owner" and value == "2002":
                self._respond(403, _page("Forbidden", "无权限"))
                return
            self._respond(200, _page("工单页", "工单处理中，详情请登录后查看。"))
            return

        self._respond(404, _page("404", "not found"))

    def do_POST(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = urllib.parse.parse_qs(raw, keep_blank_values=True)
        if parsed.path in ("/c/form-sqli", "/c/form-sqli2"):
            if any(_quote_hits(v) for values in form.values() for v in values):
                self._respond(500, _page("SQL error", "SQL syntax error near"))
                return
            self._respond(200, _page("查询结果", "无结果"))
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


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M9c triage 三臂消融基准")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument(
        "--model",
        action="store_true",
        help="rules+model 臂改用真实 T1 档（需 PROOFHOUND_T1_*）；缺省用离线替身上界",
    )
    args = parser.parse_args()

    global BENCH_DIR
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    BENCH_DIR = REPO_ROOT / "evidence" / "bench_triage" / stamp
    BENCH_DIR.mkdir(parents=True, exist_ok=True)

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