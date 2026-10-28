"""最小编排器（M2b+M2c+M3a，§5.3）：scan 阶段链路的驱动者。

链路：registry 命中 skill → 规划器产计划（结构化 JSON，强校验）→
tools/build.py 拼装 argv（红线 1：LLM 不碰命令）→ SandboxRunner 执行
（红线 5：scope 强校验不变）→ 解析器产 Signal 落盘 → 全程审计。

- 阶段间串行、阶段内子任务并行（run_dag）；M2b 仅实现 scan 阶段；
  M3a 增加确定性 triage 阶段（run_triage_phase，规则表、零 LLM 调用）；
  M3b 增加确定性 verify 阶段（run_verify_phase：带会话 baseline → sqlmap
  行为确认 → 证据门 → Verifier T2 终审 → CONFIRMED/REJECTED，唯一 LLM
  调用是 Verifier 终审）；M3d 扩展 triage：katana 爬参 Signal
  （param-endpoint）按 query 参数键启发式展开 sqli 候选（上限 20 条防
  确认洪泛 + 建/并前 check_scope 第三层纵深）；M8a 再扩展：katana
  POST 表单页 Signal（form_page）按表单字段名/页面路径提示展开 sqli
  候选（共享同一上限），verify 阶段对 crawl-form 证据类候选走
  ``sqlmap --forms`` 模式（不手拼 --data）；M8b 再扩展：param-endpoint
  另按 ``_XSS_PARAM_HINTS`` 展开 xss 候选（独立上限 10、独立
  ``triage_capped`` 计数），verify 阶段新增 ``_verify_xss``——无头
  Chromium canary 探针行为确认（``verify/browser.py``，first-party
  验证器），method=browser-confirmed 过证据门 + Verifier 终审；
  M8c 再扩展：param-endpoint 再按 ``_IDOR_PARAM_HINTS`` 展开 idor
  候选（独立上限 10、独立 ``triage_capped``），verify 阶段新增
  ``_verify_idor``——双会话属性验证（``verify/idor.py``，first-party
  纯 stdlib 验证器）：B（reference/victim）会话基准 → A 会话对比 →
  确定性属性判定（相似度/键重叠写死阈值），method=dual-session-confirmed
  过证据门 + Verifier 终审；第二身份会话挂
  ``SessionConfig.reference``，脱敏递归覆盖两会话；
- 失败预算：同类失败默认上限 2 次，命中置 blocked 并升级（task_blocked）；
  验证码/锁定一次即硬阻塞；scope 拒绝与命令构造失败视为规划缺陷，
  直接 failed、不重试；
- LLM 上下文只进结构化 state（目标/次数/Signal 摘要），原始输出只给
  evidence 引用路径（红线 3）；
- M2c：LLM 调用经 ModelRouter（T1 档）；token 预算为硬闸——调用前检查，
  超限即停止规划循环、节点 blocked 并记审计 llm_budget_exceeded
  （与 scope 同级，任何自治模式不可绕过，无关闭开关）；上下文超硬上限
  （压缩后仍超）节点 failed 并记 context_overflow，禁止静默截断。
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple
from urllib.parse import parse_qsl, urlparse

from pydantic import ValidationError

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import check_scope
from proofhound.compliance.session import SessionConfig, redact_bytes, secret_marker
from proofhound.findings.dedup import compute_dedup_key
from proofhound.findings.evidence import assemble_evidence_pack
from proofhound.findings.finding import (
    STATUS_CODE_EVIDENCE_KIND,
    Finding,
    FindingState,
    FindingStore,
    IronRuleViolationError,
    Verification,
)
from proofhound.findings.signal import Signal
from proofhound.core.context import ContextOverflowError, ContextPolicy
from proofhound.core.failures import FailureBudget, classify
from proofhound.core.plan import PlanAction, PlanValidationError
from proofhound.core.planner import Planner
from proofhound.core.tasks import (
    TaskNode,
    TaskStatus,
    aggregate_phase,
    run_dag,
)
from proofhound.llm.client import LLMError
from proofhound.llm.triage import (
    ModelCandidate as _ModelCandidate,
    ModelTriageError,
    build_candidates as build_model_candidates,
    summarize_signals as summarize_triage_signals,
    build_candidates as build_model_candidates,
    summarize_signals as summarize_triage_signals,
)
from proofhound.llm.router import ensure_router
from proofhound.llm.usage import BudgetExceededError
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.build import (
    REQUEST_BUDGET_TOOLS,
    UnknownToolError,
    build_command,
    known_tools,
)
from proofhound.tools.manifest import load_manifest
from proofhound.tools.parsers import PARSER_REGISTRY, parse_sqlmap_stdout
from proofhound.tools.sandbox import RunResult, SandboxRunner
from proofhound.verify.browser import (
    BrowserUnavailableError,
    BrowserVerifier,
    new_token as new_canary_token,
    payload_url as xss_payload_url,
)
from proofhound.verify.browser import PAYLOAD_TEMPLATES as XSS_PAYLOAD_TEMPLATES
from proofhound.verify.cmdi import (
    CMDI_CONFIRMED_METHOD,
    DELIVERY_VARIANT,
    DNS_VARIANT,
    VARIANTS as CMDI_VARIANTS,
)
from proofhound.verify.cmdi import build_probe_url as cmdi_build_probe_url
from proofhound.verify.cmdi import callback_value as cmdi_callback_value
from proofhound.verify.cmdi import delivery_probe_value as cmdi_delivery_probe_value
from proofhound.verify.cmdi import dns_probe_value as cmdi_dns_probe_value
from proofhound.verify.cmdi import fetch as cmdi_fetch_default
from proofhound.verify.cmdi import judge as cmdi_judge
from proofhound.verify.cmdi import new_cmdi_token
from proofhound.verify.cmdi import same_origin as cmdi_same_origin
from proofhound.verify.cmdi import summary_for_verifier as cmdi_summary_for_verifier
from proofhound.verify.cmdi import token_delivered as cmdi_token_delivered
from proofhound.verify.coverage import (
    CAP_PER_TYPE as COVERAGE_CAP_PER_TYPE,
    CAP_TOTAL as COVERAGE_CAP_TOTAL,
)
from proofhound.verify.coverage import build_url as coverage_build_url
from proofhound.verify.coverage import plan_for as coverage_plan_for
from proofhound.verify.coverage import (
    select_session as coverage_select_session,
)
from proofhound.verify.cvss import base_score as cvss_base_score
from proofhound.verify.cvss import severity_for_score
from proofhound.verify.error_disclosure import (
    ERROR_DISCLOSURE_CONFIRMED_METHOD,
    ERROR_TRACE_EVIDENCE_KIND,
    PROBE_BUDGET as ERROR_DISCLOSURE_PROBE_BUDGET,
)
from proofhound.verify.error_disclosure import (
    ProbeOutcome as ErrorDisclosureProbe,
)
from proofhound.verify.error_disclosure import (
    ProbeSpec as ErrorDisclosureProbeSpec,
)
from proofhound.verify.error_disclosure import (
    build_baseline as error_disclosure_baseline,
    build_probes as error_disclosure_probes,
    judge as error_disclosure_judge,
    outcome_from_response as error_disclosure_outcome,
    summary_for_verifier as error_disclosure_summary,
)
from proofhound.verify.gate import BEHAVIORAL_EVIDENCE_KIND
from proofhound.verify.gate import check as gate_check
from proofhound.verify.idor import fetch as idor_fetch_default
from proofhound.verify.idor import has_substance as idor_has_substance
from proofhound.verify.idor import judge as idor_judge
from proofhound.verify.idor import judgment_dict as idor_judgment_dict
from proofhound.verify.idor_control import (
    body_sha256 as idor_body_sha256,
    control_summary as idor_control_summary,
    judge_control as idor_judge_control,
    judge_ownership as idor_judge_ownership,
)
from proofhound.verify.prefilter import screen as prefilter_screen
from proofhound.verify.prefilter import with_query_param as prefilter_with_query_param
from proofhound.verify.raw_http import DEFAULT_TIMEOUT as RAW_HTTP_DEFAULT_TIMEOUT
from proofhound.verify.raw_http import send_raw as raw_http_send_default
from proofhound.verify.screenshot import ScreenshotCapturer
from proofhound.verify.ssti import (
    KIND_BASELINE as SSTI_KIND_BASELINE,
)
from proofhound.verify.ssti import KIND_CONTROL as SSTI_KIND_CONTROL
from proofhound.verify.ssti import KIND_EXPRESSION as SSTI_KIND_EXPRESSION
from proofhound.verify.ssti import PROBE_BUDGET as SSTI_PROBE_BUDGET
from proofhound.verify.ssti import PRODUCT_A as SSTI_PRODUCT_A
from proofhound.verify.ssti import PRODUCT_B as SSTI_PRODUCT_B
from proofhound.verify.ssti import SSTI_CONFIRMED_METHOD
from proofhound.verify.ssti import (
    SSTI_EVALUATION_EVIDENCE_KIND,
)
from proofhound.verify.ssti import SYNTAX_FAMILIES as SSTI_SYNTAX_FAMILIES
from proofhound.verify.ssti import VERDICT_REJECTED as SSTI_VERDICT_REJECTED
from proofhound.verify.ssti import Probe as SstiProbe
from proofhound.verify.ssti import build_probe_url as ssti_build_probe_url
from proofhound.verify.ssti import fetch as ssti_fetch_default
from proofhound.verify.ssti import judge as ssti_judge
from proofhound.verify.ssti import match_products as ssti_match_products
from proofhound.verify.ssti import summary_for_verifier as ssti_summary_for_verifier
from proofhound.verify.ssrf import (
    CALLBACK_PATH_PREFIX,
    NON_LOOPBACK_WARNING,
    SSRF_CONFIRMED_METHOD,
    CallbackListener,
    SsrfListenerError,
)
from proofhound.verify.ssrf import callback_url as ssrf_callback_url
from proofhound.verify.ssrf import fetch as ssrf_fetch_default
from proofhound.verify.ssrf import is_loopback_host as ssrf_is_loopback_host
from proofhound.verify.ssrf import judge as ssrf_judge
from proofhound.verify.ssrf import new_nonce_host as ssrf_new_nonce_host
from proofhound.verify.ssrf import new_token as ssrf_new_token
from proofhound.verify.ssrf import nonce_url as ssrf_nonce_url
from proofhound.verify.ssrf import resolve_callback_bind as ssrf_resolve_callback_bind
from proofhound.verify.ssrf import resolve_callback_host as ssrf_resolve_callback_host
from proofhound.verify.ssrf import resolve_callback_port as ssrf_resolve_callback_port
from proofhound.verify.ssrf import summary_for_verifier as ssrf_summary_for_verifier
from proofhound.verify.ssrf import token_delivered as ssrf_token_delivered
from proofhound.verify.ssrf import url_host_port as ssrf_url_host_port
from proofhound.verify.gate import VULN_REGISTRY
from proofhound.verify.unauth_control import (
    UNAUTH_CONFIRMED_METHOD,
    UNAUTH_EQUIVALENCE_EVIDENCE_KIND,
    VERDICT_BLOCKED as UNAUTH_BLOCKED,
    VERDICT_EXPOSED as UNAUTH_EXPOSED,
    VERDICT_REQUIRES_AUTH as UNAUTH_REQUIRES_AUTH,
    judge_unauth,
    summary_to_json as unauth_summary_to_json,
)
from proofhound.verify.unauth_judge import (
    UnauthJudge,
    UnauthJudgeError,
)
from proofhound.verify.verifier import Verifier, VerifierError

_OUTPUT_SAMPLE_LIMIT = 4096  # 失败分类的输出采样上限（字节）

# 确定性 triage 规则表（M3a）：web-probe 存活状态 → web-exposure 假设。
# 与 web-scan SKILL.md"存活"判定一致（2xx/3xx/401/403）；LLM triage 留后续切片。
_EXPOSED_STATUSES = frozenset({200, 201, 204, 301, 302, 307, 308, 401, 403})

# M17-b：`unauth-exposure` 候选的派生**范围收窄**（维护者 2026-09-30 裁定）。
# 取 `_EXPOSED_STATUSES` 的 **2xx 子集**，理由逐条：
# - **401/403 是反例**：匿名被拒正是「该资源本就要求认证」的**确定性**结局
#   （`verify/unauth_control.py::judge_unauth` 直接判 `requires_auth` → Rejected），
#   派生它们纯属浪费一次贵验证配额；
# - **3xx**：`_verify_unauth` 的取数不跟随重定向，拿到的是裸跳转响应，
#   与已认证视图比对多半判 `blocked`（覆盖不全），同样只产噪声；
# - 而该类型的立论是「**匿名直接拿到内容**」——只有 2xx 对应这个语义。
# 刻意**不复用** `_EXPOSED_STATUSES`：那个集合服务的是 web-exposure 的
# 「端点有反应」语义（含 401/403/3xx），两者语义不同，不可混用。
_UNAUTH_EXPOSED_STATUSES = frozenset({200, 201, 204})

# M3d：katana 爬参（kind="param-endpoint"）→ sqli 假设的参数键启发式。
# 精确匹配（键小写比对）：宁可漏报（保持 Signal）不可滥建——每条 sqli
# Hypothesis 都会在 verify 阶段消耗一次 L2 确认与一次行为验证。
_SQLI_PARAM_HINTS = frozenset(
    {
        "id", "uid", "user", "username", "page", "file", "include", "cat",
        "category", "search", "q", "query", "name", "order", "sort", "dir",
        "path", "item", "view", "pid",
    }
)

# M3d：每 engagement 新建 sqli Hypothesis 上限（防确认洪泛，超出记 triage_capped）
_TRIAGE_SQLI_CAP = 20

# M8b：param-endpoint → xss 假设的参数键启发式（保守小表，宁漏勿滥；
# 与 _SQLI_PARAM_HINTS 有交集——交集参数会同产两类候选，dedup 按
# vuln_type 分量区分互不合并，各自消耗一次 L2 确认）
_XSS_PARAM_HINTS = frozenset(
    {
        "name", "q", "search", "query", "keyword", "comment", "msg",
        "message", "text", "redirect", "url",
    }
)

# M8b：每 engagement 新建 xss Hypothesis 上限（独立计数、独立 triage_capped 事件）
_TRIAGE_XSS_CAP = 10

# M8c：param-endpoint → idor 假设的参数键启发式（保守表：对象标识类键名；
# 与 _SQLI_PARAM_HINTS 有交集——交集参数会同产 sqli+idor 候选，dedup 按
# vuln_type 分量区分互不合并，各自消耗一次 L2 确认；刻意不收 name 等泛化键，
# 收窄爆炸半径）
_IDOR_PARAM_HINTS = frozenset(
    {
        "id", "uid", "user", "userid", "user_id", "account", "order",
        "invoice", "doc", "document", "record", "file",
    }
)

# M8c：每 engagement 新建 idor Hypothesis 上限（独立计数、独立 triage_capped 事件）
_TRIAGE_IDOR_CAP = 10

# M18-b：param-endpoint → cmdi 假设的参数键启发式（保守小表，宁漏勿滥）。
#
# **裁定 C3**：命令注入既有确定性候选（本表）也有模型通道补盲区——与
# sqli/xss/idor 一致。当初把「关键词表」列为"不做"是针对**敏感度判定**
# （unauth-exposure 的语义判断那一半），不针对**候选生成**；候选生成侧
# 五类里四类都在用提示表，本表沿用同一取舍。
#
# 表内容偏"命令执行/网络诊断/系统命令"类参数名——这类端点最可能把取值
# 直接拼进 shell。刻意**不收** id/name 这类泛化键（那会让几乎每个端点都产
# cmdi 候选，爆炸半径过大）。
_CMDI_PARAM_HINTS = frozenset(
    {
        "cmd", "command", "exec", "execute", "run", "shell", "system",
        "ping", "host", "ip", "target", "domain", "url", "file", "path",
        "daemon", "process", "service", "script", "query", "input",
    }
)

# M18-b：每 engagement 新建 cmdi Hypothesis 上限（独立计数、独立 triage_capped 事件）。
# 独立上限是硬要求：每条 cmdi 候选在 verify 阶段会**逐条发最多 10 次真实请求**
# （1 交付探针 + 1 DNS 探针 + ≤8 载荷变体）并各开一个回调 listener，
# 不设限会给贵验证档与目标同时灌水。
_TRIAGE_CMDI_CAP = 10

# M22：param-endpoint → ssti 假设的参数键启发式（保守小表，宁漏勿滥）。
#
# 表内容是「**文本进模板**」的强语义键：模板/布局/主题/语言/渲染/格式/邮件主题/
# 问候语/签名档 —— 这类参数最可能被直接拼进模板源码（SSTI 的真实成因）。
# 刻意**不收** id/page/name/msg 这类泛化键（那会让几乎每个端点都产 ssti 候选，
# 而每条候选在 verify 阶段最多要发 8 次只读 GET）。
#
# 与 sqli/xss/idor/cmdi 四张表的**交集为 0**（刻意）：交集会让同一参数同产两条
# 候选、各消耗一次 L2 确认，而 ssti 的判据（模板求值）与那四类互不重叠。
_SSTI_PARAM_HINTS = frozenset(
    {
        "template", "tpl", "tmpl", "layout", "theme", "lang", "locale",
        "render", "format", "fmt", "greeting", "subject", "email", "preview",
        "signature", "content",
    }
)

# M22：每 engagement 新建 ssti Hypothesis 上限（独立计数、独立 triage_capped）。
# 独立上限是硬要求：每条 ssti 候选在 verify 阶段最多发 8 次只读 GET（基线 +
# 逐语法两个操作数 + 畸形对照），不设限会给目标与贵验证档同时灌水。
_TRIAGE_SSTI_CAP = 10

# M23：每 engagement 新建 error-disclosure Hypothesis 上限（独立计数、独立
# triage_capped）。候选按 **host** 派生（一个 origin 一条），每条在 verify
# 阶段最多 1 次基线 + 5 次畸形请求——不设限时会随 web-probe 信号数灌水。
_TRIAGE_ERROR_DISCLOSURE_CAP = 10

# M17-b：每 engagement 新建 unauth-exposure Hypothesis 上限（独立计数、独立
# triage_capped 事件）。**必须**有独立上限：`web-exposure` 是全池唯一**没有**
# 上限的类型（其余各有），而新生产者的候选量与 web-probe 信号数同阶，
# 每条又要花「2 次 HTTP + 1 次 T1 调用」——不设限会给贵验证档灌水。
#
# M19-b 更正：原文写「（sqli/xss/idor 各有）」并称 web-exposure 是**唯一**无上限
# 的类型。那是 M16 之前的实况——`ssrf` 自 M16 起就没有 `_TRIAGE_CAPS` 条目
# （规则表刻意不给它提示表、只走模型通道，加类型时漏登记了上限），故"唯一"
# 一直是错的。现补 `_TRIAGE_SSRF_CAP`，并由
# `tests/test_vuln_registry.py::test_every_registered_type_has_a_triage_cap`
# 断言「注册类型集合 == 上限登记表集合」，杜绝下一次漏登记。
_TRIAGE_UNAUTH_CAP = 10

# M19-b：每 engagement 新建 ssrf Hypothesis 上限（独立计数、独立 triage_capped）。
# `ssrf` 只由模型通道产出（`PROOFHOUND_TRIAGE_MODEL` 缺省关闭），但一旦开启就没有
# 任何条数上界——而每条候选在验证期都要开一个回调 listener 并发带会话探测。
_TRIAGE_SSRF_CAP = 10

#: 需要「scope 配了可用预置会话」才能验证的 vuln_type —— **由
#: `verify/gate.py::VULN_REGISTRY` 的 `requires_session` 派生**（M17-c）。
#: 两类都是**等价性/基线比对**型判定，没有已认证视图就没有可比对象：
#: - ``unauth-exposure``：匿名视图 vs 已认证视图（缺后者 ⇒ 无从比）；
#: - ``ssrf``：带会话 baseline（缺会话 ⇒ `_verify_ssrf` 直接 blocked）。
#: 在登记表里声明 `requires_session=True` ⇒ 该类型的候选在缺会话时**一次也不进
#: 贵验证档**（配额仍留给真验证）。
_VERIFY_PRECONDITIONS: frozenset[str] = frozenset(
    vuln_type
    for vuln_type, spec in VULN_REGISTRY.items()
    if spec.requires_session
)

#: vuln_type → 每 engagement 新建 Hypothesis 上限（未登记的类型不限）。
#: M17-b：由 `_ingest_candidates` 里的三个并列 if 收成一张查表——加类型时
#: 只需在此登记，不必再改判定逻辑（漏登记表现为「该类型无上限」，显式可查）。
_TRIAGE_CAPS: dict[str, int] = {
    "sqli": _TRIAGE_SQLI_CAP,
    "xss": _TRIAGE_XSS_CAP,
    "idor": _TRIAGE_IDOR_CAP,
    "ssrf": _TRIAGE_SSRF_CAP,  # M19-b
    "unauth-exposure": _TRIAGE_UNAUTH_CAP,
    "cmdi": _TRIAGE_CMDI_CAP,  # M18-b
    "ssti": _TRIAGE_SSTI_CAP,  # M22-a
    "error-disclosure": _TRIAGE_ERROR_DISCLOSURE_CAP,  # M23
}

# M9c②：**贵验证档**上限。启用廉价粗筛（``verify_prefilter``）时，cap 从
# 「候选生成侧」移到这里——候选可以放开生成（模型 triage），由廉价粗筛先
# 砍一遍，卡的是真正昂贵的 Chromium/sqlmap/双会话验证次数。
# 关闭粗筛时该上限不生效（保持 M9c 之前行为：cap 只在 triage 生成侧）。
_TRIAGE_EXPENSIVE_CAP = 60

# param-endpoint 候选的证据种类标签（爬行发现的带参端点，非行为证据）
CRAWL_ENDPOINT_EVIDENCE_KIND = "crawl-endpoint"

# M8a：form_page 候选的证据种类标签（爬行发现的 POST 表单页，非行为证据）；
# verify 阶段据此切换 sqlmap --forms 验证模式（发现方式确定性决定验证方式）
CRAWL_FORM_EVIDENCE_KIND = "crawl-form"

# M8a：form_page 候选的页面路径提示（字段名零命中时的保守回退）：path 段
# 小写去扩展名后精确匹配。宁漏勿滥——每条候选消耗一次 L2 确认与行为验证
_SQLI_PATH_HINTS = frozenset({"sqli", "sql", "login", "signin", "search"})

#: param-endpoint → 各漏洞类型的**参数键提示表**（M19-a：规则表入口的单一真相源）。
#:
#: 顺序即候选生成顺序（sqli → xss → idor → cmdi → ssti），与拆分前的
#: 「sqli 列表推导 + 三个 extend」逐条等价。
#:
#: **新增提示表必须登记在此**：`tests/test_vuln_registry.py` 的断言
#: ``test_param_hint_tables_are_all_registered`` 要求模块里每个
#: ``_*_PARAM_HINTS`` 都出现在本表，生产者穷举器也从本表派生——于是
#: 「加了一张表但枚举器没跟上」不会再静默发生（M18-b 已经实际发生过一次：
#: `_CMDI_PARAM_HINTS` 的 21 键里有 17 键从未被穷举器喂过，cmdi 只是碰巧靠
#: `file`/`query` 等 4 个交集键通过）。
_PARAM_HINT_TABLES: dict[str, tuple[frozenset[str], str]] = {
    "sqli": (_SQLI_PARAM_HINTS, "medium"),
    "xss": (_XSS_PARAM_HINTS, "medium"),
    "idor": (_IDOR_PARAM_HINTS, "medium"),
    "cmdi": (_CMDI_PARAM_HINTS, "critical"),
    "ssti": (_SSTI_PARAM_HINTS, "critical"),
}


class _TriageCandidate(NamedTuple):
    """一条 triage 候选；一个 Signal 可展开多条（按参数键/表单字段名）。"""

    vuln_type: str
    param: str | None
    severity: str
    evidence_kind: str
    source: str  # M8a：web_probe / get_param / form_page（triage_completed 摘要分量）
    #: 候选级 asset 覆盖（M23）：``None`` = 用 Signal 的 asset。
    #: ``error-disclosure`` 按 **host 级**产出（asset=origin），与触发信号
    #: 的 URL 粒度不同——没有这个字段就只能把 host 级候选挂到第一条 URL 上，
    #: 去重也就退化成按 URL 而不是按 host。
    asset: str | None = None


def _callback_token_in(value: str) -> str:
    """从注入的参数值里取回调 token（与 URL 同一真相源的唯一取法）。

    M16：token **必须**从实际注入的字符串里解析，而不是另生成一个——否则
    "注册的 token" 与 "URL 里的 token" 会对不上，confirmed 分支永远不触发
    （实现期埋点实测的严重缺陷）。取不到返回空串，调用方 fail-closed。
    """
    parsed = urlparse(value)
    path = parsed.path
    marker = f"{CALLBACK_PATH_PREFIX}"
    if not path.startswith(marker):
        return ""
    token = path[len(marker):]
    # 变体形如 ``<callback>&param=<callback>``：取第一段即可
    return token.split("&", 1)[0].strip()


def _origin_of(url: str) -> tuple[str, str, int] | None:
    """URL 的 origin（scheme, host, port）——端口按 scheme 补缺省值。

    M16：ssrf 探针的同源自检用它。返回 None 表示无法解析（调用方 fail-closed）。
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def _origin_url(url: str) -> str | None:
    """URL → origin（``scheme://host[:port]``，默认端口省略；M23）。

    用作 error-disclosure 候选的 asset：中间件错误页是 host 级现象，
    按 origin 去重才能让同一 host 的多个 URL 合成一条候选。
    非 http(s) 或不可解析返回 None（调用方 fail-closed）。
    """
    origin = _origin_of(url)
    if origin is None:
        return None
    scheme, host, port = origin
    if scheme not in ("http", "https"):
        return None
    literal = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    suffix = "" if port == default else f":{port}"
    return f"{scheme}://{literal}{suffix}"


def _host_header(host: str, port: int, tls: bool) -> str:
    """构造 ``Host`` 头（IPv6 加方括号；默认端口省略）。"""
    literal = f"[{host}]" if ":" in host else host
    default = 443 if tls else 80
    return literal if port == default else f"{literal}:{port}"


def _query_param_keys(url: str) -> list[str]:
    """从 URL query 展开参数键（保序去重、小写化；空值键保留）。"""
    keys: list[str] = []
    for key, _value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        key = key.strip().lower()
        if key and key not in keys:
            keys.append(key)
    return keys


def _form_field_names(signal: Signal) -> list[str]:
    """form_page Signal 的字段名规范化（保序去重、小写化；空白名丢弃）。"""
    names: list[str] = []
    for name in signal.form_fields:
        key = name.strip().lower()
        if key and key not in names:
            names.append(key)
    return names


def _form_page_path_hit(url: str) -> bool:
    """页面路径提示命中：path 段（小写、去扩展名）精确匹配 _SQLI_PATH_HINTS。"""
    for segment in urlparse(url).path.lower().split("/"):
        stem = segment.rsplit(".", 1)[0]
        if stem and stem in _SQLI_PATH_HINTS:
            return True
    return False


def _triage_candidates(
    signal: Signal, *, session_available: bool = False
) -> list[_TriageCandidate]:
    """triage 规则映射：可映射返回候选列表，不可映射返回空（保持 Signal）。

    ``session_available``（M17-b）：scope 是否配了**可用**的预置会话——只有能
    构造出「已认证视图」时才派生 `unauth-exposure`。缺省 ``False``，故既有调用方
    行为逐字节不变（纯函数不读 scope，故由调用方传入；等价性判定结构上要求目标
    能认证，无会话时该类型的验证恒 blocked ⇒ 派生即噪声）。
    """
    if signal.kind == "web-probe" and signal.status_code in _EXPOSED_STATUSES:
        candidates = [
            _TriageCandidate(
                vuln_type="web-exposure",
                param=None,
                severity="info",
                evidence_kind=STATUS_CODE_EVIDENCE_KIND,
                source="web_probe",
            )
        ]
        # M17-b：同一份信号再按 `_UNAUTH_EXPOSED_STATUSES` 派生 unauth-exposure
        # 候选（**并存，不取代** web-exposure——维护者 2026-09-30 裁定）。
        # 并存的理由：两者**本来就不冗余**——`web-exposure` 是「端点有反应」的
        # 纯 status-code 观察（铁律 2 禁止其 Confirmed，进报告 hypothesis 桶，
        # 也是无会话 engagement 下「哪些端点可达」的**唯一**记录）；
        # `unauth-exposure` 是「匿名拿到与已认证等价的内容」（可 Confirmed）。
        # 取代会让无会话的扫描丢掉全部信息类观察。
        if session_available and signal.status_code in _UNAUTH_EXPOSED_STATUSES:
            candidates.append(
                _TriageCandidate(
                    vuln_type="unauth-exposure",
                    param=None,
                    severity="medium",
                    evidence_kind=STATUS_CODE_EVIDENCE_KIND,
                    source="web_probe",
                )
            )
        # M23：同一份「host 可达」信号再按 **origin** 派生一条
        # error-disclosure 候选（与上面两类并存，不取代）。派生条件只看
        # 可达性（本分支已在 `_EXPOSED_STATUSES` 内）——错误页与状态码
        # 无关，401/403 的 host 同样可能有堆栈泄露；**不需要**预置会话
        # （判据与身份无关，探针不带凭据）。
        origin = _origin_url(signal.asset)
        if origin is not None:
            candidates.append(
                _TriageCandidate(
                    vuln_type="error-disclosure",
                    param=None,
                    severity="low",
                    evidence_kind=STATUS_CODE_EVIDENCE_KIND,
                    source="web_probe",
                    asset=origin,
                )
            )
        return candidates
    if signal.kind == "param-endpoint":
        keys = _query_param_keys(signal.asset)
        candidates: list[_TriageCandidate] = []
        # M19-a：五类参数键提示表由 `_PARAM_HINT_TABLES` **派生**（M22-a 起含 ssti；登记顺序即
        # 生成顺序，与拆分前的「sqli 列表推导 + 三个 extend」逐条等价）。
        # 表间交集参数会同产多条候选（`id` 既可能注入也可能越权、`query` 既可能
        # 进 SQL 也可能进 shell），dedup 按 vuln_type 分量区分，各自经独立
        # verify skill 行为验证。
        for vuln_type, (hints, severity) in _PARAM_HINT_TABLES.items():
            candidates.extend(
                _TriageCandidate(
                    vuln_type=vuln_type,
                    param=key,
                    severity=severity,
                    evidence_kind=CRAWL_ENDPOINT_EVIDENCE_KIND,
                    source="get_param",
                )
                for key in keys
                if key in hints
            )
        return candidates
    if signal.kind == "form_page":
        # M8a：表单字段名命中提示表 → 每字段一条候选（dedup 带 param 分量）；
        # 零命中回退页面路径提示（param=None）；都不命中保持 Signal
        hits = [name for name in _form_field_names(signal) if name in _SQLI_PARAM_HINTS]
        if hits:
            return [
                _TriageCandidate(
                    vuln_type="sqli",
                    param=name,
                    severity="medium",
                    evidence_kind=CRAWL_FORM_EVIDENCE_KIND,
                    source="form_page",
                )
                for name in hits
            ]
        if _form_page_path_hit(signal.asset):
            return [
                _TriageCandidate(
                    vuln_type="sqli",
                    param=None,
                    severity="medium",
                    evidence_kind=CRAWL_FORM_EVIDENCE_KIND,
                    source="form_page",
                )
            ]
        return []
    return []


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _default_tool_parsers() -> dict:
    """工具名 → 解析函数：由打包 manifests 的 parser 标识桥接 PARSER_REGISTRY。"""
    manifests_dir = Path(__file__).parent.parent / "tools" / "manifests"
    mapping = {}
    for path in sorted(manifests_dir.glob("*.yaml")):
        manifest = load_manifest(path)
        parser = PARSER_REGISTRY.get(manifest.parser or "")
        if parser is not None:
            mapping[manifest.name] = parser
    return mapping


def _default_tool_images() -> dict:
    """工具名 → 沙箱镜像覆盖（M3b）：由打包 manifests 的 image 字段聚合。"""
    manifests_dir = Path(__file__).parent.parent / "tools" / "manifests"
    mapping = {}
    for path in sorted(manifests_dir.glob("*.yaml")):
        manifest = load_manifest(path)
        if manifest.image:
            mapping[manifest.name] = manifest.image
    return mapping


class Orchestrator:
    """M2b 最小编排器：单模型规划 + scan 阶段执行。"""

    def __init__(
        self,
        registry: SkillRegistry,
        runner: SandboxRunner,
        llm,
        audit: AuditLog,
        evidence_dir: str | Path,
        *,
        budget: FailureBudget | None = None,
        tools: set[str] | None = None,
        parsers: dict | None = None,
        max_workers: int = 4,
        context_policy: ContextPolicy | None = None,
        tool_images: dict | None = None,
        browser_factory=None,
        screenshot_factory=None,
        screenshots: bool = False,
        idor_fetch=None,
        ssrf_listener_factory=None,
        ssrf_fetch=None,
        unauth_judge_factory=None,
        cmdi_fetch=None,
        ssti_fetch=None,
        raw_http_send=None,
        triage_rules: bool = True,
        triage_model: bool = False,
        verify_prefilter: bool = False,
        prefilter_fetch=None,
        expensive_cap: int = _TRIAGE_EXPENSIVE_CAP,
    ):
        # llm 接受 ModelRouter（M2c 推荐：选路/计量/预算硬闸在路由层）；
        # 旧式单模型客户端由 Planner 自动包装适配（不计量）。
        self.registry = registry
        self.runner = runner
        self.audit = audit
        self.evidence_dir = Path(evidence_dir)
        self.budget = budget or FailureBudget()
        self.tools = set(tools) if tools is not None else set(known_tools())
        self.parsers = parsers if parsers is not None else _default_tool_parsers()
        self.max_workers = max_workers
        self.router = ensure_router(llm)  # M3b：Verifier 走 T2 档复用同一路由
        self.tool_images = (
            tool_images if tool_images is not None else _default_tool_images()
        )
        self.planner = Planner(
            llm, registry, self.tools, audit, context_policy=context_policy
        )
        # M8b：verify-xss 的浏览器注入口子（测试给 FakeBrowser；None 时
        # _verify_xss 懒建真实 BrowserVerifier 并缓存于 self._browser）
        self.browser_factory = browser_factory
        self._browser = None
        # M20：证据截图（opt-in，缺省关闭 ⇒ 默认行为与 M20 之前逐字节等价）。
        # screenshot_factory 是测试注入口子；None 时懒建真实 ScreenshotCapturer。
        self.screenshots = screenshots
        self.screenshot_factory = screenshot_factory
        self._screenshotter = None
        # M20-b：覆盖截图的每类型 / 每 phase 计数（run_verify_phase 开头重置）
        self._coverage_by_type: dict[str, int] = {}
        self._coverage_total = 0
        # M8c：verify-idor 的取数注入口子（测试给罐头 fetch；None 时用
        # verify/idor.py 的真实 stdlib fetch）
        self._idor_fetch = idor_fetch if idor_fetch is not None else idor_fetch_default
        # M16：verify-ssrf 的两个注入口子——回调 listener（测试给假 listener）与
        # 宿主侧探测取数（测试给罐头 fetch）；None 时用 verify/ssrf.py 的真实实现。
        self._ssrf_listener_factory = ssrf_listener_factory
        self._ssrf_fetch = ssrf_fetch if ssrf_fetch is not None else ssrf_fetch_default
        # M16-c：verify-unauth 的敏感度判定器注入口子（测试给替身判定器；
        # None 时懒建真实 UnauthJudge，走 T1 档）
        self._unauth_judge_factory = unauth_judge_factory
        # M18：verify-cmdi 的宿主侧取数口子（测试给罐头 fetch；None 时用
        # verify/cmdi.py 的真实实现）。listener 复用 SSRF 的 ssrf_listener_factory
        # ——两者是同一件基础设施（`CallbackListener`），共用即可。
        self._cmdi_fetch = cmdi_fetch if cmdi_fetch is not None else cmdi_fetch_default
        # M22-b：verify-ssti 的取数注入口子（测试给罐头 fetch；None 时用
        # verify/ssti.py 的真实 stdlib fetch）。判据与身份无关，故会话可为 None。
        self._ssti_fetch = ssti_fetch if ssti_fetch is not None else ssti_fetch_default
        # M23：verify-error-disclosure 的**裸 TCP** 发送口子（测试给罐头发送器；
        # None 时用 verify/raw_http.py 的真实实现）。不能用 urllib/httpx——
        # 它们在客户端就会拒绝畸形请求行，探针根本发不出去。
        self._raw_http_send = (
            raw_http_send if raw_http_send is not None else raw_http_send_default
        )
        # 回调 listener 按 finding 分桶（每条候选一个独立 listener + 独立 token 空间），
        # phase 收尾统一释放（与 _close_browser 同范式）
        self._ssrf_listeners: dict[str, CallbackListener] = {}
        # M16-c：敏感度判定器懒建槽位（None = 尚未建；见 _get_unauth_judge）
        self._unauth_judge = None
        # M9c①：triage 候选来源开关。model 侧**缺省关闭**——默认行为因此
        # 与 M3a 起逐字节等价（tests/test_triage.py 断言「triage 不调 LLM」
        # 由 triage_model=False 保证）；规则侧保留为快速路径与兜底。
        self.triage_rules = triage_rules
        self.triage_model = triage_model
        # M9c②：贵验证档前置廉价粗筛（缺省关闭——默认行为与 M9c 之前
        # 逐字节等价）。开启后 cap 卡在贵验证档而非候选生成侧。
        self.verify_prefilter = verify_prefilter
        self._prefilter_fetch = prefilter_fetch
        self.expensive_cap = expensive_cap
        self._expensive_spent = 0  # 本 phase 已花的贵验证次数
        self._prefilter_advisory = 0  # 粗筛给出「不值得优先」建议的条数

    def run_scan_phase(self, targets: list[str], *, skill_name: str = "web-scan") -> TaskNode:
        """跑 scan 阶段：每目标一个子任务并行，返回阶段节点（含整棵树）。"""
        skill = self.registry.get(skill_name)
        if skill is None:
            raise KeyError(f"未注册的 skill: {skill_name}")
        if not skill.enabled:
            raise PermissionError(f"skill 未启用: {skill_name}")

        phase = TaskNode(name=f"phase:scan", kind="phase", audit=self.audit)
        phase.transition(TaskStatus.RUNNING, reason=f"scan 阶段启动，{len(targets)} 个目标")
        phase.children = [
            TaskNode(
                name=f"scan:{target}",
                kind="subtask",
                audit=self.audit,
                meta={"target": target},
            )
            for target in targets
        ]
        run_dag(
            phase.children,
            lambda node: self._run_subtask(node, skill),
            max_workers=self.max_workers,
        )
        phase.transition(aggregate_phase(phase), reason="阶段聚合")
        return phase

    # ---- triage 阶段（M3a，确定性、零 LLM 调用） ----

    def run_triage_phase(self) -> list[Finding]:
        """triage：加载 scan 阶段 Signals → 候选映射 → findings.jsonl。

        可映射 vuln_type 的 Signal 建/并 Finding 置 Hypothesis（同 dedup_key
        合并证据并记审计 finding_deduplicated）；不可映射保持 Signal。
        **默认全程规则表判定，零 LLM 调用**（与 M3a 起逐字节等价）。

        M3d：param-endpoint Signal 按 query 参数键展开 sqli 候选（启发式
        键名精确匹配 + 每 engagement 新建上限 ``_TRIAGE_SQLI_CAP`` 条防确认
        洪泛，超出记 ``triage_capped``）；建/并 Hypothesis 前对 asset 过
        check_scope（三层纵深第二层；runner 未挂 scope 时本层不触发，沙箱
        层仍是最终强校验），越界丢弃记 ``triage_out_of_scope``。

        M8a：form_page Signal（POST 表单页）按表单字段名精确匹配同一张
        ``_SQLI_PARAM_HINTS`` 展开候选，零命中回退页面路径提示
        （``_SQLI_PATH_HINTS``，param=None）；与 get_param 候选共享同一
        上限/去重/scope 校验，``triage_completed`` 增
        ``created_by_source``/``merged_by_source`` 摘要区分来源类别。

        M8b：param-endpoint 另按 ``_XSS_PARAM_HINTS`` 展开 xss 候选
        （两表交集参数同产两类候选，dedup 按 vuln_type 分量区分）；
        xss 独立上限 ``_TRIAGE_XSS_CAP`` 与独立 ``triage_capped`` 事件。

        M8c：param-endpoint 再按 ``_IDOR_PARAM_HINTS`` 展开 idor 候选
        （对象标识类键名保守表；与 sqli 表交集参数同产是设计行为）；
        idor 独立上限 ``_TRIAGE_IDOR_CAP`` 与独立 ``triage_capped`` 事件。

        M9c①：候选有**两个来源**，由 ``self.triage_rules``（缺省 True）与
        ``self.triage_model``（**缺省 False**）各自开关控制：

        - 规则表：快速路径与兜底，零 LLM、确定性可测（见
          :func:`_triage_candidates`）；
        - 模型路径：T1 档补齐关键词盲区，见
          :meth:`_model_candidates_by_asset`。参数名/字段名不在提示表内的
          真实漏洞端点（``article_id`` / ``sku`` / ``ref`` / ``bh`` 等）在
          纯规则表下**不产生任何候选**——不是验证失败，是看不见。

        两来源候选**汇入同一套** dedup / 上限 / scope 校验 / 证据包逻辑，
        故 5 层 scope 纵深与红线 5 零改动即覆盖模型候选；模型只提出候选，
        **不改变任何确认路径**（候选仍须过 L2 闸门 → 行为验证 → 证据门 →
        Verifier，红线 1/2）。

        scope 纪律：只有**通过 check_scope 的 Signal** 才送进模型——越界信号
        在到达模型之前就已丢弃，模型永远看不到 scope 外的资产。
        """
        store = FindingStore(self.evidence_dir / "findings.jsonl")
        signals, skipped = self._load_phase_signals()
        scope = getattr(self.runner, "scope", None)
        # M9c①：模型路径的送审集合 = 通过 check_scope 的候选型 Signal
        #（越界信号不送审；模型永远看不到 scope 外的资产）
        model_by_asset: dict[tuple[str, str], list[_TriageCandidate]] = {}
        if self.triage_model:
            model_by_asset = self._model_candidates_by_asset(signals, scope)
        existing_all = store.load_all()
        # M17-b：按类型的既有条数收成一张表（原为 6 个位置返回值的写回样板）。
        # 上限判定要的是「本类型已有几条」，与具体类型无关——收表后新增类型
        # 只改常量与登记处，不再扩张 `_ingest_candidates` 的形参表。
        existing_by_type: dict[str, int] = {}
        for finding in existing_all:
            existing_by_type[finding.vuln_type] = (
                existing_by_type.get(finding.vuln_type, 0) + 1
            )
        # M17-b：是否可派生 unauth-exposure——需 scope 配了**可用**的预置会话
        # （与 `_verify_unauth` 的前置判定同一谓词：有会话且能渲染出 Cookie 头）。
        # 无会话时不派生、也**不**回退产 web-exposure（后者本来就在产）。
        session = self._session()
        session_available = bool(session is not None and session.cookie_header())
        findings: list[Finding] = []
        created = merged = kept = 0
        capped_by_type: dict[str, int] = {}  # M8b：按 vuln_type 分立 triage_capped
        created_by_type: dict[str, int] = {}
        merged_by_type: dict[str, int] = {}
        created_by_source: dict[str, int] = {}
        merged_by_source: dict[str, int] = {}
        for signal in signals:
            # M9c①：两来源候选的并集（纯模型臂即 triage_rules=False）
            candidates = (
                _triage_candidates(signal, session_available=session_available)
                if self.triage_rules
                else []
            )
            if self.triage_model:
                candidates = candidates + model_by_asset.get(
                    (signal.asset, signal.kind), []
                )
            if not candidates:
                kept += 1
                continue
            if scope is not None:
                decision = check_scope(scope, [signal.asset])
                if not decision.allowed:
                    self.audit.record(
                        "triage_out_of_scope",
                        asset=signal.asset,
                        kind=signal.kind,
                        violations=decision.violations,
                    )
                    kept += 1
                    continue
            counters = {
                "created": created,
                "merged": merged,
                "capped_by_type": capped_by_type,
                "created_by_type": created_by_type,
                "merged_by_type": merged_by_type,
                "created_by_source": created_by_source,
                "merged_by_source": merged_by_source,
            }
            hits, counters = self._ingest_candidates(
                store,
                findings,
                signal,
                candidates,
                existing_by_type,
                counters,
            )
            created = counters["created"]
            merged = counters["merged"]
            if hits == 0:
                kept += 1
        # M8b/M8c：triage_capped 按 vuln_type 分立事件（各自上限各自记）。
        # M18-b：**从 `_TRIAGE_CAPS` 派生**，不再手写列表——原先查表判上限、
        # 手写列表上报，两处不同源；加 `cmdi` 时只登记了查表，导致候选被正确
        # 丢弃却**没有任何审计事件**（静默丢弃）。
        for vuln_type, limit in sorted(_TRIAGE_CAPS.items()):
            dropped = capped_by_type.get(vuln_type, 0)
            if dropped:
                self.audit.record(
                    "triage_capped",
                    vuln_type=vuln_type,
                    limit=limit,
                    dropped=dropped,
                )
        self.audit.record(
            "triage_completed",
            signals=len(signals),
            mapped=created + merged,
            created=created,
            merged=merged,
            kept_signal=kept,
            skipped_lines=skipped,
            created_by_type=created_by_type,
            merged_by_type=merged_by_type,
            created_by_source=created_by_source,
            merged_by_source=merged_by_source,
        )
        return findings

    def _ingest_candidates(
        self,
        store: FindingStore,
        findings: list[Finding],
        signal: Signal,
        candidates: list[_TriageCandidate],
        existing_by_type: dict[str, int],
        counters: dict,
    ) -> tuple[int, dict]:
        """把一批候选建/并成 Finding，返回 ``(映射条数, counters)``。

        ``existing_by_type`` 是**上限判定的状态**（按 vuln_type 的既有条数），
        必须**原地更新**，否则同一轮内多条候选会各按旧值判定、上限失效。
        ``counters`` 汇总 created/merged/…（同样原地更新）。

        M9c① 从旧 ``run_triage_phase`` 内联循环体**机械抽出**（仅
        ``cand``→``candidate``、``signal_mapped``→``mapped``），逻辑与旧代码
        逐句等价——规则路径的重建/去重/上限/计数/审计语义零改动。
        **M17-b 只做一处等价重构**：把 6 个位置返回值（created/merged/四个
        existing）收进可变容器，语义不变，只为不再扩张形参表。
        """
        mapped = 0
        created = counters["created"]
        merged = counters["merged"]
        capped_by_type = counters["capped_by_type"]
        created_by_type = counters["created_by_type"]
        merged_by_type = counters["merged_by_type"]
        created_by_source = counters["created_by_source"]
        merged_by_source = counters["merged_by_source"]
        for candidate in candidates:
            # M23：候选可声明 host 级 asset（error-disclosure）；其余类型
            # 缺省 None ⇒ 与改造前逐字节等价。
            asset = candidate.asset or signal.asset
            dedup_key = compute_dedup_key(
                asset, candidate.vuln_type, candidate.param
            )
            existing = store.get_by_dedup_key(dedup_key)
            if existing is not None:
                if signal.evidence_ref in existing.source_signal_refs:
                    continue  # 幂等：该证据已归并过
                existing.source_signal_refs.append(signal.evidence_ref)
                if candidate.evidence_kind not in existing.evidence_kinds:
                    existing.evidence_kinds.append(candidate.evidence_kind)
                existing.updated_at = _utc_now()
                store.append(existing)
                self.audit.record(
                    "finding_deduplicated",
                    finding_id=existing.id,
                    dedup_key=dedup_key,
                    evidence_ref=signal.evidence_ref,
                )
                assemble_evidence_pack(existing, evidence_base=self.evidence_dir)
                merged += 1
                merged_by_type[candidate.vuln_type] = (
                    merged_by_type.get(candidate.vuln_type, 0) + 1
                )
                merged_by_source[candidate.source] = (
                    merged_by_source.get(candidate.source, 0) + 1
                )
                mapped += 1
                findings.append(existing)
                continue
            # 按类型上限查表（M17-b 由三个并列 if 收成一张表；语义零改动，
            # 各类型仍是**独立计数、独立 triage_capped**，互不挤占）。
            cap = _TRIAGE_CAPS.get(candidate.vuln_type)
            if cap is not None and existing_by_type.get(candidate.vuln_type, 0) >= cap:
                capped_by_type[candidate.vuln_type] = (
                    capped_by_type.get(candidate.vuln_type, 0) + 1
                )
                continue
            finding = Finding(
                id=store.next_id(),
                state=FindingState.SIGNAL,
                vuln_type=candidate.vuln_type,
                severity=candidate.severity,
                asset=asset,
                param=candidate.param,
                confidence="low",
                evidence_kinds=[candidate.evidence_kind],
                dedup_key=dedup_key,
                source_signal_refs=[signal.evidence_ref],
                created_at=_utc_now(),
                updated_at=_utc_now(),
                audit=self.audit,
            )
            finding.transition(
                FindingState.HYPOTHESIS,
                actor="triage",
                reason=(
                    f"规则映射 {signal.kind}→{candidate.vuln_type}"
                    if candidate.source in ("web_probe", "get_param", "form_page")
                    else f"模型假设 {signal.kind}→{candidate.vuln_type}"
                ),
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            created += 1
            created_by_type[candidate.vuln_type] = (
                created_by_type.get(candidate.vuln_type, 0) + 1
            )
            created_by_source[candidate.source] = (
                created_by_source.get(candidate.source, 0) + 1
            )
            existing_by_type[candidate.vuln_type] = (
                existing_by_type.get(candidate.vuln_type, 0) + 1
            )
            mapped += 1
            findings.append(finding)
        counters["created"] = created
        counters["merged"] = merged
        return mapped, counters

    def _model_candidates_by_asset(self, signals, scope):
        """M9c①：T1 档产出候选，按 ``(asset, kind)`` 归位以便并回主循环。

        送审集合 = **通过 check_scope 的** Signal（越界信号不进模型上下文）。
        返回 ``{(asset, kind): [与规则表同构的候选]}``；失败按归因记审计后返回
        空 dict——fail-closed 零候选，绝不降级为"当作合法候选"（红线 2）。
        """
        eligible = []
        for signal in signals:
            if signal.kind not in ("param-endpoint", "form_page"):
                continue
            if scope is not None and not check_scope(scope, [signal.asset]).allowed:
                continue
            eligible.append(signal)
        if not eligible:
            return {}
        try:
            summaries = summarize_triage_signals(eligible)
            produced = build_model_candidates(
                self.router, summaries, audit=self.audit
            )
        except ModelTriageError as exc:
            # 输出非法（schema/白名单/JSON 坏）：fail-closed 零候选，
            # 规则结果照旧生效；不静默、不降级
            self.audit.record(
                "triage_model_invalid",
                reason=str(exc)[:500],
                signals=len(eligible),
            )
            return {}
        except (BudgetExceededError, ContextOverflowError):
            raise  # 预算/上下文硬闸优先于 triage，不可被吞
        except LLMError as exc:
            # 档位未配置 / HTTP 故障：不阻塞主链路（规则结果仍是有效产出）
            self.audit.record(
                "triage_model_failed",
                reason=str(exc)[:500],
                signals=len(eligible),
            )
            return {}
        owners: dict[str, list] = {}
        for signal in eligible:
            owners.setdefault(signal.asset, []).append(signal)
        by_asset: dict[tuple[str, str], list[_TriageCandidate]] = {}
        for item in produced:
            hit = owners.get(item.asset)
            if not hit:
                continue  # 归位不上（模型改了 URL）：丢弃，宁漏勿滥
            for signal in hit:
                by_asset.setdefault((signal.asset, signal.kind), []).append(
                    _TriageCandidate(
                        vuln_type=item.vuln_type,
                        param=item.param,
                        severity="medium",
                        evidence_kind=(
                            CRAWL_FORM_EVIDENCE_KIND
                            if signal.kind == "form_page"
                            else CRAWL_ENDPOINT_EVIDENCE_KIND
                        ),
                        # triage_completed 的 created_by_source 分量
                        source=(
                            "model_form" if signal.kind == "form_page" else "model"
                        ),
                    )
                )
        return by_asset

    def _load_phase_signals(self) -> tuple[list[Signal], int]:
        """加载 evidence_dir 下全部 *.signals.jsonl（坏行跳过并计数）。"""
        signals: list[Signal] = []
        skipped = 0
        for path in sorted(self.evidence_dir.glob("*.signals.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    signals.append(Signal.model_validate(json.loads(line)))
                except ValidationError:
                    skipped += 1
        return signals, skipped

    # ---- verify 阶段（M3b，确定性编排：无 planner、无 LLM 规划） ----

    def _verify_handlers(self) -> dict:
        """verify skill 名 → (覆盖的 vuln_type 集合, 处理函数)。"""
        return {
            "verify-sqli": (frozenset({"sqli"}), self._verify_sqli),
            # M8b：无头浏览器 canary 行为确认（XSS 唯一确认门径）
            "verify-xss": (frozenset({"xss"}), self._verify_xss),
            # M8c：双会话属性验证（IDOR 唯一确认门径）
            "verify-idor": (frozenset({"idor"}), self._verify_idor),
            # M16：带外回调确认（SSRF 唯一确认门径）——宿主 listener 收到
            # 含本次 token 的请求才算；目标响应内容永不作为证据
            "verify-ssrf": (frozenset({"ssrf"}), self._verify_ssrf),
            # M16-c：未授权暴露（唯一确认门径）——匿名/已认证**响应字节等价**
            # 才算；AI 判定器只产敏感度结论与锚点、不产证据
            "verify-unauth": (frozenset({"unauth-exposure"}), self._verify_unauth),
            # M18：命令注入（唯一确认门径）——注入的**命令发起的回调**到达
            # listener 才算；响应回显/状态码/耗时一律不是证据，另用 DNS
            # 非命中变体排除第三方代抓取
            "verify-cmdi": (frozenset({"cmdi"}), self._verify_cmdi),
            # M22：模板注入（唯一确认门径）——**同一语法下两个不同乘积都被
            # 算了出来**才算；模板语法回显/报错文本/状态码一律不是证据
            "verify-ssti": (frozenset({"ssti"}), self._verify_ssti),
            # M23：报错信息泄露（唯一确认门径）——畸形请求触发的错误页
            # 命中 ≥2 类技术披露标记、且基线干净才算；版本头只记审计
            "verify-error-disclosure": (
                frozenset({"error-disclosure"}),
                self._verify_error_disclosure,
            ),
        }

    def verify_skill_coverage(self, skill_name: str = "verify-sqli") -> frozenset[str]:
        """verify skill 覆盖的 vuln_type 集合（M5a：API 自主模式闸门按此
        圈定待确认的 Hypothesis Finding）。"""
        handlers = self._verify_handlers()
        if skill_name not in handlers:
            raise KeyError(f"skill 无 verify handler: {skill_name}")
        return handlers[skill_name][0]

    def verify_precondition_blocked(self, vuln_type: str) -> str | None:
        """该 vuln_type 的 handler 前置是否**结构上不可满足**；是则给出原因。

        M17-b：与 handler 内第一条前置检查**逐条同构**（会话/挂 scope），故凡是
        本方法判非 None 的 Finding，handler 内也必然立刻返回 ``blocked``——
        本门**不改变任何终态语义**，只是把「每条各 blocked 一次、各吃掉一次贵验证
        配额」提前成「整类一次性 blocked、零配额消耗」。

        返回 ``None`` 表示前置可满足（交给正常验证流程）。
        """
        if vuln_type not in _VERIFY_PRECONDITIONS:
            return None
        scope = getattr(self.runner, "scope", None)
        if scope is None:
            return "runner 未挂 scope（scope 防线缺失，fail-closed）"
        session = self._session()
        if session is None or not session.cookie_header():
            # 文案与 `_verify_unauth` / `_verify_ssrf` 内的原话逐字一致——它们是
            # **同一个前置条件**，两处说法不同只会让读审计的人以为是两件事。
            return "scope 未配置预置会话，无法构造已认证视图（fail-closed）"
        return None

    def run_verify_phase(self, *, skill_name: str = "verify-sqli") -> list[Finding]:
        """跑 verify 阶段：对 Hypothesis 做行为验证 + 证据门 + Verifier 终审。

        Confirmed 迁移条件（三者缺一不得确认，§5.4.2/§5.4.4）：
        行为证据存在（evidence_kinds 含 behavioral）∧ 证据门通过 ∧
        Verifier confirm；状态机铁律在 ``transition`` 层兜底（双层防守）。
        无 handler 的 Hypothesis 记 ``verify_skipped`` 跳过；返回实际处理的
        Finding 列表。
        """
        skill = self.registry.get(skill_name)
        if skill is None:
            raise KeyError(f"未注册的 skill: {skill_name}")
        if not skill.enabled:
            raise PermissionError(f"skill 未启用: {skill_name}")
        handlers = self._verify_handlers()
        if skill_name not in handlers:
            raise KeyError(f"skill 无 verify handler: {skill_name}")
        vuln_types, handler = handlers[skill_name]

        store = FindingStore(self.evidence_dir / "findings.jsonl")
        # M20-b：覆盖截图计数按 phase 重置
        self._coverage_by_type = {}
        self._coverage_total = 0
        counts = {"confirmed": 0, "rejected": 0, "blocked": 0, "skipped": 0}
        processed: list[Finding] = []
        # M17-b：前置不可满足而被整类拦下的候选（按类型聚合，收尾记一次审计）
        unavailable: dict[str, list[str]] = {}
        try:
            for finding in store.load_all():
                if finding.state is not FindingState.HYPOTHESIS:
                    continue
                if finding.vuln_type not in vuln_types:
                    self.audit.record(
                        "verify_skipped",
                        finding_id=finding.id,
                        vuln_type=finding.vuln_type,
                        reason=f"skill {skill_name} 不覆盖该漏洞类型",
                    )
                    counts["skipped"] += 1
                    continue
                finding.audit = self.audit  # store 回放出的 Finding 无审计句柄
                # M17-b：前置**结构上不可满足**的类型在贵验证档之前整类拦下。
                # 必须在 `_prefilter_or_cap` 之前——后者的 `_expensive_spent += 1`
                # 会让「注定 blocked」的候选白吃一次配额（配额语义不诚实）。
                blocked_reason = self.verify_precondition_blocked(finding.vuln_type)
                if blocked_reason is not None:
                    # 逐条记 `verify_blocked`（与 handler 内那条同语义、同文案，
                    # 故既有审计断言不受影响），收尾再为整类记一条聚合事件。
                    self.audit.record(
                        "verify_blocked",
                        finding_id=finding.id,
                        reason=blocked_reason,
                    )
                    counts["blocked"] += 1
                    unavailable.setdefault(finding.vuln_type, []).append(finding.id)
                    continue
                # M9c②：贵验证档前置廉价粗筛（关闭时此块零开销、零行为差）
                if self.verify_prefilter:
                    verdict = self._prefilter_or_cap(finding, skill_name)
                    if verdict is not None:
                        counts[verdict] += 1
                        continue
                # M20-b：按类型固定取证（不论判定结果；失败不影响验证）
                self._capture_coverage(finding, store)
                outcome = handler(finding, skill, store)
                counts[outcome] += 1
                processed.append(finding)
        finally:
            self._close_browser()  # M8b：phase 收尾释放浏览器（若本 phase 建过）
            self._close_ssrf_listeners()  # M16：回调 listener 同样不常驻
            self._close_screenshotter()  # M20：截图器同样不常驻
        # M17-b：前置不可满足的类型**聚合记一次**（不是每条一次）——审计里能看出
        # 「这个类型本次根本不可验证」，与「验证过但覆盖不全」区分得开。
        for vuln_type, ids in sorted(unavailable.items()):
            self.audit.record(
                "verify_type_unavailable",
                skill=skill_name,
                vuln_type=vuln_type,
                findings=len(ids),
                reason=self.verify_precondition_blocked(vuln_type),
                note="候选保持 Hypothesis（未消耗贵验证档配额，也未被驳回）",
            )
        if unavailable:
            self.audit.record(
                "verify_precondition_gate",
                skill=skill_name,
                blocked_types=sorted(unavailable),
                blocked_findings=sum(len(v) for v in unavailable.values()),
                expensive_spent=self._expensive_spent,
                expensive_cap=self.expensive_cap,
            )
        extra = (
            {"prefilter_advisory": self._prefilter_advisory}
            if self.verify_prefilter
            else {}
        )
        self.audit.record(
            "verify_completed",
            skill=skill_name,
            processed=len(processed),
            **counts,
            **extra,
        )
        return processed

    def _prefilter_or_cap(self, finding: Finding, skill_name: str) -> str | None:
        """M9c②：廉价粗筛（建议性）+ 贵验证档 cap。

        返回 ``None`` = 放行到贵验证档；返回 ``"capped"`` = 贵验证档配额用尽，
        **Finding 保持 Hypothesis**（不 Rejected——cap 与粗筛都只是资源调度，
        不是判定，红线 2）。

        粗筛**永不返回"丢弃"**：初版曾对 ``UNLIKELY`` 直接不进贵验证档，实测为
        负收益（发现率被砍、误报率不降），故收窄为建议性信号——只记审计
        ``verify_prefilter_unlikely``，候选照常进贵验证档。
        """
        asset = finding.asset
        param = finding.param
        if not param:
            # 表单/路径型候选：param 可能为空；尝试从 asset 的 query 里取
            # 第一个键作为扰动目标（取不到就交给 prefilter 判 UNKNOWN）
            keys = _query_param_keys(asset)
            param = keys[0] if keys else None
        try:
            result = prefilter_screen(
                asset, param, fetcher=self._prefilter_fetch
            )
        except Exception as exc:  # noqa: BLE001 - 粗筛故障绝不阻塞主链路
            self.audit.record(
                "verify_prefilter_error",
                finding_id=finding.id,
                reason=f"{type(exc).__name__}: {exc}"[:300],
            )
            result = None
        if result is not None:
            # 粗筛**只出建议、永不丢弃**（M9c② 实测：丢弃是负收益——见
            # verify/prefilter.py 的 passed 注释）。UNLIKELY 如实记审计，
            # 由贵验证档排序与人工参考；候选照常进贵验证档。
            self.audit.record(
                "verify_prefilter_unlikely"
                if result.advisory
                else "verify_prefilter_passed",
                finding_id=finding.id,
                skill=skill_name,
                # decision/reason/thresholds/长度明细全在 to_dict() 里，
                # 不重复传 decision（否则 kwarg 冲突）
                **result.to_dict(),
            )
            if result.advisory:
                self._prefilter_advisory += 1
        if self._expensive_spent >= self.expensive_cap:
            # 贵验证档配额用尽：停在 Hypothesis（不驳回），交人工/下一轮
            self.audit.record(
                "verify_capped",
                finding_id=finding.id,
                skill=skill_name,
                limit=self.expensive_cap,
            )
            return "capped"
        self._expensive_spent += 1
        return None

    def _verify_sqli(self, finding: Finding, skill, store: FindingStore) -> str:
        """verify-sqli SOP（skills/verify-sqli/SKILL.md）的确定性执行。

        返回 confirmed/rejected/blocked；blocked = 证据不足以外的一切
        未完成形态（Finding 停留原态，fail-closed）。
        """
        session = self._session()
        if session is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="scope 未配置预置会话（session），无法进行带认证验证",
            )
            return "blocked"

        # 1. 带会话 baseline（不跟随跳转：未认证会被 302 到登录页，2xx 才算数）
        baseline = self._run_baseline(finding, session)
        if baseline is None:
            return "blocked"  # 审计已在 _run_baseline 内记录
        baseline_ref, baseline_status = baseline

        # 2. sqlmap 行为确认（沙箱内执行，scope 强校验不变）；
        # M8a：crawl-form 证据类候选（POST 表单页）走 --forms 模式——
        # sqlmap 自解析页面内表单，不指定 -p、构造器永不手拼 --data
        forms_mode = CRAWL_FORM_EVIDENCE_KIND in finding.evidence_kinds
        sqlmap_params: dict = {
            "url": finding.asset,
            "with_session": True,
            "level": 1,
            "risk": 1,
        }
        if forms_mode:
            sqlmap_params["forms"] = True
        else:
            sqlmap_params["param"] = finding.param
        try:
            argv = build_command(
                "sqlmap",
                sqlmap_params,
                egress_proxy_url=getattr(self.runner, "egress_proxy_url", None),
                session=session,
            )
        except ValueError as exc:
            self.audit.record(
                "verify_blocked", finding_id=finding.id, reason=f"命令构造失败: {exc}"
            )
            return "blocked"
        result = self.runner.run(
            argv[0],
            argv[1:],
            timeout=600,
            image=self.tool_images.get("sqlmap"),
        )
        if result.rejected:
            self.audit.record(
                "verify_scope_rejected",
                finding_id=finding.id,
                violations=result.violations,
            )
            return "blocked"
        if result.exit_code != 0:
            self.audit.record(
                "verify_tool_failed",
                finding_id=finding.id,
                tool="sqlmap",
                exit_code=result.exit_code,
                stderr_path=str(result.stderr_path),
            )
            return "blocked"

        # 3. 解析验证结论：未确认 → Rejected（验证失败，§5.4.1 状态机）
        text = result.stdout_path.read_text(encoding="utf-8", errors="replace")
        report = parse_sqlmap_stdout(text)
        sqlmap_ref = f"{result.stdout_path}#L{report.anchor_line or 1}"
        if not report.confirmed:
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason=f"sqlmap 未确认注入：{report.note or '无注入点'}",
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 4. 证据入包：behavioral 标签 + method + 复现步骤 + 四段式（凭据只记 sha256 标记）
        techniques = "；".join(
            f"{t.type}（{t.title}）" if t.title else t.type for t in report.techniques
        )
        cookie_mark = secret_marker(session.cookie_header())
        sqlmap_step = (
            (
                f"沙箱内执行 sqlmap -u '{finding.asset}' --cookie '{cookie_mark}' "
                f"--forms --level 1 --risk 1 --batch"
            )
            if forms_mode
            else (
                f"沙箱内执行 sqlmap -u '{finding.asset}' --cookie '{cookie_mark}' "
                f"-p {report.parameter} --level 1 --risk 1 --batch"
            )
        )
        finding.verification = Verification(
            method="sqlmap-confirmed",
            evidence_refs=[baseline_ref, sqlmap_ref],
            baseline_diff=(
                f"带会话 baseline {baseline_status}（认证有效，非登录跳转）；"
                f"sqlmap 确认参数 {report.parameter}（{report.param_kind}）注入："
                f"{techniques}；共 {report.requests_total or '未知'} 次 HTTP 请求"
            ),
            claim=f"参数 {report.parameter} 的输入被服务端 SQL 引擎执行（注入成立）",
            expected="sqlmap 在授权目标上行为确认注入点（非版本匹配/状态码推断）",
            actual=(
                f"sqlmap 确认参数 {report.parameter}（{report.param_kind}）注入："
                f"{techniques}；共 {report.requests_total or '未知'} 次 HTTP 请求，"
                f"判定原文见 {result.stdout_path.name}"
            ),
            reproduction_steps=[
                f"以预置会话（Cookie {cookie_mark}）GET {finding.asset} "
                f"→ baseline {baseline_status}（认证有效）",
                sqlmap_step,
                f"sqlmap 判定注入点：Parameter {report.parameter} "
                f"（{report.param_kind}）；技术：{techniques}",
                f"复现 payload 示例：{report.techniques[0].payload}",
            ],
            verified_by=f"{skill.name}@{skill.manifest.version}",
            verified_at=_utc_now(),
        )
        if BEHAVIORAL_EVIDENCE_KIND not in finding.evidence_kinds:
            finding.evidence_kinds.append(BEHAVIORAL_EVIDENCE_KIND)
        finding.transition(
            FindingState.REPRODUCED,
            actor=skill.name,
            reason=f"sqlmap 确认注入（{report.parameter}，{len(report.techniques)} 种技术）",
        )
        store.append(finding)

        # 5. 证据门 → Verifier 终审 → 终态迁移（公共收尾，M8b 抽出复用）
        return self._gate_and_review(finding, skill, store)

    def _gate_and_review(
        self,
        finding: Finding,
        skill,
        store: FindingStore,
        summary: dict | None = None,
        screenshot_url: str | None = None,
    ) -> str:
        """REPRODUCED 之后的公共收尾（verify-sqli / verify-xss 共用）：
        证据门（§5.4.2）→ Verifier 终审（T2，§5.4.4）→ CONFIRMED/REJECTED。

        返回 confirmed/rejected/blocked；blocked = 门不过 / Verifier 失败 /
        铁律拦截，Finding 停留 Reproduced（fail-closed，不静默晋级）。
        """
        # 证据门：Confirmed 前必过；不过停于 Reproduced
        gate_result = gate_check(finding)
        if not gate_result.passed:
            self.audit.record(
                "verify_gate_failed",
                finding_id=finding.id,
                missing=gate_result.missing,
            )
            return "blocked"

        # Verifier 终审（T2，对抗校验；失败 fail-closed 停于 Reproduced）
        pack_dir = assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
        manifest = json.loads((pack_dir / "manifest.json").read_text(encoding="utf-8"))
        verifier = Verifier(
            self.router, self.audit, context_policy=self.planner.context_policy
        )
        try:
            verdict = verifier.review(
                finding,
                evidence_index=manifest.get("items", []),
                diff_summary=finding.verification.baseline_diff,
                # M11b：仅 verify-idor 传确定性结论块（对照/归属三态 + 锚点）；
                # 其余链路给 None → prompt 载荷逐字节不变
                extra_summary=summary,
            )
        except (VerifierError, LLMError, BudgetExceededError, ContextOverflowError) as exc:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=f"Verifier 未完成（fail-closed）: {exc}",
            )
            return "blocked"

        # 终审裁定 → 终态迁移（铁律在状态机层兜底，双层防守）
        if verdict.verdict == "confirm":
            # M6b：向量来自 Verifier（schema 层已校验合法）；分数与严重级
            # 只由代码按官方公式计算（LLM 不产数字），覆盖 triage 种子 severity
            finding.cvss_vector = verdict.cvss_vector
            finding.cvss_score = cvss_base_score(verdict.cvss_vector)
            finding.severity = severity_for_score(finding.cvss_score)
            try:
                finding.transition(
                    FindingState.CONFIRMED, actor="verifier", reason=verdict.reason
                )
            except IronRuleViolationError as exc:
                self.audit.record(
                    "verify_iron_rule_blocked", finding_id=finding.id, reason=str(exc)
                )
                return "blocked"
            outcome = "confirmed"
        else:
            finding.transition(
                FindingState.REJECTED, actor="verifier", reason=verdict.reason
            )
            outcome = "rejected"
        # M20：确认后补一张证据截图（opt-in；失败只记 screenshot_skipped，不改判）。
        # 必须在 store.append 之前追加 evidence_refs，否则落盘快照里没有这条引用。
        if outcome == "confirmed":
            shot = self._capture_screenshot(finding, screenshot_url or finding.asset)
            if shot is not None:
                finding.verification.evidence_refs.append(str(shot))
        store.append(finding)
        assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
        return outcome

    def _verify_xss(self, finding: Finding, skill, store: FindingStore) -> str:
        """verify-xss SOP（skills/verify-xss/SKILL.md）的确定性执行（M8b）。

        确认铁律：**仅 canary 执行事件可确认**（payload 在无头 Chromium 页面
        上下文中执行），"响应反射输入"永远不是证据。全部 payload 干净完成
        且无 canary → rejected；任一次尝试出错且未命中 canary → blocked
        （覆盖不全不驳回，fail-closed）。URL/payload 全部来自代码常量与
        Finding 数据（红线 1），唯一 LLM 调用是收尾的 Verifier 终审。
        """
        session = self._session()
        if session is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="scope 未配置预置会话（session），无法进行带认证验证",
            )
            return "blocked"
        scope = getattr(self.runner, "scope", None)
        if scope is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="runner 未挂 scope，浏览器验证缺 scope 防线（fail-closed）",
            )
            return "blocked"
        if not finding.param:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="xss 候选缺 param，无法构造 payload URL（fail-closed）",
            )
            return "blocked"

        # 1. 带会话 baseline（与 verify-sqli 同一可达性对照）
        baseline = self._run_baseline(finding, session)
        if baseline is None:
            return "blocked"  # 审计已在 _run_baseline 内记录
        baseline_ref, baseline_status = baseline

        # 2. 浏览器验证器（不可用 fail-closed，Finding 停留 Hypothesis）
        try:
            browser = self._get_browser(session)
        except BrowserUnavailableError as exc:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=f"浏览器不可用（fail-closed）: {exc}",
            )
            return "blocked"

        # 3. 逐 payload probe（预算门按次计数：每尝试记 xss_probe_attempt
        # 审计，上限 = 模板条数 ≤6，任一 canary 执行即停）
        hit = None  # BrowserProbeResult | None
        had_error = False
        for seq, template in enumerate(XSS_PAYLOAD_TEMPLATES, start=1):
            token = new_canary_token()
            payload = template.replace("{token}", token)
            try:
                url = xss_payload_url(finding.asset, finding.param, payload)
            except ValueError as exc:
                self.audit.record(
                    "verify_blocked",
                    finding_id=finding.id,
                    reason=f"payload URL 构造失败（fail-closed）: {exc}",
                )
                return "blocked"
            decision = check_scope(scope, [url])  # 红线 5：加载任何 URL 前过 scope
            if not decision.allowed:
                self.audit.record(
                    "verify_scope_rejected",
                    finding_id=finding.id,
                    violations=decision.violations,
                )
                return "blocked"
            result = browser.probe(
                finding_id=finding.id, seq=seq, url=url, payload=payload, token=token
            )
            self.audit.record(
                "xss_probe_attempt",
                finding_id=finding.id,
                seq=seq,
                token=token,
                canary=result.canary,
                error=result.error is not None,
                event_types=[event["type"] for event in result.events],
            )
            if result.error is not None:
                had_error = True
                continue
            if result.canary:
                hit = result
                break

        # 4. 无 canary：全部干净完成 → Rejected；存在错误 → blocked（fail-closed）
        if hit is None:
            if had_error:
                self.audit.record(
                    "verify_blocked",
                    finding_id=finding.id,
                    reason="浏览器尝试存在错误且未捕获 canary（覆盖不全，不驳回）",
                )
                return "blocked"
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason=(
                    f"全部 {len(XSS_PAYLOAD_TEMPLATES)} 条 payload 均未触发 "
                    "canary 执行事件（反射不执行/不反射）"
                ),
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 5. canary 命中：证据入包（behavioral + browser-confirmed + 四段式）
        cookie_mark = secret_marker(session.cookie_header())
        event_types = "、".join(event["type"] for event in hit.events)
        finding.verification = Verification(
            method="browser-confirmed",
            evidence_refs=[
                baseline_ref,
                str(hit.canary_path),
                str(hit.dom_path),
                str(hit.console_path),
                str(hit.requests_path),
            ],
            baseline_diff=(
                f"带会话 baseline {baseline_status}（认证有效，非登录跳转）；"
                "payload 经无头 Chromium（playwright，canary 探针）加载，"
                f"捕获 {len(hit.events)} 个执行事件（{event_types}，token 匹配）"
            ),
            claim=f"参数 {finding.param} 的输入在浏览器中被执行",
            expected="payload 中的 canary token 在页面上下文执行（置位标记或触发对话框钩子）",
            actual=(
                f"捕获 {len(hit.events)} 个 canary 事件（类型 {event_types}，"
                f"token {hit.token}）；事件原文见 {hit.canary_path.name}"
            ),
            reproduction_steps=[
                f"以预置会话（Cookie {cookie_mark}）GET {finding.asset} "
                f"→ baseline {baseline_status}（认证有效）",
                "无头 Chromium（playwright chromium，canary 探针 "
                f"add_init_script）加载 {hit.url}",
                f"探针捕获 canary 执行事件：{event_types}（token {hit.token}）",
                f"payload 原文：{hit.payload}",
            ],
            verified_by=f"{skill.name}@{skill.manifest.version}",
            verified_at=_utc_now(),
        )
        if BEHAVIORAL_EVIDENCE_KIND not in finding.evidence_kinds:
            finding.evidence_kinds.append(BEHAVIORAL_EVIDENCE_KIND)
        finding.transition(
            FindingState.REPRODUCED,
            actor=skill.name,
            reason=(
                f"浏览器 canary 确认执行（{finding.param}，"
                f"{len(hit.events)} 个事件）"
            ),
        )
        store.append(finding)

        # 6. 证据门 → Verifier 终审 → 终态（与 verify-sqli 同一收尾）
        # M20：截图取 canary 命中的那个 URL（payload 已内嵌），而不是裸 asset
        return self._gate_and_review(finding, skill, store, screenshot_url=hit.url)

    def _ssrf_listener(self, finding_id: str) -> CallbackListener:
        """懒建并缓存本 finding 的回调 listener（M16）。

        缺省只绑回环：回调地址要对目标**回连可达**才有意义。远程靶必须显式设
        ``PROOFHOUND_SSRF_CALLBACK_HOST``（非回环时打印醒目告警）——本函数不做
        任何隐式放大绑定面的动作（fail-closed）。

        测试经 ``ssrf_listener_factory`` 注入（与 ``browser_factory``/``idor_fetch``
        同款契约：**注入了就用注入的**）；None 时才建真实 listener。少了这一条，
        注入的替身与实际使用者不是同一对象，token 注册与回调会分别落在两个
        listener 上，confirmed 分支永远走不通（实现期实测踩到）。
        """
        existing = self._ssrf_listeners.get(finding_id)
        if existing is not None:
            return existing
        if self._ssrf_listener_factory is not None:
            listener = self._ssrf_listener_factory()
        else:
            # 「告知目标的地址」与「本机绑定地址」解耦：容器/远程靶要告知它够得着的
            # 名字（如 host.docker.internal），而本机只能绑自己的接口（不可解析时退
            # 0.0.0.0）。两者混用会让 listener 直接 bind 失败（实弹实测）。
            advertised = ssrf_resolve_callback_host()
            bind_host = ssrf_resolve_callback_bind(advertised)
            port = ssrf_resolve_callback_port()
            listener = CallbackListener(host=bind_host, port=port)
        listener.start()  # 不可用即抛 SsrfListenerError
        bound_host, bound_port = listener.bound_address
        if not ssrf_is_loopback_host(bound_host):
            print(
                NON_LOOPBACK_WARNING.format(host=bound_host, port=bound_port),
                file=sys.stderr,
                flush=True,
            )
        self._ssrf_listeners[finding_id] = listener
        return listener

    def _close_ssrf_listeners(self) -> None:
        """释放 verify phase 建过的全部回调 listener；异常吞咽（不遮蔽主链路）。"""
        for listener in list(self._ssrf_listeners.values()):
            try:
                listener.close()
            except Exception:  # noqa: BLE001
                pass
        self._ssrf_listeners.clear()

    def _verify_ssrf(self, finding: Finding, skill, store: FindingStore) -> str:
        """verify-ssrf SOP（skills/verify-ssrf/SKILL.md）的确定性执行（M16）。

        确认铁律：**仅回调 listener 收到含本次探针 token 的请求可确认**（带外二值
        事实）。目标响应里的 callback URL 反射、状态码、耗时一律不是证据——SSRF 的
        "答案不在目标给我们的响应里"。

        判定（`verify/ssrf.py::judge`，纯函数，宁漏勿滥）：

        - 命中 token → REPRODUCED → 证据门 → Verifier；
        - **干净未命中 + 交付证明成立** → REJECTED（真阴性）；
        - 探针出错 / 交付证明不成立 / 前置不全 / listener 不可用 → blocked
          （覆盖不全，绝不驳回）。

        防伪三道（缺一不可）：① 每探针唯一 token + 常量时间比对（不带 token 的
        请求记 `ssrf_callback_ignored`，不计命中）；② 交付证明（回取探测 URL，正文
        须含 token/nonce ⇒ 证明目标收到的就是我们报告里那个地址）；③ 随机地址对照
        探针（不含本参数的地址命中，只证明「服务端会代发请求」，**不确认**）。

        请求构造、payload 拼接、判定全是确定性代码（红线 1）；唯一 LLM 调用是收尾
        的 Verifier 终审。
        """
        session = self._session()
        if session is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="scope 未配置预置会话（session），无法做带会话 baseline",
            )
            return "blocked"
        scope = getattr(self.runner, "scope", None)
        if scope is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="runner 未挂 scope，ssrf 验证缺 scope 防线（fail-closed）",
            )
            return "blocked"
        if not finding.param:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="ssrf 候选缺 param，无法构造回调 payload（fail-closed）",
            )
            return "blocked"
        if CRAWL_FORM_EVIDENCE_KIND in finding.evidence_kinds:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="POST 表单型候选的 ssrf 验证未实现（本轮只覆盖 GET query 参数）",
            )
            return "blocked"

        # 1. scope 授权前置（红线 5）：目标 asset 必须已授权。
        # 注意：**不**对探测 URL 逐条 check_scope——探针的 query 里携带的是我们的
        # 回调地址（基础设施，非目标），check_scope 会把它当目标提取并按端口拒掉
        # （实测会让每个探针都被拒）。探测 URL 的"不越界"改由下面的同源自检保证。
        decision = check_scope(scope, [finding.asset])
        if not decision.allowed:
            self.audit.record(
                "verify_scope_rejected",
                finding_id=finding.id,
                violations=decision.violations,
            )
            return "blocked"

        # 2. 回调 listener（不可用即 blocked；回调地址须与绑定地址一致）
        try:
            listener = self._ssrf_listener(finding.id)
        except SsrfListenerError as exc:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=f"回调 listener 不可用（fail-closed）: {exc}",
            )
            return "blocked"
        bound_host, bound_port = listener.bound_address
        # 回调地址里的 host 用**告知地址**（目标回连时用的名字），端口用实际绑定端口
        advertised_host = (
            ssrf_resolve_callback_host()
            if self._ssrf_listener_factory is None
            else bound_host
        )
        callback_base = ssrf_callback_url(
            advertised_host, bound_port, ssrf_new_token()
        )
        resolved = ssrf_url_host_port(callback_base)
        if resolved != (advertised_host, bound_port):
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=(
                    "回调地址自检失败：构造出的回调地址与告知目标的地址不一致"
                    f"（{resolved} != {(advertised_host, bound_port)}）"
                ),
            )
            return "blocked"

        # 2. 带会话 baseline（与 verify-sqli/verify-xss 同一可达性对照）
        baseline = self._run_baseline(finding, session)
        if baseline is None:
            return "blocked"  # 审计已在 _run_baseline 内记录
        baseline_ref, baseline_status = baseline

        # 3. 逐探针（全部只读 GET；每个 URL 都做同源自检，见 run_probe）
        asset_origin = _origin_of(finding.asset)
        nonce_host = ssrf_new_nonce_host()
        probes: list[dict] = []
        deliveries: list[tuple[str, str]] = []  # (marker, url) 供交付证明回取
        errored = False
        hit = None  # tuple[token, variant, records] | None

        def run_probe(
            seq: int, variant: str, url: str, token: str, *, infrastructure: bool = False
        ):
            """发一次只读探测并登记 token；返回 (response, records)。

            ``infrastructure=True`` 用于**对照探针**（随机不可解析地址）：它的失败是
            预期行为（目标正确地没解析它），**不计入 errored**——否则每次干净未命中都
            会被判 blocked，rejected 分支永远不可达（实现期发现的设计缺陷）。
            它的失败仍如实记入 probes，供取证。
            """
            nonlocal errored
            # 同源自检：**载荷**探测 URL 必须与已授权的 asset 完全同源（scheme/host/port）。
            # 不同源意味着构造出了指向别处的 URL —— fail-closed 停（红线 5）。
            # 对照探针（infrastructure=True）刻意指向随机主机，不受本检约束。
            if not infrastructure and _origin_of(url) != asset_origin:
                self.audit.record(
                    "verify_scope_rejected",
                    finding_id=finding.id,
                    violations=[
                        "探测 URL 与 asset 不同源："
                        f"{_origin_of(url)} != {asset_origin}"
                    ],
                )
                return None, []
            listener.register(token)
            response = self._ssrf_fetch(url, session)
            records = [r.to_dict() for r in listener.hits(token)]
            probes.append(
                {
                    "seq": seq,
                    "variant": variant,
                    "url": url,
                    "token": token,
                    "status": response.status,
                    "error": response.error,
                    "callback_hits": len(records),
                    "elapsed_s": round(response.elapsed_s, 3),
                }
            )
            self.audit.record(
                "ssrf_probe_attempt",
                finding_id=finding.id,
                seq=seq,
                variant=variant,
                url=url,
                token=token,
                status=response.status,
                error=response.error is not None,
                callback_hits=len(records),
            )
            if response.error is not None and not infrastructure:
                errored = True
            deliveries.append((token, url))
            return response, records

        # 3a. 随机地址对照探针（不含本参数的地址：命中≠SSRF）
        control_nonce = ssrf_new_token()
        control_url = ssrf_nonce_url(bound_host, bound_port, nonce_host, control_nonce)
        _resp, control_records = run_probe(
            0, "control-random-host", control_url, control_nonce, infrastructure=True
        )
        control_hit = bool(control_records)

        # 3b. 回调 payload 变体（≤2 条：纯回调 URL；回调 URL + 同名参数二次拼接）。
        # 每轮**现生成**回调地址，并从该地址里取 token —— token 与注入 URL 必须是
        # 同一真相源。曾因"循环外生成 value、循环内另生成 token"导致注册的 token 与
        # URL 里的 token 不一致，confirmed 分支永不触发（埋点实测的严重缺陷）。
        for seq, variant in enumerate(
            ("callback-url", "callback-url+decoy-param"), start=1
        ):
            callback = ssrf_callback_url(
                advertised_host, bound_port, ssrf_new_token()
            )
            value = (
                callback
                if variant == "callback-url"
                else callback + "&" + finding.param + "=" + callback
            )
            token = _callback_token_in(value)
            if not token:
                self.audit.record(
                    "verify_blocked",
                    finding_id=finding.id,
                    reason=(
                        "内部一致性失败：注入的 payload 里取不到回调 token"
                        "（fail-closed，绝不拿不匹配的 token 继续跑）"
                    ),
                )
                return "blocked"
            url = prefilter_with_query_param(finding.asset, finding.param, value)
            _resp, records = run_probe(seq, variant, url, token)
            if records:
                hit = (token, variant, records)
                self.audit.record(
                    "ssrf_callback_received",
                    finding_id=finding.id,
                    variant=variant,
                    token=token,
                    hits=len(records),
                    sources=sorted({r.get("source_ip", "") for r in records}),
                )
                break

        # 4. 交付证明：回取每个探测 URL，正文里找我们的标记（token 或 nonce）
        delivery: list[dict] = []
        delivered_markers = 0
        for marker, url in deliveries:
            resp = self._ssrf_fetch(url, session)
            ok = resp.error is None and ssrf_token_delivered(resp, marker)
            delivered_markers += 1 if ok else 0
            delivery.append(
                {
                    "marker": marker,
                    "url": url,
                    "status": resp.status,
                    "error": resp.error,
                    "marker_found": ok,
                }
            )
        delivered = delivered_markers > 0

        # 5. 确定性判定（纯函数；全部依据落盘）
        judgment = ssrf_judge(
            callback_hit=hit is not None,
            hit_requests=hit[2] if hit else [],
            hit_variant=hit[1] if hit else "",
            control_hit=control_hit,
            delivered=delivered,
            probes=probes,
            probes_errored=errored,
            ignored=[r.to_dict() for r in listener.ignored],
        )
        callbacks_path = self.evidence_dir / f"ssrf_{finding.id}_callbacks.jsonl"
        callbacks_path.write_text(
            "".join(
                json.dumps(record, ensure_ascii=False) + "\n"
                for record in (
                    *judgment.hit_requests,
                    *[
                        {"ignored": True, **record}
                        for record in judgment.ignored_requests
                    ],
                )
            ),
            encoding="utf-8",
        )
        j_path = self.evidence_dir / f"ssrf_{finding.id}_judgment.json"
        j_path.write_bytes(
            redact_bytes(
                (
                    json.dumps(
                        {
                            "finding_id": finding.id,
                            "asset": finding.asset,
                            "param": finding.param,
                            "callback_listener": f"{bound_host}:{bound_port}",
                            "delivery_proof": delivery,
                            **judgment.to_dict(),
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8"),
                session.secret_values(),
            )
        )
        self.audit.record(
            "ssrf_callback_judged",
            finding_id=finding.id,
            verdict=judgment.verdict,
            callback_hits=len(judgment.hit_requests),
            control_hit=judgment.control_hit,
            delivered=judgment.delivered,
            probes=len(judgment.probes),
            ignored=len(judgment.ignored_requests),
        )

        # 6. blocked：覆盖不全，**不驳回**（Finding 停在 Hypothesis）
        if judgment.verdict == "blocked":
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="ssrf 判定未能完成（覆盖不全，不驳回）: "
                + "；".join(judgment.reasons),
            )
            return "blocked"

        # 7. rejected：干净未命中 + 交付证明成立（确定性真阴性，零额外 LLM 成本）
        if judgment.verdict == "rejected":
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason="；".join(judgment.reasons) + f"（判定依据见 {j_path.name}）",
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 8. confirmed：回调命中 → 证据入包（behavioral + 四段式）
        cookie_mark = secret_marker(session.cookie_header())
        sources = sorted(
            {r.get("source_ip", "") for r in judgment.hit_requests if r.get("source_ip")}
        )
        agents = sorted(
            {r.get("user_agent", "") for r in judgment.hit_requests if r.get("user_agent")}
        )
        finding.verification = Verification(
            method=SSRF_CONFIRMED_METHOD,
            evidence_refs=[
                baseline_ref,
                str(callbacks_path),
                str(j_path),
            ],
            baseline_diff=(
                f"带会话 baseline {baseline_status}（认证有效，非登录跳转）；"
                f"回调 listener 绑定 {bound_host}:{bound_port}，收到 "
                f"{len(judgment.hit_requests)} 次含本次探针 token 的请求"
            ),
            claim=f"参数 {finding.param} 使服务端向外部地址发起请求",
            expected="我们控制的回调地址应收到一次由目标服务端发起的请求（带本次探针 token）",
            actual=(
                f"listener 收到 {len(judgment.hit_requests)} 次回调（命中变体 "
                f"{judgment.hit_variant}；来源 IP {sources or '未知'}；"
                f"UA {agents or '未提供'}）；请求原文见 {callbacks_path.name}"
            ),
            reproduction_steps=[
                f"以预置会话（Cookie {cookie_mark}）GET {finding.asset} "
                f"→ baseline {baseline_status}（认证有效）",
                f"在该 URL 的 {finding.param} 参数注入回调地址（变体 {judgment.hit_variant}）",
                f"回调 listener（{bound_host}:{bound_port}）收到请求："
                f"{judgment.hit_requests[0]['request_line'] if judgment.hit_requests else ''}",
                f"交付证明：目标响应正文含本次 token（见 {j_path.name} 的 delivery_proof）",
            ],
            verified_by=f"{skill.name}@{skill.manifest.version}",
            verified_at=_utc_now(),
        )
        if BEHAVIORAL_EVIDENCE_KIND not in finding.evidence_kinds:
            finding.evidence_kinds.append(BEHAVIORAL_EVIDENCE_KIND)
        finding.transition(
            FindingState.REPRODUCED,
            actor=skill.name,
            reason=(
                f"回调确认：listener 收到 {len(judgment.hit_requests)} 次请求"
                f"（{finding.param}，变体 {judgment.hit_variant}）"
            ),
        )
        store.append(finding)

        # 9. 证据门 → Verifier 终审 → 终态（与其余三类同一收尾，无旁路）
        return self._gate_and_review(
            finding,
            skill,
            store,
            summary=ssrf_summary_for_verifier(
                judgment, callback_host_port=f"{bound_host}:{bound_port}"
            ),
        )

    def _verify_idor(self, finding: Finding, skill, store: FindingStore) -> str:

        """verify-idor SOP（skills/verify-idor/SKILL.md）的确定性执行（M8c）。

        确认铁律：**仅双会话属性违反可确认**——B（reference/victim，对象
        属主）会话基准成立（2xx 实质数据）且 A（主会话，低权限身份）会话
        同 URL 请求获得等价响应（正文相似度/JSON 键重叠达写死阈值）；
        单会话异常响应永远不是证据。判定不成立（A 被 403/404/重定向登录页
        /数据不相似）→ rejected；网络错误、B 基准不成立等覆盖不全形态 →
        blocked（不驳回，fail-closed）。请求构造与属性判定全是确定性代码
        （红线 1），唯一 LLM 调用是收尾的 Verifier 终审。
        """
        session = self._session()
        if session is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="scope 未配置预置会话（session），idor 验证需要身份 A 会话",
            )
            return "blocked"
        reference = session.reference
        if reference is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=(
                    "idor 验证需要配置第二身份会话（reference/victim）："
                    "缺第二会话无法做双会话属性对比（fail-closed）"
                ),
            )
            return "blocked"
        scope = getattr(self.runner, "scope", None)
        if scope is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="runner 未挂 scope，idor 验证缺 scope 防线（fail-closed）",
            )
            return "blocked"
        url = finding.asset
        decision = check_scope(scope, [url])  # 红线 5：请求任何 URL 前过 scope
        if not decision.allowed:
            self.audit.record(
                "verify_scope_rejected",
                finding_id=finding.id,
                violations=decision.violations,
            )
            return "blocked"
        # 脱敏清单递归覆盖两个会话（M8c：脱敏是两个会话都要）
        secrets = session.secret_values()

        # 1. B 会话基准请求（reference/victim，对象属主；每次请求按次记审计）
        resp_b = self._idor_fetch(url, reference)
        self.audit.record(
            "idor_probe_attempt",
            finding_id=finding.id,
            role="reference",
            status=resp_b.status,
            error=resp_b.error is not None,
        )
        b_path = self._idor_write_response(finding.id, "b", resp_b, secrets)
        if resp_b.error is not None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=f"B 基准请求失败（覆盖不全，不驳回）: {resp_b.error}",
            )
            return "blocked"
        if not idor_has_substance(resp_b):
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=(
                    f"B 基准不成立（状态 {resp_b.status} 或无实质数据；"
                    "属性不可测，覆盖不全不驳回）"
                ),
            )
            return "blocked"

        # 2. A 会话对比请求（主会话，低权限身份）
        resp_a = self._idor_fetch(url, session)
        self.audit.record(
            "idor_probe_attempt",
            finding_id=finding.id,
            role="attacker",
            status=resp_a.status,
            error=resp_a.error is not None,
        )
        a_path = self._idor_write_response(finding.id, "a", resp_a, secrets)
        if resp_a.error is not None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=f"A 对比请求失败（覆盖不全，不驳回）: {resp_a.error}",
            )
            return "blocked"

        # 3. **未认证对照探测**（M11b）：排除"公开/与会话无关的资源"这一
        #    更平凡的解释。未配 session_third 时用空会话（**完全不发凭据**）。
        #    scope 已在前方过 check_scope，此处请求同一 URL，无新增授权面。
        control_session = getattr(scope, "session_third", None) or SessionConfig()
        resp_c = self._idor_fetch(url, control_session)
        self.audit.record(
            "idor_probe_attempt",
            finding_id=finding.id,
            role="unauthenticated_control",
            status=resp_c.status,
            error=resp_c.error is not None,
        )
        c_path = self._idor_write_response(finding.id, "c", resp_c, secrets)
        control = idor_judge_control(resp_b, resp_c)

        # 4. **确定性属性归属提取**（M11b）：从 B 基准里提取"对象所有者"字段，
        #    与 reference 身份比对。只产结论 + 行号锚点，响应体原文不进 prompt。
        ownership = idor_judge_ownership(resp_b, scope.session_identity())

        # 结论落盘（判定依据全量结构化，供离线复核与证据链）
        summary = idor_control_summary(control, ownership)
        s_path = self.evidence_dir / f"idor_{finding.id}_control.json"
        s_path.write_bytes(
            redact_bytes(
                (
                    json.dumps(
                        {
                            "finding_id": finding.id,
                            "url": url,
                            "control_body_sha256": idor_body_sha256(resp_c.body),
                            "baseline_body_sha256": idor_body_sha256(resp_b.body),
                            **summary,
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8"),
                secrets,
            )
        )
        self.audit.record(
            "idor_control_judged",
            finding_id=finding.id,
            control_verdict=control.verdict,
            ownership_verdict=ownership.verdict,
            similarity=round(control.similarity, 3),
            same_bytes=control.same_bytes,
        )

        # 3a. 对照判定 public → **公开/与会话无关的资源**，属性违反不成立：
        #     确定性驳回（零额外 LLM 成本；理由与证据锚点齐全）
        if control.verdict == "public":
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason=(
                    "未认证对照判定为**公开/与会话无关的资源**："
                    + "；".join(control.reasons)
                    + f"（判定依据见 {s_path.name}）"
                ),
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 3b. 对照判定 blocked → 覆盖不全，**不驳回也不确认**（fail-closed）
        if control.verdict == "blocked":
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=(
                    "未认证对照无法判定（覆盖不全，不驳回）: "
                    + "；".join(control.reasons)
                ),
            )
            return "blocked"

        # 3c. 对照 protected 但归属**无证据** → 按 M11a 裁决第 2 条驳回：
        #     "reference 可访问 + 攻击者拿到等价响应"本身不构成属性违反
        if ownership.verdict != "matched":
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason=(
                    "未认证对照成立（资源受会话保护），但**缺对象归属证据**："
                    f"归属判定={ownership.verdict}"
                    + (
                        f"（命中字段 {ownership.field}={ownership.value}，"
                        "与 reference 身份不一致）"
                        if ownership.verdict == "mismatched"
                        else "（B 基准中未找到可归属 reference 身份的字段）"
                    )
                    + f"；判定依据见 {s_path.name}"
                ),
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 5. 确定性属性判定（阈值写死；判定依据全量结构化落盘）
        judgment = idor_judge(resp_b, resp_a)
        j_path = self.evidence_dir / f"idor_{finding.id}_judgment.json"
        j_path.write_bytes(
            redact_bytes(
                (
                    json.dumps(
                        idor_judgment_dict(finding.id, url, judgment),
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8"),
                secrets,
            )
        )
        overlap_text = (
            "—" if judgment.json_overlap is None else f"{judgment.json_overlap:.3f}"
        )
        if not judgment.violation:
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason=(
                    f"双会话属性判定不成立：A 会话 {resp_a.status}，"
                    f"与 B 基准正文相似度 {judgment.similarity:.3f}、"
                    f"JSON 键重叠 {overlap_text}，未达属性违反阈值"
                ),
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 4. 属性违反成立：证据入包（behavioral + dual-session-confirmed + 四段式）
        cookie_mark_a = secret_marker(session.cookie_header())
        cookie_mark_b = secret_marker(reference.cookie_header())
        finding.verification = Verification(
            method="dual-session-confirmed",
            evidence_refs=[
                str(b_path),
                str(a_path),
                str(j_path),
                str(c_path),
                str(s_path),
            ],
            baseline_diff=(
                f"B 会话基准 {resp_b.status}（reference/victim，实质数据 "
                f"{len(resp_b.body.strip())} 字节）；A 会话对比 {resp_a.status}；"
                f"正文相似度 {judgment.similarity:.3f}（阈值 0.9）；"
                f"JSON 键重叠 {overlap_text}（阈值 0.8）"
            ),
            claim=f"身份 A 可经参数 {finding.param or 'URL'} 访问身份 B 的私有对象",
            expected=(
                "A 会话请求同 URL 应被拒绝（403/404/重定向登录页）"
                "或返回与 B 基准不同的数据"
            ),
            actual=(
                f"A 会话获得 {resp_a.status} 且与 B 基准达到属性违反阈值"
                f"（正文相似度 {judgment.similarity:.3f}、JSON 键重叠 "
                f"{overlap_text}）；判定依据见 {j_path.name}"
            ),
            reproduction_steps=[
                f"以身份 B 会话（reference/victim，Cookie {cookie_mark_b}）"
                f"GET {url} → 基准 {resp_b.status}（实质数据）",
                f"以身份 A 会话（Cookie {cookie_mark_a}）GET {url} "
                f"→ 对比 {resp_a.status}",
                "确定性属性判定（verify/idor.py）：正文相似度 "
                f"{judgment.similarity:.3f}（阈值 0.9）、JSON 键重叠 "
                f"{overlap_text}（阈值 0.8）→ 属性违反成立",
            ],
            verified_by=f"{skill.name}@{skill.manifest.version}",
            verified_at=_utc_now(),
        )
        if BEHAVIORAL_EVIDENCE_KIND not in finding.evidence_kinds:
            finding.evidence_kinds.append(BEHAVIORAL_EVIDENCE_KIND)
        finding.transition(
            FindingState.REPRODUCED,
            actor=skill.name,
            reason=(
                f"双会话属性违反成立（A 会话 {resp_a.status}，"
                f"相似度 {judgment.similarity:.3f}）"
            ),
        )
        store.append(finding)

        # 6. 证据门 → Verifier 终审 → 终态（与 verify-sqli/xss 同一收尾）；
        #    确定性结论块一并送审（protected + matched 才走到这里）
        return self._gate_and_review(finding, skill, store, summary=summary)

    def _idor_write_response(
        self, finding_id: str, role: str, resp, secrets: list[str]
    ) -> Path:
        """idor 响应证据落盘（脱敏后写 evidence_dir 顶层，browser.py 同范式）。"""
        path = self.evidence_dir / f"idor_{finding_id}_{role}_response.txt"
        text = f"GET {resp.url}\nstatus: {resp.status}\n"
        if resp.error is not None:
            text += f"error: {resp.error}\n"
        text += f"\n{resp.body}"
        path.write_bytes(redact_bytes(text.encode("utf-8"), secrets))
        return path

    def _verify_unauth(self, finding: Finding, skill, store: FindingStore) -> str:
        """verify-unauth SOP（skills/verify-unauth/SKILL.md）的确定性执行（M16-c）。

        确认铁律：**仅"匿名视图 ≡ 已认证视图"可确认**——已认证（预置会话）与
        **完全不发凭据**的匿名客户端请求**同一 URL**，前者的响应与后者**逐字节
        相同或相似度 ≥ 阈值**才算暴露成立。判定由
        ``verify/unauth_control.py::judge_unauth`` 做（纯确定性，零 LLM）。

        LLM 只出现在两处：① **独立敏感度判定器**（T1）——只产结论与行号锚点，
        **不产证据**（``GATE_MATRIX`` 的 behavioral_kinds 不认它，故它判错
        不可能造成误确认）；② Verifier 终审（T2）。

        失败语义：匿名被拒 → Rejected（资源本就要求认证）；匿名请求失败 /
        内容两者都不是 → blocked（覆盖不全，不驳回）；判定器失败 → blocked。
        """
        session = self._session()
        if session is None or not session.cookie_header():
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="scope 未配置预置会话，无法构造已认证视图（fail-closed）",
            )
            return "blocked"
        scope = getattr(self.runner, "scope", None)
        if scope is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="runner 未挂 scope，verify-unauth 缺 scope 防线（fail-closed）",
            )
            return "blocked"
        url = finding.asset
        decision = check_scope(scope, [url])  # 红线 5：请求任何 URL 前过 scope
        if not decision.allowed:
            self.audit.record(
                "verify_scope_rejected",
                finding_id=finding.id,
                violations=decision.violations,
            )
            return "blocked"

        secrets = session.secret_values()

        # 1. 已认证基准请求（预置会话）
        resp_auth = self._idor_fetch(url, session)
        self.audit.record(
            "unauth_probe_attempt",
            finding_id=finding.id,
            role="authenticated",
            status=resp_auth.status,
            error=resp_auth.error is not None,
        )
        auth_path = self._idor_write_response(finding.id, "auth", resp_auth, secrets)
        if resp_auth.error is not None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=f"已认证基准请求失败（覆盖不全，不驳回）: {resp_auth.error}",
            )
            return "blocked"

        # 2. 匿名对照请求（**完全不发凭据**：空 SessionConfig）
        resp_anon = self._idor_fetch(url, SessionConfig())
        self.audit.record(
            "unauth_probe_attempt",
            finding_id=finding.id,
            role="anonymous",
            status=resp_anon.status,
            error=resp_anon.error is not None,
        )
        anon_path = self._idor_write_response(finding.id, "anon", resp_anon, secrets)

        # 3. 确定性判定（唯一产证据的地方）
        judgment = judge_unauth(resp_auth, resp_anon)
        control_json = judgment.as_summary()
        c_path = self.evidence_dir / f"unauth_{finding.id}_control.json"
        c_path.write_bytes(
            redact_bytes(
                (unauth_summary_to_json(control_json) + "\n").encode("utf-8"),
                secrets,
            )
        )
        self.audit.record(
            "unauth_control_judged",
            finding_id=finding.id,
            verdict=judgment.verdict,
            anon_status=judgment.anon_status,
            byte_identical=judgment.byte_identical,
            similarity=round(judgment.similarity, 3),
        )

        # 3a. 匿名被拒 → 资源本就要求认证 → 确定性驳回（零 LLM 成本）
        if judgment.verdict == UNAUTH_REQUIRES_AUTH:
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason=(
                    "匿名对照被拒 → 该资源本就要求认证，未授权暴露不成立："
                    + "；".join(judgment.reasons)
                    + f"（判定依据见 {c_path.name}）"
                ),
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 3b. 覆盖不全 → 停 Hypothesis（既不驳回也不确认，fail-closed）
        if judgment.verdict != UNAUTH_EXPOSED:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="；".join(judgment.reasons)
                + f"（判定依据见 {c_path.name}）",
            )
            return "blocked"

        summary = {"unauth_control": control_json}

        # 4. 独立敏感度判定器（T1）：只产结论 + 锚点，**不产证据**
        judge = self._get_unauth_judge()
        if judge is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="未配置模型路由，无法做敏感度判定（fail-closed）",
            )
            return "blocked"
        sent_path = self.evidence_dir / f"unauth_judge_{finding.id}_sent.txt"
        sent_path.write_bytes(redact_bytes(resp_anon.body.encode("utf-8"), secrets))
        try:
            jr = judge.judge(
                resp_anon.body,
                finding_id=finding.id,
                url=url,
                secrets=secrets,
            )
        except (UnauthJudgeError, LLMError, BudgetExceededError, ContextOverflowError) as exc:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=f"敏感度判定器未完成（覆盖不全，不驳回）: {exc}",
            )
            return "blocked"
        summary["unauth_judge"] = jr.as_summary()

        # 5. 证据入包（method/标签只来自确定性判定；判定器结论仅入摘要）
        equiv = (
            "匿名响应与已认证视图**逐字节相同**（sha256 一致）"
            if judgment.byte_identical
            else f"匿名响应与已认证视图相似度 {judgment.similarity:.3f}"
        )
        finding.verification = Verification(
            method=UNAUTH_CONFIRMED_METHOD,
            evidence_refs=[auth_path.name, anon_path.name, c_path.name, sent_path.name],
            baseline_diff=(
                f"已认证基准 {judgment.baseline_status}、匿名对照 "
                f"{judgment.anon_status}；{equiv}；"
                f"匿名请求**未携带任何凭据**"
            ),
            claim=f"{url} 无需认证即可获得与已认证用户等价的内容",
            expected="匿名请求应被拒（3xx/4xx）或得到与会话相关的内容",
            actual=(
                f"匿名请求返回 {judgment.anon_status}，且响应与已认证视图"
                f"{'逐字节相同' if judgment.byte_identical else f'相似度 {judgment.similarity:.3f}'}"
                f"；敏感度判定 category={jr.category}（judge_input_truncated="
                f"{jr.truncated}）"
            ),
            reproduction_steps=[
                f"带预置会话 GET {url} → {judgment.baseline_status}（已认证视图）",
                f"**不带任何凭据** GET {url} → {judgment.anon_status}（匿名视图）",
                f"确定性比对：byte_identical={judgment.byte_identical}、"
                f"similarity={judgment.similarity:.3f}（判据见 {c_path.name}）",
                f"敏感度判定（T1，结论非证据）：category={jr.category}、"
                f"anchors={jr.anchors}",
            ],
            verified_by=f"{skill.name}@{skill.manifest.version}",
            verified_at=_utc_now(),
        )
        if UNAUTH_EQUIVALENCE_EVIDENCE_KIND not in finding.evidence_kinds:
            finding.evidence_kinds.append(UNAUTH_EQUIVALENCE_EVIDENCE_KIND)
        finding.transition(
            FindingState.REPRODUCED,
            actor=skill.name,
            reason=f"匿名/已认证响应等价（byte_identical={judgment.byte_identical}）",
        )
        store.append(finding)

        # 6. 证据门 → Verifier 终审 → 终态迁移（公共收尾）
        return self._gate_and_review(finding, skill, store, summary=summary)

    def _verify_cmdi(self, finding: Finding, skill, store: FindingStore) -> str:
        """verify-cmdi SOP（skills/verify-cmdi/SKILL.md）的确定性执行（M18）。

        确认铁律：**仅"我们注入的命令发起的回调"到达 listener 可确认**（带外二值
        事实）。响应体里回显出来的 ``curl ...`` 文本、状态码、耗时一律不是证据
        ——命令注入的"答案不在目标给我们的响应里"。

        判定（`verify/cmdi.py::judge`，纯函数，宁漏勿滥）：

        - 命中 token ∧ 交付证明成立 ∧ DNS 变体未命中 → REPRODUCED → 证据门 → Verifier；
        - **DNS 非命中变体命中** → blocked（有第三方在代抓取，观测不可信）；
        - 交付证明不成立 / 探针出错 → blocked（覆盖不全，绝不驳回）；
        - 干净未命中 + 交付证明成立 → REJECTED（真阴性）。

        防伪三道（缺一不可）：① 每探针唯一 token + 常量时间比对（不带 token 的
        请求记 ``cmdi_callback_ignored``，不计命中）；② 交付证明（先注入**纯
        token**，目标原样回显 ⇒ 载荷"送达"有据）；③ **DNS 非命中变体**（不可解析
        主机名：真 shell 与"替我们抓取的中间件"都发不出我们能收到的请求 ⇒ 它命中
        即说明命中来自第三方）。

        **与 verify-ssrf 的两处结构差异**（都是本类型性质决定的，不是简化）：
        ① **不需要预置会话**——判据是"注入的命令发起的回调"，与身份无关
        （ssrf 的带会话 baseline 是为证明"服务端在替已认证用户发请求"）；
        ② **多一道 DNS 探针**——命令注入可能打在 WAF/反代/截图服务前面。

        请求构造、载荷拼接、判定全是确定性代码（红线 1）；唯一 LLM 调用是收尾
        的 Verifier 终审。
        """
        if not finding.param:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="cmdi 候选缺 param，无法构造注入载荷（fail-closed）",
            )
            return "blocked"
        if CRAWL_FORM_EVIDENCE_KIND in finding.evidence_kinds:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="POST 表单型候选的 cmdi 验证未实现（本轮只覆盖 GET query 参数）",
            )
            return "blocked"
        scope = getattr(self.runner, "scope", None)
        if scope is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="runner 未挂 scope，cmdi 验证缺 scope 防线（fail-closed）",
            )
            return "blocked"

        # 1. scope 授权前置（红线 5）：目标 asset 必须已授权。
        # 与 ssrf 同纪律：**不**对探测 URL 逐条 check_scope——载荷里携带的是我们的
        # 回调地址（基础设施，非目标），check_scope 会把它当目标提取并按端口拒掉。
        # 探测 URL 的"不越界"改由下面的**同源自检**保证。
        decision = check_scope(scope, [finding.asset])
        if not decision.allowed:
            self.audit.record(
                "verify_scope_rejected",
                finding_id=finding.id,
                violations=decision.violations,
            )
            return "blocked"

        # 2. 回调 listener（复用 SSRF 的同一件基础设施；不可用即 blocked）
        try:
            listener = self._ssrf_listener(finding.id)
        except SsrfListenerError as exc:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=f"回调 listener 不可用（fail-closed）: {exc}",
            )
            return "blocked"
        bound_host, bound_port = listener.bound_address
        advertised_host = (
            ssrf_resolve_callback_host()
            if self._ssrf_listener_factory is None
            else bound_host
        )

        # 会话**可选**：有就带上（更贴近操作员的真实请求），没有也能验证
        session = self._session()

        probes: list[dict] = []
        errored = False
        hit: tuple[str, str, list[dict]] | None = None

        def run_probe(seq: int, variant: str, url: str, token: str, *,
                      infrastructure: bool = False):
            """发一次探测并登记 token；返回 (response, records)。

            ``infrastructure=True`` 用于 **DNS 非命中探针**：它的失败是**预期行为**
            （正确的结果就是解析不了），**不计入 errored**——否则每次干净未命中都会
            被判 blocked，rejected 分支永远不可达（ssrf 实现期踩过的同一个坑）。
            它的失败仍如实记入 probes 供取证。
            """
            nonlocal errored
            # 同源自检：**载荷**探测 URL 必须与已授权的 asset 完全同源（红线 5）。
            # ``infrastructure=True`` 只用于 DNS 非命中探针：它的 URL 同样由 asset
            # 构造（因而同源），但"目标解析不了这个随机主机名"是**预期结果**，故其
            # 失败不计入 errored——否则每次干净未命中都会被判 blocked。
            if not infrastructure and not cmdi_same_origin(url, finding.asset):
                self.audit.record(
                    "verify_scope_rejected",
                    finding_id=finding.id,
                    violations=[
                        f"探测 URL 与 asset 不同源：{url} vs {finding.asset}"
                    ],
                )
                return None, []
            listener.register(token)
            response = self._cmdi_fetch(url, session)
            records = [r.to_dict() for r in listener.hits(token)]
            probes.append(
                {
                    "seq": seq,
                    "variant": variant,
                    "url": url,
                    "token": token,
                    "status": response.status,
                    "error": response.error,
                    "callback_hits": len(records),
                    "elapsed_s": round(response.elapsed_s, 3),
                }
            )
            self.audit.record(
                "cmdi_probe_attempt",
                finding_id=finding.id,
                seq=seq,
                variant=variant,
                url=url,
                token=token,
                status=response.status,
                error=response.error is not None,
                callback_hits=len(records),
            )
            if response.error is not None and not infrastructure:
                errored = True
            return response, records

        def callback_url_for(token: str) -> str:
            """由 token 现构造回调地址（**token 与注入 URL 必须同一真相源**）。

            ssrf 实现期踩过的坑：循环外生成 value、循环内另生成 token ⇒ 注册的
            token 与载荷里的 token 不一致，confirmed 分支永不触发。
            """
            return ssrf_callback_url(advertised_host, bound_port, token)

        # 3. DNS 非命中变体（先做：它命中就说明本次观测不可信，无需再打目标）
        dns_token = new_cmdi_token()
        dns_value, dns_control_url = cmdi_dns_probe_value(
            ssrf_new_nonce_host(), bound_port, dns_token
        )
        # **必须投递到靶**：把 `;curl http://<nonce>.invalid/c/<token>` 作为**目标
        # 参数值**发出去。只有靶（或其前置中间件）真的收到了这次抓取尝试，
        # "第三方代抓取"才可能被观测到——宿主自己去取那个 `.invalid` 地址等于什么
        # 都没测。M18-a 实现期此处误把**对照地址本身**当成探测 URL（`dns_value`
        # 算完就丢了）⇒ 该变体从未到达靶，`dns_misfire` 恒为 False，而 Confirmed
        # 的证据文本仍声称"已排除第三方代抓取"（无观测支撑的陈述）。
        dns_url = cmdi_build_probe_url(finding.asset, finding.param, dns_value)
        _dns_resp, dns_records = run_probe(
            0, DNS_VARIANT, dns_url, dns_token, infrastructure=True
        )
        dns_misfire = bool(dns_records)

        # 4. 交付证明探针（纯 token，不含命令分隔符）
        delivery_token = new_cmdi_token()
        delivery_url = cmdi_build_probe_url(
            finding.asset, finding.param, cmdi_delivery_probe_value(delivery_token)
        )
        delivery_resp, _ = run_probe(1, DELIVERY_VARIANT, delivery_url, delivery_token)
        # 交付证明的判据：**响应正文里出现我们的纯 token**（`token_delivered`
        # 只搜前 DELIVERY_PROOF_CHARS 个字符，上限确定）。探针出错则交付证明不成立。
        delivered = bool(
            delivery_resp is not None
            and delivery_resp.error is None
            and cmdi_token_delivered(delivery_resp, delivery_token)
        )

        # 5. 载荷变体（全部只读 GET；命中即停）
        for seq, (variant, template) in enumerate(CMDI_VARIANTS, start=2):
            if dns_misfire or hit is not None:
                break
            token = new_cmdi_token()
            url = cmdi_build_probe_url(
                finding.asset, finding.param, cmdi_callback_value(template, callback_url_for(token))
            )
            _resp, records = run_probe(seq, variant, url, token)
            if records:
                hit = (token, variant, records)

        # 6. 确定性判定（纯函数；全部依据落盘）
        judgment = cmdi_judge(
            callback_hit=hit is not None,
            hit_requests=hit[2] if hit else [],
            hit_variant=hit[1] if hit else "",
            delivered=delivered,
            dns_misfire=dns_misfire,
            probes=probes,
            probes_errored=errored,
            ignored=[r.to_dict() for r in listener.ignored],
        )
        callbacks_path = self.evidence_dir / f"cmdi_{finding.id}_callbacks.jsonl"
        callbacks_path.write_text(
            "".join(
                json.dumps(record, ensure_ascii=False) + "\n"
                for record in (
                    *judgment.hit_requests,
                    *[
                        {"ignored": True, **record}
                        for record in judgment.ignored_requests
                    ],
                )
            ),
            encoding="utf-8",
        )
        j_path = self.evidence_dir / f"cmdi_{finding.id}_judgment.json"
        secrets = session.secret_values() if session is not None else []
        j_path.write_bytes(
            redact_bytes(
                (
                    json.dumps(
                        {
                            "finding_id": finding.id,
                            "asset": finding.asset,
                            "param": finding.param,
                            "callback_listener": f"{bound_host}:{bound_port}",
                            "delivery_probe_url": delivery_url,
                            "dns_probe_url": dns_url,
                            "dns_control_url": dns_control_url,
                            **judgment.to_dict(),
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8"),
                secrets,
            )
        )
        self.audit.record(
            "cmdi_callback_judged",
            finding_id=finding.id,
            verdict=judgment.verdict,
            callback_hits=len(judgment.hit_requests),
            delivered=judgment.delivered,
            dns_misfire=judgment.dns_misfire,
            probes=len(judgment.probes),
            ignored=len(judgment.ignored_requests),
        )

        # 7. blocked：覆盖不全，**不驳回**（Finding 停在 Hypothesis）
        if judgment.verdict == "blocked":
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="cmdi 判定未能完成（覆盖不全，不驳回）: "
                + "；".join(judgment.reasons),
            )
            return "blocked"

        # 8. rejected：干净未命中 + 交付证明成立（确定性真阴性，零额外 LLM 成本）
        if judgment.verdict == "rejected":
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason="；".join(judgment.reasons) + f"（判定依据见 {j_path.name}）",
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 9. confirmed：回调命中 → 证据入包（behavioral + 四段式）
        sources = sorted(
            {r.get("source_ip", "") for r in judgment.hit_requests if r.get("source_ip")}
        )
        agents = sorted(
            {r.get("user_agent", "") for r in judgment.hit_requests if r.get("user_agent")}
        )
        finding.verification = Verification(
            method=CMDI_CONFIRMED_METHOD,
            evidence_refs=[
                str(callbacks_path),
                str(j_path),
            ],
            baseline_diff=(
                f"回调 listener 绑定 {bound_host}:{bound_port}，收到 "
                f"{len(judgment.hit_requests)} 次含本次探针 token 的请求；"
                f"交付证明成立（纯 token 探针被目标原样回显）；"
                f"DNS 非命中变体未命中（排除第三方代抓取）"
            ),
            claim=f"参数 {finding.param} 被拼接进服务端执行的命令，可执行任意命令",
            expected="我们注入的命令应使目标向回调地址发起一次请求（带本次探针 token）",
            actual=(
                f"listener 收到 {len(judgment.hit_requests)} 次回调（命中变体 "
                f"{judgment.hit_variant}；来源 IP {sources or '未知'}；"
                f"UA {agents or '未提供'}）；请求原文见 {callbacks_path.name}"
            ),
            reproduction_steps=[
                f"注入纯 token 值确认参数回显（交付证明）→ "
                f"marker_found={delivered}",
                f"注入 DNS 非命中变体 → 命中={dns_misfire}"
                f"（命中即说明有第三方代抓取）",
                f"注入载荷变体 {judgment.hit_variant} → "
                f"listener 收到 {len(judgment.hit_requests)} 次回调",
                f"回调请求原文（含来源 IP/UA/路径）：{callbacks_path.name}",
            ],
            verified_by=f"{skill.name}@{skill.manifest.version}",
            verified_at=_utc_now(),
        )
        if BEHAVIORAL_EVIDENCE_KIND not in finding.evidence_kinds:
            finding.evidence_kinds.append(BEHAVIORAL_EVIDENCE_KIND)
        finding.transition(
            FindingState.REPRODUCED,
            actor=skill.name,
            reason=(
                f"回调 listener 收到含本次 token 的请求（变体 {judgment.hit_variant}）"
            ),
        )
        store.append(finding)

        # 10. 证据门 → Verifier 终审 → 终态迁移（公共收尾）
        summary = cmdi_summary_for_verifier(
            judgment, callback_host_port=f"{bound_host}:{bound_port}"
        )
        return self._gate_and_review(finding, skill, store, summary=summary)

    def _verify_ssti(self, finding: Finding, skill, store: FindingStore) -> str:
        """verify-ssti SOP（skills/verify-ssti/SKILL.md）的确定性执行（M22-b）。

        确认铁律：**同一语法下两个不同乘积都被算了出来**，且基线干净、**畸形
        模板对照**不成立。页面里的模板语法回显、报错文本、状态码一律不是证据
        ——「参数被看见了」不等于「被求值了」。

        判定（``verify/ssti.py::judge``，纯函数，宁漏勿滥）：

        - 两个乘积都中 + 基线干净 + 畸形对照干净 → REPRODUCED → 证据门 → Verifier；
        - 三个语法族的探针全部干净未命中 → **REJECTED**（真阴性，actor=本 skill）；
        - 只中一个 / 基线本身含乘积 / 畸形对照也出数 / 请求出错 / 缺 param /
          POST 表单型候选 → blocked（覆盖不全，**绝不驳回**）。

        探针固定、只 GET、无副作用，每候选 **≤8 次**（1 基线 + 3 语法 × 2 探针 +
        1 畸形对照，命中即停）。请求构造与判定全是确定性代码（红线 1），唯一
        LLM 调用是收尾的 Verifier 终审。
        """
        scope = getattr(self.runner, "scope", None)
        if scope is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="runner 未挂 scope，ssti 验证缺 scope 防线（fail-closed）",
            )
            return "blocked"
        param = finding.param
        if not param:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="ssti 候选缺 param，无法构造模板探针（fail-closed，不凭空造 URL）",
            )
            return "blocked"
        if CRAWL_FORM_EVIDENCE_KIND in finding.evidence_kinds:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason="POST 表单型候选的 ssti 验证未实现（本轮只覆盖 GET query 参数）",
            )
            return "blocked"
        url = finding.asset
        decision = check_scope(scope, [url])  # 红线 5：请求任何 URL 前过 scope
        if not decision.allowed:
            self.audit.record(
                "verify_scope_rejected",
                finding_id=finding.id,
                violations=decision.violations,
            )
            return "blocked"

        # 判据与身份无关：有预置会话就带上（提高可达性），没有也照判
        session = self._session()
        secrets = session.secret_values() if session is not None else []

        probes: list = []
        evidence_paths: list[Path] = []

        # 1. 基线：原样响应必须**不含**这两个乘积（反事实的落脚点）
        evidence_paths.append(
            self._ssti_probe(
                finding,
                url,
                label="baseline",
                kind=SSTI_KIND_BASELINE,
                syntax=None,
                session=session,
                secrets=secrets,
                probes=probes,
            )
        )

        # 2. 逐语法：两个乘积都中即停，并补该语法的**畸形模板对照**
        hit = None
        for family in SSTI_SYNTAX_FAMILIES:
            errored = False
            for suffix, expression in (("a", family.expr_a), ("b", family.expr_b)):
                evidence_paths.append(
                    self._ssti_probe(
                        finding,
                        ssti_build_probe_url(url, param, expression),
                        label=f"{family.label}-expr-{suffix}",
                        kind=SSTI_KIND_EXPRESSION,
                        syntax=family.label,
                        session=session,
                        secrets=secrets,
                        probes=probes,
                    )
                )
                if probes[-1].error is not None:
                    errored = True
            first, second = probes[-2], probes[-1]
            if (
                not errored
                and SSTI_PRODUCT_A in first.products
                and SSTI_PRODUCT_B in second.products
            ):
                hit = family
                break

        if hit is not None:
            evidence_paths.append(
                self._ssti_probe(
                    finding,
                    ssti_build_probe_url(url, param, hit.malformed),
                    label=f"{hit.label}-malformed",
                    kind=SSTI_KIND_CONTROL,
                    syntax=hit.label,
                    session=session,
                    secrets=secrets,
                    probes=probes,
                )
            )

        # 3. 差分求值判定（纯函数；判定依据全量落盘供离线复核）
        judgment = ssti_judge(probes)
        summary = ssti_summary_for_verifier(
            judgment, probes, url=url, param=param
        )
        j_path = self.evidence_dir / f"ssti_{finding.id}_judgment.json"
        j_path.write_bytes(
            redact_bytes(
                (
                    json.dumps(
                        {"finding_id": finding.id, **summary},
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8"),
                secrets,
            )
        )
        self.audit.record(
            "ssti_judged",
            finding_id=finding.id,
            verdict=judgment.verdict,
            syntax=judgment.syntax,
            products=list(judgment.products),
            probes=len(probes),
            budget=SSTI_PROBE_BUDGET,
        )

        # 4a. 判不了：覆盖不全（不驳回）
        if not judgment.confirmed and judgment.verdict != SSTI_VERDICT_REJECTED:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=(
                    "ssti 差分求值未完成（覆盖不全，不驳回）: "
                    + "；".join(judgment.reasons)
                ),
            )
            return "blocked"

        # 4b. 真阴性：三个语法族全部干净未命中 ⇒ 驳回
        if judgment.verdict == "rejected":
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason=(
                    "ssti 差分求值不成立："
                    + "；".join(judgment.reasons)
                    + f"（判定依据见 {j_path.name}）"
                ),
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 4c. 成立：证据入包（具名标签 + 差分求值 method + 四段式）
        evidence_paths.append(j_path)
        baseline_probe = probes[0]
        # 只取**命中族**的表达式探针：`probes` 里还留着前面失败族的探针，
        # 直接用 [0]/[1] 会在非第一族命中时写出**照抄不可复现**的 URL
        # （实测缺陷：命中 `${ }` 族时复现步骤写的是 `{{ }}` 族的 URL）。
        hit_probes = [
            p
            for p in probes
            if p.kind == SSTI_KIND_EXPRESSION and p.syntax == hit.label
        ]
        control_probe = next(
            (p for p in probes if p.kind == SSTI_KIND_CONTROL), None
        )
        finding.verification = Verification(
            method=SSTI_CONFIRMED_METHOD,
            evidence_refs=[str(path) for path in evidence_paths],
            baseline_diff=(
                f"基线 {baseline_probe.status}（正文不含 "
                f"{SSTI_PRODUCT_A}/{SSTI_PRODUCT_B}）；"
                f"命中族 {hit.label} 的两个表达式探针都出现乘积；"
                f"畸形模板对照 "
                f"{'未执行' if control_probe is None else f'{control_probe.status}（不含乘积）'}"
            ),
            claim=(
                f"参数 {param} 的取值被服务端当模板求值"
                f"（{judgment.engines or judgment.syntax}）"
            ),
            expected=(
                "原样响应不应出现模板表达式算出的乘积：参数只应被回显或转义，"
                "畸形模板（少一个右括号）也不应算出任何数字"
            ),
            actual=(
                f"探针 {hit.expr_a} / {hit.expr_b} 的响应分别出现 "
                f"{SSTI_PRODUCT_A} / {SSTI_PRODUCT_B}；"
                f"畸形模板对照未出现乘积；判定依据见 {j_path.name}"
            ),
            reproduction_steps=[
                f"GET {baseline_probe.url}（基线）→ {baseline_probe.status}，"
                f"正文不含 {SSTI_PRODUCT_A}/{SSTI_PRODUCT_B}",
                f"GET {hit_probes[0].url} → 正文出现 {SSTI_PRODUCT_A}",
                f"GET {hit_probes[1].url} → 正文出现 {SSTI_PRODUCT_B}",
                f"GET {control_probe.url if control_probe else url}（畸形模板对照）"
                " → 正文不含乘积（排除「strip 非数字后强算」）",
            ],
            verified_by=f"{skill.name}@{skill.manifest.version}",
            verified_at=_utc_now(),
        )
        if SSTI_EVALUATION_EVIDENCE_KIND not in finding.evidence_kinds:
            finding.evidence_kinds.append(SSTI_EVALUATION_EVIDENCE_KIND)
        finding.transition(
            FindingState.REPRODUCED,
            actor=skill.name,
            reason=(
                f"模板求值成立（{judgment.syntax}）：两个不同乘积 "
                f"{SSTI_PRODUCT_A}/{SSTI_PRODUCT_B} 都被算出，基线干净、"
                "畸形模板对照未出数"
            ),
        )
        store.append(finding)

        # 5. 证据门 → Verifier 终审 → 终态迁移（公共收尾）。
        # 确认截图取**命中族**的探针 URL：图里应直接看到乘积（如 36481），
        # 截裸 asset 只会得到未求值的页面（与 XSS 传 canary URL 同一取舍）。
        return self._gate_and_review(
            finding,
            skill,
            store,
            summary=summary,
            screenshot_url=hit_probes[0].url,
        )

    def _ssti_probe(
        self,
        finding: Finding,
        url: str,
        *,
        label: str,
        kind: str,
        syntax: str | None,
        session,
        secrets: list[str],
        probes: list,
    ) -> Path:
        """一次 ssti 探针：请求 → 按次审计 → 证据落盘（脱敏）→ 记入 probes。

        返回证据文件路径（进 ``verification.evidence_refs``，可离线调出）。
        """
        resp = self._ssti_fetch(url, session)
        products = ssti_match_products(resp.body)
        self.audit.record(
            "ssti_probe_attempt",
            finding_id=finding.id,
            label=label,
            kind=kind,
            syntax=syntax,
            status=resp.status,
            error=resp.error is not None,
            products=sorted(products),
        )
        path = self.evidence_dir / f"ssti_{finding.id}_{label}_response.txt"
        text = f"GET {url}\nstatus: {resp.status}\n"
        if resp.error is not None:
            text += f"error: {resp.error}\n"
        text += f"\n{resp.body}"
        path.write_bytes(redact_bytes(text.encode("utf-8"), secrets))
        probes.append(
            SstiProbe(
                label=label,
                kind=kind,
                syntax=syntax,
                url=url,
                status=resp.status,
                error=resp.error,
                products=products,
            )
        )
        return path

    # ---- M23：服务器报错信息泄露（按 host 的畸形请求差分） ----

    def _verify_error_disclosure(
        self, finding: Finding, skill, store: FindingStore
    ) -> str:
        """verify-error-disclosure SOP 的确定性执行（M23）。

        确认铁律：**同一 host 的正常 GET 干净，而畸形请求的错误页命中 ≥2 类
        技术披露标记**。只命中 1 类、基线本身带标记、探针没能发出、畸形请求
        未被拒绝——一律 blocked（覆盖不全，绝不驳回）。

        请求全部经**裸 TCP** 发出（``verify/raw_http.py``）：urllib/httpx 会在
        客户端拒绝或规范化非法请求行，畸形请求根本到不了服务器。发出前过
        ``check_scope``（红线 5）；**不发任何凭据**（判据与身份无关）。版本头
        只记 ``server_header_disclosed`` 审计，**不构成** Confirmed 证据。

        每 host ≤1 次基线 + ≤5 条探针（命中即停）；唯一 LLM 调用是收尾的
        Verifier 终审。
        """
        scope = getattr(self.runner, "scope", None)
        if scope is None:
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=(
                    "runner 未挂 scope，error-disclosure 验证缺 scope 防线"
                    "（fail-closed）"
                ),
            )
            return "blocked"
        origin = _origin_of(finding.asset)
        if origin is None or origin[0] not in ("http", "https"):
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=(
                    "候选 asset 不是可解析的 http(s) origin，无法构造畸形请求"
                    f"（fail-closed）: {finding.asset}"
                ),
            )
            return "blocked"
        scheme, host, port = origin
        decision = check_scope(scope, [finding.asset])  # 红线 5：发请求前过 scope
        if not decision.allowed:
            self.audit.record(
                "verify_scope_rejected",
                finding_id=finding.id,
                violations=decision.violations,
            )
            return "blocked"

        tls = scheme == "https"
        host_header = _host_header(host, port, tls)
        origin_url = _origin_url(finding.asset) or finding.asset
        secrets: list[str] = []  # 本类型**不发任何凭据**（交接单硬要求）
        evidence_paths: list[Path] = []
        baseline = self._error_disclosure_probe(
            finding,
            spec=ErrorDisclosureProbeSpec(
                label="baseline",
                description="正常 GET（基线对照）",
                request=error_disclosure_baseline(host_header),
            ),
            host=host,
            port=port,
            tls=tls,
            evidence_paths=evidence_paths,
        )

        probes: list[ErrorDisclosureProbe] = []
        # 基线不可用（连不上 / 本身已带标记）时不再发探针：判据的反事实
        # 已经不可能成立，多发只会白花钱（判定仍是 blocked，不是 rejected）。
        baseline_usable = baseline.error is None and not baseline.classes
        if baseline_usable:
            for spec in error_disclosure_probes(host_header):
                probes.append(
                    self._error_disclosure_probe(
                        finding,
                        spec=spec,
                        host=host,
                        port=port,
                        tls=tls,
                        evidence_paths=evidence_paths,
                    )
                )
                # 命中即停：一条 4xx/5xx 且 ≥2 类标记已足以确认，省下剩余探针。
                last = probes[-1]
                if (
                    last.status is not None
                    and 400 <= last.status <= 599
                    and len(last.classes) >= 2
                ):
                    break

        judgment = error_disclosure_judge(baseline, probes)
        summary = error_disclosure_summary(
            judgment, baseline, probes, origin=origin_url
        )
        j_path = self.evidence_dir / f"error_disclosure_{finding.id}_judgment.json"
        j_path.write_bytes(
            redact_bytes(
                (
                    json.dumps(
                        {"finding_id": finding.id, **summary},
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8"),
                secrets,
            )
        )
        self.audit.record(
            "error_disclosure_judged",
            finding_id=finding.id,
            verdict=judgment.verdict,
            matched=list(judgment.matched),
            probe=judgment.probe,
            probes=len(probes),
            budget=ERROR_DISCLOSURE_PROBE_BUDGET,
            server_header=judgment.server_header,
        )
        # 版本头：单独审计，**不进** evidence_kinds / verification（维护者裁定）
        if judgment.server_header:
            self.audit.record(
                "server_header_disclosed",
                finding_id=finding.id,
                origin=origin_url,
                header=judgment.server_header,
                note="仅作审计/报告分类线索，不构成确认证据",
            )

        # 1a. 判不了：覆盖不全（不驳回）
        if not judgment.confirmed and judgment.verdict != "rejected":
            self.audit.record(
                "verify_blocked",
                finding_id=finding.id,
                reason=(
                    "error-disclosure 差分未完成（覆盖不全，不驳回）: "
                    + "；".join(judgment.reasons)
                ),
            )
            return "blocked"

        # 1b. 真阴性：畸形请求被拒绝但零标记 ⇒ 通用错误页（不信"看起来像报错"）
        if judgment.verdict == "rejected":
            finding.transition(
                FindingState.REJECTED,
                actor=skill.name,
                reason=(
                    "报错信息泄露不成立："
                    + "；".join(judgment.reasons)
                    + f"（判定依据见 {j_path.name}）"
                ),
            )
            store.append(finding)
            assemble_evidence_pack(finding, evidence_base=self.evidence_dir)
            return "rejected"

        # 2. 成立：具名证据标签 + method + 四段式（响应正文只在证据文件里）
        evidence_paths.append(j_path)
        hit = next(p for p in probes if p.label == judgment.probe)
        finding.verification = Verification(
            method=ERROR_DISCLOSURE_CONFIRMED_METHOD,
            evidence_refs=[str(path) for path in evidence_paths],
            baseline_diff=(
                f"基线 {baseline.status}（正文 {baseline.body_bytes}B，0 类标记）；"
                f"畸形探针 {hit.label} → {hit.status}，命中 "
                f"{len(hit.classes)} 类标记 {sorted(hit.classes)}"
            ),
            claim=(
                f"{host_header} 在收到畸形 HTTP 请求时把服务器内部异常/堆栈/"
                "源码路径回显给客户端"
            ),
            expected=(
                "正常 GET 不应出现堆栈帧、框架版本或源码路径；畸形请求应只得到"
                "不含内部信息的通用错误页"
            ),
            actual=(
                f"探针 {hit.label}（{hit.description}）返回 {hit.status}，正文命中 "
                f"{len(hit.classes)} 类标记：{', '.join(sorted(hit.classes))}"
            ),
            reproduction_steps=[
                f"GET {origin_url}/ → {baseline.status}（正文零技术披露标记）",
                (
                    f"发送畸形请求（{hit.description}，sha256 "
                    f"{hit.request_sha256[:12]}）→ {hit.status}"
                ),
                (
                    f"响应正文命中 {len(hit.classes)} 类标记："
                    f"{', '.join(sorted(hit.classes))}"
                ),
            ],
            verified_by=f"{skill.name}@{skill.manifest.version}",
            verified_at=_utc_now(),
        )
        if ERROR_TRACE_EVIDENCE_KIND not in finding.evidence_kinds:
            finding.evidence_kinds.append(ERROR_TRACE_EVIDENCE_KIND)
        finding.transition(
            FindingState.REPRODUCED,
            actor=skill.name,
            reason=(
                f"畸形请求 {hit.label} 的错误页命中 {len(hit.classes)} 类技术披露"
                f"标记（{', '.join(sorted(hit.classes))}），基线干净"
            ),
        )
        store.append(finding)

        # 3. 证据门 → Verifier 终审 → 终态迁移（公共收尾）
        return self._gate_and_review(finding, skill, store, summary=summary)

    def _error_disclosure_probe(
        self,
        finding: Finding,
        *,
        spec: ErrorDisclosureProbeSpec,
        host: str,
        port: int,
        tls: bool,
        evidence_paths: list[Path],
    ) -> ErrorDisclosureProbe:
        """一次裸 HTTP 探针：发送 → 按次审计 → 证据落盘（脱敏）→ 归一化结果。

        证据里**不写原始请求字节**（含控制字符）：只记转义摘要与 sha256
        （交接单 §8 第 5 条）。
        """
        response = self._raw_http_send(
            host, port, spec.request, tls=tls, timeout=RAW_HTTP_DEFAULT_TIMEOUT
        )
        outcome = error_disclosure_outcome(spec, response)
        self.audit.record(
            "error_disclosure_probe_attempt",
            finding_id=finding.id,
            label=spec.label,
            description=spec.description,
            status=response.status,
            error=response.error is not None,
            error_kind=response.error_kind,
            classes=sorted(outcome.classes),
            body_bytes=len(response.body),
            truncated=response.truncated,
            request_sha256=outcome.request_sha256,
        )
        path = self.evidence_dir / (
            f"error_disclosure_{finding.id}_{spec.label}_response.txt"
        )
        text = (
            f"request: {spec.request_repr}\n"
            f"request_sha256: {outcome.request_sha256}\n"
            f"origin: {host}:{port} tls={tls}\n"
            f"status: {response.status} {response.reason}\n"
        )
        if response.error is not None:
            text += f"error: [{response.error_kind}] {response.error}\n"
        server = response.header("server")
        if server:
            text += f"server: {server}\n"
        content_type = response.header("content-type")
        if content_type:
            text += f"content-type: {content_type}\n"
        text += (
            f"matched_classes: {', '.join(sorted(outcome.classes)) or 'none'}\n"
            f"body_bytes: {len(response.body)} (truncated={response.truncated})\n"
            f"\n{response.body_text}"
        )
        path.write_bytes(redact_bytes(text.encode("utf-8"), []))
        evidence_paths.append(path)
        return outcome

    def _get_unauth_judge(self):
        """懒建敏感度判定器（测试经 ``unauth_judge_factory`` 注入替身）。

        无模型路由（``self.router`` 为 None）时返回 None——调用方 fail-closed。
        """
        if self._unauth_judge is None:
            if self._unauth_judge_factory is not None:
                self._unauth_judge = self._unauth_judge_factory()
            elif self.router is None:
                return None
            else:
                self._unauth_judge = UnauthJudge(self.router, self.audit)
        return self._unauth_judge

    def _get_browser(self, session: SessionConfig):
        """懒建/复用浏览器验证器（M8b）；不可用抛 BrowserUnavailableError。

        测试经 ``browser_factory`` 注入 FakeBrowser；否则建真实
        BrowserVerifier（playwright 懒导入在 ``start()`` 内）。
        """
        if self._browser is None:
            if self.browser_factory is not None:
                self._browser = self.browser_factory()
            else:
                browser = BrowserVerifier(
                    scope=getattr(self.runner, "scope", None),
                    evidence_dir=self.evidence_dir,
                    session=session,
                )
                browser.start()  # 不可用即抛 BrowserUnavailableError
                self._browser = browser
        return self._browser

    def _close_browser(self) -> None:
        """释放 verify phase 建过的浏览器（若有）；异常吞咽（不遮蔽主链路）。"""
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None

    # ---- M20：证据截图 ----

    def _get_screenshotter(self):
        """懒建截图器：首次截图时才启动 Chromium，phase 收尾统一释放。"""
        if self._screenshotter is not None:
            return self._screenshotter
        if self.screenshot_factory is not None:
            self._screenshotter = self.screenshot_factory()
            return self._screenshotter
        scope = getattr(self.runner, "scope", None)
        if scope is None:
            raise BrowserUnavailableError(
                "runner 未挂 scope，截图缺 scope 防线（fail-closed）"
            )
        capturer = ScreenshotCapturer(
            scope=scope,
            evidence_dir=self.evidence_dir,
            session=self._session(),
        )
        capturer.start()  # 不可用即抛 BrowserUnavailableError
        self._screenshotter = capturer
        return capturer

    def _close_screenshotter(self) -> None:
        """释放 verify phase 建过的截图器（若有）；异常吞咽（不遮蔽主链路）。"""
        if self._screenshotter is not None:
            try:
                self._screenshotter.close()
            except Exception:
                pass
            self._screenshotter = None

    def _capture_screenshot(self, finding: Finding, url: str):
        """给已确认的 Finding 截一张页面图（M20）；失败只记审计，**不改判**。

        返回 PNG 路径或 None。刻意**不抛异常**：截图是补充证据，浏览器缺失/
        超时都不该让一条已确认的 Finding 变成 blocked——这与各验证器的
        fail-closed 语义相反（fail-open），理由与边界写在 README「证据截图」节。
        """
        if not self.screenshots:
            return None
        try:
            capturer = self._get_screenshotter()
            result = capturer.capture(url, name=f"shot_{finding.id}")
        except Exception as exc:  # 浏览器不可用 / 注入替身异常
            self.audit.record(
                "screenshot_skipped",
                finding_id=finding.id,
                url=url,
                reason=f"截图器不可用（fail-open，不阻断确认）: {exc}",
            )
            return None
        if result.error is not None or result.path is None:
            self.audit.record(
                "screenshot_skipped",
                finding_id=finding.id,
                url=url,
                reason=result.error or "未产出文件",
            )
            return None
        self.audit.record(
            "screenshot_captured",
            finding_id=finding.id,
            url=url,
            file=result.path.name,
            bytes=result.bytes,
            sha256=result.sha256,
            width=result.width,
            height=result.height,
            status=result.status,
            blocked_requests=result.blocked_requests,
        )
        return result.path

    # ---- M20-b：覆盖截图（按类型的固定取证镜头） ----

    def _capture_coverage(self, finding: Finding, store: FindingStore) -> None:
        """按类型的固定镜头留图（**不论判定结果**）；引用只进 ``coverage_refs``。

        与 :meth:`_capture_screenshot`（确认后补证）刻意分开：这里的图证明
        「这条端点被真的测过」，**不是**「漏洞成立」。故：

        - 不进 ``evidence_kinds``、不进 ``verification.evidence_refs``；
        - 失败/超限只记审计，绝不影响验证流程（fail-open）；
        - 每类型 / 每 phase 都有上限（资源调度，不是判定）。
        """
        if not self.screenshots:
            return
        plan = coverage_plan_for(finding.vuln_type)
        if plan is None:
            return
        if self._coverage_by_type.get(finding.vuln_type, 0) >= COVERAGE_CAP_PER_TYPE:
            self.audit.record(
                "coverage_shot_capped",
                finding_id=finding.id,
                vuln_type=finding.vuln_type,
                reason=f"每类型上限 {COVERAGE_CAP_PER_TYPE} 条候选",
            )
            return
        if self._coverage_total >= COVERAGE_CAP_TOTAL:
            self.audit.record(
                "coverage_shot_capped",
                finding_id=finding.id,
                vuln_type=finding.vuln_type,
                reason=f"本 phase 上限 {COVERAGE_CAP_TOTAL} 张",
            )
            return
        try:
            capturer = self._get_screenshotter()
        except Exception as exc:
            self.audit.record(
                "coverage_shot_skipped",
                finding_id=finding.id,
                vuln_type=finding.vuln_type,
                reason=f"截图器不可用: {exc}",
            )
            return

        session = self._session()
        secrets = session.secret_values() if session is not None else []
        records: list[dict] = []
        refs: list[str] = []
        for shot in plan:
            if self._coverage_total >= COVERAGE_CAP_TOTAL:
                self.audit.record(
                    "coverage_shot_capped",
                    finding_id=finding.id,
                    vuln_type=finding.vuln_type,
                    reason=f"本 phase 上限 {COVERAGE_CAP_TOTAL} 张",
                )
                break
            try:
                url = coverage_build_url(finding.asset, finding.param, shot)
            except ValueError as exc:
                self.audit.record(
                    "coverage_shot_skipped",
                    finding_id=finding.id,
                    vuln_type=finding.vuln_type,
                    label=shot.label,
                    reason=str(exc),
                )
                continue
            selected, skip_reason = coverage_select_session(session, shot.session)
            if skip_reason is not None:
                self.audit.record(
                    "coverage_shot_skipped",
                    finding_id=finding.id,
                    vuln_type=finding.vuln_type,
                    label=shot.label,
                    reason=skip_reason,
                )
                continue
            result = capturer.capture(
                url, name=f"cover_{finding.id}_{shot.label}", session=selected
            )
            self._coverage_total += 1
            if result.error is not None or result.path is None:
                self.audit.record(
                    "coverage_shot_skipped",
                    finding_id=finding.id,
                    vuln_type=finding.vuln_type,
                    label=shot.label,
                    url=url,
                    reason=result.error or "未产出文件",
                )
                continue
            refs.append(str(result.path))
            records.append(
                {
                    "label": shot.label,
                    "session": shot.session,
                    "url": url,
                    "file": result.path.name,
                    "sha256": result.sha256,
                    "bytes": result.bytes,
                    "width": result.width,
                    "height": result.height,
                    "status": result.status,
                }
            )
            self.audit.record(
                "coverage_shot_captured",
                finding_id=finding.id,
                vuln_type=finding.vuln_type,
                label=shot.label,
                session=shot.session,
                url=url,
                file=result.path.name,
                bytes=result.bytes,
                sha256=result.sha256,
                width=result.width,
                height=result.height,
                status=result.status,
                blocked_requests=result.blocked_requests,
            )
        if not refs:
            return
        self._coverage_by_type[finding.vuln_type] = (
            self._coverage_by_type.get(finding.vuln_type, 0) + 1
        )
        finding.coverage_refs.extend(r for r in refs if r not in finding.coverage_refs)
        sidecar = self.evidence_dir / f"coverage_{finding.id}.json"
        sidecar.write_bytes(
            redact_bytes(
                (
                    json.dumps(
                        {
                            "finding_id": finding.id,
                            "vuln_type": finding.vuln_type,
                            "asset": finding.asset,
                            "param": finding.param,
                            "shots": records,
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8"),
                secrets,
            )
        )
        store.append(finding)  # coverage_refs 落进 append-only 快照

    def _run_baseline(
        self, finding: Finding, session: SessionConfig
    ) -> tuple[str, int] | None:
        """带会话 baseline：httpx 探目标 URL（不跟随跳转），返回
        ``(evidence_ref, status_code)``；失败记审计并返回 None。"""
        try:
            argv = build_command(
                "httpx",
                {
                    "target": finding.asset,
                    "with_session": True,
                    "follow_redirects": False,
                    "tech_detect": False,
                },
                egress_proxy_url=getattr(self.runner, "egress_proxy_url", None),
                session=session,
            )
        except ValueError as exc:
            self.audit.record(
                "verify_blocked", finding_id=finding.id, reason=f"命令构造失败: {exc}"
            )
            return None
        result = self.runner.run(argv[0], argv[1:])
        if result.rejected:
            self.audit.record(
                "verify_scope_rejected",
                finding_id=finding.id,
                violations=result.violations,
            )
            return None
        if result.exit_code != 0:
            self.audit.record(
                "verify_baseline_failed",
                finding_id=finding.id,
                reason=f"httpx exit={result.exit_code}",
                stderr_path=str(result.stderr_path),
            )
            return None
        parser = self.parsers.get("httpx")
        text = result.stdout_path.read_text(encoding="utf-8", errors="replace")
        signals, _ = parser(text, evidence_path=str(result.stdout_path), skill="verify")
        for signal in signals:
            if signal.status_code is not None and 200 <= signal.status_code < 300:
                return signal.evidence_ref, signal.status_code
        statuses = [s.status_code for s in signals]
        self.audit.record(
            "verify_baseline_failed",
            finding_id=finding.id,
            reason=f"带会话请求未获 2xx（疑似会话失效或登录跳转）: {statuses}",
        )
        return None

    def _session(self) -> SessionConfig | None:
        """当前 engagement 的预置会话（来自 scope 配置；无则 None）。"""
        scope = getattr(self.runner, "scope", None)
        return getattr(scope, "session", None) if scope is not None else None

    # ---- 子任务主循环 ----

    def _run_subtask(self, node: TaskNode, skill) -> None:
        node.transition(TaskStatus.RUNNING, reason="子任务启动")
        while True:
            state = {
                "target": node.meta["target"],
                "attempts": node.attempts,
                "failure_counts": dict(node.failure_counts),
                "signals": node.meta.get("signals", []),
            }
            try:
                plan = self.planner.plan(state, skill)
            except BudgetExceededError as exc:
                # token 预算硬闸：停止规划循环、节点 blocked（与 scope 同级不可绕过）
                self.audit.record(
                    "llm_budget_exceeded",
                    node_id=node.id,
                    name=node.name,
                    tier=exc.tier,
                    used=exc.used,
                    limit=exc.limit,
                    scope=exc.scope,
                )
                node.transition(TaskStatus.BLOCKED, reason=f"LLM 预算硬闸: {exc}")
                return
            except ContextOverflowError as exc:
                # 上下文超硬上限（压缩后仍超）：failed，禁止静默截断
                self.audit.record(
                    "context_overflow",
                    node_id=node.id,
                    name=node.name,
                    chars=exc.chars,
                    limit=exc.limit,
                )
                node.transition(TaskStatus.FAILED, reason=f"上下文超限: {exc}")
                return
            except (PlanValidationError, LLMError) as exc:
                node.transition(TaskStatus.FAILED, reason=f"规划失败: {exc}")
                return
            outcome = "ok"
            for action in plan.actions:
                if action.action == "finish":
                    node.transition(
                        TaskStatus.DONE, reason=action.rationale or "规划器判定完成"
                    )
                    return
                if action.action == "escalate":
                    reason = action.rationale or "规划器升级人工"
                    self.audit.record(
                        "task_blocked", node_id=node.id, name=node.name, reason=reason
                    )
                    node.transition(TaskStatus.BLOCKED, reason=reason)
                    return
                outcome = self._exec_run_tool(node, action, skill)
                if outcome != "ok":
                    break
            if outcome == "ok":
                node.transition(TaskStatus.DONE, reason="计划动作全部完成")
                return
            if outcome == "retry":
                continue  # 带着失败计数重新规划
            return  # failed / blocked 已在 _exec_run_tool 完成迁移

    # ---- 单动作执行 ----

    def _resolve_request_budget(self, node: TaskNode, tool: str):
        """消费 ``request_budget`` 的工具：取授权预算并**留痕来源**（M19-c）。

        限制 54 的核心论证是"缺省放行**不等于**无痕放行，因为审计里能分辨
        ``source=default/explicit``"——但 ``Scope.request_budget_source()`` 此前
        只有测试和 demo 在调，生产链路一次也没记过。本方法把「用了哪个来源、
        多少速率/并发/总量/时间窗」写进 ``request_budget_resolved`` 审计。

        `runner` 未挂 scope 时 fail-closed（没有授权来源就没有预算）。
        """
        if tool not in REQUEST_BUDGET_TOOLS:
            return None
        scope = getattr(self.runner, "scope", None)
        if scope is None:
            node.transition(
                TaskStatus.FAILED,
                reason=(
                    f"工具 {tool} 需要 scope 提供请求量授权，"
                    "但 runner 未挂 scope（fail-closed）"
                ),
            )
            self.audit.record(
                "request_budget_unavailable",
                node_id=node.id,
                tool=tool,
                reason="runner 未挂 scope，无授权来源",
            )
            return None
        budget = scope.resolved_request_budget()
        self.audit.record(
            "request_budget_resolved",
            node_id=node.id,
            tool=tool,
            source=scope.request_budget_source(),
            rate_rps=budget.rate_rps,
            concurrency=budget.concurrency,
            max_requests=budget.max_requests,
            window_minutes=budget.window_minutes,
        )
        return budget

    def _exec_run_tool(self, node: TaskNode, action: PlanAction, skill) -> str:
        """执行 run_tool 动作，返回 ok/retry/failed/blocked。"""
        request_budget = self._resolve_request_budget(node, action.tool)
        if action.tool in REQUEST_BUDGET_TOOLS and request_budget is None:
            return "failed"  # 迁移与审计已在 _resolve_request_budget 内完成
        try:
            argv = build_command(
                action.tool,
                action.params,
                egress_proxy_url=self.runner.egress_proxy_url,
                session=self._session(),
                request_budget=request_budget,
            )
        except (UnknownToolError, ValueError) as exc:
            node.transition(TaskStatus.FAILED, reason=f"命令构造失败（规划缺陷）: {exc}")
            return "failed"

        node.attempts += 1
        result = self.runner.run(argv[0], argv[1:])

        if result.rejected:
            node.transition(
                TaskStatus.FAILED,
                reason=f"scope 拒绝（规划缺陷）: {'; '.join(result.violations)}",
            )
            return "failed"
        if result.exit_code == 0:
            self._record_signals(node, action, skill, result)
            return "ok"

        category = classify(self._sample_output(result))
        exhausted = self.budget.record(node, category)
        self.audit.record(
            "attempt_failed",
            node_id=node.id,
            tool=action.tool,
            exit_code=result.exit_code,
            category=category.value,
            count=node.failure_counts[category.value],
            budget_limit=self.budget.limit_per_category,
        )
        if exhausted:
            reason = f"失败预算耗尽（{category.value} × {node.failure_counts[category.value]}），升级人工"
            self.audit.record(
                "task_blocked",
                node_id=node.id,
                name=node.name,
                category=category.value,
                count=node.failure_counts[category.value],
                reason=reason,
            )
            node.transition(TaskStatus.BLOCKED, reason=reason)
            return "blocked"
        return "retry"

    # ---- Signal 落盘 ----

    def _record_signals(
        self, node: TaskNode, action: PlanAction, skill, result: RunResult
    ) -> None:
        parser = self.parsers.get(action.tool)
        if parser is None:
            self.audit.record(
                "signals_recorded",
                node_id=node.id,
                tool=action.tool,
                count=0,
                note=f"工具 {action.tool} 无解析器",
            )
            return
        text = result.stdout_path.read_text(encoding="utf-8", errors="replace")
        signals, skipped = parser(
            text, evidence_path=str(result.stdout_path), skill=skill.name
        )
        signals_path = self.evidence_dir / f"{result.stdout_path.stem}.signals.jsonl"
        with signals_path.open("w", encoding="utf-8") as fh:
            for signal in signals:
                fh.write(signal.model_dump_json() + "\n")
        node.meta.setdefault("signals", []).extend(
            {
                "asset": s.asset,
                "status_code": s.status_code,
                "kind": s.kind,
                "evidence_ref": s.evidence_ref,
            }
            for s in signals
        )
        self.audit.record(
            "signals_recorded",
            node_id=node.id,
            tool=action.tool,
            count=len(signals),
            skipped_lines=skipped,
            signals_path=str(signals_path),
        )

    @staticmethod
    def _sample_output(result: RunResult) -> str:
        """取 stdout/stderr 尾部采样用于失败分类（有界，不进 LLM 上下文）。"""
        chunks = []
        for path in (result.stderr_path, result.stdout_path):
            if path and Path(path).is_file():
                chunks.append(
                    Path(path)
                    .read_bytes()[-_OUTPUT_SAMPLE_LIMIT:]
                    .decode("utf-8", errors="replace")
                )
        return "\n".join(chunks)
