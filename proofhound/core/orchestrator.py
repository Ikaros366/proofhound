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
from proofhound.tools.build import UnknownToolError, build_command, known_tools
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
from proofhound.verify.cvss import base_score as cvss_base_score
from proofhound.verify.cvss import severity_for_score
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

# M17-b：每 engagement 新建 unauth-exposure Hypothesis 上限（独立计数、独立
# triage_capped 事件）。**必须**有独立上限：`web-exposure` 是全池唯一**没有**
# 上限的类型（sqli/xss/idor 各有），而新生产者的候选量与 web-probe 信号数同阶，
# 每条又要花「2 次 HTTP + 1 次 T1 调用」——不设限会给贵验证档灌水。
_TRIAGE_UNAUTH_CAP = 10

#: 需要「scope 配了可用预置会话」才能验证的 vuln_type（M17-b）。
#: 两类都是**等价性/基线比对**型判定，没有已认证视图就没有可比对象：
#: - ``unauth-exposure``：匿名视图 vs 已认证视图（缺后者 ⇒ 无从比）；
#: - ``ssrf``：带会话 baseline（缺会话 ⇒ `_verify_ssrf` 直接 blocked）。
#: 登记在此 ⇒ 该类型的候选在缺会话时**一次也不进贵验证档**（配额仍留给真验证）。
_VERIFY_PRECONDITIONS: frozenset[str] = frozenset({"unauth-exposure", "ssrf"})

#: vuln_type → 每 engagement 新建 Hypothesis 上限（未登记的类型不限）。
#: M17-b：由 `_ingest_candidates` 里的三个并列 if 收成一张查表——加类型时
#: 只需在此登记，不必再改判定逻辑（漏登记表现为「该类型无上限」，显式可查）。
_TRIAGE_CAPS: dict[str, int] = {
    "sqli": _TRIAGE_SQLI_CAP,
    "xss": _TRIAGE_XSS_CAP,
    "idor": _TRIAGE_IDOR_CAP,
    "unauth-exposure": _TRIAGE_UNAUTH_CAP,
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


class _TriageCandidate(NamedTuple):
    """一条 triage 候选；一个 Signal 可展开多条（按参数键/表单字段名）。"""

    vuln_type: str
    param: str | None
    severity: str
    evidence_kind: str
    source: str  # M8a：web_probe / get_param / form_page（triage_completed 摘要分量）


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
        return candidates
    if signal.kind == "param-endpoint":
        keys = _query_param_keys(signal.asset)
        candidates = [
            _TriageCandidate(
                vuln_type="sqli",
                param=key,
                severity="medium",
                evidence_kind=CRAWL_ENDPOINT_EVIDENCE_KIND,
                source="get_param",
            )
            for key in keys
            if key in _SQLI_PARAM_HINTS
        ]
        # M8b：同一份 query 键再按 XSS 提示表展开 xss 候选（两表交集参数
        # 会同产 sqli+xss 两条候选，dedup 按 vuln_type 分量区分）
        candidates.extend(
            _TriageCandidate(
                vuln_type="xss",
                param=key,
                severity="medium",
                evidence_kind=CRAWL_ENDPOINT_EVIDENCE_KIND,
                source="get_param",
            )
            for key in keys
            if key in _XSS_PARAM_HINTS
        )
        # M8c：同一份 query 键再按 IDOR 提示表展开 idor 候选（与 sqli 表
        # 交集参数同产是设计行为——id 类键既可能注入也可能越权，各自经
        # 独立 verify skill 行为验证）
        candidates.extend(
            _TriageCandidate(
                vuln_type="idor",
                param=key,
                severity="medium",
                evidence_kind=CRAWL_ENDPOINT_EVIDENCE_KIND,
                source="get_param",
            )
            for key in keys
            if key in _IDOR_PARAM_HINTS
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
        idor_fetch=None,
        ssrf_listener_factory=None,
        ssrf_fetch=None,
        unauth_judge_factory=None,
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
        # M8b/M8c：triage_capped 按 vuln_type 分立事件（各自上限各自记）
        for vuln_type, limit in (
            ("sqli", _TRIAGE_SQLI_CAP),
            ("xss", _TRIAGE_XSS_CAP),
            ("idor", _TRIAGE_IDOR_CAP),
            ("unauth-exposure", _TRIAGE_UNAUTH_CAP),  # M17-b
        ):
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
            dedup_key = compute_dedup_key(
                signal.asset, candidate.vuln_type, candidate.param
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
                asset=signal.asset,
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
                outcome = handler(finding, skill, store)
                counts[outcome] += 1
                processed.append(finding)
        finally:
            self._close_browser()  # M8b：phase 收尾释放浏览器（若本 phase 建过）
            self._close_ssrf_listeners()  # M16：回调 listener 同样不常驻
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
        return self._gate_and_review(finding, skill, store)

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

    def _exec_run_tool(self, node: TaskNode, action: PlanAction, skill) -> str:
        """执行 run_tool 动作，返回 ok/retry/failed/blocked。"""
        try:
            argv = build_command(
                action.tool,
                action.params,
                egress_proxy_url=self.runner.egress_proxy_url,
                session=self._session(),
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
