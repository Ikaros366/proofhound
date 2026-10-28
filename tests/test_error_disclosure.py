"""M23：verify-error-disclosure —— 标记判定（纯函数）+ 编排层五态 + 生产者。

## 这份文件钉住什么

1. **纯函数层**（``proofhound/verify/error_disclosure.py``）：七类标记各自可命中、
   「≥2 类才够」的**否定方向**（只中 1 类 → blocked）、基线污染、版本头**不**
   构成证据，以及五条探针的字节形态（``…`` = E2 80 A6、``%zz``、``HTTP/9.9``、
   ``G\\x01ET``、>8KB URI）。
2. **编排层**（``Orchestrator._verify_error_disclosure``）：confirmed 走证据门 +
   Verifier + 四段式；rejected 是**真阴性**（通用 400 / WAF 页必须被驳回）；
   blocked 是**覆盖不全**（只中 1 类、基线被污染、连接重置、畸形请求未被拒绝）。
3. **生产者**：``web-probe`` 信号按 **origin（host 级）** 派生候选，两条同 host
   信号只建一条 Finding——中间件错误页是 host 级现象，按 URL 去重会重复测同一层。

## 为什么 PHP 靶是 confirmed（M23 裁定）

``Fatal error:`` 与 ``#0 /...`` 同属 PHP 一类；若只有六类，``php-like`` 靶
（500 + Fatal error + 路径 + #0）只会命中 1 类而被判 blocked。维护者裁定新增
第 7 类 ``path_disclosure``（绝对源码路径 + 行号），故 PHP 靶命中
``php_error`` + ``path_disclosure`` = 2 类。
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core.orchestrator import Orchestrator, _origin_url, _triage_candidates
from proofhound.findings.dedup import compute_dedup_key
from proofhound.findings.finding import Finding, FindingState, FindingStore, Verification
from proofhound.findings.signal import Signal
from proofhound.llm.router import ModelRouter, Tier
from proofhound.skills.registry import SkillRegistry
from proofhound.verify import error_disclosure as ed
from proofhound.verify.gate import GATE_MATRIX
from proofhound.verify.gate import check as gate_check
from proofhound.verify.raw_http import RawResponse

REPO = Path(__file__).resolve().parent.parent
ASSET = "http://127.0.0.1:8080"
CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

CONFIRM_REPLY = json.dumps(
    {
        "verdict": "confirm",
        "reason": "基线干净、畸形请求的错误页命中 Java 堆栈与 Tomcat 版本两类标记",
        "cvss_vector": CVSS,
        "cvss_rationale": "错误页回显内部堆栈，机密性受影响但无完整性/可用性影响",
    },
    ensure_ascii=False,
)

JAVA_BODY = (
    "<html><head><title>Apache Tomcat/9.0.65 - Error report</title></head><body>"
    "<h1>HTTP Status 400 – Bad Request</h1>"
    "<pre>java.lang.IllegalArgumentException: Invalid character found in the request "
    "target. [0xe2 0x80 0xa6]\n"
    "\tat org.apache.coyote.http11.Http11InputBuffer.parseRequestLine"
    "(Http11InputBuffer.java:505)\n"
    "\tat org.apache.coyote.http11.Http11Protocol$Http11ConnectionHandler.process"
    "(Http11Protocol.java:670)\n</pre>"
    "<hr><h3>Apache Tomcat/9.0.65</h3></body></html>"
)

PHP_BODY = (
    "<html><body><br />\n<b>Fatal error</b>: Uncaught RuntimeException: boom in "
    "/var/www/html/app/index.php:12\nStack trace:\n"
    "#0 /var/www/html/app/index.php(5): handler()\n#1 {main}\n</body></html>"
)

GENERIC_BODY = "<html><body><h1>400 Bad Request</h1></body></html>"
WAF_BODY = "<html><body><h1>Request blocked</h1><p>Request ID 8f2a</p></body></html>"


class MockRouter(ModelRouter):
    """罐头 T2 路由（继承 ModelRouter 过 ``ensure_router`` 的 isinstance 闸）。"""

    def __init__(self, reply: str = CONFIRM_REPLY) -> None:
        self.reply = reply
        self.calls = 0
        self.configs = {Tier.T2: SimpleNamespace(model="canned-verifier")}

    def complete(self, tier, messages):
        self.calls += 1
        return self.reply


class FakeSender:
    """按**请求字节**分派罐头响应（模拟中间件/网关的不同错误页形态）。"""

    def __init__(
        self,
        responses: dict[str, RawResponse] | None = None,
        *,
        baseline: RawResponse | None = None,
        default: RawResponse | None = None,
    ) -> None:
        self.responses = responses or {}
        self.baseline = baseline or RawResponse(
            status=200, body=b"<html><body><h1>home</h1></body></html>"
        )
        self.default = default or RawResponse(
            status=400, body=GENERIC_BODY.encode(), headers={"server": "nginx/1.25.3"}
        )
        self.calls: list[str] = []
        self.sent: list[bytes] = []

    @staticmethod
    def label_for(payload: bytes) -> str:
        if b"HTTP/9.9" in payload:
            return "bad-version"
        if b"%zz" in payload:
            return "bad-percent"
        if b"G\x01ET" in payload:
            return "ctl-method"
        if b"\xe2\x80\xa6" in payload:
            return "unicode-path"
        if len(payload) > 8000:
            return "long-uri"
        return "baseline"

    def __call__(self, host, port, payload, *, tls, timeout):
        label = self.label_for(payload)
        self.calls.append(label)
        self.sent.append(payload)
        if label == "baseline":
            return self.baseline
        return self.responses.get(label, self.default)


class _Runner:
    def __init__(self, scope: Scope) -> None:
        self.scope = scope


@pytest.fixture
def env(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    audit = AuditLog(evidence_dir / "audit.jsonl")
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080])
    return SimpleNamespace(
        evidence_dir=evidence_dir,
        audit=audit,
        registry=SkillRegistry(REPO / "skills").discover(),
        store=FindingStore(evidence_dir / "findings.jsonl"),
        scope=scope,
        router=MockRouter(),
    )


def _finding(env, *, asset: str = ASSET):
    finding = Finding(
        id=env.store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type="error-disclosure",
        severity="low",
        asset=asset,
        param=None,
        confidence="low",
        evidence_kinds=["status-code"],
        dedup_key=compute_dedup_key(asset, "error-disclosure", None),
        source_signal_refs=[],
        created_at="2026-10-28T00:00:00.000+00:00",
        updated_at="2026-10-28T00:00:00.000+00:00",
        audit=env.audit,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="测试种子")
    env.store.append(finding)
    return finding


def _orch(env, sender: FakeSender | None = None, *, scope: Scope | None = None):
    return Orchestrator(
        env.registry,
        _Runner(scope or env.scope),
        env.router,
        env.audit,
        evidence_dir=env.evidence_dir,
        raw_http_send=sender or FakeSender(),
    )


def _events(env, name: str) -> list[dict]:
    return [e for e in env.audit.read_all() if e.get("event") == name]


# =====================================================================
# 一、纯函数：标记分类
# =====================================================================


@pytest.mark.parametrize(
    "body,expected",
    [
        (JAVA_BODY, {"java_stack", "middleware_version"}),
        (PHP_BODY, {"php_error", "path_disclosure"}),
        (
            'Traceback (most recent call last):\n  File "/app/x.py", line 3',
            {"python_traceback"},
        ),
        (
            "System.NullReferenceException: Object reference\r\n"
            "   at Microsoft.AspNetCore.Mvc.Internal.ActionMethodExecutor",
            {"dotnet_exception"},
        ),
        (
            "TypeError: x is undefined\n    at Object.<anonymous> "
            "(/app/node_modules/express/lib/router.js:1:1)",
            # 真 Node 错误页通常同时回显源码路径 ⇒ 两类（这正是本类型的判据）
            {"node_stack", "path_disclosure"},
        ),
        ("Jetty(9.4.43.v20210629)", {"middleware_version"}),
        (GENERIC_BODY, set()),
        (WAF_BODY, set()),
    ],
)
def test_marker_classes_are_deterministic(body, expected):
    assert ed.matched_class_names(body) == frozenset(expected)


def test_php_error_with_html_bold_tag_is_still_php_class():
    """``display_errors=html`` 会输出 ``<b>Fatal error</b>:``——标记必须兼容。"""
    assert "php_error" in ed.matched_class_names(
        "<b>Fatal error</b>: Uncaught Exception in /srv/app.php:7"
    )


def test_generic_exception_word_alone_is_not_evidence():
    """只有 ``Exception`` 一个单词（无堆栈/路径）不算任何类——这是 ≥2 类规则的根基。"""
    assert ed.matched_class_names("<p>An Exception occurred</p>") == frozenset()


def test_plain_slash_segment_is_not_path_disclosure():
    """``/admin/users`` 这种普通 URL 路径不算源码路径：必须多级目录 + 源码扩展名 + 行号。"""
    assert ed.matched_class_names("<a href='/admin/users'>x</a>") == frozenset()


# =====================================================================
# 二、纯函数：版本头只记审计、探针形态
# =====================================================================


@pytest.mark.parametrize(
    "headers,value",
    [
        ({"server": "nginx/1.25.3"}, "nginx/1.25.3"),
        ({"server": "Apache-Coyote/1.1"}, "Apache-Coyote/1.1"),
        ({"x-powered-by": "PHP/8.2.0"}, "PHP/8.2.0"),
        ({"server": "cloudflare"}, None),
        ({}, None),
    ],
)
def test_server_header_disclosed(headers, value):
    assert ed.server_header_disclosed(headers) == value


def test_version_header_never_becomes_evidence():
    """版本头只返回字符串（审计），判定器**不读**它——confirmed 只看正文两类标记。"""
    baseline = ed.ProbeOutcome("baseline", "n", "sha", "repr", status=200)
    probe = ed.ProbeOutcome(
        "p", "d", "sha", "repr", status=400, classes=frozenset({"middleware_version"})
    )
    judgment = ed.judge(baseline, [probe])
    assert judgment.verdict == ed.VERDICT_BLOCKED
    assert "只命中 1 类" in judgment.reasons[0]


def test_probes_are_five_and_bytes_are_malformed():
    specs = ed.build_probes("h:8080")
    assert [spec.label for spec in specs] == [
        "unicode-path",
        "bad-percent",
        "bad-version",
        "ctl-method",
        "long-uri",
    ]
    assert len(specs) == ed.PROBE_BUDGET == 5
    assert specs[0].request.startswith(b"GET /\xe2\x80\xa6proof HTTP/1.1\r\n")
    assert b"/%zz " in specs[1].request
    assert b"HTTP/9.9" in specs[2].request
    assert specs[3].request.startswith(b"G\x01ET ")
    assert len(specs[4].request) > 8192
    # 证据只记 repr/sha256（不落原始控制字符）
    assert "\\x01" in specs[3].request_repr
    assert "\x01" not in specs[3].request_repr


def test_baseline_is_a_plain_get():
    request = ed.build_baseline("h:8080")
    assert request.startswith(b"GET / HTTP/1.1\r\n")
    assert request.endswith(b"\r\n\r\n")
    assert b"Cookie" not in request


# =====================================================================
# 三、纯函数：judge 三态与优先级
# =====================================================================


def _outcome(label, *, status=400, body="", error=None, kind=None):
    classes = ed.matched_class_names(body) if body else frozenset()
    return ed.ProbeOutcome(
        label=label,
        description=label,
        request_sha256="0" * 64,
        request_repr="repr",
        status=status,
        error=error,
        error_kind=kind,
        classes=classes,
        body_bytes=len(body),
    )


def _clean_baseline(status=200):
    return _outcome("baseline", status=status, body="<h1>home</h1>")


def test_judge_confirmed_on_two_classes():
    judgment = ed.judge(_clean_baseline(), [_outcome("p", body=JAVA_BODY)])
    assert judgment.verdict == ed.VERDICT_CONFIRMED
    assert judgment.matched == ("java_stack", "middleware_version")
    assert judgment.probe == "p"


def test_judge_confirmed_beats_single_class_probe():
    """先有单类探针、后有双类探针：必须判 confirmed（顺序不能反）。"""
    probes = [
        _outcome("one", body="Fatal error: boom"),
        _outcome("two", body=JAVA_BODY),
    ]
    assert ed.judge(_clean_baseline(), probes).verdict == ed.VERDICT_CONFIRMED


def test_judge_single_class_is_blocked():
    judgment = ed.judge(_clean_baseline(), [_outcome("p", body="Fatal error: boom")])
    assert judgment.verdict == ed.VERDICT_BLOCKED
    assert "只命中 1 类" in judgment.reasons[0]


def test_judge_rejected_on_generic_400():
    judgment = ed.judge(_clean_baseline(), [_outcome("p", body=GENERIC_BODY)])
    assert judgment.verdict == ed.VERDICT_REJECTED


def test_judge_rejected_on_waf_403():
    judgment = ed.judge(_clean_baseline(), [_outcome("p", status=403, body=WAF_BODY)])
    assert judgment.verdict == ed.VERDICT_REJECTED


def test_judge_blocked_when_baseline_is_polluted():
    polluted = _outcome("baseline", status=200, body=JAVA_BODY)
    judgment = ed.judge(polluted, [_outcome("p", body=JAVA_BODY)])
    assert judgment.verdict == ed.VERDICT_BLOCKED
    assert "基线响应本身命中" in judgment.reasons[0]


def test_judge_blocked_when_probe_errors():
    judgment = ed.judge(
        _clean_baseline(),
        [_outcome("p", status=None, error="reset", kind="reset")],
    )
    assert judgment.verdict == ed.VERDICT_BLOCKED
    assert "未能完成" in judgment.reasons[0]


def test_judge_blocked_when_malformed_request_is_not_rejected():
    judgment = ed.judge(_clean_baseline(), [_outcome("p", status=200, body="ok")])
    assert judgment.verdict == ed.VERDICT_BLOCKED
    assert "未被拒绝" in judgment.reasons[0]


def test_judge_blocked_when_markers_on_non_error_response():
    judgment = ed.judge(_clean_baseline(), [_outcome("p", status=200, body=JAVA_BODY)])
    assert judgment.verdict == ed.VERDICT_BLOCKED
    assert "非错误响应" in judgment.reasons[0]


def test_judge_without_probes_is_blocked():
    assert ed.judge(_clean_baseline(), []).verdict == ed.VERDICT_BLOCKED
    assert ed.judge(None, []).verdict == ed.VERDICT_BLOCKED


# =====================================================================
# 四、编排层：五态
# =====================================================================


def test_handler_registered_and_gate_requires_named_kind(env):
    handlers = Orchestrator._verify_handlers(Orchestrator.__new__(Orchestrator))
    covered, fn = handlers["verify-error-disclosure"]
    assert covered == frozenset({"error-disclosure"})
    assert callable(fn)

    requirement = GATE_MATRIX["error-disclosure"]
    assert requirement.methods == frozenset({ed.ERROR_DISCLOSURE_CONFIRMED_METHOD})
    assert requirement.behavioral_kinds == frozenset({ed.ERROR_TRACE_EVIDENCE_KIND})

    finding = _finding(env)
    assert not gate_check(finding).passed
    finding.verification = Verification(
        method=ed.ERROR_DISCLOSURE_CONFIRMED_METHOD, evidence_refs=["x.txt"]
    )
    finding.evidence_kinds.append("behavioral")
    assert not gate_check(finding).passed, "笼统 behavioral 不是本类型的证据"
    finding.evidence_kinds.append(ed.ERROR_TRACE_EVIDENCE_KIND)
    assert gate_check(finding).passed


def test_confirmed_tomcat_like(env):
    sender = FakeSender(
        {
            "unicode-path": RawResponse(
                status=400,
                body=JAVA_BODY.encode(),
                headers={"server": "Apache-Coyote/1.1"},
            )
        }
    )
    orch = _orch(env, sender)
    finding = _finding(env)

    outcome = orch._verify_error_disclosure(
        finding, env.registry.get("verify-error-disclosure"), env.store
    )

    assert outcome == "confirmed"
    assert sender.calls == ["baseline", "unicode-path"], "命中即停：不该发剩余探针"

    stored = env.store.load_all()[0]
    assert stored.state is FindingState.CONFIRMED
    assert stored.verification is not None
    assert stored.verification.method == ed.ERROR_DISCLOSURE_CONFIRMED_METHOD
    assert stored.verification.claim and stored.verification.expected
    assert stored.verification.actual
    assert len(stored.verification.reproduction_steps) == 3
    assert ed.ERROR_TRACE_EVIDENCE_KIND in stored.evidence_kinds
    assert stored.cvss_score is not None and stored.cvss_score > 0

    # 证据：基线 + 命中探针 + 判定 JSON，全部可离线调出
    assert len(stored.verification.evidence_refs) == 3
    for ref in stored.verification.evidence_refs:
        assert Path(ref).is_file(), ref
    judgment = json.loads(
        (env.evidence_dir / f"error_disclosure_{stored.id}_judgment.json").read_text(
            encoding="utf-8"
        )
    )
    assert judgment["verdict"] == "confirmed"
    assert judgment["matched_classes"] == ["java_stack", "middleware_version"]
    assert judgment["server_header_disclosed"] == "Apache-Coyote/1.1"
    assert judgment["probe"] == "unicode-path"

    # 审计：按次、判定、版本头三件
    assert len(_events(env, "error_disclosure_probe_attempt")) == 2
    judged = _events(env, "error_disclosure_judged")
    assert judged and judged[0]["verdict"] == "confirmed"
    headers = _events(env, "server_header_disclosed")
    assert headers and headers[0]["header"] == "Apache-Coyote/1.1"


def test_php_like_confirmed_by_php_plus_path(env):
    """M23 裁定：PHP 靶靠 php_error + path_disclosure 两类成立（不是放宽阈值）。"""
    sender = FakeSender(
        {"unicode-path": RawResponse(status=500, body=PHP_BODY.encode())}
    )
    orch = _orch(env, sender)
    finding = _finding(env)

    assert (
        orch._verify_error_disclosure(
            finding, env.registry.get("verify-error-disclosure"), env.store
        )
        == "confirmed"
    )
    judgment = json.loads(
        (env.evidence_dir / f"error_disclosure_{finding.id}_judgment.json").read_text(
            encoding="utf-8"
        )
    )
    assert judgment["matched_classes"] == ["path_disclosure", "php_error"]


def test_generic_400_is_rejected(env):
    sender = FakeSender()  # 默认：所有探针 400 通用错误页
    orch = _orch(env, sender)
    finding = _finding(env)

    outcome = orch._verify_error_disclosure(
        finding, env.registry.get("verify-error-disclosure"), env.store
    )

    assert outcome == "rejected"
    assert sender.calls == [
        "baseline",
        "unicode-path",
        "bad-percent",
        "bad-version",
        "ctl-method",
        "long-uri",
    ], "零标记时必须跑完 5 条探针才敢驳回"
    stored = env.store.load_all()[0]
    assert stored.state is FindingState.REJECTED
    assert "报错信息泄露不成立" in (stored.rejection_reason or "")


def test_waf_403_is_rejected(env):
    sender = FakeSender(default=RawResponse(status=403, body=WAF_BODY.encode()))
    orch = _orch(env, sender)
    finding = _finding(env)
    assert (
        orch._verify_error_disclosure(
            finding, env.registry.get("verify-error-disclosure"), env.store
        )
        == "rejected"
    )


def test_single_class_is_blocked_not_rejected(env):
    sender = FakeSender(default=RawResponse(status=400, body=b"Fatal error: boom"))
    orch = _orch(env, sender)
    finding = _finding(env)

    outcome = orch._verify_error_disclosure(
        finding, env.registry.get("verify-error-disclosure"), env.store
    )

    assert outcome == "blocked"
    stored = env.store.load_all()[0]
    assert stored.state is FindingState.HYPOTHESIS, "覆盖不全不得驳回（宁漏勿滥）"
    blocked = _events(env, "verify_blocked")
    assert blocked and "只命中 1 类" in blocked[0]["reason"]


def test_polluted_baseline_is_blocked_without_probes(env):
    sender = FakeSender(
        baseline=RawResponse(status=200, body=JAVA_BODY.encode())
    )
    orch = _orch(env, sender)
    finding = _finding(env)

    assert (
        orch._verify_error_disclosure(
            finding, env.registry.get("verify-error-disclosure"), env.store
        )
        == "blocked"
    )
    assert sender.calls == ["baseline"], "基线已污染时不该再发探针（反事实不成立）"
    blocked = _events(env, "verify_blocked")
    assert blocked and "基线响应本身命中" in blocked[0]["reason"]


def test_connection_reset_is_blocked(env):
    sender = FakeSender(
        default=RawResponse(error="连接被重置", error_kind="reset")
    )
    orch = _orch(env, sender)
    finding = _finding(env)
    assert (
        orch._verify_error_disclosure(
            finding, env.registry.get("verify-error-disclosure"), env.store
        )
        == "blocked"
    )
    blocked = _events(env, "verify_blocked")
    assert blocked and "未能完成" in blocked[0]["reason"]


def test_scope_violation_blocks_before_any_request(env):
    sender = FakeSender()
    orch = _orch(env, sender, scope=Scope(domains=["example.com"]))
    finding = _finding(env)

    assert (
        orch._verify_error_disclosure(
            finding, env.registry.get("verify-error-disclosure"), env.store
        )
        == "blocked"
    )
    assert sender.calls == [], "越界资产不得发出任何请求（红线 5）"
    assert _events(env, "verify_scope_rejected")


def test_no_credentials_are_sent(env):
    env.scope.session = SessionConfig(cookies={"PHPSESSID": "supersecretcookie"})
    sender = FakeSender(
        {"unicode-path": RawResponse(status=400, body=JAVA_BODY.encode())}
    )
    orch = _orch(env, sender)
    finding = _finding(env)

    orch._verify_error_disclosure(
        finding, env.registry.get("verify-error-disclosure"), env.store
    )

    for payload in sender.sent:
        assert b"supersecretcookie" not in payload
        assert b"Cookie" not in payload


def test_judgment_json_contains_no_response_body(env):
    sender = FakeSender(
        {"unicode-path": RawResponse(status=400, body=JAVA_BODY.encode())}
    )
    orch = _orch(env, sender)
    finding = _finding(env)
    orch._verify_error_disclosure(
        finding, env.registry.get("verify-error-disclosure"), env.store
    )

    path = env.evidence_dir / f"error_disclosure_{finding.id}_judgment.json"
    raw = path.read_bytes()
    assert b"IllegalArgumentException" not in raw, "红线 3：正文不进送审摘要"
    assert b"\xe2\x80\xa6" not in raw, "原始畸形字节不进证据（只记 sha256/repr）"
    assert b"java_stack" in raw


def test_full_phase_wiring(env):
    """走 ``run_verify_phase``：handler 挂在生产调度上，计数与审计如实。"""
    sender = FakeSender(
        {"unicode-path": RawResponse(status=400, body=JAVA_BODY.encode())}
    )
    _finding(env)
    orch = _orch(env, sender)

    processed = orch.run_verify_phase(skill_name="verify-error-disclosure")

    assert [f.id for f in processed] == ["F-2026-0001"]
    assert env.store.load_all()[0].state is FindingState.CONFIRMED
    completed = _events(env, "verify_completed")
    assert completed and completed[0]["confirmed"] == 1


# =====================================================================
# 五、生产者：web-probe → host 级候选
# =====================================================================


def _web_probe(asset: str, ref: str = "raw.log#L1") -> Signal:
    return Signal(
        asset=asset,
        status_code=200,
        kind="web-probe",
        source_tool="httpx",
        skill="web-scan",
        evidence_ref=ref,
    )


def test_web_probe_derives_host_level_candidate():
    first = [
        c
        for c in _triage_candidates(_web_probe("http://example.com/a"))
        if c.vuln_type == "error-disclosure"
    ]
    second = [
        c
        for c in _triage_candidates(_web_probe("http://example.com/b?x=1"))
        if c.vuln_type == "error-disclosure"
    ]
    assert len(first) == 1 and len(second) == 1
    assert first[0].asset == second[0].asset == "http://example.com"
    assert first[0].param is None
    assert first[0].source == "web_probe"


def test_origin_url_normalises_default_ports():
    assert _origin_url("http://h/a?x=1") == "http://h"
    assert _origin_url("http://h:80/a") == "http://h"
    assert _origin_url("https://h:443/a") == "https://h"
    assert _origin_url("https://h:8443/a") == "https://h:8443"
    assert _origin_url("ftp://h/a") is None


def test_triage_creates_one_finding_per_host(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    raw = evidence_dir / "synthetic.log"
    raw.write_text("x\n", encoding="utf-8")
    signals = [
        _web_probe("http://127.0.0.1:8080/a", "synthetic.log#L1"),
        _web_probe("http://127.0.0.1:8080/b?q=1", "synthetic.log#L2"),
    ]
    (evidence_dir / "synthetic.signals.jsonl").write_text(
        "\n".join(s.model_dump_json() for s in signals) + "\n", encoding="utf-8"
    )
    audit = AuditLog(evidence_dir / "audit.jsonl")
    orch = Orchestrator(
        SkillRegistry(REPO / "skills").discover(),
        _Runner(Scope(networks=["127.0.0.0/8"], ports=[8080])),
        None,
        audit,
        evidence_dir=evidence_dir,
    )

    orch.run_triage_phase()

    findings = [
        f
        for f in FindingStore(evidence_dir / "findings.jsonl").load_all()
        if f.vuln_type == "error-disclosure"
    ]
    assert len(findings) == 1, "同一 host 的两条信号必须合成一条候选"
    assert findings[0].asset == "http://127.0.0.1:8080"
    deduped = [e for e in audit.read_all() if e.get("event") == "finding_deduplicated"]
    assert len(deduped) == 1
