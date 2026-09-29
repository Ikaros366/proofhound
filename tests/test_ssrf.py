"""M16 verify-ssrf：回调 listener + 判定器 + 编排层接线。

三层覆盖（与既有 verify-* 测试同范式）：

1. **纯函数**：token/nonce 生成、回调 URL 构造、交付证明、`judge` 判定表分支；
2. **真 listener**（真起回环 HTTP 服务）：token 匹配才算命中、路径不匹配记 ignored、
   `forget` 后不计命中、总命中数有上限、响应体是固定横幅；
3. **编排层** `_verify_ssrf`：confirmed（回调命中 + 证据门 + Verifier）/ rejected
   （干净未命中 + 交付证明）/ blocked（前置不全、探针出错、交付证明不成立）。

纪律：本文件不测「目标响应能作为证据」——那正是设计上禁止的形态；
所有 confirmed 路径都必须由**真 listener 收到请求**驱动。"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings import (
    Finding,
    FindingState,
    FindingStore,
    compute_dedup_key,
)
from proofhound.llm.router import ModelRouter, Tier
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.sandbox import RunResult
from proofhound.verify import ssrf
from proofhound.verify.gate import GATE_MATRIX, check as gate_check

ASSET = "http://127.0.0.1:8080/e/fetch3?target=1"
PARAM = "target"
COOKIE = "df6a4b9c0e1f2a3b4c5d6e7f890abcde"
SESSION = SessionConfig(cookies={"phsess": COOKIE, "security": "low"})
VERIFIER_CONFIRM = json.dumps(
    {
        "verdict": "confirm",
        "reason": "回调事实与交付证明齐全",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    ensure_ascii=False,
)
VERIFIER_REJECT = "{\"verdict\": \"reject\", \"reason\": \"回调不足\"}"


# =====================================================================
# 一、纯函数
# =====================================================================


def test_new_token_is_prefixed_random_and_unique():
    tokens = {ssrf.new_token() for _ in range(200)}
    assert len(tokens) == 200  # 无碰撞
    for token in tokens:
        assert token.startswith(ssrf.TOKEN_PREFIX)
        assert len(token) == len(ssrf.TOKEN_PREFIX) + 32


def test_new_nonce_host_is_unresolvable_tld():
    hosts = {ssrf.new_nonce_host() for _ in range(50)}
    assert len(hosts) == 50
    for host in hosts:
        assert host.endswith(".invalid")


def test_callback_and_nonce_url_shapes():
    assert ssrf.callback_url("127.0.0.1", 1234, "t") == "http://127.0.0.1:1234/c/t"
    assert (
        ssrf.nonce_url("127.0.0.1", 1234, "n.invalid", "z")
        == "http://n.invalid:1234/n/z"
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://127.0.0.1:9/c/t", ("127.0.0.1", 9)),
        ("http://localhost/c/t", ("localhost", 80)),
        ("https://example.com/c/t", ("example.com", 443)),
        ("not a url", None),
        ("http://:80/c/t", None),
        ("http://127.0.0.1:99999/c/t", None),
    ],
)
def test_url_host_port(url, expected):
    assert ssrf.url_host_port(url) == expected


@pytest.mark.parametrize(
    ("host", "loopback"),
    [
        ("127.0.0.1", True),
        ("127.5.5.5", True),
        ("::1", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("0.0.0.0", False),
        ("10.0.0.1", False),
        ("example.com", False),
    ],
)
def test_is_loopback_host(host, loopback):
    assert ssrf.is_loopback_host(host) is loopback


def test_resolve_callback_host_defaults_to_loopback():
    assert ssrf.resolve_callback_host({}) == "127.0.0.1"
    assert ssrf.resolve_callback_host({ssrf.ENV_CALLBACK_HOST: "10.0.0.5"}) == "10.0.0.5"
    # 显式空串 = 配置错误，fail-closed 抛错（不给静默回退）
    with pytest.raises(ssrf.SsrfListenerError):
        ssrf.resolve_callback_host({ssrf.ENV_CALLBACK_HOST: "   "})


def test_resolve_callback_port_validation():
    assert ssrf.resolve_callback_port({}) == 0
    assert ssrf.resolve_callback_port({ssrf.ENV_CALLBACK_PORT: "8123"}) == 8123
    for bad in ("abc", "0", "70000", "-1"):
        with pytest.raises(ssrf.SsrfListenerError):
            ssrf.resolve_callback_port({ssrf.ENV_CALLBACK_PORT: bad})


def test_token_delivered_requires_nonempty_marker():
    resp = ssrf.ProbeResponse(url="u", status=200, body="xx phssrf_abc xx")
    assert ssrf.token_delivered(resp, "phssrf_abc") is True
    assert ssrf.token_delivered(resp, "phssrf_zzz") is False
    # 空标记若放行会让 `in` 恒真——必须显式 fail-closed
    assert ssrf.token_delivered(resp, "") is False


def test_delivery_proof_search_is_bounded():
    marker = "phssrf_marker"
    huge = "x" * (ssrf.DELIVERY_PROOF_CHARS + 100) + marker
    resp = ssrf.ProbeResponse(url="u", status=200, body=huge)
    assert ssrf.token_delivered(resp, marker) is False  # 超出搜索窗口


def test_judge_callback_hit_confirms_regardless_of_other_signals():
    j = ssrf.judge(
        callback_hit=True,
        hit_requests=[{"source_ip": "10.1.2.3"}],
        hit_variant="callback-url",
        control_hit=False,
        delivered=False,  # 交付证明失败也不影响命中（命中本身就是事实）
    )
    assert j.verdict == "confirmed"
    assert j.hit_variant == "callback-url"


def test_judge_clean_miss_with_delivery_is_rejected():
    j = ssrf.judge(
        callback_hit=False,
        hit_requests=[],
        control_hit=True,
        delivered=True,
    )
    assert j.verdict == "rejected"
    assert j.control_hit is True


def test_judge_clean_miss_without_delivery_is_blocked():
    j = ssrf.judge(callback_hit=False, hit_requests=[], delivered=False)
    assert j.verdict == "blocked"
    assert any("交付证明" in r for r in j.reasons)


def test_judge_probe_error_is_blocked_even_when_delivered():
    j = ssrf.judge(
        callback_hit=False,
        hit_requests=[],
        delivered=True,
        probes_errored=True,
    )
    assert j.verdict == "blocked"
    assert any("探针存在错误" in r for r in j.reasons)


def test_summary_for_verifier_carries_no_payload_text():
    j = ssrf.judge(
        callback_hit=True,
        hit_requests=[
            {
                "source_ip": "10.1.2.3",
                "user_agent": "python-requests/2",
                "request_line": "GET /c/tok HTTP/1.1",
                "path": "/c/tok",
            }
        ],
        hit_variant="callback-url",
        delivered=True,
    )
    summary = ssrf.summary_for_verifier(j, callback_host_port="127.0.0.1:9999")
    blob = json.dumps(summary, ensure_ascii=False)
    assert summary["ssrf_verdict"] == "confirmed"
    assert summary["callback_hit"] is True
    assert summary["callback_hit_sources"] == ["10.1.2.3"]
    # 红线 3：请求行/UA 原文一行不进 Verifier 摘要（只给枚举与计数）
    assert "request_line" not in blob
    assert "python-requests" not in blob
    assert "/c/tok" not in blob


# =====================================================================
# 二、真 listener（真起回环 HTTP 服务）
# =====================================================================


@pytest.fixture
def listener():
    lis = ssrf.CallbackListener().start()
    try:
        yield lis
    finally:
        lis.close()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
            return resp.status, resp.read().decode("ascii", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("ascii", "replace")


def test_listener_binds_random_loopback_port(listener):
    host, port = listener.bound_address
    assert host == "127.0.0.1"
    assert port > 0
    assert listener.running is True


def test_listener_records_only_matching_token(listener):
    token = ssrf.new_token()
    other = ssrf.new_token()
    listener.register(token)
    status, body = _get(ssrf.callback_url("127.0.0.1", listener.port, token))
    assert status == 200
    assert body == ssrf.BANNER
    hits = listener.hits(token)
    assert len(hits) == 1
    assert hits[0].token == token
    assert hits[0].source_ip == "127.0.0.1"
    assert hits[0].path == f"/c/{token}"
    # 未登记的 token 不算命中
    _get(ssrf.callback_url("127.0.0.1", listener.port, other))
    assert listener.hits(other) == ()
    assert any(ssrf.UNKNOWN_REASON == r.reason for r in listener.ignored)


def test_listener_ignores_paths_without_token(listener):
    status, _ = _get(f"http://127.0.0.1:{listener.port}/")
    assert status == 200  # 永远回同一个横幅，不泄漏任何东西
    status, _ = _get(f"http://127.0.0.1:{listener.port}/random")
    assert status == 200
    assert [r.reason for r in listener.ignored] == [
        ssrf.IGNORED_REASON,
        ssrf.IGNORED_REASON,
    ]


def test_listener_forget_stops_counting(listener):
    token = ssrf.new_token()
    listener.register(token)
    _get(ssrf.callback_url("127.0.0.1", listener.port, token))
    assert listener.has_hit(token) is True
    listener.forget(token)
    assert listener.has_hit(token) is False
    _get(ssrf.callback_url("127.0.0.1", listener.port, token))
    assert listener.has_hit(token) is False
    assert any(ssrf.EXPIRED_REASON == r.reason for r in listener.ignored)


def test_listener_caps_hits_per_token(listener):
    token = ssrf.new_token()
    listener.register(token)
    url = ssrf.callback_url("127.0.0.1", listener.port, token)
    for _ in range(ssrf.MAX_HITS_PER_TOKEN + 5):
        _get(url)
    assert len(listener.hits(token)) == ssrf.MAX_HITS_PER_TOKEN
    assert listener.dropped == 5


def test_listener_serves_any_path_without_leaking(listener):
    # 目标可能把我们的响应体回显到它自己的页面——正文必须**不含任何可变内容**
    for path in (f"/c/{ssrf.new_token()}", "/n/x", "/", "/../../etc/passwd"):
        status, body = _get(f"http://127.0.0.1:{listener.port}{path}")
        assert status == 200
        assert body == ssrf.BANNER


def test_listener_close_is_idempotent(listener):
    listener.close()
    listener.close()  # 幂等
    assert listener.running is False


# =====================================================================
# 三、编排层 _verify_ssrf
# =====================================================================


class FakeRunner:
    """只回预制 httpx 输出（baseline 用），零真实执行。"""

    def __init__(self, scope, evidence_dir, httpx_status=200):
        self.scope = scope
        self.evidence_dir = evidence_dir
        self.httpx_status = httpx_status
        self.calls = []
        self.egress_proxy_url = None
        self._seq = 0

    def run(self, tool, args, timeout=300, image=None):
        self.calls.append((tool, list(args)))
        assert tool == "httpx", f"ssrf 链路只该跑 baseline，实得 {tool}"
        self._seq += 1
        stdout = self.evidence_dir / f"base{self._seq}.stdout.log"
        stderr = self.evidence_dir / f"base{self._seq}.stderr.log"
        stdout.write_text(
            json.dumps({"url": ASSET, "status_code": self.httpx_status}) + "\n",
            encoding="utf-8",
        )
        stderr.write_text("", encoding="utf-8")
        return RunResult(
            rejected=False,
            command=[tool, *args],
            exit_code=0,
            stdout_path=stdout,
            stderr_path=stderr,
        )


class MockRouter(ModelRouter):
    """罐头 T2 路由（继承 ModelRouter 以过 ensure_router 的 isinstance 闸）。"""

    def __init__(self, reply=VERIFIER_CONFIRM):
        self.reply = reply
        self.calls = []
        self.configs = {Tier.T2: SimpleNamespace(model="kimi-k3-test")}

    def complete(self, tier, messages):
        self.calls.append((tier, messages))
        return self.reply


class VictimFixture:
    """模拟 SSRF 目标的**服务端行为**：只有当参数取值是我们给的 URL 时才回连。

    ``follows_parameter=True`` = 真漏洞（取数）；``False`` = 安全形态（取值被忽略，
    只在正文里原样回显 ⇒ 交付证明成立但不会回连）。
    """

    def __init__(self, listener, *, follows_parameter=True, probe_error=False):
        self.listener = listener
        self.follows_parameter = follows_parameter
        self.probe_error = probe_error
        self.seen = []

    def __call__(self, url, session):
        self.seen.append(url)
        if self.probe_error:
            return ssrf.ProbeResponse(url=url, error="URLError: 连接被拒")
        if self.follows_parameter:
            target = _injected_value(url)
            if target is not None:
                # 目标代我们取数：真的去请求那个 URL（命中 listener）
                try:
                    status, body = _get(target)
                except Exception as exc:  # noqa: BLE001 - 目标取数失败即探针失败
                    return ssrf.ProbeResponse(
                        url=url, error=f"URLError: {type(exc).__name__}: {exc}"
                    )
                # 真实目标通常会把"取到了什么"渲染进页面——这里连**受控地址**
                # 一并回显，正是交付证明要看到的形态（本仓库基准 fixture 的 E 族
                # 同样回显取值）。替身必须与真实形态对齐，否则交付证明会假性失败。
                return ssrf.ProbeResponse(
                    url=url,
                    status=200,
                    body=(
                        f"<html>已抓取 {target}：状态码 {status} 正文 {body}</html>"
                    ),
                )
        # 取值被忽略（或非回调地址）：正文原样回显 ⇒ 交付证明可成立
        return ssrf.ProbeResponse(
            url=url, status=200, body=f"<html>参数取值：{url}</html>"
        )


def _injected_value(url: str) -> str | None:
    """从探测 URL 里取回我们注入的参数值（即回调 URL）；取不到返回 None。"""
    from urllib.parse import parse_qs, urlparse

    query = parse_qs(urlparse(url).query)
    values = query.get(PARAM) or []
    for value in values:
        if value.startswith("http://"):
            return value
    return None


def _httpx_line(status: int) -> str:
    return json.dumps({"url": ASSET, "status_code": status, "title": "bench"}) + "\n"


def _seed_ssrf(store: FindingStore, audit: AuditLog, **overrides) -> Finding:
    base = dict(
        vuln_type="ssrf",
        asset=ASSET,
        param=PARAM,
        title="SSRF 候选",
        evidence_kinds=["crawl-endpoint"],
    )
    base.update(overrides)
    finding = Finding(
        id=store.next_id(),
        state=FindingState.SIGNAL,
        severity="medium",
        confidence="low",
        dedup_key=compute_dedup_key(base["asset"], base["vuln_type"], base.get("param")),
        created_at="2026-09-29T00:00:00.000+00:00",
        updated_at="2026-09-29T00:00:00.000+00:00",
        audit=audit,
        **base,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="seed", reason="测试种子")
    store.append(finding)
    return finding


@pytest.fixture
def env(tmp_path, make_skill_dir):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    audit = AuditLog(evidence_dir / "audit.jsonl")
    scope = Scope(networks=["127.0.0.0/8"], ports=[8080], session=SESSION)
    registry = SkillRegistry(make_skill_dir(name="verify-ssrf")).discover()
    return SimpleNamespace(
        evidence_dir=evidence_dir,
        audit=audit,
        scope=scope,
        registry=registry,
        store=FindingStore(evidence_dir / "findings.jsonl"),
    )


@pytest.fixture
def listener():
    lis = ssrf.CallbackListener().start()
    try:
        yield lis
    finally:
        lis.close()


def _orch(env, listener, *, follows_parameter=True, probe_error=False, router_reply=VERIFIER_CONFIRM):
    runner = FakeRunner(env.scope, env.evidence_dir)
    router = MockRouter(router_reply)
    victim = VictimFixture(
        listener, follows_parameter=follows_parameter, probe_error=probe_error
    )
    orch = Orchestrator(
        env.registry,
        runner,
        router,
        env.audit,
        evidence_dir=env.evidence_dir,
        # 真 listener + 受控 fetch：SSRF 的 confirmed 路径必须由真回调驱动
        ssrf_listener_factory=lambda: listener,
        ssrf_fetch=victim,
    )
    return orch, runner, router, victim


# ---------------------------------------------------------- blocked 前置


def test_blocked_without_session(env, listener):
    env.scope = Scope(networks=["127.0.0.0/8"], ports=[8080])  # 无 session
    finding = _seed_ssrf(env.store, env.audit)
    orch, _runner, router, _victim = _orch(env, listener)
    outcome = orch._verify_ssrf(finding, orch.registry.get("verify-ssrf"), env.store)
    assert outcome == "blocked"
    assert finding.state is FindingState.HYPOTHESIS  # 停留原态，不驳回
    assert router.calls == []
    assert any("预置会话" in (e.get("reason") or "") for e in env.audit.read_all())


def test_blocked_without_param(env, listener):
    finding = _seed_ssrf(env.store, env.audit, param=None)
    orch, _runner, router, _victim = _orch(env, listener)
    outcome = orch._verify_ssrf(finding, orch.registry.get("verify-ssrf"), env.store)
    assert outcome == "blocked"
    assert finding.state is FindingState.HYPOTHESIS
    assert router.calls == []


def test_blocked_for_form_page_candidate(env, listener):
    finding = _seed_ssrf(env.store, env.audit, evidence_kinds=["crawl-form"])
    orch, _runner, _router, _victim = _orch(env, listener)
    outcome = orch._verify_ssrf(finding, orch.registry.get("verify-ssrf"), env.store)
    assert outcome == "blocked"
    assert any("POST 表单" in (e.get("reason") or "") for e in env.audit.read_all())


def test_blocked_when_baseline_not_2xx(env, listener):
    finding = _seed_ssrf(env.store, env.audit)
    runner = FakeRunner(env.scope, env.evidence_dir, httpx_status=403)
    orch = Orchestrator(
        env.registry,
        runner,
        MockRouter(),
        env.audit,
        evidence_dir=env.evidence_dir,
        ssrf_listener_factory=lambda: listener,
        ssrf_fetch=VictimFixture(listener),
    )
    outcome = orch._verify_ssrf(finding, orch.registry.get("verify-ssrf"), env.store)
    assert outcome == "blocked"
    assert finding.state is FindingState.HYPOTHESIS


def test_blocked_when_probe_errors(env, listener):
    finding = _seed_ssrf(env.store, env.audit)
    orch, _runner, _router, _victim = _orch(env, listener, probe_error=True)
    outcome = orch._verify_ssrf(finding, orch.registry.get("verify-ssrf"), env.store)
    assert outcome == "blocked"
    assert any(
        "探针存在错误" in (e.get("reason") or "") for e in env.audit.read_all()
    )


def test_blocked_when_delivery_unproven(env, listener):
    finding = _seed_ssrf(env.store, env.audit)

    def silent_fetch(url, session):
        # 目标既不取数，也不回显取值 ⇒ 无法证明 payload 被原样接收
        return ssrf.ProbeResponse(url=url, status=200, body="<html>静态帮助页</html>")

    orch = Orchestrator(
        env.registry,
        FakeRunner(env.scope, env.evidence_dir),
        MockRouter(),
        env.audit,
        evidence_dir=env.evidence_dir,
        ssrf_listener_factory=lambda: listener,
        ssrf_fetch=silent_fetch,
    )
    outcome = orch._verify_ssrf(finding, orch.registry.get("verify-ssrf"), env.store)
    assert outcome == "blocked"
    assert finding.state is FindingState.HYPOTHESIS  # 宁漏勿滥：不驳回
    assert any(
        "交付证明不成立" in (e.get("reason") or "") for e in env.audit.read_all()
    )


# ---------------------------------------------------------- rejected / confirmed


def test_rejected_on_clean_miss_with_delivery_proof(env, listener):
    finding = _seed_ssrf(env.store, env.audit)
    orch, runner, router, victim = _orch(env, listener, follows_parameter=False)
    outcome = orch._verify_ssrf(finding, orch.registry.get("verify-ssrf"), env.store)
    assert outcome == "rejected"
    assert finding.state is FindingState.REJECTED
    assert finding.verification is None  # 驳回不携带 verification
    assert router.calls == []  # 确定性真阴性：零 LLM 成本
    assert [tool for tool, _ in runner.calls] == ["httpx"]
    # 判定 JSON 落盘且如实记录交付证明
    judgment = json.loads(
        (env.evidence_dir / f"ssrf_{finding.id}_judgment.json").read_text(encoding="utf-8")
    )
    assert judgment["verdict"] == "rejected"
    assert judgment["hit_requests"] == []  # 无回调命中
    assert judgment["delivered"] is True
    assert len(judgment["probes"]) == 3  # 1 对照 + 2 变体（对照探针真的会发出）
    variants = sorted(p["variant"] for p in judgment["probes"])
    assert variants == [
        "callback-url",
        "callback-url+decoy-param",
        "control-random-host",
    ]
    assert any("ssrf_probe_attempt" == e["event"] for e in env.audit.read_all())


def test_control_hit_alone_does_not_confirm(env, listener):
    """随机地址对照命中 ≠ SSRF：只有**依赖我们参数**的回调才算数。"""
    finding = _seed_ssrf(env.store, env.audit)

    def control_only_fetch(url, session):
        # 目标对**任何**输入都代发一次请求（包括随机地址对照），但从不跟随
        # 我们的参数值 —— 正是要防的"目标自己访问了别的地址"形态
        # 对照探针的路径前缀是 /n/（随机主机名不可解析，故这里直接按**路径**识别，
        # 而不是去改写主机名/端口——对照 URL 的端口本来就是监听端口）。
        if "/n/" in url:
            nonce = url.rsplit("/n/", 1)[-1]
            try:
                _get(f"http://127.0.0.1:{listener.port}/n/{nonce}")
            except Exception:  # noqa: BLE001 - 连不上只是没命中，不抛穿
                pass
        return ssrf.ProbeResponse(url=url, status=200, body=f"<html>{url}</html>")

    orch = Orchestrator(
        env.registry,
        FakeRunner(env.scope, env.evidence_dir),
        MockRouter(),
        env.audit,
        evidence_dir=env.evidence_dir,
        ssrf_listener_factory=lambda: listener,
        ssrf_fetch=control_only_fetch,
    )
    outcome = orch._verify_ssrf(finding, orch.registry.get("verify-ssrf"), env.store)
    assert outcome == "rejected"  # 不是 confirmed！
    assert finding.state is FindingState.REJECTED
    judgment = json.loads(
        (env.evidence_dir / f"ssrf_{finding.id}_judgment.json").read_text(encoding="utf-8")
    )
    assert judgment["control_hit"] is True
    assert judgment["hit_requests"] == []  # 对照命中 ≠ SSRF 确认


def test_confirmed_full_chain_via_real_callback(env, listener):
    finding = _seed_ssrf(env.store, env.audit)
    orch, runner, router, victim = _orch(env, listener, follows_parameter=True)
    processed = orch.run_verify_phase(skill_name="verify-ssrf")

    assert [f.id for f in processed] == [finding.id]
    # run_verify_phase 从 store 重新加载 Finding（磁盘快照回放），断言对象必须
    # 用返回的那个；沿用 test_verify_phase.py 的既有写法。
    finding = processed[0]
    assert finding.state is FindingState.CONFIRMED
    assert finding.confidence == "confirmed"
    assert "behavioral" in finding.evidence_kinds

    verification = finding.verification
    assert verification.method == ssrf.SSRF_CONFIRMED_METHOD
    assert verification.verified_by == "verify-ssrf@1.0.0"
    assert len(verification.evidence_refs) == 3  # baseline + 回调记录 + 判定 JSON
    assert any(ref.endswith("_callbacks.jsonl") for ref in verification.evidence_refs)
    assert any(ref.endswith("_judgment.json") for ref in verification.evidence_refs)
    # 四段式
    assert PARAM in verification.claim
    assert verification.expected
    assert "listener 收到" in verification.actual
    assert len(verification.reproduction_steps) == 4
    # 复现步骤里不得出现 Cookie 原文（脱敏是两个会话都要，单会话同理）
    assert COOKIE not in " ".join(verification.reproduction_steps)
    assert "sha256:" in verification.reproduction_steps[0]
    # CVSS 由代码算分，severity 被覆盖
    assert finding.cvss_vector and finding.cvss_score is not None
    assert finding.verifier.verdict == "confirm"
    assert router.calls  # Verifier 终审确实被调用

    # 真回调记录落盘：请求行/source_ip 都在（取证），且条数受上限保护
    callbacks = (
        env.evidence_dir / f"ssrf_{finding.id}_callbacks.jsonl"
    ).read_text(encoding="utf-8").strip().splitlines()
    records = [json.loads(line) for line in callbacks]
    hit_records = [r for r in records if not r.get("ignored")]
    assert hit_records
    assert hit_records[0]["source_ip"] == "127.0.0.1"
    assert hit_records[0]["request_line"].startswith("GET /c/")

    # 审计链：probe 逐次 + 回调收到 + 判定 + 状态迁移
    events = [e["event"] for e in env.audit.read_all()]
    assert "ssrf_probe_attempt" in events
    assert "ssrf_callback_received" in events
    assert "ssrf_callback_judged" in events
    assert "verifier_verdict" in events
    completed = [
        e for e in env.audit.read_all() if e["event"] == "verify_completed"
    ][0]
    assert completed["confirmed"] == 1


def test_verifier_reject_keeps_finding_rejected(env, listener):
    finding = _seed_ssrf(env.store, env.audit)
    orch, _runner, router, _victim = _orch(
        env, listener, follows_parameter=True, router_reply=VERIFIER_REJECT
    )
    outcome = orch._verify_ssrf(finding, orch.registry.get("verify-ssrf"), env.store)
    assert outcome == "rejected"
    assert finding.state is FindingState.REJECTED
    assert finding.verifier.verdict == "reject"
    assert router.calls


def test_listeners_are_released_after_phase(env, listener):
    """回调 listener 不常驻：phase 收尾必须释放（与 _close_browser 同纪律）。"""
    _seed_ssrf(env.store, env.audit)
    orch, _runner, _router, _victim = _orch(env, listener, follows_parameter=True)
    orch.run_verify_phase(skill_name="verify-ssrf")
    assert orch._ssrf_listeners == {}


def test_verify_handlers_cover_ssrf_and_stay_disjoint():
    """四类漏洞的 method 白名单与 verify skill 覆盖面**互不染指**。"""
    from proofhound.core.orchestrator import Orchestrator as _O

    handlers = _O._verify_handlers(SimpleNamespace(_verify_sqli=1, _verify_xss=1, _verify_idor=1, _verify_ssrf=1))
    assert set(handlers) == {"verify-sqli", "verify-xss", "verify-idor", "verify-ssrf"}
    covered = [handlers[name][0] for name in handlers]
    assert covered[0] == frozenset({"sqli"})
    assert covered[1] == frozenset({"xss"})
    assert covered[2] == frozenset({"idor"})
    assert covered[3] == frozenset({"ssrf"})
    # 两两不相交
    for i, left in enumerate(covered):
        for right in covered[i + 1:]:
            assert not (left & right)


def test_gate_methods_are_mutually_exclusive_and_ssrf_only_accepts_callback():
    all_methods: list[str] = []
    for requirement in GATE_MATRIX.values():
        all_methods.extend(requirement.methods)
    assert len(all_methods) == len(set(all_methods)), "method 白名单跨类型重用了名字"
    assert GATE_MATRIX["ssrf"].methods == frozenset({ssrf.SSRF_CONFIRMED_METHOD})
    assert GATE_MATRIX["ssrf"].behavioral_kinds == frozenset({"behavioral"})


def test_non_ssrf_method_cannot_pass_ssrf_gate():
    """拿别的类型的结论来确认 ssrf：证据门必须拦（白名单互不染指）。"""
    from proofhound.findings.finding import Verification

    finding = Finding(
        id="F-2026-9002",
        vuln_type="ssrf",
        state=FindingState.REPRODUCED,
        asset=ASSET,
        param=PARAM,
        dedup_key="k",
        evidence_kinds=["behavioral"],
        verification=Verification(method="browser-confirmed", evidence_refs=["x"]),
        created_at="2026-09-29T00:00:00Z",
        updated_at="2026-09-29T00:00:00Z",
    )
    result = gate_check(finding)
    assert result.passed is False
    assert any("不在白名单" in item for item in result.missing)

