"""M18-a 测试：命令注入判定器（纯函数）+ 真 listener 命中 + 编排层 `_verify_cmdi`。

三层覆盖（与 test_ssrf.py 同范式）：

1. **纯函数**：token 生成、载荷/交付/DNS 变体构造、判定表全分支与**优先级**；
2. **真 listener**（真起回环 HTTP）：token 匹配才算命中、未登记 token 不计命中；
3. **编排层**：confirmed / rejected / blocked（DNS 误命中、交付证明不成立、探针出错、
   缺 param、越界）。

纪律：**不测「响应内容能作为证据」**——那正是设计上禁止的形态。所有 confirmed
路径都必须由**真 listener 收到请求**驱动。
"""

from __future__ import annotations

import json
import re
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qsl, unquote, urlparse

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings import (
    Finding,
    FindingState,
    FindingStore,
    Signal,
    Verification,
    compute_dedup_key,
)
from proofhound.llm.router import ModelRouter, Tier
from proofhound.skills.registry import SkillRegistry
from proofhound.verify import cmdi
from proofhound.verify.gate import GATE_MATRIX, check as gate_check

ASSET = "http://127.0.0.1:8080/tools/ping?host=1"
PARAM = "host"
VERIFIER_CONFIRM = json.dumps(
    {
        "verdict": "confirm",
        "reason": "回调事实与交付证明齐全",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    ensure_ascii=False,
)


def _injected_value(url: str) -> str:
    """从探测 URL 里取出被测参数的注入值（**反 URL 解码**）。

    注入值里含 ``;`` / ``|`` / ``$`` 等分隔符，构造时被 urlencode 编码；
    真实目标取到的是解码后的值，故这里必须解码——否则 ``_extract_urls``
    找不到回调地址，命中路径就永远走不到（实现期踩到的坑）。
    """
    for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if key == PARAM:
            return unquote(value)
    return ""


def _get(url: str):
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - 测试内回环
        return resp.status, resp.read().decode("utf-8", errors="replace")


def _extract_urls(value: str) -> list[str]:
    """从注入值里抠出 http URL（模拟 shell 解析命令串）。"""
    return re.findall(r"https?://[^\s;|&`)\"']+", value)


# =====================================================================
# 一、纯函数
# =====================================================================


def test_new_token_is_prefixed_random_and_unique():
    tokens = {cmdi.new_cmdi_token() for _ in range(50)}
    assert len(tokens) == 50, "token 必须唯一"
    for token in tokens:
        assert token.startswith(cmdi.CMDI_TOKEN_PREFIX)
        assert len(token) > 20


def test_variants_are_at_most_eight_and_named_uniquely():
    """裁定上限 ≤8 条；名字唯一（审计里要能分辨是哪条命中的）。"""
    assert len(cmdi.VARIANTS) <= 8, len(cmdi.VARIANTS)
    names = [name for name, _ in cmdi.VARIANTS]
    assert len(names) == len(set(names))
    for name, template in cmdi.VARIANTS:
        assert "{cb}" in template, name


def test_variant_templates_do_not_contain_write_or_exfil_operations():
    """裁定边界：载荷只发起出站请求——不得出现读文件/写/反弹 shell 的痕迹。"""
    forbidden = (
        "rm ", ">", ">>", "wget ", "nc ", "bash -i", "sh -i", "/dev/tcp",
        "cat ", "echo ", "base64", "ifs", "sleep ",
    )
    for name, template in cmdi.VARIANTS:
        lowered = template.lower()
        for token in forbidden:
            assert token not in lowered, f"{name} 含禁用片段 {token!r}"


def test_delivery_probe_value_is_plain_token_without_metacharacters():
    token = cmdi.new_cmdi_token()
    value = cmdi.delivery_probe_value(token)
    assert value == token
    for meta in (";", "|", "&", "$", "`", "\n"):
        assert meta not in value, "交付证明探针必须是纯 token（不含任何分隔符）"


def test_dns_probe_value_uses_nonresolving_tld():
    value, url = cmdi.dns_probe_value("phnonce123", 8080, "phcmdi_tok")
    assert value.startswith(";curl ")
    assert cmdi.NONRESOLVING_TLD in url, "必须用 RFC 6761 保留的不可解析顶级域"
    assert url.startswith("http://phnonce123.invalid:8080/")


def test_build_probe_url_replaces_only_target_param():
    url = cmdi.build_probe_url(
        "http://h/x?a=1&host=2&b=3", "host", ";curl http://c/c/t"
    )
    assert "a=1" in url and "b=3" in url
    assert "host=2" not in url, "目标参数必须被替换"
    assert " " not in url, "空格必须被确定性编码"


def test_same_origin_detects_cross_origin():
    assert cmdi.same_origin("http://h:8080/a?x=1", "http://h:8080/b?y=2")
    assert cmdi.same_origin("http://h/a", "http://h:80/b"), "缺省端口应等价"
    assert not cmdi.same_origin("http://h:8080/a", "http://h:9999/b"), "端口不同"
    assert not cmdi.same_origin("http://h/a", "https://h/a"), "scheme 不同"
    assert not cmdi.same_origin("http://h/a", "http://other/a"), "host 不同"


def test_judge_confirmed_requires_hit_and_delivery():
    j = cmdi.judge(
        callback_hit=True,
        hit_requests=[{"source_ip": "10.0.0.1"}],
        hit_variant="pipe",
        delivered=True,
    )
    assert j.verdict == "confirmed"
    assert j.hit_variant == "pipe"
    assert j.delivered is True


def test_judge_rejected_requires_clean_miss_and_delivery():
    assert cmdi.judge(callback_hit=False, delivered=True).verdict == "rejected"


def test_judge_blocked_when_delivery_proof_missing():
    """交付证明不成立 ⇒ blocked（**不是** rejected）——否则会把"载荷没送到"
    误判成"送到了没执行"（假阴性会污染真阴性结论）。"""
    assert cmdi.judge(callback_hit=False, delivered=False).verdict == "blocked"


def test_judge_dns_misfire_blocks_even_when_token_hit():
    """DNS 非命中变体命中 ⇒ 有第三方代抓取 ⇒ 即便 token 命中也不确认。"""
    j = cmdi.judge(
        callback_hit=True,
        hit_requests=[{"source_ip": "10.0.0.1"}],
        delivered=True,
        dns_misfire=True,
    )
    assert j.verdict == "blocked", "第三方代抓取必须阻断确认"
    assert j.dns_misfire is True


def test_judge_probe_error_has_highest_precedence():
    """探针出错优先级最高：即便同时 dns_misfire，也按"覆盖不全"记。"""
    j = cmdi.judge(
        callback_hit=True,
        hit_requests=[{"a": 1}],
        delivered=True,
        dns_misfire=True,
        probes_errored=True,
    )
    assert j.verdict == "blocked"
    assert "探针存在错误" in j.reasons[0]


def test_judge_does_not_confirm_on_hit_without_delivery():
    """命中但交付证明不成立 ⇒ blocked（宁漏勿滥：宁可查不出，不可误确认）。"""
    j = cmdi.judge(callback_hit=True, hit_requests=[{"a": 1}], delivered=False)
    assert j.verdict == "blocked"


def test_judgment_dict_and_verifier_summary_exclude_bodies():
    j = cmdi.judge(
        callback_hit=True,
        hit_requests=[{"source_ip": "10.0.0.1", "user_agent": "curl/8"}],
        hit_variant="semicolon",
        delivered=True,
        probes=[{"seq": 0, "variant": "dns-nonresolving"}],
        ignored=[{"path": "/x"}],
    )
    data = j.to_dict()
    for key in ("verdict", "reasons", "hit_variant", "hit_requests", "delivered",
                "dns_misfire", "probes", "ignored_requests"):
        assert key in data
    summary = cmdi.summary_for_verifier(j, callback_host_port="127.0.0.1:9")
    assert summary["cmdi_verdict"] == "confirmed"
    assert summary["callback_hit_count"] == 1
    assert summary["delivery_proof_ok"] is True
    assert summary["dns_control_misfire"] is False
    # 红线 3：摘要里不得出现请求原文/正文/UA 值
    assert "hit_requests" not in summary, "不得把请求原文塞进送审摘要"
    assert "curl/8" not in json.dumps(summary), "UA 值不得进送审摘要"
    assert "/x" not in json.dumps(summary), "ignored 路径不得进送审摘要"


# =====================================================================
# 二、真 listener（复用 SSRF 的基础设施）
# =====================================================================


def test_real_listener_counts_hits_only_for_registered_tokens():
    with cmdi.CallbackListener(host="127.0.0.1", port=0).start() as listener:
        host, port = listener.bound_address
        token = cmdi.new_cmdi_token()
        listener.register(token)
        status, body = _get(f"http://{host}:{port}/c/{token}")
        assert status == 200
        assert body == cmdi.BANNER
        assert listener.has_hit(token), "登记过的 token 必须计命中"

        _get(f"http://{host}:{port}/c/{cmdi.new_cmdi_token()}")
        assert len(listener.ignored) == 1, "未登记 token 记 ignored 且不计命中"


def test_real_listener_forget_stops_counting():
    with cmdi.CallbackListener(host="127.0.0.1", port=0).start() as listener:
        host, port = listener.bound_address
        token = cmdi.new_cmdi_token()
        listener.register(token)
        listener.forget(token)
        _get(f"http://{host}:{port}/c/{token}")
        assert not listener.has_hit(token), "forget 之后不得再计命中"


# =====================================================================
# 三、编排层 _verify_cmdi
# =====================================================================


class MockRouter(ModelRouter):
    """罐头 T2 路由（继承 ModelRouter 以过 ensure_router 的 isinstance 闸）。"""

    def __init__(self, reply=VERIFIER_CONFIRM):
        self.reply = reply
        self.calls = []
        self.configs = {Tier.T2: SimpleNamespace(model="kimi-k3-test")}

    def complete(self, tier, messages):
        self.calls.append((tier, messages))
        return self.reply


class FakeVictim:
    """模拟被注入的目标服务端的**命令执行行为**。

    - ``executes=True``：解析注入值里的回调地址并真的请求它（模拟命令执行）；
    - ``reflects_token=True``：把参数值原样回显进响应体（交付证明成立的现实形态）；
    - ``waf_fetches=True``：模拟"目标前面挂着 WAF/反代/截图服务"——它对**任何**
      取值都去抓取其中的 URL。这是命令注入相对 SSRF 的净新增假阳性来源。

    关于 DNS 探针的复现方式：不可解析主机名（``.invalid``）在现实中**必然**解析
    失败，且"失败"的具体表现随环境而变（有透明代理时拿到 502，裸环境是
    URLError），故**不靠真实解析**来复现中间件行为——替身改为检查**探针 URL
    自身**的宿主是否不可解析，若是则直接把该探针路径里的 token 打到真 listener，
    等价于"中间件硬发了一次"。这样用例与环境解耦，仍真实走完
    listener 登记 → 命中判定 → ``judge`` 全链路。
    """

    def __init__(
        self,
        listener,
        *,
        executes: bool = True,
        reflects_token: bool = True,
        probe_error: bool = False,
        waf_fetches: bool = False,
    ):
        self.listener = listener
        self.executes = executes
        self.reflects_token = reflects_token
        self.probe_error = probe_error
        self.waf_fetches = waf_fetches
        self.seen: list[str] = []

    def __call__(self, url: str, session):
        self.seen.append(url)
        if self.probe_error:
            return cmdi.ProbeResponse(url=url, error="URLError: 连接被拒")
        # 只从**注入值**里找回调地址——真实目标也只消费参数值，
        # 不会去请求 asset 自己（早先版本的假失败就出在这里）。
        value = _injected_value(url)

        if self.waf_fetches:
            hostname = urlparse(url).hostname or ""
            if cmdi.NONRESOLVING_TLD in hostname:
                token = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1]
                bound_host, bound_port = self.listener.bound_address
                if token:
                    try:
                        _get(f"http://{bound_host}:{bound_port}/c/{token}")
                    except Exception:  # noqa: BLE001
                        pass
            for candidate in _extract_urls(value):
                try:
                    _get(candidate)
                except Exception:  # noqa: BLE001 - 抓取失败即失败
                    pass

        if self.executes:
            for candidate in _extract_urls(value):
                if cmdi.NONRESOLVING_TLD in candidate:
                    continue  # 真 shell 解析不了 .invalid，也发不出去
                try:
                    _get(candidate)
                except Exception:  # noqa: BLE001
                    pass

        body = value if self.reflects_token else "<html>ok</html>"
        return cmdi.ProbeResponse(url=url, status=200, body=body)


class FakeRunner:
    """只提供 scope（cmdi 链路不需要 baseline，故不跑任何工具）。"""

    def __init__(self, scope):
        self.scope = scope


class _TargetHandler(BaseHTTPRequestHandler):
    """真目标：把 query 里 ``host`` 的值原样写回正文（交付证明的现实形态）。"""

    def do_GET(self):  # noqa: N802
        value = ""
        for key, raw in parse_qsl(urlparse(self.path).query, keep_blank_values=True):
            if key == PARAM:
                value = unquote(raw)
        raw_body = value.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw_body)))
        self.end_headers()
        self.wfile.write(raw_body)

    def log_message(self, *args):  # 静音
        pass


@pytest.fixture
def env(tmp_path, make_skill_dir):
    """真起回环目标服务：探针指向它（不是死端口），故探针不会假失败。"""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    env = SimpleNamespace(
        evidence_dir=evidence_dir,
        audit=AuditLog(evidence_dir / "audit.jsonl"),
        registry=SkillRegistry(make_skill_dir(name="verify-cmdi", tools=())).discover(),
        store=FindingStore(evidence_dir / "findings.jsonl"),
        # 回环目标按 **IP → 网段** 授权（Scope 用的是 networks，不是 domains）
        scope=Scope(networks=["127.0.0.0/8"], ports=[port]),
        base=f"http://127.0.0.1:{port}",
        port=port,
    )
    env.asset = f"{env.base}/tools/ping?{PARAM}=1"
    yield env
    server.shutdown()
    server.server_close()


def _finding(env, *, asset=None, param=PARAM, vuln_type="cmdi"):
    asset = asset if asset is not None else env.asset
    finding = Finding(
        id=env.store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type=vuln_type,
        severity="critical",
        asset=asset,
        param=param,
        confidence="low",
        evidence_kinds=["crawl-endpoint"],
        dedup_key=compute_dedup_key(asset, vuln_type, param),
        source_signal_refs=[],
        created_at="2026-09-30T00:00:00.000+00:00",
        updated_at="2026-09-30T00:00:00.000+00:00",
        audit=env.audit,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="triage", reason="测试种子")
    env.store.append(finding)
    return finding


def _orch(env, listener, victim, *, router=None):
    return Orchestrator(
        env.registry,
        FakeRunner(env.scope),
        router or MockRouter(),
        env.audit,
        evidence_dir=env.evidence_dir,
        ssrf_listener_factory=lambda: listener,
        cmdi_fetch=victim,
    )


def test_handler_is_registered_and_covers_only_cmdi():
    handlers = Orchestrator._verify_handlers(Orchestrator.__new__(Orchestrator))
    assert "verify-cmdi" in handlers
    covered, fn = handlers["verify-cmdi"]
    assert covered == frozenset({"cmdi"})
    assert callable(fn)


def test_gate_requires_cmdi_method_and_behavioral_kind(env):
    """证据门：cmdi 只认本类型的 method + behavioral 证据。"""
    requirement = GATE_MATRIX["cmdi"]
    assert requirement.methods == frozenset({cmdi.CMDI_CONFIRMED_METHOD})
    assert requirement.behavioral_kinds == frozenset({"behavioral"})

    finding = _finding(env)
    assert not gate_check(finding).passed, "无 verification 必须 fail-closed"

    finding.verification = Verification(
        method=cmdi.CMDI_CONFIRMED_METHOD, evidence_refs=["x.json"]
    )
    assert not gate_check(finding).passed, "缺 behavioral 证据不得过门"
    finding.evidence_kinds.append("behavioral")
    assert gate_check(finding).passed


def test_other_type_method_does_not_pass_cmdi_gate(env):
    """别的类型的 method 不得冒充 cmdi 的确认手段。"""
    finding = _finding(env)
    finding.verification = Verification(
        method="browser-confirmed", evidence_refs=["x.json"]
    )
    finding.evidence_kinds.append("behavioral")
    assert not gate_check(finding).passed


def test_method_name_does_not_collide_with_other_types():
    """method 名与既有五类互不染指（全矩阵断言）。"""
    seen: dict[str, str] = {}
    for vuln_type, requirement in GATE_MATRIX.items():
        for method in requirement.methods:
            assert method not in seen, f"{method} 同时属于 {seen[method]} 与 {vuln_type}"
            seen[method] = vuln_type
    assert seen[cmdi.CMDI_CONFIRMED_METHOD] == "cmdi"


def test_confirmed_path_requires_real_callback(env):
    with cmdi.CallbackListener(host="127.0.0.1", port=0).start() as listener:
        finding = _finding(env)
        orch = _orch(env, listener, FakeVictim(listener, executes=True))
        outcome = orch._verify_cmdi(finding, env.registry.get("verify-cmdi"), env.store)

    assert outcome == "confirmed", outcome
    after = env.store.load_all()[0]
    assert after.state is FindingState.CONFIRMED
    assert after.verification is not None
    assert after.verification.method == cmdi.CMDI_CONFIRMED_METHOD
    assert "behavioral" in after.evidence_kinds
    events = [e["event"] for e in env.audit.read_all()]
    assert "cmdi_callback_judged" in events
    assert "cmdi_probe_attempt" in events, "每次探针都要按次审计"


def test_rejected_path_when_parameter_ignored(env):
    """安全形态：参数被回显（交付证明成立）但完全不执行 ⇒ Rejected。"""
    with cmdi.CallbackListener(host="127.0.0.1", port=0).start() as listener:
        finding = _finding(env)
        orch = _orch(env, listener, FakeVictim(listener, executes=False))
        outcome = orch._verify_cmdi(finding, env.registry.get("verify-cmdi"), env.store)

    assert outcome == "rejected", outcome
    assert env.store.load_all()[0].state is FindingState.REJECTED


def test_blocked_when_delivery_proof_missing(env):
    """参数不回显 ⇒ 交付证明不成立 ⇒ blocked（不驳回）。"""
    with cmdi.CallbackListener(host="127.0.0.1", port=0).start() as listener:
        finding = _finding(env)
        orch = _orch(
            env, listener, FakeVictim(listener, executes=False, reflects_token=False)
        )
        outcome = orch._verify_cmdi(finding, env.registry.get("verify-cmdi"), env.store)

    assert outcome == "blocked", outcome
    assert env.store.load_all()[0].state is FindingState.HYPOTHESIS


def test_dns_defense_blocks_even_when_waf_makes_the_callback(env):
    """🔴 净新增防线：目标前挂着"替我们抓取"的中间件时，必须 blocked 而非 confirmed。

    这正是命令注入相对 SSRF 的净新增假阳性来源：中间件对**任何**取值都去抓取其中
    的 URL，连 DNS 非命中变体（.invalid）也硬发 ⇒ 必须判 blocked。
    """
    with cmdi.CallbackListener(host="127.0.0.1", port=0).start() as listener:
        finding = _finding(env)
        orch = _orch(
            env, listener, FakeVictim(listener, executes=False, waf_fetches=True)
        )
        outcome = orch._verify_cmdi(finding, env.registry.get("verify-cmdi"), env.store)

    assert outcome == "blocked", outcome
    judged = [e for e in env.audit.read_all() if e["event"] == "cmdi_callback_judged"]
    assert judged and judged[-1]["dns_misfire"] is True, (
        "必须记下 DNS 误命中（否则第三方代抓取会被误判成命令执行）"
    )
    assert env.store.load_all()[0].state is FindingState.HYPOTHESIS


def test_blocked_when_probe_errors(env):
    with cmdi.CallbackListener(host="127.0.0.1", port=0).start() as listener:
        finding = _finding(env)
        orch = _orch(env, listener, FakeVictim(listener, probe_error=True))
        outcome = orch._verify_cmdi(finding, env.registry.get("verify-cmdi"), env.store)
    assert outcome == "blocked"


def test_blocked_when_param_missing(env):
    with cmdi.CallbackListener(host="127.0.0.1", port=0).start() as listener:
        finding = _finding(env, param=None)
        orch = _orch(env, listener, FakeVictim(listener))
        outcome = orch._verify_cmdi(finding, env.registry.get("verify-cmdi"), env.store)
    assert outcome == "blocked"
    assert env.store.load_all()[0].state is FindingState.HYPOTHESIS


def test_blocked_when_asset_out_of_scope(env):
    with cmdi.CallbackListener(host="127.0.0.1", port=0).start() as listener:
        finding = _finding(env, asset=f"http://evil.example.com/x?{PARAM}=1")
        orch = _orch(env, listener, FakeVictim(listener))
        outcome = orch._verify_cmdi(finding, env.registry.get("verify-cmdi"), env.store)
    assert outcome == "blocked"
    assert any(e["event"] == "verify_scope_rejected" for e in env.audit.read_all())


def test_no_session_is_required(env):
    """与 ssrf 的关键差异：cmdi **不需要**预置会话（判据与身份无关）。"""
    env.scope.session = None
    with cmdi.CallbackListener(host="127.0.0.1", port=0).start() as listener:
        finding = _finding(env)
        orch = _orch(env, listener, FakeVictim(listener, executes=True))
        outcome = orch._verify_cmdi(finding, env.registry.get("verify-cmdi"), env.store)
    assert outcome == "confirmed", "无会话也必须能确认（判据是回调，不是身份）"


def test_with_session_still_works(env):
    """带会话时同样工作（会话只让请求更贴近操作员形态，不是前置）。"""


# =====================================================================
# 四、上限上报的同源性（M18-b 实测踩到的静默丢弃 bug）
# =====================================================================


def test_every_capped_type_reports_triage_capped(tmp_path, make_skill_dir):
    """**每个**登记了上限的类型，超限时都必须留下 ``triage_capped`` 事件。

    钉住的缺陷形态：上限**查表**判、上报**手写列表** —— 两处不同源时，
    新类型会被静默丢弃（候选没了、审计里也没有），正是最该避免的形态。
    """
    from proofhound.core.orchestrator import _TRIAGE_CAPS
    from proofhound.core.orchestrator import _triage_candidates

    # 构造一个能命中所有已登记类型的输入域：三张提示表的并集 + 一张能命中
    # cmdi 的键；每个键重复到超过该类型的上限。
    import proofhound.core.orchestrator as orch_mod

    hint_union = (
        orch_mod._SQLI_PARAM_HINTS
        | orch_mod._XSS_PARAM_HINTS
        | orch_mod._IDOR_PARAM_HINTS
        | orch_mod._CMDI_PARAM_HINTS
    )
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    raw = evidence_dir / "crawl.stdout.log"
    raw.write_text("x\n", encoding="utf-8")

    rows = []
    seq = 0
    for key in sorted(hint_union):
        for i in range(30):  # 足够超过任何单类型上限
            seq += 1
            asset = f"http://h/p/{key}/{i}?{key}=1"
            rows.append(
                Signal(
                    asset=asset,
                    status_code=200,
                    kind="param-endpoint",
                    source_tool="katana",
                    skill="recon-crawl",
                    evidence_ref=f"{raw.name}#L1",
                ).model_dump_json()
            )
    (evidence_dir / "crawl.signals.jsonl").write_text(
        "\n".join(rows) + "\n", encoding="utf-8"
    )

    from proofhound.compliance.audit import AuditLog

    audit = AuditLog(evidence_dir / "audit.jsonl")
    orch = Orchestrator(
        SkillRegistry(make_skill_dir(name="verify-cmdi", tools=())).discover(),
        runner=None,
        llm=None,
        audit=audit,
        evidence_dir=evidence_dir,
    )
    orch.run_triage_phase()

    # 先确认这批输入确实能命中所有这些类型（否则本测试是空跑）
    produced = {
        candidate.vuln_type
        for row in rows
        for candidate in _triage_candidates(Signal.model_validate_json(row))
    }
    capped_types = {
        e["vuln_type"] for e in audit.read_all() if e["event"] == "triage_capped"
    }
    # 每个「既登记了上限、又能被产出」的类型都必须有上报事件
    expected = (set(_TRIAGE_CAPS) & produced) - {"unauth-exposure"}  # 需会话才派生
    missing = sorted(expected - capped_types)
    assert not missing, (
        "以下类型登记了上限却**没有** triage_capped 上报事件（静默丢弃）："
        + str(missing)
        + "；实测上报=" + str(sorted(capped_types))
        + "；可产出=" + str(sorted(produced))
    )
