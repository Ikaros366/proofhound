"""M26-a：``python -m proofhound.fastjsonprobe`` 的端到端测试（真 TCP + 本机 HTTP，零外网）。

靶复用 ``scripts/demo_fastjson.py`` 的 :class:`FastjsonTargetServer`（与实弹同一份七靶
实现，避免测试与演示两套仿真漂移；``tests/test_xxeprobe.py`` 先例）。这里钉住的是
**命令行这一层**：

- 三态与**通道归位**（dns / tcp-ldap 各自独立）；
- 退出码 0/1/2 的语义（2 是结构性失败，不是"测过且安全"）；
- 预算（每入口 ≤12）与"命中即停"；
- 证据（``probe_*.json`` 无正文、``response_*.txt`` 0600 且脱敏、token 只留 sha8、
  ``summary.json`` 连跑两次逐字节一致）；
- 四条结构性边界：scope 越界零请求、观察点全不可用即 2、``raw`` 编码、编码协商；
- **静默 TCP 连接的端口归因**（MySQL 是服务端先说话；这是裁定 C3-P1 的落点）。
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用 demo 靶（test_xxeprobe 先例）

import demo_fastjson  # noqa: E402

from proofhound import fastjsonprobe  # noqa: E402
from proofhound.compliance.scope import Scope  # noqa: E402
from proofhound.verify import fastjson as fj  # noqa: E402
from proofhound.verify.observe import LocalStubDnsServer  # noqa: E402

TOKEN_PATTERN = re.compile(rb"phfj_?[0-9a-f]{32}", re.IGNORECASE)


# --------------------------------------------------------------- 固件


def _run(kind: str, tmp_path: Path, **kwargs) -> demo_fastjson.RunResult:
    """默认参数：DNS 窗口压到 0.8s（命中即刻返回，不拖慢套件）。"""
    kwargs.setdefault("dns_wait", 0.8)
    kwargs.setdefault("tcp_wait", 0.4)
    return demo_fastjson.run_once(kind, out_root=tmp_path, **kwargs)


def _main_for(
    target: demo_fastjson.FastjsonTargetServer,
    stub: LocalStubDnsServer,
    tmp_path: Path,
    *extra: str,
    path: str = "dns",
) -> int:
    scope = demo_fastjson.write_scope(
        tmp_path / "scope.yaml", port=int(target.url.rsplit(":", 1)[1])
    )
    return fastjsonprobe.main(
        [
            "--url",
            f"{target.url}/login/{path}",
            "--scope",
            str(scope),
            "--out",
            str(tmp_path / "evidence"),
            "--dns-provider",
            "stub",
            "--dns-api",
            stub.url,
            "--dns-wait",
            "0.8",
            "--tcp-wait",
            "0.3",
            *extra,
        ]
    )


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _audit(out_dir: Path) -> list[dict]:
    path = out_dir / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------------- 三态与通道


@pytest.mark.parametrize("kind", demo_fastjson.TARGETS)
def test_verdict_matches_expected(kind, tmp_path):
    result = _run(kind, tmp_path)
    verdict, channel = demo_fastjson.EXPECTED[kind]
    assert result.report is not None
    assert result.report.judgment.verdict == verdict
    if channel is not None:
        assert result.report.judgment.channels == (channel,)
    else:
        assert result.report.judgment.channels == ()


def test_confirmed_dns_records_attribution(tmp_path):
    result = _run("dns", tmp_path)
    assert result.report.exit_code == 0
    payload = _read_json(result.out_dir / "observations.json")
    assert payload["counts"]["attributed"] >= 1
    attributed = {
        item["probe"] for item in payload["observations"] if item["attributed"]
    }
    assert fj.GADGET_DNS_NESTED in attributed


def test_confirmed_tcp_uses_a_layer_chain(tmp_path):
    """gadget 顺序里 class-cache 排在 ldap-jdbcrowset 之前 ⇒ 这条确认来自 A 层两步链。"""
    result = _run("ldap", tmp_path)
    assert result.report.judgment.channels == ("tcp-ldap",)
    rows = [_read_json(path) for path in sorted(result.out_dir.glob("request_*.json"))]
    hit = [
        row
        for row in rows
        if "java.lang.Class" in row["json"] and "JdbcRowSetImpl" in row["json"]
    ]
    assert hit, "证据里没有 A 层两步链的请求"
    assert result.report.summary["counts"]["gadgets"] == 2


def test_echo_is_never_confirmed(tmp_path):
    result = _run("echo", tmp_path)
    assert result.report.judgment.verdict == "blocked"
    assert result.report.judgment.facts["echo_suspect"] is True
    bodies = b"".join(
        path.read_bytes() for path in sorted(result.out_dir.glob("response_*.txt"))
    )
    assert b"@type" in bodies and b"stub.local" in bodies


def test_prefetch_control_hit_blocks(tmp_path):
    result = _run("prefetch", tmp_path)
    assert result.report.judgment.verdict == "blocked"
    assert result.report.judgment.facts["control_hit"] is True
    assert any("阴性对照命中" in reason for reason in result.report.judgment.reasons)


def test_safe_rejects_after_all_gadgets_refused(tmp_path):
    result = _run("safe", tmp_path)
    judgment = result.report.judgment
    assert judgment.verdict == "rejected"
    assert judgment.facts["all_gadgets_refused"] is True
    assert result.report.summary["counts"]["gadgets"] == len(fj.GADGETS)
    assert result.report.exit_code == 1


def test_swallow_and_plain_block_without_gadgets(tmp_path):
    for kind in ("swallow", "plain"):
        result = _run(kind, tmp_path / kind)
        assert result.report.judgment.verdict == "blocked"
        assert result.report.summary["counts"]["gadgets"] == 0


# --------------------------------------------------------------- 预算


def test_request_budget_never_exceeds_cap(tmp_path):
    result = _run("safe", tmp_path)
    assert len(result.requests) <= fj.MAX_REQUESTS_PER_ENTRY
    assert len(result.requests) == 11  # 1 baseline + 1 对照 + 8 gadget + 1 阴性对照


def test_hit_stops_gadget_phase(tmp_path):
    result = _run("dns", tmp_path)
    # 第一个 gadget 即命中 ⇒ 只发 1 个 gadget；随后是阴性对照与复测
    assert result.report.summary["counts"]["gadgets"] == 1
    assert any(row["role"] == "retest" for row in result.report.summary["probes"])


def test_retest_reuses_gadget_with_fresh_callback(tmp_path):
    result = _run("dns", tmp_path)
    payload = _read_json(result.out_dir / "observations.json")
    probes = {item["probe"] for item in payload["observations"] if item["attributed"]}
    assert fj.GADGET_DNS_NESTED in probes
    assert f"{fj.GADGET_DNS_NESTED}-retest" in probes


# --------------------------------------------------------------- 端口归因（C3-P1）


def test_silent_tcp_connect_confirms_via_port_attribution(tmp_path):
    """MySQL 是服务端先说话：靶连上就静默，命中只能靠**独占端口**归因。"""
    with LocalStubDnsServer(domain="stub.local") as stub:
        with demo_fastjson.FastjsonTargetServer(stub_url=stub.url) as target:
            target.silent_tcp = True
            result = demo_fastjson.run_once(
                "ldap",
                out_root=tmp_path,
                shared=(stub, target),
                dns_wait=0.5,
                tcp_wait=0.4,
            )
    assert result.report.judgment.verdict == "confirmed"
    assert result.report.judgment.channels == ("tcp-ldap",)
    payload = _read_json(result.out_dir / "observations.json")
    observations = payload["observations"]
    assert observations
    for observation in observations:
        assert observation["attributed"] is True
        assert observation["token_sha8"] == ""  # 读不到 token：归因靠端口
        assert observation["source"] == "127.0.0.1"


# --------------------------------------------------------------- 编码与入口形态


def test_raw_json_body_mode(tmp_path):
    result = _run("dns", tmp_path, encoding=fj.ENCODING_RAW)
    assert result.report.judgment.verdict == "confirmed"
    assert result.report.summary["target"]["encoding"] == fj.ENCODING_RAW
    assert result.report.summary["target"]["content_type"] == fj.JSON_CONTENT_TYPE
    # 靶确实按 JSON body 解出来了
    assert any(item.decoded and "@type" in item.decoded for item in result.requests)


def test_encoding_negotiation_falls_back_to_second_variant(tmp_path):
    """第一份阳性对照被静默 ⇒ 补试另一个 base64 变体（§5.4 的编码协商）。"""
    with LocalStubDnsServer(domain="stub.local") as stub:
        with demo_fastjson.FastjsonTargetServer(stub_url=stub.url) as target:
            target.fail_first_parse_control = True
            result = demo_fastjson.run_once(
                "dns",
                out_root=tmp_path,
                encoding=fj.ENCODING_B64,
                shared=(stub, target),
                dns_wait=0.5,
                tcp_wait=0.4,
            )
    assert result.report.judgment.verdict == "confirmed"
    assert result.report.summary["target"]["encoding"] == fj.ENCODING_B64URL
    roles = [row["role"] for row in result.report.summary["probes"]]
    assert roles.count(fj.ROLE_PARSE_CONTROL) == 2  # 主编码静默 ⇒ 补试了一次


def test_json_template_keeps_business_fields(tmp_path):
    template = tmp_path / "captured.json"
    template.write_text('{"logname":"alice","passwd":"x"}', encoding="utf-8")
    out_dir = tmp_path / "evidence"
    with LocalStubDnsServer(domain="stub.local") as stub:
        with demo_fastjson.FastjsonTargetServer(stub_url=stub.url) as target:
            scope = demo_fastjson.write_scope(
                tmp_path / "scope.yaml", port=int(target.url.rsplit(":", 1)[1])
            )
            config = fastjsonprobe.ProbeConfig(
                url=f"{target.url}/login/dns",
                scope=Scope.from_file(scope),
                out_dir=out_dir,
                json_template=template,
                dns_provider="stub",
                dns_api=stub.url,
                dns_wait=0.8,
                tcp_wait=0.4,
            )
            report = fastjsonprobe.run_fastjsonprobe(config)
    assert report.judgment.verdict == "confirmed"
    rows = [_read_json(path) for path in sorted(out_dir.glob("request_*.json"))]
    baseline = rows[0]
    assert json.loads(baseline["json"]) == {"logname": "alice", "passwd": "x"}
    gadget = [
        row for row in rows if "@type" in row["json"] and "Inet4Address" in row["json"]
    ]
    assert gadget, "模板模式下没有发出嵌套 @type 的探针"
    parsed = json.loads(gadget[0]["json"])
    assert parsed["logname"]["@type"] == "java.net.Inet4Address"
    assert parsed["passwd"] == "x"


# --------------------------------------------------------------- 退出码


def test_cli_exit_zero_on_confirmed(tmp_path):
    with LocalStubDnsServer(domain="stub.local") as stub:
        with demo_fastjson.FastjsonTargetServer(stub_url=stub.url) as target:
            assert _main_for(target, stub, tmp_path) == 0
    assert (tmp_path / "evidence" / "judgment.json").is_file()


def test_cli_exit_one_on_rejected(tmp_path):
    with LocalStubDnsServer(domain="stub.local") as stub:
        with demo_fastjson.FastjsonTargetServer(stub_url=stub.url) as target:
            assert _main_for(target, stub, tmp_path, path="safe") == 1


def test_cli_exit_two_without_scope(tmp_path):
    code = fastjsonprobe.main(
        ["--url", "http://127.0.0.1:1/login", "--scope", str(tmp_path / "nope.yaml")]
    )
    assert code == 2


def test_cli_exit_two_when_out_of_scope(tmp_path):
    with LocalStubDnsServer(domain="stub.local") as stub:
        with demo_fastjson.FastjsonTargetServer(stub_url=stub.url) as target:
            port = int(target.url.rsplit(":", 1)[1])
            scope = demo_fastjson.write_scope(
                tmp_path / "scope.yaml", port=port, ports=[port + 1]
            )
            code = fastjsonprobe.main(
                [
                    "--url",
                    f"{target.url}/login/dns",
                    "--scope",
                    str(scope),
                    "--out",
                    str(tmp_path / "evidence"),
                    "--dns-provider",
                    "stub",
                    "--dns-api",
                    stub.url,
                ]
            )
            assert code == 2
            assert not target.requests
    events = [event["event"] for event in _audit(tmp_path / "evidence")]
    assert "fastjson_scope_rejected" in events


def test_cli_exit_two_when_all_observers_unavailable(tmp_path, monkeypatch):
    monkeypatch.setenv("PROOFHOUND_SSRF_CALLBACK_BIND", "192.0.2.123")
    with demo_fastjson.FastjsonTargetServer() as target:
        scope = demo_fastjson.write_scope(
            tmp_path / "scope.yaml", port=int(target.url.rsplit(":", 1)[1])
        )
        code = fastjsonprobe.main(
            [
                "--url",
                f"{target.url}/login/dns",
                "--scope",
                str(scope),
                "--out",
                str(tmp_path / "evidence"),
                "--dns-provider",
                "none",
            ]
        )
        assert code == 2
        assert not target.requests
    events = [event["event"] for event in _audit(tmp_path / "evidence")]
    assert "fastjson_observer_unavailable" in events


# --------------------------------------------------------------- 证据


def test_summary_is_byte_identical_across_runs(tmp_path):
    with LocalStubDnsServer(domain="stub.local") as stub:
        with demo_fastjson.FastjsonTargetServer(stub_url=stub.url) as target:
            first = demo_fastjson.run_once(
                "dns", out_root=tmp_path / "a", shared=(stub, target), dns_wait=0.5
            )
            second = demo_fastjson.run_once(
                "dns", out_root=tmp_path / "b", shared=(stub, target), dns_wait=0.5
            )
    assert (first.out_dir / "summary.json").read_bytes() == (
        second.out_dir / "summary.json"
    ).read_bytes()


def test_evidence_files_are_private(tmp_path):
    result = _run("dns", tmp_path)
    for pattern in ("probe_*.json", "request_*.json", "response_*.txt"):
        paths = list(result.out_dir.glob(pattern))
        assert paths, pattern
        for path in paths:
            assert path.stat().st_mode & 0o777 == 0o600, path


def test_evidence_contains_no_cookie_and_no_raw_token(tmp_path):
    result = _run("ldap", tmp_path)
    for path in result.out_dir.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        assert demo_fastjson.DEMO_COOKIE.encode() not in data, path
        assert not TOKEN_PATTERN.search(data), path


def test_probe_rows_carry_no_response_body(tmp_path):
    result = _run("dns", tmp_path)
    for path in sorted(result.out_dir.glob("probe_*.json")):
        row = _read_json(path)
        assert "body" not in row
        assert set(row) >= {"probe", "role", "status", "answered", "refused", "hit"}


def test_observations_only_carry_sha8(tmp_path):
    result = _run("dns", tmp_path)
    payload = _read_json(result.out_dir / "observations.json")
    text = json.dumps(payload, ensure_ascii=False)
    assert "phfj_" not in text
    assert payload["observations"][0]["token_sha8"].startswith("sha256:")


def test_audit_events_cover_the_flow(tmp_path):
    result = _run("dns", tmp_path)
    events = [event["event"] for event in _audit(result.out_dir)]
    for expected in (
        "fastjson_started",
        "fastjson_probe_attempt",
        "fastjson_observation",
        "fastjson_judged",
        "fastjson_completed",
    ):
        assert expected in events
    judged = [event for event in _audit(result.out_dir) if event["event"] == "fastjson_judged"]
    assert judged[-1]["verdict"] == "confirmed"


def test_control_observed_is_audited_for_prefetch(tmp_path):
    result = _run("prefetch", tmp_path)
    events = [event["event"] for event in _audit(result.out_dir)]
    assert "fastjson_control_observed" in events


def test_summary_has_no_timestamp_or_output_path(tmp_path):
    result = _run("dns", tmp_path)
    text = (result.out_dir / "summary.json").read_text(encoding="utf-8")
    assert "generated_at" not in text
    assert str(tmp_path) not in text
    assert "evidence" not in text
    assert not TOKEN_PATTERN.search(text.encode())
