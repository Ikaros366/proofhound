"""M25-a：``python -m proofhound.xxeprobe`` 的端到端测试（真 TCP，零外网）。

靶复用 ``scripts/demo_xxe.py`` 的 :class:`XxeTargetServer`（同一份六靶实现，
避免测试与实弹两套仿真漂移）。这里钉住的是**命令行这一层**：

- 三态与**通道归位**（file / callback 各自独立）；
- 退出码 0/1/2 的语义（2 是结构性失败，不是"测过且安全"）；
- 证据文件（``probe_*.json`` 无正文、``response_*.txt`` 0600 且脱敏、
  ``summary.json`` 连跑两次逐字节一致、``summary.md`` 不含 canary 签名）；
- 四条结构性边界：scope 越界零请求、白名单默认拒绝、实体膨胀拒发、
  每端点 ≤4 次请求。
"""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用 demo 靶（test_demo_killer 先例）

import demo_xxe  # noqa: E402

from proofhound import xxeprobe  # noqa: E402
from proofhound.verify import xxe  # noqa: E402
from proofhound.verify.ssrf import SsrfListenerError  # noqa: E402

COOKIE = "test-cookie-9f3c2a7b5d1e4f68"
SHADOW_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [
  <!ENTITY alive "PROOFHOUND&#45;ALIVE">
  <!ENTITY x SYSTEM "file:///etc/shadow">
]>
<r><value>&x;</value><ctrl>&alive;</ctrl></r>
"""


@pytest.fixture()
def target():
    with demo_xxe.XxeTargetServer() as server:
        yield server


def write_scope(
    path: Path, port: int, *, ports: list[int] | None = None, cookie: str | None = None
) -> Path:
    lines = ["networks: [127.0.0.0/8]", f"ports: {json.dumps(ports or [port])}"]
    if cookie:
        lines += ["session:", "  cookies:", f"    phsess: {cookie}"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def run_cli(
    target,
    scope: Path,
    out_dir: Path,
    *,
    path: str = "/soap/file",
    extra: list[str] | None = None,
    wait: float = 0.2,
) -> int:
    argv = [
        "--url",
        target.url(path),
        "--scope",
        str(scope),
        "--out",
        str(out_dir),
        "--callback-host",
        "127.0.0.1",
        "--callback-wait",
        str(wait),
        "--timeout",
        "5",
    ]
    argv.extend(extra or [])
    return xxeprobe.main(argv)


def read_summary(out_dir: Path) -> dict:
    return json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))


def audit_events(out_dir: Path) -> list[dict]:
    path = out_dir / "audit.jsonl"
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# =====================================================================
# 一、六个靶的三态与通道
# =====================================================================


def test_file_target_confirms_file_channel(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    assert run_cli(target, scope, out) == 0
    summary = read_summary(out)
    assert summary["judgment"]["verdict"] == "confirmed"
    assert summary["judgment"]["channels"] == ["file"]
    assert summary["facts"]["file_canary_hit"] is True
    assert summary["facts"]["callback_hit"] is False
    for name in (
        "probe_1.json",
        "probe_2.json",
        "probe_3.json",
        "probe_4.json",
        "response_1.txt",
        "response_2.txt",
        "response_3.txt",
        "response_4.txt",
        "judgment.json",
        "summary.json",
        "summary.md",
        "audit.jsonl",
    ):
        assert (out / name).is_file(), name


def test_file_probe_carries_real_passwd_content(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    run_cli(target, scope, out)
    leaked = (out / "response_2.txt").read_text(encoding="utf-8", errors="replace")
    assert "root:x:0:0" in leaked
    assert stat.S_IMODE((out / "response_2.txt").stat().st_mode) == 0o600


def test_fault_target_confirms_despite_500(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    assert run_cli(target, scope, out, path="/soap/fault") == 0
    summary = read_summary(out)
    assert summary["judgment"]["verdict"] == "confirmed"
    assert summary["judgment"]["channels"] == ["file"]
    assert summary["probes"][1]["status"] == 500  # 500 + faultstring ≠ blocked
    assert summary["facts"]["alive_replaced"] is True


def test_oob_target_confirms_callback_channel(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    assert run_cli(target, scope, out, path="/soap/oob", wait=2.0) == 0
    summary = read_summary(out)
    assert summary["judgment"]["verdict"] == "confirmed"
    assert summary["judgment"]["channels"] == ["callback"]
    assert summary["facts"]["callback_hit"] is True
    assert summary["facts"]["callback_control_hit"] is False
    judgment = json.loads((out / "judgment.json").read_text(encoding="utf-8"))
    assert len(judgment["callbacks"]["probe_hits"]) >= 1
    assert judgment["callbacks"]["control_hits"] == []
    # token 只以 sha256 前 8 位出现在证据里
    for hit in judgment["callbacks"]["probe_hits"]:
        assert hit["token_sha8"].startswith("sha256:")
        assert len(hit["token_sha8"]) == len("sha256:") + 8


def test_safe_target_rejects(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    assert run_cli(target, scope, out, path="/soap/safe") == 1
    summary = read_summary(out)
    assert summary["judgment"]["verdict"] == "rejected"
    assert summary["facts"]["alive_replaced"] is True
    assert summary["judgment"]["channels"] == []


def test_echo_target_rejects_without_false_confirm(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    assert run_cli(target, scope, out, path="/soap/echo") == 1
    summary = read_summary(out)
    assert summary["judgment"]["verdict"] == "rejected"
    echoed = (out / "response_2.txt").read_text(encoding="utf-8", errors="replace")
    assert "file:///etc/passwd" in echoed  # 路径字样出现了
    assert "root:x:0:0" not in echoed  # 但内容没有 ⇒ 不是证据
    assert summary["facts"]["alive_literal_echoed"] is True


def test_error_target_blocks(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    assert run_cli(target, scope, out, path="/soap/error") == 1
    summary = read_summary(out)
    assert summary["judgment"]["verdict"] == "blocked"
    assert "阳性对照未被替换" in summary["judgment"]["reasons"][0]


# =====================================================================
# 二、结构性边界
# =====================================================================


def test_scope_rejected_sends_zero_requests(target, tmp_path):
    scope = write_scope(tmp_path / "narrow.yaml", target.port, ports=[1])
    out = tmp_path / "run"
    assert run_cli(target, scope, out) == 2
    assert target.requests == []
    events = [event["event"] for event in audit_events(out)]
    assert "xxe_scope_rejected" in events
    assert not (out / "summary.json").exists()


def test_template_with_non_whitelisted_file_is_refused(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    template = tmp_path / "shadow.xml"
    template.write_text(SHADOW_TEMPLATE, encoding="utf-8")
    out = tmp_path / "run"
    assert run_cli(target, scope, out, extra=["--body-template", str(template)]) == 2
    assert target.requests == []
    events = [event["event"] for event in audit_events(out)]
    assert "xxe_file_rejected" in events


def test_allow_file_records_override_and_proceeds(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    template = tmp_path / "shadow.xml"
    template.write_text(SHADOW_TEMPLATE, encoding="utf-8")
    out = tmp_path / "run"
    code = run_cli(
        target,
        scope,
        out,
        extra=["--body-template", str(template), "--allow-file", "/etc/shadow"],
    )
    assert code == 1  # 没有已知签名 ⇒ 内容通道零覆盖 ⇒ blocked（不驳回）
    assert target.requests, "放行后必须真的发出请求"
    events = [event["event"] for event in audit_events(out)]
    assert "xxe_file_override" in events
    summary = read_summary(out)
    assert summary["canary"]["available"] is False
    assert summary["judgment"]["verdict"] == "blocked"


def test_request_count_per_endpoint_at_most_four(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    run_cli(target, scope, out)
    assert len(target.requests) == 4 == xxe.MAX_REQUESTS_PER_ENDPOINT


def test_no_entity_amplification_in_sent_bodies(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    run_cli(target, scope, tmp_path / "run")
    assert target.requests
    for item in target.requests:
        assert xxe.entity_amplification_reasons(item.body) == ()
        text = item.body.decode("utf-8")
        assert text.count("SYSTEM") <= 1


def test_session_headers_are_injected(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port, cookie=COOKIE)
    run_cli(target, scope, tmp_path / "run")
    assert all(COOKIE in item.headers.get("cookie", "") for item in target.requests)


def test_missing_scope_file_exits_2(target, tmp_path):
    code = xxeprobe.main(["--url", target.url("/soap/file"), "--scope", str(tmp_path / "nope.yaml")])
    assert code == 2


def test_missing_template_exits_2(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    code = run_cli(
        target,
        scope,
        tmp_path / "run",
        extra=["--body-template", str(tmp_path / "nope.xml")],
    )
    assert code == 2


def test_listener_failure_exits_2(target, tmp_path, monkeypatch):
    scope = write_scope(tmp_path / "lab.yaml", target.port)

    class _Boom:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            raise SsrfListenerError("绑定失败（测试用）")

        def close(self):
            pass

    monkeypatch.setattr(xxeprobe, "CallbackListener", _Boom)
    code = run_cli(target, scope, tmp_path / "run")
    assert code == 2
    assert target.requests == []
    events = [event["event"] for event in audit_events(tmp_path / "run")]
    assert "xxe_listener_failed" in events


# =====================================================================
# 三、证据与审计
# =====================================================================


def test_evidence_never_contains_session_cookie(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port, cookie=COOKIE)
    out = tmp_path / "run"
    run_cli(target, scope, out)
    for path in out.iterdir():
        if path.is_file():
            assert COOKIE.encode() not in path.read_bytes(), path.name


def test_probe_json_has_no_body(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    run_cli(target, scope, out)
    text = (out / "probe_2.json").read_text(encoding="utf-8")
    assert "file://" not in text
    assert "&x;" not in text
    payload = json.loads(text)
    assert payload["probe"] == "file"
    assert payload["canary_hit"] is True
    assert payload["alive_seen"] is True


def test_summary_md_has_no_canary_signature(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    run_cli(target, scope, out)
    text = (out / "summary.md").read_text(encoding="utf-8")
    assert "root:x:0:0" not in text
    # 但结论本身要在：confirmed + 通道
    assert "CONFIRMED" in text and "file" in text


def test_summary_json_is_byte_identical_across_runs(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    first = tmp_path / "a"
    second = tmp_path / "b"
    run_cli(target, scope, first)
    run_cli(target, scope, second)
    assert (first / "summary.json").read_bytes() == (second / "summary.json").read_bytes()


def test_summary_json_has_no_timestamp_or_out_dir(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    run_cli(target, scope, out)
    text = (out / "summary.json").read_text(encoding="utf-8")
    assert str(out) not in text
    assert "T00:" not in text
    assert "generated_at" not in text


def test_audit_records_the_expected_events(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    run_cli(target, scope, out)
    events = [event["event"] for event in audit_events(out)]
    assert events[0] == "xxe_started"
    assert events.count("xxe_probe_attempt") == 4
    assert "xxe_listener_started" in events
    assert "xxe_judged" in events
    assert events[-1] == "xxe_completed"

    judged = next(event for event in audit_events(out) if event["event"] == "xxe_judged")
    assert judged["verdict"] == "confirmed"
    assert judged["channels"] == ["file"]


def test_judgment_records_both_channels_and_negatives(target, tmp_path):
    scope = write_scope(tmp_path / "lab.yaml", target.port)
    out = tmp_path / "run"
    run_cli(target, scope, out)
    payload = json.loads((out / "judgment.json").read_text(encoding="utf-8"))
    facts = payload["facts"]
    assert facts["file_canary_hit"] is True
    assert facts["baseline_canary_hit"] is False
    assert facts["negative_canary_hit"] is False
    assert facts["callback_control_hit"] is False
    assert facts["all_probes_answered"] is True
    assert "canary_signature" in facts


# =====================================================================
# 四、平台/入口的静态契约
# =====================================================================


def test_cli_layer_stays_out_of_the_registry():
    """分层意图（M30 重述）：**CLI 层**不碰登记表，登记在编排层完成。

    M25-a 时的写法是"assert xxe 不在 VULN_REGISTRY"——那是对**当时状态**的断言，
    不是对分层纪律的断言；M30 登记之后它会假阳性地失败。真正要守的是：CLI 模块
    不 import 也不写 gate，登记表由编排层维护。
    """
    import inspect

    from proofhound import xxeprobe
    from proofhound.verify.gate import VULN_REGISTRY

    source = inspect.getsource(xxeprobe)
    assert "VULN_REGISTRY" not in source
    assert "proofhound.verify.gate" not in source
    # 登记表本身由编排层接上（M30），CLI 只提供判定与证据
    assert "xxe" in VULN_REGISTRY
    assert VULN_REGISTRY["xxe"].behavioral_kinds == frozenset({"xml-entity-resolution"})
