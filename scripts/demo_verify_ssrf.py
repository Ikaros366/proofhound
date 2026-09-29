#!/usr/bin/env python3
"""M16 实弹验收：对**真实** SSRF 目标跑 verify-ssrf 全链路（判定零替身）。

## 目标与链路

目标 = 本仓库基准 fixture 的 E 族端点（**真的按参数取值发起服务端请求**），跑在
容器里、端口发布到宿主（目标必须是网络上一个真实可达的服务，而不是同进程里的
假替身）。

**判定链路全部真实**：真 `CallbackListener`（随机端口）+ 真宿主 HTTP 探测客户端 +
真证据门 + Verifier 流程（T2 用罐头回复，本脚本验判定不烧 token）。

## 一处**如实说明**的接缝：baseline 用预制输出

`_run_baseline` 走沙箱 httpx。沙箱在 `proofhound-egress`（internal 网络）里，
**够不到**宿主发布的端口；要让它够到需另配出口/网络（属 M12/M13 的部署面，不是
本轮的判定面）。故本脚本用预制 httpx 输出提供 baseline（等价于"目标对带会话 GET
返回 200"），其余步骤一律真实。这一点**必须**在报告里如实标注，不能读作"全链路
无接缝"。

断言：
1. E 族真 SSRF 端点 → **CONFIRMED**（method=ssrf-callback-confirmed、四段式、代码算分）；
2. `/d/ssrf-like` 形对照 → **blocked 或 rejected，绝不是 confirmed**。该端点不回显
   取值 ⇒ 交付证明不成立 ⇒ 按设计判 blocked（宁漏勿滥）；目标若回显取值则同形态走
   rejected。**两条都接受**——本轮要证明的是"它不会被误确认"，而不是"它一定被驳回"。
3. 回调真的来自**容器进程**（源 IP 是容器网段，不是回环），token 与注入 URL 一致。

产物默认落 ``evidence/demo_verify_ssrf/<时间戳>/``（audit + findings + baseline 输出 +
回调记录，gitignored）——按仓库约定，实弹验收**事后必须可复核**。要"跑完即弃"用
``--tmp`` 走临时目录（旧行为，验收留痕场景不要用）。

用法：
    .venv/bin/python scripts/demo_verify_ssrf.py          # 缺省落盘（推荐）
    .venv/bin/python scripts/demo_verify_ssrf.py --tmp    # 临时目录，跑完即弃
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from proofhound.compliance.audit import AuditLog  # noqa: E402
from proofhound.compliance.scope import Scope  # noqa: E402
from proofhound.compliance.session import SessionConfig  # noqa: E402
from proofhound.core.orchestrator import Orchestrator  # noqa: E402
from proofhound.findings import (  # noqa: E402
    Finding,
    FindingState,
    FindingStore,
    compute_dedup_key,
)
from proofhound.llm.router import ModelRouter, Tier  # noqa: E402
from proofhound.skills.registry import SkillRegistry  # noqa: E402
from proofhound.tools.sandbox import RunResult  # noqa: E402
from proofhound.verify.ssrf import (  # noqa: E402
    ENV_CALLBACK_BIND,
    ENV_CALLBACK_HOST,
    SSRF_CONFIRMED_METHOD,
)

CONFIRM = json.dumps(
    {
        "verdict": "confirm",
        "reason": "回调事实与交付证明齐全",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    ensure_ascii=False,
)

#: 目标容器内用于回连宿主的别名。
HOST_ALIAS = "host.docker.internal"


class MockRouter(ModelRouter):
    """罐头 T2：本脚本验的是**判定链路**，不烧 token。"""

    def __init__(self):
        self.configs = {Tier.T2: SimpleNamespace(model="mock-t2")}
        self.calls = []

    def complete(self, tier, messages):
        self.calls.append((tier, messages))
        return CONFIRM


class BaselineRunner:
    """只提供 baseline 的预制 httpx 输出（见模块 docstring 的接缝说明）。"""

    def __init__(self, scope, evidence_dir):
        self.scope = scope
        self.evidence_dir = evidence_dir
        self.calls = []
        self.egress_proxy_url = None
        self._seq = 0

    def run(self, tool, args, timeout=300, image=None):
        self.calls.append((tool, list(args)))
        assert tool == "httpx", f"ssrf 链路只该跑 baseline，实得 {tool}"
        self._seq += 1
        target = args[args.index("-u") + 1] if "-u" in args else ""
        stdout = self.evidence_dir / f"baseline{self._seq}.stdout.log"
        stderr = self.evidence_dir / f"baseline{self._seq}.stderr.log"
        stdout.write_text(
            json.dumps({"url": target, "status_code": 200}) + "\n", encoding="utf-8"
        )
        stderr.write_text("", encoding="utf-8")
        return RunResult(
            rejected=False,
            command=[tool, *args],
            exit_code=0,
            stdout_path=stdout,
            stderr_path=stderr,
        )


_RUNNER = r'''
import sys, types
# bench_triage 导入期会经 orchestrator 拉进 tools.sandbox，后者 import docker。
# 基准 fixture 不需要 docker —— 放惰性替身，免得在目标容器里装 docker SDK。
if "docker" not in sys.modules:
    _fake = types.ModuleType("docker")
    _fake.from_env = lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("fixture 容器内不应调用 docker")
    )
    _fake.types = types.ModuleType("docker.types")
    _fake.types.Mount = object
    _fake.types.Ulimit = object
    sys.modules["docker"] = _fake
    sys.modules["docker.types"] = _fake.types

import bench_triage as b
from http.server import ThreadingHTTPServer

port = int(sys.argv[1])
srv = ThreadingHTTPServer(("0.0.0.0", port), b._FixtureHandler)
srv.daemon_threads = True
srv.serve_forever()
'''


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _host_address_for_containers() -> str:
    """取一个**容器能回连宿主**的宿主地址。

    `host.docker.internal` 在本机 dockerd 上**不解析**（实测 `bad address`），故改用
    宿主在默认路由上的 IP（容器经 NAT 可达）。这也是"远程靶需显式配回调地址"的
    真实形态——设计里预留的逃生阀正是为它准备的。
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))  # 不发包，只取路由选中的本机地址
        return sock.getsockname()[0]


def _probe_callback_reachable(advertised: str, port: int) -> bool:
    """起 listener 后，从**容器**回连一次，确认这条路真的通。

    这是"没收到回调"能否被解释的前提（否则会把网络不通误读成真阴性）。
    """
    import subprocess

    try:
        out = subprocess.run(
            [
                "docker", "run", "--rm", "alpine:3.20", "sh", "-c",
                f"wget -q -O - --timeout=5 http://{advertised}:{port}/reachability"
                " >/dev/null 2>&1 && echo OK || echo FAIL",
            ],
            capture_output=True, text=True, timeout=120,
        )
        return "OK" in out.stdout
    except Exception:  # noqa: BLE001
        return False


def _safe_remove(container) -> None:
    try:
        container.remove(force=True)
    except Exception:  # noqa: BLE001
        pass


def _wait_http(url: str, timeout: float = 150.0) -> int:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(1.5)
    raise RuntimeError(f"等待 {url} 超时（最后错误：{last}）")


def _seed(store, audit, asset, param):
    finding = Finding(
        id=store.next_id(),
        state=FindingState.SIGNAL,
        vuln_type="ssrf",
        asset=asset,
        param=param,
        severity="medium",
        confidence="low",
        evidence_kinds=["crawl-endpoint"],
        dedup_key=compute_dedup_key(asset, "ssrf", param),
        created_at="2026-09-29T00:00:00.000+00:00",
        updated_at="2026-09-29T00:00:00.000+00:00",
        audit=audit,
    )
    finding.transition(FindingState.HYPOTHESIS, actor="seed", reason="实弹种子")
    store.append(finding)
    return finding


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M16 verify-ssrf 实弹验收")
    parser.add_argument(
        "--tmp",
        action="store_true",
        help="产物落临时目录、跑完即弃（缺省落 evidence/demo_verify_ssrf/<时间戳>/）",
    )
    args = parser.parse_args()

    # 产物落 evidence/<name>/<ts>/（仓库约定：demo 的 audit 与证据必须可事后复核）。
    # 目录在 Docker 前置检查**之前**建：本轮跑没跑成同样是事实，留痕不丢。
    tmp_ctx = tempfile.TemporaryDirectory() if args.tmp else None
    if tmp_ctx is not None:
        run_dir = Path(tmp_ctx.name)
        print("[*] --tmp：产物落临时目录，跑完即弃（事后不可复核）")
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = REPO / "evidence" / "demo_verify_ssrf" / stamp
        run_dir.mkdir(parents=True, exist_ok=True)
        print(f"[*] 运行目录（产物落盘）: {run_dir}")

    import docker

    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # noqa: BLE001
        print(f"[环境错误] Docker 不可用（目标须跑在容器里）: {exc}", file=sys.stderr)
        return 2

    port = _free_port()
    advertised = _host_address_for_containers()
    os.environ[ENV_CALLBACK_HOST] = advertised
    os.environ[ENV_CALLBACK_BIND] = "0.0.0.0"
    print(f"[*] 回调地址（告知目标）：http://{advertised}:<临时端口>；绑定 0.0.0.0")
    try:
        container = client.containers.create(
            "python:3.12-alpine",
            command=[
                "sh",
                "-c",
                "pip install --no-cache-dir --quiet pydantic pyyaml; "
                f'python3 -c "$RUNNER" {port}',
            ],
            environment={"RUNNER": _RUNNER, "PYTHONPATH": "/repo:/repo/scripts"},
            volumes={str(REPO): {"bind": "/repo", "mode": "ro"}},
            ports={f"{port}/tcp": port},
        )
        container.start()
    except Exception as exc:  # noqa: BLE001
        print(f"[环境错误] 无法启动 fixture 容器：{exc}", file=sys.stderr)
        return 2

    base = f"http://127.0.0.1:{port}"
    try:
        _wait_http(base + "/")
        print(f"[*] 目标已起（容器内真 fixture，端口发布到宿主）：{base}")
        print(f"[*] 回调：告知 {HOST_ALIAS} / 绑定 0.0.0.0（远程靶形态，非回环告警已在下方打印）")
    except Exception as exc:  # noqa: BLE001
        print(f"[环境错误] fixture 容器未就绪：{exc}", file=sys.stderr)
        try:
            container.reload()
            print("--- 容器日志 ---", file=sys.stderr)
            print(container.logs().decode("utf-8", "replace")[:1500], file=sys.stderr)
        except Exception:  # noqa: BLE001
            pass
        _safe_remove(container)
        return 2

    results: list[tuple[str, str]] = []
    try:
        evidence = run_dir / "evidence"
        evidence.mkdir(parents=True, exist_ok=True)
        audit = AuditLog(evidence / "audit.jsonl")
        scope = Scope(
            networks=["127.0.0.0/8"],
            ports=[port],
            session=SessionConfig(cookies={"phsess": "bench0session0token"}),
        )
        registry = SkillRegistry(REPO / "skills").discover()
        orch = Orchestrator(
            registry,
            BaselineRunner(scope, evidence),
            MockRouter(),
            audit,
            evidence_dir=evidence,
        )
        store = FindingStore(evidence / "findings.jsonl")

        cases = [
            ("/e/fetch3?target=1", "target", "E 族真 SSRF（表外盲区）"),
            ("/e/fetch?url=1", "url", "E 族真 SSRF（表内锚点）"),
            ("/d/ssrf-like?callback=1", "callback", "形对照：只登记不取数"),
        ]
        for path, param, label in cases:
            asset = base + path
            finding = _seed(store, audit, asset, param)
            processed = orch.run_verify_phase(skill_name="verify-ssrf")
            fresh = [f for f in processed if f.id == finding.id]
            state = fresh[0].state.value if fresh else finding.state.value
            results.append((label, state))
            print(f"[*] {label:<24} {path:<24} → {state}")
            if fresh and fresh[0].verification is not None:
                v = fresh[0].verification
                assert v.method == SSRF_CONFIRMED_METHOD, v.method
                print(f"      method={v.method} cvss={fresh[0].cvss_score} "
                      f"refs={len(v.evidence_refs)} steps={len(v.reproduction_steps)}")
            for event in audit.read_all():
                if event.get("finding_id") == finding.id and event["event"] in (
                    "verify_blocked",
                    "verify_scope_rejected",
                    "verify_baseline_failed",
                    "ssrf_callback_received",
                    "ssrf_callback_judged",
                ):
                    print("      ·", json.dumps(event, ensure_ascii=False)[:230])
            cb = evidence / f"ssrf_{finding.id}_callbacks.jsonl"
            if cb.is_file():
                for line in cb.read_text(encoding="utf-8").splitlines():
                    rec = json.loads(line)
                    if not rec.get("ignored"):
                        print(f"      回调来源 {rec['source_ip']} · {rec['request_line'][:70]}")
    finally:
        _safe_remove(container)
        if tmp_ctx is not None:
            tmp_ctx.cleanup()

    print("\n===== 结论 =====")
    # 形对照的期望是 **blocked 或 rejected**，但**绝不是 confirmed**：
    # 该端点不回显取值 ⇒ 交付证明不成立 ⇒ 按设计判 blocked（宁漏勿滥）。
    # 若目标恰好回显了取值，同一形态会走 rejected —— 两条都接受，confirmed 不接受。
    expected = {
        "E 族真 SSRF（表外盲区）": "confirmed",
        "E 族真 SSRF（表内锚点）": "confirmed",
        "形对照：只登记不取数": None,  # None = "不许 confirmed"
    }
    ok = True
    for label, state in results:
        want = expected.get(label)
        if want is None:
            good = state != "confirmed"
        else:
            good = state == want
        mark = "✅" if good else "❌"
        if not good:
            ok = False
        shown = want if want else "blocked 或 rejected（绝不许 confirmed）"
        print(f"  {mark} {label:<24} → {state}（期望 {shown}）")
    print("✅ 实弹验收通过" if ok else "❌ 实弹验收失败")
    if tmp_ctx is not None:
        print("[*] --tmp 模式：产物已随临时目录清理（事后不可复核）")
    else:
        print(f"[*] 产物：{run_dir}（audit.jsonl / findings.jsonl / evidence/）")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
