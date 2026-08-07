#!/usr/bin/env python3
"""M2c Live 演示（不进 pytest）：真实 LLM key + 本地靶标跑完整 web-scan 编排。

链路：本地 http.server 靶标 → ModelRouter（T1 档真实调用，计量 + 预算硬闸）
→ 规划器 → Docker 沙箱 httpx（network_mode=host，egress=open，同 e2e 打法）
→ Signal 落盘 → 打印审计链。

用法：
    .venv/bin/python scripts/demo_live.py                 # 正常跑通（读 .env 的 T1 配置）
    .venv/bin/python scripts/demo_live.py --max-tokens 0  # 低预算演示：首次调用前即被闸

.env 需要：PROOFHOUND_T1_BASE_URL / PROOFHOUND_T1_API_KEY / PROOFHOUND_T1_MODEL
产物（审计、证据、Signal）落 evidence/demo_live/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import argparse
import functools
import json
import sys
import threading
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.core.context import ContextPolicy
from proofhound.core.orchestrator import Orchestrator
from proofhound.llm.client import LLMError
from proofhound.llm.router import ModelRouter, Tier
from proofhound.llm.usage import TokenBudget, UsageTracker
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.egress import EgressPolicy
from proofhound.tools.installer import InstallError, ToolInstaller
from proofhound.tools.manifest import load_manifest
from proofhound.tools.sandbox import SandboxConfig, SandboxRunner

MANIFEST_PATH = REPO_ROOT / "proofhound" / "tools" / "manifests" / "httpx.yaml"
SKILLS_DIR = REPO_ROOT / "skills"
SANDBOX_IMAGE = "alpine:3.20"


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def start_target() -> tuple[ThreadingHTTPServer, str]:
    """自带本地靶标：tmp 目录下一个带标题的 index.html。"""
    import tempfile

    served = Path(tempfile.mkdtemp(prefix="proofhound-target-"))
    (served / "index.html").write_text(
        "<html><head><title>ProofHound Demo Target</title></head>"
        "<body>demo</body></html>",
        encoding="utf-8",
    )
    handler = functools.partial(_QuietHandler, directory=str(served))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M2c live 演示")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="覆盖 env 的 Run 级 token 预算（0 = 首次调用前即被闸，演示硬闸）",
    )
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = REPO_ROOT / "evidence" / "demo_live" / stamp
    evidence_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(evidence_dir / "audit.jsonl")

    # 1. 预算与路由（T1 档真实 key；缺配置给清晰报错）
    try:
        budget = (
            TokenBudget(max_total=args.max_tokens)
            if args.max_tokens is not None
            else TokenBudget.from_env(args.env_file)
        )
        tracker = UsageTracker()
        router = ModelRouter.from_env(args.env_file, audit=audit, tracker=tracker, budget=budget)
    except LLMError as exc:
        print(f"[配置错误] {exc}", file=sys.stderr)
        return 2
    if Tier.T1 not in router.configs:
        print(
            "[配置错误] 未配置 T1 档：请在 .env 提供 PROOFHOUND_T1_BASE_URL / "
            "PROOFHOUND_T1_API_KEY / PROOFHOUND_T1_MODEL",
            file=sys.stderr,
        )
        return 2
    print(f"[*] T1 模型: {router.configs[Tier.T1].model}；预算: "
          f"{budget.max_total if budget else '不限'} tokens/run")

    # 2. 本地靶标 + scope（仅 127.0.0.1 与靶标端口）
    server, base_url = start_target()
    port = int(base_url.rsplit(":", 1)[1])
    scope = Scope(networks=["127.0.0.0/8"], ports=[port])
    print(f"[*] 本地靶标: {base_url}（scope 仅放行 127.0.0.0/8:{port}）")

    # 3. Docker 沙箱 + httpx 工具（白名单源 + SHA256，装入 tools.d/ 持久复用）
    try:
        import docker

        docker_client = docker.from_env()
        docker_client.ping()
    except Exception as exc:
        print(f"[环境错误] Docker 不可用: {exc}", file=sys.stderr)
        return 2
    try:
        docker_client.images.get(SANDBOX_IMAGE)
    except Exception:
        print(f"[*] 拉取沙箱镜像 {SANDBOX_IMAGE} ...")
        docker_client.images.pull(SANDBOX_IMAGE)
    try:
        ToolInstaller(REPO_ROOT / "tools.d").ensure(load_manifest(MANIFEST_PATH))
    except InstallError as exc:
        print(f"[环境错误] httpx 安装失败（需访问 github.com）: {exc}", file=sys.stderr)
        return 2

    runner = SandboxRunner(
        scope,
        audit,
        evidence_dir=evidence_dir,
        tools_dir=REPO_ROOT / "tools.d",
        config=SandboxConfig(
            image=SANDBOX_IMAGE,
            network_mode="host",
            egress=EgressPolicy(mode="open"),
        ),
        client=docker_client,
    )
    registry = SkillRegistry(SKILLS_DIR, audit).discover()
    orch = Orchestrator(
        registry,
        runner,
        router,
        audit,
        evidence_dir=evidence_dir,
        context_policy=ContextPolicy.from_env(args.env_file),
    )

    # 4. 跑 scan 阶段
    print("[*] 启动 web-scan 编排 ...")
    phase = orch.run_scan_phase([base_url])
    server.shutdown()

    print(f"\n[结果] 阶段 {phase.name}: {phase.status.value}")
    for child in phase.children:
        print(f"  - {child.name}: {child.status.value}（attempts={child.attempts}）")

    # 5. Signal 汇总
    print("\n[Signals]")
    for path in sorted(evidence_dir.glob("*.signals.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                s = json.loads(line)
                print(f"  - {s['asset']} status={s.get('status_code')} "
                      f"title={s.get('title')!r} evidence={s['evidence_ref']}")

    # 6. 用量与审计链
    print(f"\n[用量] 合计 {tracker.total_tokens()} tokens（"
          f"{len(tracker.records)} 次调用）")
    for r in tracker.records:
        print(f"  - {r.tier}/{r.model}: prompt={r.prompt_tokens} "
              f"completion={r.completion_tokens} latency={r.latency_ms:.0f}ms "
              f"estimated={r.estimated}")
    print(f"\n[审计链] {audit.path}")
    for e in audit.read_all():
        fields = {k: v for k, v in e.items() if k not in ("ts", "event")}
        print(f"  {e['ts']}  {e['event']}: {json.dumps(fields, ensure_ascii=False)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
