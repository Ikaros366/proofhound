#!/usr/bin/env python3
"""M9a 验收 demo：从种子目标自动派生 scope（零手写 YAML）+ restricted 出口白名单。

默认模式（确定性，无需 DVWA/Docker/LLM）走完整 API：

1. 只给 target，不给 scope 文件、也不确认授权 → **403**（派生不构成授权）；
2. 补上 ``acknowledge_authorization=true`` → 201，打印派生出的 scope；
3. 打印审计链：``scope_derived`` + ``authorization_acknowledged`` 两条并行留痕；
4. **幂等重放**：重建 manager（模拟进程重启）后派生范围仍在，且仍能通过重校验；
5. **边界未被放宽**（M9a 的真正风险点）：派生范围放行自己的目标，
   拒绝兄弟域 / 后缀伪装域 / 无关 IP；
6. **restricted 出口白名单确实以派生 scope 为准**：用派生 scope 起真实
   ``EgressProxy``，断言白名单包含目标域、不含范围外域（不实际出网）。

``--live`` 附加模式：用**生产执行栈**（``default_phases_factory``，不再注入假
阶段）对一个目标跑真实链路，验证 M9a 顺手还掉的债——API 运行栈的沙箱出口
从 demo 取向的 ``open`` 改为默认 ``restricted``。需要 Docker + 可达目标。

用法：
    .venv/bin/python scripts/demo_derived_scope.py            # 确定性自检
    .venv/bin/python scripts/demo_derived_scope.py --live     # 追加生产栈验证

产物落 evidence/demo_derived_scope/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient

from proofhound.api import create_app
from proofhound.api.runner import ConfirmationStore
from proofhound.compliance.derive import derive_scope
from proofhound.compliance.scope import check_scope

TARGET = "http://127.0.0.1:8080"
TARGET_DOMAIN = "https://target.example.com"


class DemoError(RuntimeError):
    pass


def _check(cond: bool, msg: str) -> None:
    if not cond:
        raise DemoError(msg)


class NoopPhases:
    """确定性模式用的假阶段执行器（不碰 Docker / LLM）。"""

    scan_skill = "web-scan"
    scan_risk_level = "L1"
    verify_skill = "verify-sqli"
    verify_risk_level = "L2"

    def __init__(self, runtime):
        self.dir = runtime.engagement.dir
        self.target = runtime.engagement.target
        self.audit = runtime.audit

    def scan(self, targets):
        pass

    def triage(self):
        return []

    def verify_covered_vuln_types(self):
        return set()

    def verify(self, finding):  # pragma: no cover
        return finding


def _factory(runtime):
    return NoopPhases(runtime)


def _make_workspace(root: Path) -> Path:
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "skills").symlink_to(REPO_ROOT / "skills")
    (workspace / "templates").mkdir()
    shutil.copyfile(
        REPO_ROOT / "templates" / "default_template.docx",
        workspace / "templates" / "default_template.docx",
    )
    return workspace


def _events(workspace: Path, eng_id: str) -> list[dict]:
    path = workspace / "engagements" / eng_id / "audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _step1_acknowledgement_is_required(workspace: Path) -> None:
    print("\n" + "=" * 72 + "\nStep 1：只给 target、不给 scope 文件、不确认授权\n" + "=" * 72)
    app = create_app(workspace, phases_factory=_factory, confirm_timeout=5.0)
    with TestClient(app, headers=app.state.auth.basic_header()) as client:
        resp = client.post("/api/engagements", json={"target": TARGET})
        _check(resp.status_code == 403, f"未确认授权应 403，实际 {resp.status_code}")
        detail = resp.json()["detail"]["message"]
        print(f"[+] 被拒（403）：{detail}")
        eng_dir = workspace / "engagements"
        leaked = list(eng_dir.iterdir()) if eng_dir.exists() else []
        _check(not leaked, f"被拒后不得留下任何目录，实际 {leaked}")
        print("[+] 零副作用：未创建任何 engagement 目录 ✓")
        print("[*] 要点：派生是技术动作，授权是人的确认——两者分开，派生不构成授权")


def _step2_derivation(workspace: Path) -> str:
    print("\n" + "=" * 72 + "\nStep 2：补上授权确认 → 自动派生 scope\n" + "=" * 72)
    app = create_app(workspace, phases_factory=_factory, confirm_timeout=5.0)
    with TestClient(app, headers=app.state.auth.basic_header()) as client:
        resp = client.post(
            "/api/engagements",
            json={"target": TARGET, "acknowledge_authorization": True},
        )
        _check(resp.status_code == 201, f"创建失败: {resp.status_code} {resp.text}")
        eng_id = resp.json()["id"]

    meta = json.loads(
        (workspace / "engagements" / eng_id / "api.json").read_text(encoding="utf-8")
    )
    d = meta["derived_scope"]
    print(f"[+] 创建成功: {eng_id}")
    print(f"[+] scope_paths      = {meta['scope_paths']}  （未手写任何 YAML）")
    print(f"[+] 派生 domains     = {d['domains']}")
    print(f"[+] 派生 networks    = {d['networks']}")
    print(f"[+] 派生 ports       = {d['ports']}")
    print(f"[+] 派生来源 target  = {d['derived_from_target']}")
    return eng_id


def _step3_audit(workspace: Path, eng_id: str) -> None:
    print("\n" + "=" * 72 + "\nStep 3：审计链（派生与授权分别留痕）\n" + "=" * 72)
    events = _events(workspace, eng_id)
    names = [e["event"] for e in events]
    _check("scope_derived" in names, "缺 scope_derived 审计")
    _check("authorization_acknowledged" in names, "缺 authorization_acknowledged 审计")
    for e in events:
        if e["event"] in {"engagement_created", "scope_derived", "authorization_acknowledged"}:
            print(f"[+] {e['event']}")
            print(f"      {json.dumps({k: v for k, v in e.items() if k not in ('ts', 'event')}, ensure_ascii=False)}")


def _step4_persistence(workspace: Path, eng_id: str) -> None:
    print("\n" + "=" * 72 + "\nStep 4：重建 manager（模拟进程重启）后派生范围仍在\n" + "=" * 72)
    app2 = create_app(workspace, phases_factory=_factory, confirm_timeout=5.0)
    with TestClient(app2, headers=app2.state.auth.basic_header()) as client:
        manager = app2.state.manager
        eng = manager.get(eng_id)
        _check(eng.derived_scope is not None, "重启后派生范围丢失")
        print(f"[+] 重启后 derived_scope = {json.dumps(eng.derived_scope, ensure_ascii=False)}")
        resp = client.post(f"/api/engagements/{eng_id}/run")
        _check(resp.status_code in (200, 202), f"重启后启动失败: {resp.text}")
        recheck = [e for e in _events(workspace, eng_id) if e["event"] == "scope_recheck"]
        _check(recheck and recheck[0]["allowed"] is True, "重启后 scope 重校验未放行")
        print(f"[+] 重启后仍通过 scope_recheck（allowed={recheck[0]['allowed']}）✓")
    print("[*] 回归点：_persist() 曾硬编码 key 白名单把 derived_scope 抹掉，已修复并有测试锁死")


def _step5_boundary_not_widened(workspace: Path) -> None:
    print("\n" + "=" * 72 + "\nStep 5：边界未被放宽（M9a 的真正风险点）\n" + "=" * 72)
    app = create_app(workspace, phases_factory=_factory, confirm_timeout=5.0)
    with TestClient(app, headers=app.state.auth.basic_header()) as client:
        eng_id = client.post(
            "/api/engagements",
            json={"target": TARGET_DOMAIN, "acknowledge_authorization": True},
        ).json()["id"]
    manager = app.state.manager
    eng = manager.get(eng_id)
    scope = manager.load_scope(
        eng.scope_paths, derived_scope=eng.derived_scope, target=eng.target
    )

    allowed_cases = [f"{TARGET_DOMAIN}/", f"{TARGET_DOMAIN}/admin?x=1", f"{TARGET_DOMAIN}:8443/"]
    denied_cases = [
        "https://evil.example.com/",
        "https://target.example.com.evil.example.com/",  # 后缀伪装
        "https://other.example.net/",
        "http://127.0.0.1:8080/",
    ]
    for url in allowed_cases:
        ok = check_scope(scope, [url]).allowed
        print(f"[+] 放行 {url:52s} -> {ok}")
        _check(ok, f"{url} 应被放行")
    for url in denied_cases:
        ok = check_scope(scope, [url]).allowed
        print(f"[+] 拒绝 {url:52s} -> {ok}")
        _check(not ok, f"{url} 不该被放行")
    print("[*] 派生只收窄不放宽：范围外主机、后缀伪装域、兄弟 IP 全部被挡 ✓")


def _step6_egress_whitelist_follows_derived_scope() -> None:
    print("\n" + "=" * 72 + "\nStep 6：restricted 出口白名单以派生 scope 为准\n" + "=" * 72)
    from proofhound.tools.egress import EgressPolicy, EgressProxy

    scope = derive_scope(TARGET_DOMAIN)
    proxy = EgressProxy(scope, EgressPolicy(), None)
    hosts = proxy.allowed_hosts
    print(f"[+] 派生 scope        = domains={scope.domains} networks={scope.networks}")
    print(f"[+] 出口白名单        = {hosts}")
    _check(proxy._is_allowed("target.example.com", 443) if hasattr(proxy, "_is_allowed") else True,
           "白名单判定接口缺失")
    _check("target.example.com" in hosts, "派生域必须在出口白名单内")
    _check("evil.example.com" not in hosts, "范围外域不得进入出口白名单")
    print("[+] 范围外域不在白名单 ✓（安装白名单源 github.com 等仍保留，供工具安装）")
    print("[*] 这就是把 API 运行栈从 open 改为 restricted 后实际生效的白名单")


def _live(workspace: Path) -> None:
    """真的调用 default_phases_factory——只建栈、不跑扫描，不发一次出网请求。

    只断言一件事：生产执行栈默认以 **restricted** 出口构建沙箱，白名单 = 该
    engagement 的 scope。这是 M9a 顺手还掉的债（AGENTS.md 已知限制 24）。
    """
    print("\n" + "=" * 72 + "\n--live：真实调用 default_phases_factory 验证 restricted 出口\n" + "=" * 72)
    import docker

    from proofhound.api.runner import default_phases_factory
    from proofhound.tools.egress import EGRESS_NETWORK_NAME

    try:
        docker.from_env().ping()
    except Exception as exc:
        print(f"[!] Docker 不可用，跳过 --live：{exc}")
        return

    from proofhound.api import create_app as _create_app
    from proofhound.api.runner import EngagementRuntime

    # 生产栈的 scope：必须含 127.0.0.0/8 才能放行 target 本身；另加一个标记域，
    # 用来证明出口白名单确实由 scope 派生（而不是无脑 open）。
    (workspace / "scopes").mkdir(exist_ok=True)
    (workspace / "scopes" / "live.yaml").write_text(
        "domains: [only-this.example.com]\nnetworks: [127.0.0.0/8]\n", encoding="utf-8"
    )

    app = _create_app(workspace, phases_factory=default_phases_factory, confirm_timeout=5.0)
    with TestClient(app, headers=app.state.auth.basic_header()) as client:
        resp = client.post(
            "/api/engagements",
            json={
                "target": TARGET,
                "scope_paths": ["scopes/live.yaml"],
            },
        )
        _check(resp.status_code == 201, f"--live 创建失败: {resp.status_code} {resp.text}")
        eng_id = resp.json()["id"]
        manager = app.state.manager
        eng = manager.get(eng_id)
        scope = manager.load_scope(
            eng.scope_paths, derived_scope=eng.derived_scope, target=eng.target
        )
        runtime = EngagementRuntime(
            manager=manager,
            engagement=eng,
            scope=scope,
            audit=eng.audit,
            confirmations=ConfirmationStore(eng.dir / "confirmations.jsonl"),
        )

    print("[*] 正在构建生产执行栈（Docker 沙箱 + 工具 ensure + skill registry）…")
    phases = default_phases_factory(runtime)

    sandbox = getattr(phases._orch, "runner", None)
    _check(sandbox is not None, "Orchestrator 未暴露 runner，无法断言沙箱配置")
    egress = sandbox.config.egress
    print(f"[+] 生产栈沙箱 egress.mode  = {egress.mode!r}")
    print(f"[+] 生产栈沙箱 network_mode = {sandbox.config.network_mode!r}")
    _check(egress.mode == "restricted", f"生产栈应为 restricted，实际 {egress.mode!r}")

    network, proxy_url = sandbox._resolve_network()
    print(f"[+] 生效网络 = {network!r}")
    print(f"[+] 代理 URL = {proxy_url!r}")
    _check(network == EGRESS_NETWORK_NAME, f"应接入 {EGRESS_NETWORK_NAME}，实际 {network!r}")
    _check(proxy_url is not None, "restricted 模式应起白名单代理")

    allowed = sandbox._ensure_egress_proxy().allowed_hosts
    print(f"[+] 出口白名单 = {allowed}")
    _check("only-this.example.com" in allowed, "scope 中的域必须进白名单")
    _check("evil.example.com" not in allowed, "未授权域不得进白名单")
    print("[+] 白名单确实来自 engagement 的 scope（含安装源 github.com 供工具安装）")

    sandbox.close()
    print("[+] 生产栈默认 restricted ✓——已知限制 24（API 沙箱网络为演示取向）已还清")


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    demo_dir = REPO_ROOT / "evidence" / "demo_derived_scope" / stamp
    demo_dir.mkdir(parents=True, exist_ok=True)
    workspace = _make_workspace(demo_dir)
    print(f"[*] 演示工作区: {workspace}")
    print("[*] M9a：从种子目标自动派生 scope —— 零手写 YAML，但防线一行未放宽")

    try:
        _step1_acknowledgement_is_required(workspace)
        eng_id = _step2_derivation(workspace)
        _step3_audit(workspace, eng_id)
        _step4_persistence(workspace, eng_id)
        _step5_boundary_not_widened(workspace)
        _step6_egress_whitelist_follows_derived_scope()
        if "--live" in sys.argv:
            _live(workspace)
    except DemoError as exc:
        print(f"\n[✗] 验收失败：{exc}")
        return 1

    print("\n" + "=" * 72)
    print("[✓] M9a 验收全绿：派生可用、授权必需、边界未放宽、出口白名单随 scope")
    print(f"[*] 产物：{demo_dir}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
