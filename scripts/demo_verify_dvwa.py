#!/usr/bin/env python3
"""M3b DVWA 实靶验收 demo（不进 pytest）：verify-sqli 垂直切片全链路。

链路：DVWA 就绪（容器 + create_db + 确定性登录，零 LLM）→ 预置会话注入
scope（Cookie 不落文件）→ 种子 Hypothesis（正例 sqli / 反例 version-cve +
纯 status-code）→ run_verify_phase（带会话 baseline → 沙箱 sqlmap 确认 →
证据门 → Verifier T2 终审）→ 正例 Confirmed + 离线 show 证据包 → 反例铁律
拦截演示 → 审计链凭据脱敏自检。

用法：
    .venv/bin/python scripts/demo_verify_dvwa.py                     # 默认 http://127.0.0.1:8080
    .venv/bin/python scripts/demo_verify_dvwa.py --dvwa-url http://127.0.0.1:8080

.env 需要：PROOFHOUND_T2_*（Verifier 终审，kimi-k3）；T1 仅用于异模型核对打印。
Docker 必需；vulnerables/web-dvwa 不在本地且不可达时需拉取（daemon 代理）。
产物（审计、证据、findings）落 evidence/demo_verify/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用 seed_finding

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.compliance.session import SessionConfig
from proofhound.core.orchestrator import Orchestrator
from proofhound.findings import FindingState, FindingStore, IronRuleViolationError
from proofhound.llm.client import LLMError
from proofhound.llm.router import ModelRouter, Tier
from proofhound.llm.usage import TokenBudget, UsageTracker
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.egress import EgressPolicy
from proofhound.tools.installer import InstallError, ToolInstaller
from proofhound.tools.manifest import load_manifest
from proofhound.tools.sandbox import SandboxConfig, SandboxRunner
from proofhound.verify.gate import check as gate_check

import seed_finding

SKILLS_DIR = REPO_ROOT / "skills"
MANIFESTS_DIR = REPO_ROOT / "proofhound" / "tools" / "manifests"
SANDBOX_IMAGE = "alpine:3.20"
SQLMAP_IMAGE = "python:3.12-alpine"
DVWA_IMAGE = "vulnerables/web-dvwa:latest"

_USER_TOKEN_RE = re.compile(
    r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]", re.IGNORECASE
)


class DvwaError(RuntimeError):
    """DVWA 就绪/登录/安全配置失败。"""


# ---- DVWA 确定性交互（零 LLM；urllib + cookiejar） ----


def _extract_user_token(html: str) -> str:
    match = _USER_TOKEN_RE.search(html)
    if not match:
        raise DvwaError("页面中未找到 user_token（DVWA 布局变更？）")
    return match.group(1)


def _make_cookie(name: str, value: str, domain: str) -> http.cookiejar.Cookie:
    return http.cookiejar.Cookie(
        version=0, name=name, value=value,
        port=None, port_specified=False,
        domain=domain, domain_specified=False, domain_initial_dot=False,
        path="/", path_specified=True,
        secure=False, expires=None, discard=True,
        comment=None, comment_url=None, rest={}, rfc2109=False,
    )


class DvwaClient:
    """DVWA 的最小确定性客户端：setup → login → security=low → 自检。"""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.host = urllib.parse.urlparse(self.base_url).hostname or "127.0.0.1"
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def probe(self) -> bool:
        try:
            self.opener.open(f"{self.base_url}/login.php", timeout=5)
            return True
        except (urllib.error.URLError, OSError):
            return False

    def get(self, path: str) -> str:
        with self.opener.open(f"{self.base_url}{path}", timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def post(self, path: str, data: dict) -> str:
        payload = urllib.parse.urlencode(data).encode("utf-8")
        with self.opener.open(f"{self.base_url}{path}", data=payload, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def ensure_database(self) -> None:
        html = self.get("/setup.php")
        token = _extract_user_token(html)
        self.post("/setup.php", {
            "create_db": "Create / Reset Database",
            "user_token": token,
        })

    def login(self, username: str = "admin", password: str = "password") -> None:
        html = self.get("/login.php")
        token = _extract_user_token(html)
        body = self.post("/login.php", {
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": token,
        })
        if "Login failed" in body:
            raise DvwaError("DVWA 登录失败（admin/password 被拒）")
        if not any(c.name == "PHPSESSID" for c in self.jar):
            raise DvwaError("登录后未获得 PHPSESSID")

    def set_security_low(self) -> None:
        # DVWA 安全级别存于客户端 cookie；直接置 low（与 security.php 表单等效）
        self.jar.set_cookie(_make_cookie("security", "low", self.host))

    def session_cookies(self) -> dict[str, str]:
        return {c.name: c.value for c in self.jar}

    def assert_low_and_injectable(self) -> None:
        """确定性核验：sqli 页带 id=1' 应回显 MySQL 语法错误（security=low 特征）。"""
        body = self.get("/vulnerabilities/sqli/?id=1%27&Submit=Submit")
        if "First name" not in self.get("/vulnerabilities/sqli/?id=1&Submit=Submit"):
            raise DvwaError("sqli 页未返回预期内容（认证失效？）")
        if "error in your SQL syntax" not in body:
            raise DvwaError("id=1' 未触发 SQL 语法错误回显（security 非 low？）")


def ensure_dvwa(docker_client, base_url: str, port: int):
    """确保 DVWA 可达；不可达则起容器并等待。返回 (client, 我们启动的容器|None)。"""
    client = DvwaClient(base_url)
    container = None
    if client.probe():
        print(f"[*] DVWA 已可达: {base_url}")
    else:
        print(f"[*] DVWA 不可达，启动容器 {DVWA_IMAGE}（127.0.0.1:{port}）...")
        try:
            docker_client.images.get(DVWA_IMAGE)
        except Exception:
            print(f"[*] 拉取镜像 {DVWA_IMAGE} ...")
            docker_client.images.pull(DVWA_IMAGE)
        container = docker_client.containers.run(
            DVWA_IMAGE,
            detach=True,
            name=f"proofhound-dvwa-{datetime.now(timezone.utc).strftime('%H%M%S')}",
            ports={"80/tcp": ("127.0.0.1", port)},
            auto_remove=True,
        )
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if client.probe():
                break
            time.sleep(2)
        else:
            raise DvwaError("DVWA 容器启动后 120s 内未就绪")
        print(f"[*] DVWA 容器就绪: {container.short_id}")
    print("[*] 初始化数据库（setup.php create_db）...")
    client.ensure_database()
    print("[*] 确定性登录（admin/password，零 LLM）...")
    client.login()
    client.set_security_low()
    client.assert_low_and_injectable()
    print("[*] 会话就绪：security=low 且 sqli 页可注入特征已核验")
    return client, container


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M3b DVWA 实靶验收")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument("--dvwa-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.dvwa_url)
    port = parsed.port or 80
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = REPO_ROOT / "evidence" / "demo_verify" / stamp
    evidence_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(evidence_dir / "audit.jsonl")

    # 1. 模型路由（Verifier 走 T2；预算硬闸沿用）
    try:
        budget = TokenBudget.from_env(args.env_file)
        tracker = UsageTracker()
        router = ModelRouter.from_env(args.env_file, audit=audit, tracker=tracker, budget=budget)
    except LLMError as exc:
        print(f"[配置错误] {exc}", file=sys.stderr)
        return 2
    if Tier.T2 not in router.configs:
        print("[配置错误] 未配置 T2 档（Verifier 终审需要）：PROOFHOUND_T2_*", file=sys.stderr)
        return 2
    t1 = router.configs.get(Tier.T1)
    t2 = router.configs[Tier.T2]
    print(f"[*] T1（发现端）: {t1.model if t1 else '未配置'}；T2（Verifier）: {t2.model}")
    if t1 and t1.model == t2.model:
        print("[警告] T1 与 T2 同模型，违反红线 4（Verifier 与发现端须异模型）")

    # 2. Docker + DVWA 就绪
    try:
        import docker

        docker_client = docker.from_env()
        docker_client.ping()
    except Exception as exc:
        print(f"[环境错误] Docker 不可用: {exc}", file=sys.stderr)
        return 2
    try:
        dvwa, dvwa_container = ensure_dvwa(docker_client, args.dvwa_url, port)
    except DvwaError as exc:
        print(f"[环境错误] {exc}", file=sys.stderr)
        return 2

    # 3. 工具与沙箱（httpx 静态二进制走 alpine；sqlmap 走 python 镜像）
    for image in (SANDBOX_IMAGE, SQLMAP_IMAGE):
        try:
            docker_client.images.get(image)
        except Exception:
            print(f"[*] 拉取沙箱镜像 {image} ...")
            docker_client.images.pull(image)
    installer = ToolInstaller(REPO_ROOT / "tools.d")
    for tool in ("httpx", "sqlmap"):
        try:
            result = installer.ensure(load_manifest(MANIFESTS_DIR / f"{tool}.yaml"))
            print(f"[*] 工具 {tool}: {result.status}（{result.detail or result.version}）")
        except InstallError as exc:
            print(f"[环境错误] {tool} 安装失败（需访问白名单源）: {exc}", file=sys.stderr)
            return 2

    # 4. scope + 预置会话（Cookie 只在内存与审计脱敏标记中，不落文件）
    cookies = dvwa.session_cookies()
    scope = Scope(
        networks=["127.0.0.0/8"],
        ports=[port],
        session=SessionConfig(cookies=cookies),
    )
    runner = SandboxRunner(
        scope,
        audit,
        evidence_dir=evidence_dir,
        tools_dir=REPO_ROOT / "tools.d",
        config=SandboxConfig(
            image=SANDBOX_IMAGE, network_mode="host", egress=EgressPolicy(mode="open")
        ),
        client=docker_client,
    )
    registry = SkillRegistry(SKILLS_DIR, audit).discover()
    orch = Orchestrator(registry, runner, router, audit, evidence_dir=evidence_dir)

    # 5. 种子：正例 sqli Hypothesis + 反例 version-cve（纯 status-code）Hypothesis
    sqli_url = f"{args.dvwa_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
    seed_finding.main([
        "--dir", str(evidence_dir), "--asset", sqli_url,
        "--vuln-type", "sqli", "--param", "id",
        "--title", "DVWA sqli id 参数 SQL 注入",
    ])
    seed_finding.main([
        "--dir", str(evidence_dir), "--asset", args.dvwa_url,
        "--vuln-type", "version-cve",
        "--title", "反例：版本匹配型 CVE（纯 status-code 证据）",
    ])

    # 6. verify 阶段（确定性编排；唯一 LLM 调用 = Verifier T2 终审）
    print("\n[*] 启动 verify 阶段（baseline → sqlmap → 证据门 → Verifier）...")
    print("    （sqlmap 实跑约需数分钟）")
    processed = orch.run_verify_phase(skill_name="verify-sqli")
    confirmed_id = None
    for finding in processed:
        print(f"  - {finding.id} [{finding.state.value}] {finding.vuln_type} {finding.asset}")
        if finding.state is FindingState.CONFIRMED:
            confirmed_id = finding.id
            print(f"    method={finding.verification.method} "
                  f"verified_by={finding.verification.verified_by}")
            print(f"    verifier={finding.verifier.model} verdict={finding.verifier.verdict}")
            print(f"    reason={finding.verifier.reason}")
        elif finding.state is FindingState.REJECTED:
            print(f"    rejection_reason={finding.rejection_reason}")

    # 7. 反例：铁律 e2e 再现（version-cve + 纯 status-code 拒转 Confirmed）
    print("\n[*] 反例铁律演示（version-cve 种子）...")
    store = FindingStore(evidence_dir / "findings.jsonl")
    negative = next(f for f in store.load_all() if f.vuln_type == "version-cve")
    gate = gate_check(negative)
    print(f"  - 证据门: passed={gate.passed} missing={gate.missing}")
    # 铁律演示在内存副本上进行（不挂 audit、不落 store）：保持审计链与
    # findings.jsonl 一致，演示不影响正式状态
    from proofhound.findings import Finding

    shadow = Finding.model_validate(negative.model_dump())
    shadow.transition(FindingState.REPRODUCED, actor="demo", reason="推进到铁律闸前")
    try:
        shadow.transition(FindingState.CONFIRMED, actor="demo", reason="铁律反例演示")
        print("  - [失败] 铁律未拦截！")  # 不应到达
        return 1
    except IronRuleViolationError as exc:
        print(f"  - 状态机铁律拦截: {exc}")

    # 8. 离线调出正例证据包（纯文件查询）
    if confirmed_id:
        print(f"\n[*] 离线调出证据包: python -m proofhound.findings show {confirmed_id}")
        from proofhound.findings.__main__ import main as findings_main

        findings_main(["show", confirmed_id, "--dir", str(evidence_dir)])

    # 9. 凭据脱敏自检：审计/findings/全部证据文件不得出现 Cookie 原文
    print("\n[*] 凭据脱敏自检 ...")
    cookie_value = dvwa.session_cookies().get("PHPSESSID", "")
    leaks = []
    for path in evidence_dir.rglob("*"):
        if path.is_file() and cookie_value and cookie_value.encode() in path.read_bytes():
            leaks.append(str(path))
    if leaks:
        print(f"  - [失败] Cookie 原文泄漏: {leaks}")
        return 1
    print("  - 通过：audit.jsonl / findings.jsonl / 全部证据文件均无 PHPSESSID 原文（仅 sha256 标记）")

    # 10. 用量与审计链
    print(f"\n[用量] 合计 {tracker.total_tokens()} tokens（{len(tracker.records)} 次调用）")
    for r in tracker.records:
        print(f"  - {r.tier}/{r.model}: prompt={r.prompt_tokens} "
              f"completion={r.completion_tokens} latency={r.latency_ms:.0f}ms "
              f"estimated={r.estimated}")
    print(f"\n[审计链] {audit.path}（{len(audit.read_all())} 条）")
    for e in audit.read_all():
        fields = {k: v for k, v in e.items() if k not in ("ts", "event")}
        print(f"  {e['ts']}  {e['event']}: {json.dumps(fields, ensure_ascii=False)[:300]}")

    if dvwa_container is not None:
        print(f"\n[*] 清理 DVWA 容器 {dvwa_container.short_id}（--rm 自动删除）")
        dvwa_container.stop()
    return 0 if confirmed_id else 1


if __name__ == "__main__":
    sys.exit(main())
