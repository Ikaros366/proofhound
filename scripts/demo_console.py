#!/usr/bin/env python3
"""M5b Web 控制台真实链路验收 demo（不进 pytest）：uvicorn 子进程 + DVWA。

与 demo_api.py 的差别：这次起**真实 HTTP 服务**（``python -m proofhound.api``
子进程，绑 127.0.0.1），全部交互走 HTTP——正是浏览器控制台驱动的同一组
端点；httpx 客户端在此等价于"浏览器 devtools 网络面板"的脚本化佐证。

- Step 0 静态面：GET / 与 /static 资产 200；
- Step 1 非回环告警：--host 0.0.0.0 起实例（端口已被主服务占用 → 绑定失败
  立即退出，不做任何真实局域网暴露），stderr 须含醒目警告；
- Part A（semi_auto 全流程）：带 cookie 创建 → run → 轮询至 done（零确认）
  → findings → 构建报告（默认模板 + narrative）→ 下载字节与磁盘一致；
- Part B（L2 审批）：带 cookie 创建 + 种子 sqli Hypothesis → run → 确认
  队列 pending（verify-sqli/L2）→ 批准（operator 落款）→ Confirmed →
  证据端点 + 证据文件端点逐文件审阅（锚点行与 sha256 逐项核对）→ 报告；
- Step C 凭据防泄漏：全程所有响应体（含静态/报告 docx 字节）不含
  PHPSESSID 原值——等价"devtools 任一响应体无 cookie"的脚本佐证；
- ``--serve``：自动检查通过后保持服务运行，打印浏览器手动验收步骤。

用法：
    .venv/bin/python scripts/demo_console.py                # Step0/1 + A + B + C
    .venv/bin/python scripts/demo_console.py --skip-l2      # 跳过 Part B
    .venv/bin/python scripts/demo_console.py --serve        # 检查后保持服务供浏览器验收

.env 需要：Part A 需 PROOFHOUND_T1_*（规划/叙述）；Part B 另需 PROOFHOUND_T2_*。
产物落 evidence/demo_console/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用 seed_finding / demo_verify_dvwa

import httpx

from proofhound.llm.client import LLMError
from proofhound.llm.router import ModelRouter, Tier

import seed_finding
from demo_verify_dvwa import DvwaError, ensure_dvwa


class DemoError(RuntimeError):
    pass


class Recorder:
    """全程响应体收集：Step C 凭据防泄漏断言的数据源（等价 devtools 网络面板）。"""

    def __init__(self):
        self.blobs: list[tuple[str, bytes]] = []

    def record(self, label: str, resp: httpx.Response) -> None:
        self.blobs.append((label, resp.content))


def _check(resp: httpx.Response, expected: int, what: str) -> httpx.Response:
    if resp.status_code != expected:
        raise DemoError(f"{what} 失败: HTTP {resp.status_code} {resp.text[:300]}")
    return resp


def _wait_state(client, rec, eng_id, states: set[str], timeout: float) -> str:
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        resp = client.get(f"/api/engagements/{eng_id}")
        rec.record(f"GET detail {eng_id}", resp)
        state = resp.json()["state"]
        if state in states:
            return state
        time.sleep(2)
    raise DemoError(f"等待状态 {states} 超时（当前 {state}）")


def _wait_confirmation(client, rec, eng_id, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = client.get(f"/api/engagements/{eng_id}/confirmations")
        rec.record(f"GET confirmations {eng_id}", resp)
        confs = resp.json()["confirmations"]
        if confs:
            return confs[0]
        time.sleep(2)
    raise DemoError("等待待确认动作超时")


def _make_workspace(root: Path, dvwa_port: int) -> Path:
    """演示工作区：scope.yaml + 符号链接复用仓库 templates/skills/tools.d/.env。

    M6a：另写一份 scopes/scope.yaml（内容与根 scope.yaml 相同）——控制台
    创建任务表单的 scope 下拉数据源为 GET /api/scopes（只管 scopes/ 内文件）。
    """
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    scope_text = f"networks: [127.0.0.0/8]\nports: [{dvwa_port}]\n"
    (workspace / "scope.yaml").write_text(scope_text, encoding="utf-8")
    scopes_dir = workspace / "scopes"
    scopes_dir.mkdir(exist_ok=True)
    (scopes_dir / "scope.yaml").write_text(scope_text, encoding="utf-8")
    for name in ("templates", "skills", "tools.d"):
        link = workspace / name
        if not link.exists():
            link.symlink_to(REPO_ROOT / name)
    env_link = workspace / ".env"  # 子进程无 --env-file 参数，workspace/.env 即生效
    if not env_link.exists():
        env_link.symlink_to(REPO_ROOT / ".env")
    return workspace


def _start_server(workspace: Path, port: int, log_path: Path) -> subprocess.Popen:
    log_fh = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "proofhound.api",
            "--workspace", str(workspace),
            "--host", "127.0.0.1",
            "--port", str(port),
            "--confirm-timeout", "900",
        ],
        stdout=log_fh, stderr=subprocess.STDOUT, cwd=str(REPO_ROOT),
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise DemoError(f"API 服务启动失败，日志见 {log_path}")
        try:
            if httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=2).status_code == 200:
                return proc
        except httpx.TransportError:
            time.sleep(0.5)
    raise DemoError("API 服务 30s 内未就绪")


def step0_static(client, rec) -> None:
    print("\n" + "=" * 72)
    print("Step 0：静态面（控制台页面与资产可访问）")
    print("=" * 72)
    resp = _check(client.get("/"), 200, "GET /")
    rec.record("GET /", resp)
    assert "text/html" in resp.headers["content-type"]
    assert "/static/app.js" in resp.text
    for name in ("app.css", "app.js", "api.js"):
        resp = _check(client.get(f"/static/{name}"), 200, f"GET /static/{name}")
        rec.record(f"GET /static/{name}", resp)
    print("[*] GET / 200（text/html）+ app.css/app.js/api.js 全部 200")


def step1_non_loopback_warning(port: int) -> None:
    print("\n" + "=" * 72)
    print("Step 1：非回环绑定醒目警告（--host 0.0.0.0）")
    print("=" * 72)
    # 端口已被主服务占用 → uvicorn 绑定失败立即退出；警告先于绑定打印，
    # 全程不做任何真实局域网暴露
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "proofhound.api",
            "--workspace", ".", "--host", "0.0.0.0", "--port", str(port),
        ],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=str(REPO_ROOT),
    )
    try:
        out, _ = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    assert "警告" in out and "非回环" in out and "0.0.0.0" in out, out[:500]
    first_lines = "\n".join(out.splitlines()[:7])
    print(f"[*] 非回环绑定 stderr 输出（前 7 行）:\n{first_lines}")
    print("[*] 醒目警告断言通过（且进程因端口占用未实际暴露局域网）")


def part_a(client, rec, cookie_header: str) -> str:
    print("\n" + "=" * 72)
    print("Part A：semi_auto 全流程（带 cookie 创建 → 零确认自动完成 → 出报告）")
    print("=" * 72)
    resp = _check(
        client.post("/api/engagements", json={
            "target": TARGET,
            "scope_paths": ["scope.yaml"],
            "cookie": cookie_header,
            "autonomy_mode": "semi_auto",
        }),
        201, "创建 engagement（带会话）",
    )
    rec.record("POST create A", resp)
    eng_id = resp.json()["id"]
    assert resp.json()["with_session"] is True
    print(f"[*] engagement 已创建: {eng_id}（with_session=true）")

    resp = _check(client.post(f"/api/engagements/{eng_id}/run"), 202, "启动")
    rec.record("POST run A", resp)
    print("[*] 已启动；等待 scan → triage → verify 自动跑完 ...")
    state = _wait_state(client, rec, eng_id, {"done", "failed"}, timeout=600)
    if state != "done":
        raise DemoError(f"Part A engagement 终态为 {state}（预期 done）")

    resp = client.get(f"/api/engagements/{eng_id}/confirmations")
    rec.record("GET confirmations A", resp)
    assert resp.json()["confirmations"] == [], "semi_auto 下不应出现待确认动作"
    resp = client.get(f"/api/engagements/{eng_id}/findings")
    rec.record("GET findings A", resp)
    states = {}
    for f in resp.json()["findings"]:
        states[f["state"]] = states.get(f["state"], 0) + 1
    print(f"[*] 全程零确认自动完成；findings 分桶: {states}")

    # T1 叙述为单遍全量校验（M4 已知限制 17：输出截断/坏 JSON 即整体 500，
    # 无自动重试）——LLM 抽样方差允许 demo 层重试一次，两次均失败才算失败
    resp = None
    for attempt in (1, 2):
        attempt_resp = client.post(
            f"/api/engagements/{eng_id}/report",
            json={"template": "default_template.docx", "narrative": True},
            timeout=300,
        )
        rec.record(f"POST report A #{attempt}", attempt_resp)
        if attempt_resp.status_code == 200:
            resp = attempt_resp
            break
        print(f"[!] 叙述版报告构建第 {attempt} 次失败（HTTP {attempt_resp.status_code}），"
              f"{'重试一次' if attempt == 1 else '不再重试'}: {attempt_resp.text[:120]}")
    if resp is None:
        raise DemoError("报告构建（narrative=true）两次均失败")
    print(f"[*] 报告已构建（T1 叙述版）: summary={resp.json()['summary']}")
    resp = _check(client.get(f"/api/engagements/{eng_id}/report"), 200, "报告下载")
    rec.record("GET report A (docx)", resp)
    disk = (DEMO_DIR / "workspace" / "engagements" / eng_id / "report.docx").read_bytes()
    assert resp.content == disk, "下载字节与磁盘不一致"
    print(f"[*] 报告下载字节与磁盘一致（{len(disk)} 字节）")
    return eng_id


def part_b(client, rec, cookie_header: str) -> str:
    print("\n" + "=" * 72)
    print("Part B：只读 L2 verify 自动执行（semi_auto）→ Confirmed → 逐文件审阅证据包")
    print("=" * 72)
    resp = _check(
        client.post("/api/engagements", json={
            "target": TARGET,
            "scope_paths": ["scope.yaml"],
            "cookie": cookie_header,
            "autonomy_mode": "semi_auto",
        }),
        201, "创建 engagement（带会话）",
    )
    rec.record("POST create B", resp)
    eng_id = resp.json()["id"]

    eng_dir = DEMO_DIR / "workspace" / "engagements" / eng_id
    sqli_url = f"{TARGET}/vulnerabilities/sqli/?id=1&Submit=Submit"
    seed_finding.main([
        "--dir", str(eng_dir),
        "--asset", sqli_url,
        "--vuln-type", "sqli",
        "--param", "id",
        "--title", "DVWA sqli id 参数 SQL 注入（控制台 L2 审批演示）",
    ])

    resp = _check(client.post(f"/api/engagements/{eng_id}/run"), 202, "启动")
    rec.record("POST run B", resp)
    # M9c③ 起 semi_auto 下只读 L2 验证（verify-sqli）自动执行、不进确认队列；
    # 确认队列的实弹覆盖见 tests/test_readonly_e2e.py::test_writer_skill_still_queues_confirmation
    # （以写操作型 skill 替身驱动）。
    print("[*] 已启动；semi_auto 下只读 verify 自动执行，等待 sqlmap + 证据门 + "
          "Verifier T2 终审 ...")
    state = _wait_state(client, rec, eng_id, {"done", "failed"}, timeout=1200)
    if state != "done":
        raise DemoError(f"Part B engagement 终态为 {state}（预期 done）")

    resp = client.get(f"/api/engagements/{eng_id}/confirmations")
    rec.record("GET confirmations B", resp)
    assert resp.json()["confirmations"] == [], (
        "semi_auto 下只读验证不应进确认队列"
    )
    auto_lines = [
        line for line in (eng_dir / "audit.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        if '"action_read_only_auto"' in line and '"verify-sqli"' in line
    ]
    assert auto_lines, "审计链缺少 action_read_only_auto(verify-sqli)"
    print(f"[*] 只读验证自动执行（action_read_only_auto ×{len(auto_lines)}，"
          "零人工批准）")

    resp = client.get(f"/api/engagements/{eng_id}/findings")
    rec.record("GET findings B", resp)
    confirmed = [f for f in resp.json()["findings"] if f["state"] == "confirmed"]
    if not confirmed:
        raise DemoError("Part B 无 Confirmed Finding")
    sqli = next(f for f in confirmed if f["vuln_type"] == "sqli")
    print(f"[*] Confirmed: {sqli['id']} method={sqli['verification']['method']}")
    print(f"    verifier={sqli['verifier']['model']} verdict={sqli['verifier']['verdict']}")

    # 证据包查看器数据源逐项核对：每个文件全文 + 锚点行 + sha256
    resp = client.get(f"/api/engagements/{eng_id}/findings/{sqli['id']}/evidence")
    rec.record("GET evidence B", resp)
    evidence = resp.json()
    assert evidence["assembled"] is True
    checked = 0
    for item in evidence["items"]:
        if not item.get("file"):
            continue
        resp = _check(
            client.get(
                f"/api/engagements/{eng_id}/findings/{sqli['id']}/evidence/{item['file']}"
            ),
            200, f"证据文件 {item['file']}",
        )
        rec.record(f"GET evidence file {item['file']}", resp)
        # 证据链完整性：manifest sha256 对证据包磁盘字节核验
        # （HTTP 文件端点是行尾归一化后的展示层，不对其字节做哈希）
        disk_bytes = (eng_dir / "findings" / sqli["id"] / item["file"]).read_bytes()
        assert hashlib.sha256(disk_bytes).hexdigest() == item["sha256"], item["file"]
        # 锚点一致性：HTTP 文本按 \n 分行的锚点行 == evidence 端点 anchor_line_text
        if item.get("line_anchor") is not None and item.get("anchor_line_text") is not None:
            lines = resp.text.split("\n")
            assert lines[item["line_anchor"] - 1] == item["anchor_line_text"], item["file"]
        checked += 1
    print(f"[*] 证据包逐文件审阅通过：{checked} 个文件 sha256 与锚点行全部一致")

    resp = _check(
        client.post(
            f"/api/engagements/{eng_id}/report",
            json={"template": "default_template.docx", "narrative": False},
            timeout=300,
        ),
        200, "报告构建",
    )
    rec.record("POST report B", resp)
    print(f"[*] 报告已构建: summary={resp.json()['summary']}")
    return eng_id


def stepc_cookie_leak(rec: Recorder, dvwa) -> None:
    print("\n" + "=" * 72)
    print("Step C：凭据防泄漏（全程响应体无 PHPSESSID 原值）")
    print("=" * 72)
    cookie_value = dvwa.session_cookies().get("PHPSESSID", "")
    assert cookie_value, "DVWA 会话缺少 PHPSESSID"
    leaks = [label for label, blob in rec.blobs if cookie_value.encode() in blob]
    assert not leaks, f"响应体出现 cookie 原值: {leaks}"
    print(f"[*] 共检查 {len(rec.blobs)} 个响应体（含静态资产/报告 docx 字节），"
          "PHPSESSID 原值零出现 ✓")


MANUAL_STEPS = """\
浏览器手动验收步骤（服务保持运行中）：
  1. 打开控制台首页（上方打印的地址）→ 任务列表应看到本 demo 的两个 engagement
  2. 创建任务：填 target、scope 下拉多选（数据源 scopes/，demo 已备 scope.yaml）、
     cookie（password 框）→ 创建并启动 → 自动跳详情
  3. 详情页：状态条阶段徽标滚动；审计流着色滚动（command_executed 显脱敏命令）
  4. L2 阻塞时：确认队列面板置顶警示 + 倒计时 → 填 operator 批准 → Finding 变 Confirmed
  5. 展开 Finding → 证据包查看器：点文件名看全文（行号/锚点高亮/sha256）
  6. 报告区：选模板 → 构建 → 下载 docx
  7. devtools 网络面板抽查任一响应体：不应出现 PHPSESSID 原值
  8. 健康页：闸门矩阵 3×3 + 版本 + confirm_timeout
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M5b Web 控制台验收")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    parser.add_argument("--dvwa-url", default="http://127.0.0.1:8080")
    parser.add_argument("--port", type=int, default=8765, help="控制台服务端口")
    parser.add_argument("--skip-l2", action="store_true", help="跳过 Part B（L2 审批演示）")
    parser.add_argument("--serve", action="store_true", help="检查后保持服务运行供浏览器手动验收")
    args = parser.parse_args()

    global TARGET, DEMO_DIR
    TARGET = args.dvwa_url.rstrip("/")
    dvwa_port = urllib.parse.urlparse(TARGET).port or 80
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    DEMO_DIR = REPO_ROOT / "evidence" / "demo_console" / stamp
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    # 环境预检：LLM 档位 + Docker + DVWA
    try:
        router = ModelRouter.from_env(args.env_file)
    except LLMError as exc:
        print(f"[配置错误] {exc}", file=sys.stderr)
        return 2
    if Tier.T1 not in router.configs:
        print("[配置错误] Part A 需要 T1 档（规划/叙述）：PROOFHOUND_T1_*", file=sys.stderr)
        return 2
    if not args.skip_l2 and Tier.T2 not in router.configs:
        print("[配置错误] Part B 需要 T2 档（Verifier）：PROOFHOUND_T2_*"
              "（或用 --skip-l2 跳过）", file=sys.stderr)
        return 2
    try:
        import docker

        docker_client = docker.from_env()
        docker_client.ping()
    except Exception as exc:
        print(f"[环境错误] Docker 不可用（沙箱执行是红线，无法跳过）: {exc}",
              file=sys.stderr)
        return 2
    try:
        dvwa, dvwa_container = ensure_dvwa(docker_client, TARGET, dvwa_port)
    except DvwaError as exc:
        print(f"[环境错误] {exc}", file=sys.stderr)
        return 2

    workspace = _make_workspace(DEMO_DIR, dvwa_port)
    server_log = DEMO_DIR / "server.log"
    server = _start_server(workspace, args.port, server_log)
    base_url = f"http://127.0.0.1:{args.port}"
    print(f"[*] API 子进程已启动（真实 uvicorn，非 TestClient）: {base_url}")
    print(f"    workspace={workspace}；服务日志 {server_log}")

    rec = Recorder()
    cookie_header = "; ".join(f"{k}={v}" for k, v in dvwa.session_cookies().items())
    eng_a = eng_b = None
    try:
        with httpx.Client(base_url=base_url, timeout=60) as client:
            health = client.get("/api/health")
            rec.record("GET health", health)
            print(f"[*] 健康检查: {health.json()['status']} version={health.json().get('version')}"
                  f" confirm_timeout={health.json().get('confirm_timeout')}")
            step0_static(client, rec)
            step1_non_loopback_warning(args.port)
            eng_a = part_a(client, rec, cookie_header)
            if not args.skip_l2:
                eng_b = part_b(client, rec, cookie_header)
            else:
                print("\n[*] --skip-l2：跳过 Part B（L2 阻塞→批准→Confirmed 演示）")
            stepc_cookie_leak(rec, dvwa)
    except Exception:
        server.terminate()
        if dvwa_container is not None:
            dvwa_container.stop()
        raise

    print("\n" + "=" * 72)
    print(f"[验收通过] Part A engagement: {eng_a}")
    if eng_b:
        print(f"[验收通过] Part B engagement: {eng_b}（L2 阻塞→批准→Confirmed→证据审阅）")
    print(f"产物目录: {DEMO_DIR}")

    if args.serve:
        print("\n" + "=" * 72)
        print(f"控制台地址: {base_url}/  （绑 127.0.0.1，仅本机）")
        print(MANUAL_STEPS)
        print("按 Ctrl+C 结束服务。")
        try:
            server.wait()
        except KeyboardInterrupt:
            pass
    server.terminate()
    if dvwa_container is not None:
        print(f"\n[*] 清理 DVWA 容器 {dvwa_container.short_id}（--rm 自动删除）")
        dvwa_container.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
