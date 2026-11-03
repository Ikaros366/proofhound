"""M32：扫描种子归一（target 的路径不再被当成扫描根）。

背景（实测 ``eng-20261103T032027Z-87899ebd``，target ``https://100.80.4.50:8443/login``）：

- ``dirsearch -u .../login`` 把 ``/login`` 当目录根 ⇒ 43 条结果里 40 条是
  ``/login/xxx/index.html`` 的 301，**应用根一个请求都没打**；
- ``katana -u .../login -d 2`` 从入口页起算深度 ⇒ 1115 行输出里 1081 行
  ``max depth reached``；
- ``httpx`` 不受影响（单点探活，探入口页正是它的用途，故**不**归一到根）。

两条边界：状态边界（子任务 target 换成扫描根，规划器看到的就是根）与执行
边界（种子类工具的 params.target 再兜一次，防规划器把入口页写回去）。
"""

import json
import uuid
from pathlib import Path

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import split_scan_seed
from proofhound.core.orchestrator import Orchestrator
from proofhound.core.tasks import TaskStatus
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.sandbox import RunResult


# ---------- 纯函数 ----------


@pytest.mark.parametrize(
    ("target", "root", "entry"),
    [
        # 触发本里程碑的真实 target
        ("https://100.80.4.50:8443/login", "https://100.80.4.50:8443/", "/login"),
        # 子目录应用：只上抬一层，不把 /app 也扔掉
        ("https://h/app/login", "https://h/app/", "/app/login"),
        ("https://h/a/b/login", "https://h/a/b/", "/a/b/login"),
        # 文件型入口
        ("https://h/index.php", "https://h/", "/index.php"),
        # query 归入口页，不进扫描根
        ("https://h/login?next=/x", "https://h/", "/login?next=/x"),
        # 已是目录 / 根：原样（幂等）
        ("https://h/", "https://h/", None),
        ("https://h", "https://h", None),
        ("https://h/app/", "https://h/app/", None),
        # 非 http(s) / 无 netloc：不猜，原样透传
        ("127.0.0.1:8000", "127.0.0.1:8000", None),
        ("example.com/login", "example.com/login", None),
        # IPv6 字面量
        ("https://[::1]:8443/login", "https://[::1]:8443/", "/login"),
    ],
)
def test_split_scan_seed(target, root, entry):
    assert split_scan_seed(target) == (root, entry)


def test_split_scan_seed_is_idempotent():
    root, entry = split_scan_seed("https://h:8443/login")
    assert (root, entry) == ("https://h:8443/", "/login")
    # 对扫描根再调用一次：不再变化（否则两条边界来回归一会漂移）
    assert split_scan_seed(root) == (root, None)


def test_split_scan_seed_strips_whitespace():
    assert split_scan_seed("  https://h/login  ") == ("https://h/", "/login")


# ---------- 编排集成 ----------


class FakeLLM:
    """记录 planner 收到的 messages，回复给定计划（可回显任意 target）。"""

    def __init__(self, reply: str):
        self.reply = reply
        self.messages: list[list[dict]] = []

    def complete(self, messages):
        self.messages.append(messages)
        return self.reply

    def last_state(self) -> dict:
        return json.loads(self.messages[-1][-1]["content"])["state"]


class FakeRunner:
    """SandboxRunner 替身：只记录 argv，不碰 Docker。"""

    egress_proxy_url = None

    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        self.calls: list[list[str]] = []

    def run(self, tool, args, timeout=300, image=None):
        self.calls.append([tool, *args])
        uid = uuid.uuid4().hex[:12]
        stdout = self.evidence_dir / f"{uid}.stdout.log"
        stderr = self.evidence_dir / f"{uid}.stderr.log"
        stdout.write_text("", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        return RunResult(
            rejected=False,
            command=[tool, *args],
            exit_code=0,
            stdout_path=stdout,
            stderr_path=stderr,
        )


def _plan_for(skill: str, tool: str, target: str) -> str:
    return json.dumps(
        {
            "actions": [
                {
                    "action": "run_tool",
                    "skill": skill,
                    "tool": tool,
                    "params": {"target": target},
                    "expected_output": "signals",
                }
            ]
        }
    )


@pytest.fixture
def registry_katana(make_skill_dir):
    return SkillRegistry(make_skill_dir(name="recon-crawl", tools=("katana",))).discover()


@pytest.fixture
def registry_httpx(make_skill_dir):
    return SkillRegistry(make_skill_dir()).discover()


def _make_orch(registry, tmp_path, reply: str):
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    runner = FakeRunner(tmp_path / "evidence")
    llm = FakeLLM(reply)
    orch = Orchestrator(
        registry, runner, llm, audit, evidence_dir=tmp_path / "evidence"
    )
    return orch, runner, llm, audit


def _events(audit: AuditLog) -> list[dict]:
    return [
        json.loads(line)
        for line in audit.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_run_scan_phase_normalizes_seed(registry_katana, tmp_path):
    """子任务 target / 规划状态都是扫描根；入口页进 meta 与审计。"""
    target = "https://100.80.4.50:8443/login"
    orch, runner, llm, audit = _make_orch(
        registry_katana, tmp_path, _plan_for("recon-crawl", "katana", target)
    )

    phase = orch.run_scan_phase([target], skill_name="recon-crawl")

    assert phase.status == TaskStatus.DONE
    assert [c.name for c in phase.children] == ["scan:https://100.80.4.50:8443/"]
    node = phase.children[0]
    assert node.meta["target"] == "https://100.80.4.50:8443/"
    assert node.meta["entry_path"] == "/login"

    # 规划器看到的是扫描根 + 入口页（入口页不丢，但不再是"起点即根"）
    state = llm.last_state()
    assert state["target"] == "https://100.80.4.50:8443/"
    assert state["entry_path"] == "/login"

    # 状态边界：一条 seed_normalized
    normalized = [e for e in _events(audit) if e["event"] == "seed_normalized"]
    assert len(normalized) == 1
    assert normalized[0]["entry_path"] == "/login"

    # 执行边界：规划器把入口页写回了 params，执行前仍被归一到根
    at_exec = [e for e in _events(audit) if e["event"] == "seed_normalized_at_exec"]
    assert len(at_exec) == 1
    assert at_exec[0]["tool"] == "katana"
    assert runner.calls[0][:3] == ["katana", "-u", "https://100.80.4.50:8443/"]


def test_executor_does_not_log_when_planner_uses_root(registry_katana, tmp_path):
    """规划器按状态回填扫描根时，执行边界是恒等变换（不重复记审计）。"""
    target = "https://h:8443/login"
    orch, runner, _llm, audit = _make_orch(
        registry_katana, tmp_path, _plan_for("recon-crawl", "katana", "https://h:8443/")
    )

    orch.run_scan_phase([target], skill_name="recon-crawl")

    assert not [e for e in _events(audit) if e["event"] == "seed_normalized_at_exec"]
    assert runner.calls[0][:3] == ["katana", "-u", "https://h:8443/"]


def test_httpx_is_not_a_seed_tool(registry_httpx, tmp_path):
    """httpx 是单点探活：规划器要探入口页就探入口页（不被归一）。"""
    target = "https://h:8443/login"
    orch, runner, _llm, audit = _make_orch(
        registry_httpx, tmp_path, _plan_for("web-scan", "httpx", target)
    )

    phase = orch.run_scan_phase([target])

    # 执行边界不碰 httpx：argv 仍是规划器给的入口页
    assert runner.calls[0][:3] == ["httpx", "-u", "https://h:8443/login"]
    assert not [e for e in _events(audit) if e["event"] == "seed_normalized_at_exec"]
    # 但状态边界照旧归一：子任务 target 是根（探入口页是规划器的显式选择）
    assert phase.children[0].meta["target"] == "https://h:8443/"


def test_state_has_no_entry_path_when_target_is_already_root(registry_httpx, tmp_path):
    """无归一时**不加** ``entry_path`` 键——既有 prompt 载荷逐字节不变。"""
    target = "http://127.0.0.1:8000"
    orch, _runner, llm, audit = _make_orch(
        registry_httpx, tmp_path, _plan_for("web-scan", "httpx", target)
    )

    orch.run_scan_phase([target])

    state = llm.last_state()
    assert state["target"] == target
    assert "entry_path" not in state
    assert not [e for e in _events(audit) if e["event"] == "seed_normalized"]


def test_duplicate_scan_roots_are_merged(registry_httpx, tmp_path):
    """两个入口页归一到同一根：只跑一个子任务，合并记审计（不静默丢）。"""
    orch, runner, _llm, audit = _make_orch(
        registry_httpx, tmp_path, _plan_for("web-scan", "httpx", "https://h/")
    )

    phase = orch.run_scan_phase(["https://h/a", "https://h/b"])

    assert [c.name for c in phase.children] == ["scan:https://h/"]
    assert len(runner.calls) == 1
    merged = [e for e in _events(audit) if e["event"] == "seed_duplicate_merged"]
    assert len(merged) == 1
    assert merged[0]["target"] == "https://h/b"
    assert merged[0]["first_target"] == "https://h/a"


def test_scan_root_target_keeps_old_behaviour(registry_httpx, tmp_path):
    """回归：无路径 target 的子任务名与 meta 与 M32 之前一致。"""
    target = "http://127.0.0.1:8000"
    orch, _runner, _llm, _audit = _make_orch(
        registry_httpx, tmp_path, _plan_for("web-scan", "httpx", target)
    )

    phase = orch.run_scan_phase([target])

    assert phase.children[0].name == f"scan:{target}"
    assert phase.children[0].meta["target"] == target
    assert phase.children[0].meta["entry_path"] is None
