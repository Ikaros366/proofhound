"""沙箱隔离硬化档的真实容器验证（M12，docker 标记）。

正例：硬化档下工具**仍能正常执行**（否则就是拿可用性换安全，不可接受）。
负例（越界尝试）：Docker socket 不可达、rootfs 与工具目录不可写、容器内非 root、
无 capability、进程数有上限且 fork 炸弹被截断。

纯配置与逃生阀见 ``tests/test_sandbox_profile.py``（无 Docker 也跑）。
"""

from __future__ import annotations

import pytest

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.tools.egress import EgressPolicy
from proofhound.tools.sandbox import SCRATCH_DIR, SandboxConfig, SandboxRunner

pytestmark = pytest.mark.docker

TARGET = "http://127.0.0.1:9/"

#: 硬化探针：一行一个 键=值，供断言容器内隔离属性
PROBE = """#!/bin/sh
echo "uid=$(id -u)"
echo "home=$HOME"
echo "cwd=$(pwd)"
if [ -S /var/run/docker.sock ]; then echo "docker_sock=PRESENT"; else echo "docker_sock=ABSENT"; fi
if touch /m12_rootfs_probe 2>/dev/null; then echo "rootfs=WRITABLE"; else echo "rootfs=READONLY"; fi
if touch /opt/tools/m12_probe 2>/dev/null; then echo "tools=WRITABLE"; else echo "tools=READONLY"; fi
if touch "$HOME/m12_probe" 2>/dev/null; then echo "home=WRITABLE"; else echo "home=UNWRITABLE"; fi
echo "pids_max=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo NA)"
echo "cap_eff=$(awk '/CapEff/ {print $2}' /proc/self/status)"
echo "args: $@"
"""

#: 受限 fork 炸弹：请求 1200 个后台进程；pids 上限远小于此，故循环必然被打断
#: （busybox sh 遇 fork 失败即终止，因此脚本不会打印 requested 计数——这本身就是
#:  "上限生效" 的可观测证据）。
FORK_BOMB = """#!/bin/sh
n=0
while [ "$n" -lt 1200 ]; do
  sleep 30 &
  n=$((n + 1))
done
echo "requested=$n"
"""


@pytest.fixture
def probe_tools_dir(tmp_path):
    """工具目录：硬化探针 + fork 炸弹探针。"""
    root = tmp_path / "tools.d"
    for name, body in (("probe-tool", PROBE), ("fork-tool", FORK_BOMB)):
        tool_dir = root / name
        tool_dir.mkdir(parents=True)
        script = tool_dir / name
        script.write_text(body, encoding="utf-8")
        script.chmod(0o755)
    return root


def _make_runner(tmp_path, docker_client, sandbox_image, tools_dir, **config_kwargs):
    scope = Scope(networks=["127.0.0.0/8"])
    audit = AuditLog(tmp_path / "evidence" / "audit.jsonl")
    return SandboxRunner(
        scope,
        audit,
        evidence_dir=tmp_path / "evidence",
        tools_dir=tools_dir,
        config=SandboxConfig(
            image=sandbox_image, egress=EgressPolicy(mode="none"), **config_kwargs
        ),
        client=docker_client,
    )


@pytest.fixture
def runner(tmp_path, docker_client, sandbox_image, probe_tools_dir):
    return _make_runner(tmp_path, docker_client, sandbox_image, probe_tools_dir)


def _run(runner, tool="probe-tool"):
    result = runner.run(tool, [TARGET])
    assert not result.rejected
    assert result.exit_code == 0, result.stderr_path.read_text(encoding="utf-8")
    return result.stdout_path.read_text(encoding="utf-8")


def _spy_create(monkeypatch):
    from docker.models.containers import ContainerCollection

    calls = []
    original = ContainerCollection.create

    def spy(self, *args, **kwargs):
        calls.append(kwargs)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(ContainerCollection, "create", spy)
    return calls


# ---- 正例：硬化档下工具仍可执行 ----


def test_hardened_container_still_runs_tool(runner):
    out = _run(runner)
    assert f"args: {TARGET}" in out


def test_container_runs_as_non_root(runner):
    out = _run(runner)
    assert "uid=0" not in out
    assert "uid=65534" in out


def test_home_is_writable_scratch_so_stateful_tools_work(runner):
    """sqlmap 要往 ~/.sqlmap 写会话/输出——rootfs 只读时必须仍有一处可写。"""
    out = _run(runner)
    assert f"home={SCRATCH_DIR}" in out
    assert f"cwd={SCRATCH_DIR}" in out
    assert "home=WRITABLE" in out


# ---- 负例：越界尝试 ----


def test_rootfs_and_tools_dir_are_not_writable(runner):
    out = _run(runner)
    assert "rootfs=READONLY" in out
    assert "tools=READONLY" in out


def test_docker_socket_is_absent_inside_container(runner):
    """沙箱容器不得触及宿主 Docker 守护进程（无 socket 挂载）。"""
    out = _run(runner)
    assert "docker_sock=ABSENT" in out


def test_all_capabilities_dropped(runner):
    out = _run(runner)
    cap_eff = next(line for line in out.splitlines() if line.startswith("cap_eff="))
    assert cap_eff.split("=", 1)[1].strip("0") == ""


def test_pids_limit_is_enforced_in_container(runner):
    """机制断言：容器内 cgroup pids 上限 == 配置值（不是"配了但没生效"）。"""
    out = _run(runner)
    assert f"pids_max={runner.config.pids_limit}" in out


def test_fork_bomb_is_truncated_and_reclaimed(runner, docker_client):
    """fork 炸弹被 pids 上限截断，且容器与其全部子进程都被回收。

    断言的是可观测事实而非 shell 文案：循环请求 1200 个进程却**没能跑完**
    （`requested=` 一行不出现，busybox sh 遇 fork 失败即终止），且跑完前后
    运行中容器集合没有扩张——宿主不被拖挂。
    """
    before = {c.id for c in docker_client.containers.list()}

    result = runner.run("fork-tool", [TARGET])

    assert result.exit_code is not None  # 容器正常收尾，没有挂死
    stdout = result.stdout_path.read_text(encoding="utf-8")
    assert "requested=1200" not in stdout  # 循环被打断 ⇒ 上限确实生效
    assert runner.config.pids_limit < 1200

    after = {c.id for c in docker_client.containers.list()}
    assert after <= before  # 无残留容器（含 fork 出来的子进程一并回收）


# ---- 容器参数与审计 ----


def test_hardening_kwargs_passed_to_docker(runner, monkeypatch):
    calls = _spy_create(monkeypatch)
    _run(runner)

    kwargs = calls[0]
    assert kwargs["user"] == "65534:65534"
    assert kwargs["working_dir"] == SCRATCH_DIR
    assert kwargs["read_only"] is True
    assert list(kwargs["tmpfs"]) == [SCRATCH_DIR]
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges:true"]
    assert kwargs["pids_limit"] == runner.config.pids_limit
    assert kwargs["ulimits"][0]["Name"] == "nofile"
    assert kwargs["ulimits"][0]["Soft"] == runner.config.nofile_limit


def test_isolation_profile_recorded_in_audit(runner):
    runner.run("probe-tool", [TARGET])

    entry = runner.audit.read_all()[-1]
    assert entry["event"] == "command_executed"
    assert entry["sandbox"]["mode"] == "strict"
    assert entry["sandbox"]["read_only_rootfs"] is True
    assert entry["sandbox"]["cap_drop"] == ["ALL"]


def test_relaxed_mode_restores_pre_m12_container(
    tmp_path, docker_client, sandbox_image, probe_tools_dir, monkeypatch
):
    """逃生阀：relaxed 下不得出现任何硬化参数，工具仍能跑（回到 M12 之前语义）。"""
    runner = _make_runner(
        tmp_path, docker_client, sandbox_image, probe_tools_dir, hardening=False
    )
    calls = _spy_create(monkeypatch)
    out = _run(runner)

    assert "uid=0" in out  # 旧语义：容器内为 root
    kwargs = calls[0]
    for key in ("user", "read_only", "tmpfs", "cap_drop", "security_opt",
                "pids_limit", "ulimits", "working_dir"):
        assert key not in kwargs
    assert runner.audit.read_all()[-1]["sandbox"] == {"mode": "relaxed"}
