"""Docker 沙箱执行器（§5.2 / §5.8）。

- 通过 ``/var/run/docker.sock`` 以兄弟容器方式拉起任务容器；
- 宿主工具目录只读挂载到容器 ``/opt/tools``；
- CPU（nano_cpus）/ 内存（mem_limit）配额，网络模式可配；
- 每条命令执行前先过 scope 校验（红线 5），越界直接拒绝、不启动容器、
  记审计日志；
- 原始输出 100% 落盘 ``evidence/``（红线 3），审计日志只记摘要与路径。
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import docker
from docker.types import Mount

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope, check_scope

CONTAINER_TOOLS_DIR = "/opt/tools"


@dataclass
class SandboxConfig:
    image: str = "alpine:3.20"
    nano_cpus: int = 1_000_000_000  # 1 CPU
    mem_limit: str = "512m"
    network_mode: str = "bridge"


@dataclass
class RunResult:
    rejected: bool
    command: list[str]
    exit_code: int | None = None
    violations: list[str] = field(default_factory=list)
    no_targets: bool = False
    stdout_path: Path | None = None
    stderr_path: Path | None = None


class SandboxRunner:
    """在独立容器中执行工具命令，强制执行 scope 校验与审计。"""

    def __init__(
        self,
        scope: Scope,
        audit: AuditLog,
        evidence_dir: str | Path,
        tools_dir: str | Path,
        config: SandboxConfig | None = None,
        client: docker.DockerClient | None = None,
    ):
        self.scope = scope
        self.audit = audit
        self.evidence_dir = Path(evidence_dir)
        self.tools_dir = Path(tools_dir)
        self.config = config or SandboxConfig()
        self._client = client or docker.from_env()

    def run(self, tool: str, args: list[str], timeout: int = 300) -> RunResult:
        """执行 ``tool args...``；越界命令拒绝执行并记审计日志。"""
        command = [tool, *args]
        decision = check_scope(self.scope, args)
        if not decision.allowed:
            self.audit.record(
                "command_rejected",
                command=command,
                tool=tool,
                violations=decision.violations,
            )
            return RunResult(
                rejected=True, command=command, violations=decision.violations
            )

        run_id = uuid.uuid4().hex[:12]
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = self.evidence_dir / f"{run_id}.stdout.log"
        stderr_path = self.evidence_dir / f"{run_id}.stderr.log"

        env = {
            "PATH": (
                f"{CONTAINER_TOOLS_DIR}/{tool}"
                ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            )
        }
        container = self._client.containers.create(
            self.config.image,
            command=command,
            environment=env,
            mounts=[
                Mount(
                    target=CONTAINER_TOOLS_DIR,
                    source=str(self.tools_dir.resolve()),
                    type="bind",
                    read_only=True,
                )
            ],
            nano_cpus=self.config.nano_cpus,
            mem_limit=self.config.mem_limit,
            network_mode=self.config.network_mode,
        )
        try:
            container.start()
            status = container.wait(timeout=timeout)
            exit_code = status.get("StatusCode", -1)
            stdout = container.logs(stdout=True, stderr=False) or b""
            stderr = container.logs(stderr=True, stdout=False) or b""
        finally:
            container.remove(force=True)

        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        self.audit.record(
            "command_executed",
            command=command,
            tool=tool,
            image=self.config.image,
            targets=[t.host for t in decision.targets],
            no_targets=decision.no_targets,
            exit_code=exit_code,
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        )
        return RunResult(
            rejected=False,
            command=command,
            exit_code=exit_code,
            no_targets=decision.no_targets,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
