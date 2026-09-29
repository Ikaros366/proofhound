"""Docker 沙箱执行器（§5.2 / §5.8）。

- 通过 ``/var/run/docker.sock`` 以兄弟容器方式拉起任务容器；
- 宿主工具目录只读挂载到容器 ``/opt/tools``；
- CPU（nano_cpus）/ 内存（mem_limit）配额；
- **隔离硬化档（M12，缺省严格）**：容器内降权为非 root（nobody）+ rootfs
  只读 + 仅 ``/tmp`` 为 tmpfs 可写（工具写 ``$HOME`` 也落这里）+ 丢弃全部
  capability + ``no-new-privileges`` + ``pids_limit`` + ``RLIMIT_NOFILE``；
  逐项进 ``command_executed`` 审计的 ``sandbox`` 字段（隔离强度与证据同源
  可查）。逃生阀 ``PROOFHOUND_SANDBOX_HARDENING=relaxed`` 退回 M12 之前
  的容器参数（默认 strict，非法值 fail-closed）；
- 网络出口策略（M2a，见 ``tools/egress.py``）：默认 restricted——容器接入
  internal 出口网络，HTTP(S) 流量强制经白名单正向代理出站；``open`` 沿用
  配置的 ``network_mode``（M1 行为）；``none`` 完全断网；
- 每条命令执行前先过 scope 校验（红线 5），越界或未识别出目标直接拒绝、
  不启动容器、记审计日志；
- 原始输出 100% 落盘 ``evidence/``（红线 3），审计日志只记摘要与路径；
- M3b：``run(..., image=...)`` 可按次覆盖沙箱镜像（ToolManifest.image 声明，
  如 sqlmap 需 python 镜像）；scope 配了预置会话时，审计与返回值中的命令
  经凭据脱敏（只记 sha256 前 8 位），容器执行仍用原始 argv。
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import docker
from docker.types import Mount, Ulimit

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope, check_scope
from proofhound.compliance.session import redact_argv, redact_bytes
from proofhound.tools.egress import EGRESS_NETWORK_NAME, EgressPolicy, EgressProxy

CONTAINER_TOOLS_DIR = "/opt/tools"
SCRATCH_DIR = "/tmp"  # 硬化档下容器内唯一可写位置（tmpfs，随容器销毁）
SCRATCH_USER = "65534:65534"  # nobody:nogroup（alpine / python 基础镜像均有）


@dataclass
class SandboxConfig:
    image: str = "alpine:3.20"
    nano_cpus: int = 1_000_000_000  # 1 CPU
    mem_limit: str = "512m"
    network_mode: str = "bridge"  # 仅 egress.mode="open" 时生效
    egress: EgressPolicy = field(default_factory=EgressPolicy)
    # ---- 隔离硬化档（M12）----
    # 缺省严格：fail-closed 方向——宁可让工具跑不起来，也不静默降级隔离。
    # ``hardening=False`` 逐字节回到 M12 之前的容器参数，仅作逃生阀。
    hardening: bool = True
    cap_drop: tuple[str, ...] = ("ALL",)
    pids_limit: int = 512
    nofile_limit: int = 4096
    scratch_size: str = "64m"
    run_as: str = SCRATCH_USER

    def isolation_profile(self) -> dict:
        """审计用：本次执行的隔离档摘要（严格档逐项列出落实的边界）。"""
        if not self.hardening:
            return {"mode": "relaxed"}
        return {
            "mode": "strict",
            "user": self.run_as,
            "read_only_rootfs": True,
            "tmpfs": (
                f"{SCRATCH_DIR}:rw,nosuid,size={self.scratch_size},mode=1777"
            ),
            "cap_drop": list(self.cap_drop),
            "no_new_privileges": True,
            "pids_limit": self.pids_limit,
            "nofile_limit": self.nofile_limit,
        }


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
        base_dir: str | Path | None = None,
    ):
        self.scope = scope
        self.audit = audit
        self.evidence_dir = Path(evidence_dir)
        self.tools_dir = Path(tools_dir)
        self.config = config or SandboxConfig()
        self._client = client or docker.from_env()
        self._base_dir = base_dir  # 目标列表文件（-l 等）相对路径的解析基准
        self._egress_proxy: EgressProxy | None = None

    def run(
        self,
        tool: str,
        args: list[str],
        timeout: int = 300,
        image: str | None = None,
    ) -> RunResult:
        """执行 ``tool args...``；越界命令拒绝执行并记审计日志。

        ``image`` 可按次覆盖沙箱镜像（如 sqlmap 需要 python 镜像，由
        ToolManifest.image 声明）；审计与返回值中的命令经会话凭据脱敏
        （M3b：只记 sha256 前 8 位），容器执行仍用原始 argv。
        """
        image = image or self.config.image
        command = [tool, *args]
        secrets = self._session_secrets()
        redacted_command = redact_argv(command, secrets)
        decision = check_scope(self.scope, args, base_dir=self._base_dir)
        if not decision.allowed:
            self.audit.record(
                "command_rejected",
                command=redacted_command,
                tool=tool,
                violations=decision.violations,
                no_targets=decision.no_targets,
                file_targets=decision.file_targets,
            )
            return RunResult(
                rejected=True,
                command=redacted_command,
                violations=decision.violations,
                no_targets=decision.no_targets,
            )

        run_id = uuid.uuid4().hex[:12]
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = self.evidence_dir / f"{run_id}.stdout.log"
        stderr_path = self.evidence_dir / f"{run_id}.stderr.log"

        network_mode, proxy_url = self._resolve_network()
        env = {
            "PATH": (
                f"{CONTAINER_TOOLS_DIR}/{tool}"
                ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            )
        }
        if self.config.hardening:
            # rootfs 只读，故 HOME/TMPDIR 必须指向唯一的可写 tmpfs；否则
            # 往 ~/.sqlmap 写会话/输出的工具（sqlmap）会直接失败。
            env["HOME"] = SCRATCH_DIR
            env["TMPDIR"] = SCRATCH_DIR
            env["PYTHONDONTWRITEBYTECODE"] = "1"
        if proxy_url:
            env["HTTP_PROXY"] = proxy_url
            env["HTTPS_PROXY"] = proxy_url
            env["ALL_PROXY"] = proxy_url
            env["http_proxy"] = proxy_url
            env["https_proxy"] = proxy_url
            env["all_proxy"] = proxy_url
        create_kwargs: dict = {
            "image": image,
            "command": command,
            "environment": env,
            "mounts": [
                Mount(
                    target=CONTAINER_TOOLS_DIR,
                    source=str(self.tools_dir.resolve()),
                    type="bind",
                    read_only=True,
                )
            ],
            "nano_cpus": self.config.nano_cpus,
            "mem_limit": self.config.mem_limit,
            "network_mode": network_mode,
        }
        if self.config.hardening:
            # M12：非 root + rootfs 只读 + 仅 /tmp 可写 + 去全部 capability
            # + 禁提权 + 进程数/FD 上限。磁盘写满因此结构性不可能（rootfs
            # 只读、可写面只有 64m tmpfs）。
            create_kwargs.update(
                user=self.config.run_as,
                working_dir=SCRATCH_DIR,
                read_only=True,
                tmpfs={
                    SCRATCH_DIR: (
                        f"rw,nosuid,size={self.config.scratch_size},mode=1777"
                    )
                },
                cap_drop=list(self.config.cap_drop),
                security_opt=["no-new-privileges:true"],
                pids_limit=self.config.pids_limit,
                ulimits=[
                    Ulimit(
                        name="nofile",
                        soft=self.config.nofile_limit,
                        hard=self.config.nofile_limit,
                    )
                ],
            )
        container = self._client.containers.create(**create_kwargs)
        try:
            container.start()
            status = container.wait(timeout=timeout)
            exit_code = status.get("StatusCode", -1)
            stdout = container.logs(stdout=True, stderr=False) or b""
            stderr = container.logs(stderr=True, stdout=False) or b""
        finally:
            container.remove(force=True)

        # 证据落盘前字节级脱敏（sqlmap 会回显 Cookie 请求头）；审计哈希
        # 与落盘内容一致，证据链不断裂
        stdout = redact_bytes(stdout, secrets)
        stderr = redact_bytes(stderr, secrets)
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        self.audit.record(
            "command_executed",
            command=redacted_command,
            tool=tool,
            image=image,
            targets=[t.host for t in decision.targets],
            no_targets=decision.no_targets,
            file_targets=decision.file_targets,
            egress=self._egress_audit_fields(network_mode),
            sandbox=self.config.isolation_profile(),
            exit_code=exit_code,
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        )
        return RunResult(
            rejected=False,
            command=redacted_command,
            exit_code=exit_code,
            no_targets=decision.no_targets,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )

    def _session_secrets(self) -> list[str]:
        """当前 scope 预置会话的凭据子串清单（无会话为空）。"""
        if self.scope.session is None:
            return []
        return self.scope.session.secret_values()

    def close(self) -> None:
        """关闭出口代理（restricted 模式下由 ``run()`` 懒启动）。"""
        if self._egress_proxy is not None:
            self._egress_proxy.close()
            self._egress_proxy = None

    @property
    def egress_proxy_url(self) -> str | None:
        """restricted 模式下的白名单代理地址；供不读 proxy 环境变量、
        需要显式代理参数的工具（如 httpx ``-proxy``）使用。其余模式为 None。"""
        if self.config.egress.mode != "restricted":
            return None
        return self._ensure_egress_proxy().proxy_url

    def __enter__(self) -> "SandboxRunner":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- 网络出口 ----

    def _resolve_network(self) -> tuple[str, str | None]:
        """按出口策略解析 (network_mode, proxy_url)。"""
        mode = self.config.egress.mode
        if mode == "none":
            return "none", None
        if mode == "open":
            return self.config.network_mode, None
        # restricted：internal 出口网络 + 白名单正向代理
        return EGRESS_NETWORK_NAME, self._ensure_egress_proxy().proxy_url

    def _ensure_egress_proxy(self) -> EgressProxy:
        if self._egress_proxy is None:
            self._egress_proxy = EgressProxy(self.scope, self.config.egress, self.audit)
            self._egress_proxy.start(self._client)
        return self._egress_proxy

    def _egress_audit_fields(self, network_mode: str) -> dict:
        policy = self.config.egress
        fields: dict = {"mode": policy.mode, "network": network_mode}
        if policy.mode == "restricted":
            fields["allowed_hosts"] = (
                self._egress_proxy.allowed_hosts if self._egress_proxy else []
            )
        return fields
