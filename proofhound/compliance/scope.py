"""Scope 授权模型与命令目标校验（架构红线 5：授权前置）。

每条拟执行命令在进入沙箱前，先从参数中提取目标（URL / IP / 域名，含
host:port 形式），与授权 scope 比对；任一目标越界即拒绝。

文件目标（M2a 起）：``httpx -l targets.txt`` 这类从文件读取目标的情形，
校验阶段在宿主侧解析文件内容，逐行提取目标逐一过 scope——任一行越界即
整命令拒绝；文件不存在、含无法解析的行均为 fail-closed 拒绝。

默认策略（M2a 起）：整条命令未识别出任何目标时**拒绝**（fail-closed），
消除 M1 的 no_targets 放行口子；确需放行须显式传 ``allow_no_targets=True``。

已知限制：
- 目标文件只在校验阶段于宿主侧读取；把目标文件挂载进容器属编排器职责
  （M2 后续切片处理）。
- 裸域名识别基于正则，形如 ``out.json`` 的参数可能被误判为域名目标
  （fail-closed 方向，最多误拒，不会误放）。

M3b：``Scope`` 增加可选 ``session``（预置会话，§5.3 认证旁路第①条）；
``--cookie``/``-H``/``--header`` 等凭据旗标的值从目标提取中剔除。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

from proofhound.compliance.session import SessionConfig

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\.?$"
)
_HOST_PORT_RE = re.compile(r"^(?P<host>[^:/\s]+):(?P<port>\d{1,5})$")

# 默认识别为"目标列表文件"的参数旗标（httpx/nuclei 等均用 -l）
DEFAULT_TARGET_FILE_FLAGS: tuple[str, ...] = ("-l", "--list", "-list")

# 代理旗标：其值是基础设施端点（出口白名单代理），不是扫描目标，
# 从目标提取中剔除；实际外联仍由出口代理白名单强制（tools/egress.py）。
DEFAULT_PROXY_FLAGS: tuple[str, ...] = (
    "-proxy",
    "--proxy",
    "-http-proxy",
    "--http-proxy",
)

# 凭据旗标（M3b）：其值是会话凭据（Cookie/自定义请求头），既不是扫描目标，
# 也不参与目标提取——防止 cookie 中域名形态子串被裸域名正则误判为目标
# （fail-closed 方向再收紧）。凭据值的脱敏由 sandbox runner 在审计前执行。
DEFAULT_SECRET_FLAGS: tuple[str, ...] = ("--cookie", "-H", "--header")


@dataclass(frozen=True)
class Target:
    """从命令参数中提取出的单个目标。"""

    host: str
    port: int | None = None
    is_ip: bool = False


class Scope(BaseModel):
    """授权范围：域名（含其子域名）、IP/CIDR 网段、端口白名单。

    ``ports`` 为空表示不限制端口；命令中未显式给出端口的目标也不受端口限制。
    """

    domains: list[str] = Field(default_factory=list)
    networks: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    # 预置会话（M3b，§5.3 认证旁路第①条）：授权配置中的 Cookie/请求头，
    # 供构造器注入工具参数；其值在审计/state/日志中只记 sha256 前 8 位。
    session: SessionConfig | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        """从 scope 授权文件（YAML）加载。"""
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)

    def check_target(self, target: Target) -> str | None:
        """校验单个目标，返回 None 表示放行，否则返回拒绝原因。"""
        if self.ports and target.port is not None and target.port not in self.ports:
            return f"端口 {target.port} 不在授权范围"
        if target.is_ip:
            addr = ipaddress.ip_address(target.host)
            if any(addr in net for net in self._parsed_networks()):
                return None
            return f"IP {target.host} 不在授权网段内"
        host = target.host.rstrip(".").lower()
        for domain in self.domains:
            d = domain.rstrip(".").lower()
            if host == d or host.endswith("." + d):
                return None
        return f"域名 {target.host} 不在授权列表内"

    def _parsed_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(item, strict=False) for item in self.networks]


@dataclass
class ScopeDecision:
    """一次命令的 scope 校验结论。"""

    allowed: bool
    targets: list[Target] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    no_targets: bool = False
    file_targets: list[str] = field(default_factory=list)  # 目标文件路径（已解析）


def check_scope(
    scope: Scope,
    argv: list[str],
    *,
    base_dir: str | Path | None = None,
    target_file_flags: tuple[str, ...] = DEFAULT_TARGET_FILE_FLAGS,
    proxy_flags: tuple[str, ...] = DEFAULT_PROXY_FLAGS,
    secret_flags: tuple[str, ...] = DEFAULT_SECRET_FLAGS,
    allow_no_targets: bool = False,
) -> ScopeDecision:
    """从命令参数（含目标列表文件）提取目标并逐一比对 scope。

    - 文件目标旗标（默认 ``-l``/``--list``/``-list``，支持 ``-l file`` 与
      ``-l=file`` 两种形式）指向的文件逐行解析；任一行越界、文件不可读、
      含无法解析的行，均为 fail-closed 拒绝。
    - 代理旗标（``-proxy`` 等）的值是基础设施端点而非扫描目标，从目标
      提取中剔除；实际外联由出口白名单代理强制。
    - 凭据旗标（``--cookie``/``-H``/``--header``，M3b）的值是会话凭据，
      同样从目标提取中剔除（不参与目标判定）。
    - 整条命令未识别出任何目标时默认拒绝；``allow_no_targets=True`` 才放行
      并以 ``no_targets`` 标注。
    """
    rest, files = _strip_flag_values(argv, target_file_flags)
    rest, _proxies = _strip_flag_values(rest, proxy_flags)
    rest, _secrets = _strip_flag_values(rest, secret_flags)
    targets = extract_targets(rest)
    violations: list[str] = []
    resolved_files: list[str] = []

    for file_ref in files:
        path = Path(file_ref)
        if not path.is_absolute():
            path = Path(base_dir) / path if base_dir else Path.cwd() / path
        resolved_files.append(str(path))
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            violations.append(f"目标文件不可读: {path}（{exc.strerror or exc}）")
            continue
        for lineno, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            target = _parse_token(line)
            if target is None:
                violations.append(f"目标文件 {path} 第 {lineno} 行无法解析: {line!r}")
                continue
            if target not in targets:
                targets.append(target)

    for target in targets:
        reason = scope.check_target(target)
        if reason:
            violations.append(reason)

    if not targets and not violations:
        if allow_no_targets:
            return ScopeDecision(
                allowed=True, no_targets=True, file_targets=resolved_files
            )
        return ScopeDecision(
            allowed=False,
            no_targets=True,
            violations=["未识别出目标（no_targets），按默认策略拒绝"],
            file_targets=resolved_files,
        )
    return ScopeDecision(
        allowed=not violations,
        targets=targets,
        violations=violations,
        file_targets=resolved_files,
    )


def _strip_flag_values(
    argv: list[str], flags: tuple[str, ...]
) -> tuple[list[str], list[str]]:
    """把指定旗标及其值从 argv 中剥离，返回 (剩余参数, 值列表)。

    被消费的 token 不再参与常规目标提取，避免 ``targets.txt`` 这类文件名
    被裸域名正则误判为目标。
    """
    rest: list[str] = []
    files: list[str] = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token in flags:
            if i + 1 < len(argv):
                files.append(argv[i + 1])
                i += 2
                continue
            i += 1  # 旗标缺值：丢弃旗标，后续按 no_targets/常规解析处理
            continue
        flag, sep, value = token.partition("=")
        if sep and flag in flags and value:
            files.append(value)
            i += 1
            continue
        rest.append(token)
        i += 1
    return rest, files


def extract_targets(argv: list[str]) -> list[Target]:
    """从命令参数中提取目标（去重、保持顺序）。"""
    seen: set[Target] = set()
    targets: list[Target] = []
    for token in argv:
        target = _parse_token(token)
        if target is not None and target not in seen:
            seen.add(target)
            targets.append(target)
    return targets


def _parse_token(token: str) -> Target | None:
    if not token or token.startswith("-"):
        return None
    if "://" in token:
        parsed = urlparse(token)
        if not parsed.hostname:
            return None
        try:
            port = parsed.port
        except ValueError:
            port = None
        return _make_target(parsed.hostname, port)
    match = _HOST_PORT_RE.match(token)
    if match:
        host, port = match.group("host"), int(match.group("port"))
        if port > 65535:
            return None
        if _is_ip(host) or _DOMAIN_RE.match(host):
            return _make_target(host, port)
        return None
    if _is_ip(token):
        return Target(host=token, is_ip=True)
    if _DOMAIN_RE.match(token):
        return Target(host=token.rstrip("."), is_ip=False)
    return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _make_target(host: str, port: int | None) -> Target:
    host = host.rstrip(".")
    return Target(host=host, port=port, is_ip=_is_ip(host))
