"""Scope 授权模型与命令目标校验（架构红线 5：授权前置）。

每条拟执行命令在进入沙箱前，先从参数中提取目标（URL / IP / 域名，含
host:port 形式），与授权 scope 比对；任一目标越界即拒绝。

已知限制（M1）：
- 目标仅从命令行参数提取；`httpx -l targets.txt` 这类从文件读目标的
  情形暂不解析文件内容，未识别到目标时放行并在审计日志中标注
  （ScopeDecision.no_targets）。
- 裸域名识别基于正则，形如 ``out.json`` 的参数可能被误判为域名目标
  （fail-closed 方向，最多误拒，不会误放）。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\.?$"
)
_HOST_PORT_RE = re.compile(r"^(?P<host>[^:/\s]+):(?P<port>\d{1,5})$")


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


def check_scope(scope: Scope, argv: list[str]) -> ScopeDecision:
    """从命令参数提取目标并逐一比对 scope。"""
    targets = extract_targets(argv)
    if not targets:
        return ScopeDecision(allowed=True, no_targets=True)
    violations = []
    for target in targets:
        reason = scope.check_target(target)
        if reason:
            violations.append(reason)
    return ScopeDecision(allowed=not violations, targets=targets, violations=violations)


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
