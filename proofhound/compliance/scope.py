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

M16-b：``Scope`` 增加可选 ``request_budget``（**请求量授权语义**）。既有 scope 只表达
"允许打哪些目标"（域名/IP/端口），**不表达"本次允许发多少请求"**——而无差别字典爆破
（dirsearch 实测：t=25 自然吞吐约 820 rps、自带词表全量 12308 请求 / 15s）在缺这一维
授权时不应上线。故新增 :class:`RequestBudget`（速率 / 并发 / 请求总量 / 时间窗），由
**主动按字典发请求**的构造器读取并翻成工具旗标（见 ``tools/build.py::_build_dirsearch``）。

**缺省值语义（维护者裁定，刻意非 fail-closed）**：``request_budget`` 缺省为 ``None``，
由构造器替换为**保守缺省值**（50 rps / 5 并发 / 5000 请求）——即**开箱即用但保守**。
该缺省**显式记为 ``source="default"`` 进审计**，与 ``source="explicit"`` 可区分：
缺省放行**不等于**无痕放行。这与 ``PROOFHOUND_SANDBOX_EGRESS``/``_HARDENING``
"非法值抛错、缺省即最严"的纪律**有意不同**，理由与残余风险见 AGENTS.md 已知限制 54。
但**非法值仍然一律显式抛错**（越界即 ``ValidationError``，绝不静默回落到放宽值）。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field

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


# M16-b：请求量授权语义的**缺省值**（维护者裁定为"保守缺省、开箱即用"）。
# 刻意不用 fail-closed 的 None-即拒绝，理由与残余风险见模块 docstring 与
# AGENTS.md 已知限制 54；非法值仍一律显式抛错。
DEFAULT_RATE_RPS = 50
DEFAULT_CONCURRENCY = 5
DEFAULT_MAX_REQUESTS = 5000


class RequestBudget(BaseModel):
    """本次授权允许发出的请求量（速率 / 并发 / 总量 / 时间窗）。

    由**主动按字典发请求**的工具构造器读取并翻成工具旗标。四个维度各自设硬上限
    （``le``），越界即 Pydantic ``ValidationError``——**显式抛错，不静默回落**。

    - ``rate_rps``：请求速率上限（每秒）。
    - ``concurrency``：并发连接数（同时最多几个在途请求）。
    - ``max_requests``：本次授权的**请求总量上限**。构造器据此**截词表**，是确定性
      硬闸（不依赖工具自觉）。
    - ``window_minutes``：可选的**授权时间窗**（分钟）。构造器翻成工具自限时旗标，
      调用方**同时**收窄沙箱超时为 ``min(300, window*60)``——两道，非一道。
    """

    model_config = ConfigDict(extra="forbid")

    rate_rps: int = Field(default=DEFAULT_RATE_RPS, ge=1, le=200)
    concurrency: int = Field(default=DEFAULT_CONCURRENCY, ge=1, le=20)
    max_requests: int = Field(default=DEFAULT_MAX_REQUESTS, ge=1, le=50000)
    window_minutes: int | None = Field(default=None, ge=1, le=1440)

    def max_seconds(self) -> int | None:
        """时间窗秒数；未声明返回 ``None``（表示不设工具自限时）。"""
        return None if self.window_minutes is None else self.window_minutes * 60


def default_request_budget() -> RequestBudget:
    """保守缺省预算（维护者裁定：不写 scope 也开箱即用，但记为 ``source="default"``）。"""
    return RequestBudget()


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
    # M11b：**第三身份**会话（可选）。verify-idor 的未认证对照探测在未配置时
    # 自动退化为**完全不发凭据**的匿名请求——匿名探测已足以否定"公开资源"
    # （见 verify/idor_control.py 的语义说明），故本字段是**可选增强**而非必需。
    session_third: SessionConfig | None = None
    # M16-b：请求量授权（可选）。``None`` = 未显式授权，构造器替换为保守缺省值并
    # 在审计里记 ``source="default"``（见模块 docstring 的"缺省值语义"与限制 54）。
    request_budget: RequestBudget | None = None

    def session_identity(self) -> str | None:
        """reference 会话的身份标识（供归属比对的**期望值**）。

        M11b 解析顺序：

        1. **声明式** ``reference.identity``（推荐）——真系统的对象页展示的是
           用户名/所有者名，而会话凭据常是随机 session id，两者**不同源**；
           demo_idor_fixture 实测即是（正文 ``属主：b`` vs 凭据
           ``8071f6e5d4c3b2a1``），只推凭据会让归属判定一律 ``absent``。
        2. 回退：reference 会话的凭据值（``phsess`` 优先，否则第一个 cookie 值）
           ——向后兼容既有配置。

        都取不到时返回 ``None``，此时归属判定一律 ``absent``（**不做"有 owner
        字段就算证据"的放松**）。给出 ``identity`` **不放宽**判据：归属字段名与
        字段值仍须同时命中才算 ``matched``。
        """
        reference = self.session.reference if self.session else None
        if reference is None:
            return None
        if reference.identity and reference.identity.strip():
            return reference.identity.strip()
        if reference.cookies.get("phsess"):
            return reference.cookies["phsess"]
        for value in reference.cookies.values():
            if value:
                return value
        return None

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        """从 scope 授权文件（YAML）加载。"""
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)

    def resolved_request_budget(self) -> RequestBudget:
        """本次生效的请求预算；未显式配置时返回**保守缺省值**。

        M16-b：返回缺省对象**不代表**"已获显式授权"——授权来源由
        :meth:`request_budget_source` 单独给出并记入审计。
        """
        return self.request_budget or default_request_budget()

    def request_budget_source(self) -> str:
        """请求预算的来源：``"explicit"``（scope 显式声明）/ ``"default"``（保守缺省）。

        单独成一个方法而不是塞进预算对象：预算的**值**与授权的**来源**是两件事，
        审计要能分辨"维护者显式授权 50 rps"与"没人写、按缺省放了 50 rps"。
        """
        return "explicit" if self.request_budget is not None else "default"

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
