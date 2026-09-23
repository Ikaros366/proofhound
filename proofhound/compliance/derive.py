"""从种子目标派生 scope（M9a，架构红线 5：授权前置不放松，只降摩擦）。

设计意图
--------
M9a 之前，创建 engagement 必须手写 scope YAML（`scopes/*.yaml`）并显式传入。
本模块让"只给一个目标"就能得到一个**可用且可审计**的 scope，把摩擦降到接近零，
同时把两件事拆开——这两件事在 M9a 之前是混在一起的：

- **派生（derivation）**：纯确定性动作，从 `https://target.com/path` 提取
  `domains: [target.com]` / `networks: [10.0.0.5/32]` + 端口。零 LLM、零网络。
- **授权（authorization）**：操作员的显式确认，由 API 层的
  `acknowledge_authorization` 承载并落审计——**不由本模块负责，也不因此被取消**。

派生结果与手写 YAML **同构**（就是 `Scope` 的字段），因此下游 5 层
`check_scope`、出口白名单 `tools/egress.py`（白名单 = scope）继续原样生效，
一行都不用改。

安全纪律（本模块的核心约束）
----------------------------
派生只能是"收窄"，绝不能因为图方便而放宽授权：

1. **只从种子目标的 host 派生，绝不扩张**——不跟随重定向、不解析页面里的
   链接、不把爬到的域名并进来。扩张授权范围是安全事故，不是便利。
2. **任何可疑形态一律 fail-closed 报错**，宁可让操作员手写 scope，也不产出
   一个过宽的授权：拒绝空结果、拒绝 `0.0.0.0/0` 与 `::/0` 这样的全网段、
   拒绝裸 TLD（`com`、`cn`）与通配符 `*`。
3. **`ports` 语义与 `Scope` 既有约定严格一致**：空 = 不限端口。种子显式带
   端口时派生 `ports: [port]`；种子是默认端口（http→80 / https→443）时
   省略 `ports`。**刻意不从 scheme 推导 `ports: [443]`**——那会把操作员
   已经授权的同一台主机挡在 80/8080 之外，是"派生反而更严"的意外，不是本意。
4. **派生结果必须持久化**为实际生效的那一份（由调用方落盘 + 记审计），
   禁止每次扫描时现算——否则"操作员看到的"与"实际生效的"会漂移。

与 `compliance/scope.py` 的关系：复用其 `_DOMAIN_RE` / `_is_ip` / `_make_target`
等既有解析设施，不重复造轮子；`Scope` 模型本身一行不改。
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from proofhound.compliance.scope import (
    _DOMAIN_RE,
    _HOST_PORT_RE,
    _is_ip,
    _make_target,
    Scope,
)

#: 各 scheme 的默认端口；种子显式给出这些端口时不写入 `ports`（见模块 docstring 第 3 条）。
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}

#: 明确拒绝的网段——这类派生等于"授权全部"，属安全事故而非便利。
_FORBIDDEN_NETWORKS: tuple[str, ...] = ("0.0.0.0/0", "::/0")

#: 常见单标签 TLD；`http://com` 这种形态无法判定是域名还是拼写错误，
#: fail-closed 让操作员显式写 scope。判定为"完整域名需至少一个点"失败时的补充防线。
_KNOWN_TLDS: frozenset[str] = frozenset(
    {
        "com", "cn", "net", "org", "edu", "gov", "mil", "int", "io", "co", "dev",
        "app", "ai", "me", "info", "biz", "top", "xyz", "site", "online", "tech",
        "uk", "us", "jp", "kr", "de", "fr", "ru", "au", "ca", "in", "br", "nl",
        "hk", "tw", "sg", "local", "localhost", "test", "internal", "lan",
    }
)

#: 私网/回环之外的公网单主机网段仍是 /32 或 /128——本模块不因地址类型改变行为，
#: 但拒绝把"单主机"写成更大的网段（那是扩张）。
_ALLOWED_HOST_PREFIX = {"ipv4": 32, "ipv6": 128}

#: 显式放行的单标签主机（本地靶场常用）；其余单标签一律拒绝。
_LOCALHOST_NAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain"})


class ScopeDerivationError(ValueError):
    """派生失败：输入不可解析或会得出过宽的授权范围。

    一律 fail-closed——调用方应把它转成 4xx 并提示操作员显式提供 scope 文件，
    绝不允许吞掉异常后继续（那就成了"派生失败 = 放行"）。
    """


def _normalize_seed(target: str) -> str:
    """补齐 scheme，使 `target.com:8080/path`、`127.0.0.1:8080` 等形态可解析。"""
    seed = (target or "").strip()
    if not seed:
        raise ScopeDerivationError("目标为空，无法派生 scope")
    if "://" not in seed:
        seed = "http://" + seed
    return seed


def _extract_host_port(seed: str) -> tuple[str, int | None, str | None]:
    """返回 (host, port, scheme)。解析失败或形态可疑一律抛错。"""
    parsed = urlparse(seed)
    scheme = (parsed.scheme or "").lower() or None
    host = parsed.hostname
    if not host:
        raise ScopeDerivationError(
            f"目标 {seed!r} 中解析不出主机名，无法派生 scope（请显式提供 scope 文件）"
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ScopeDerivationError(f"目标 {seed!r} 的端口非法：{exc}") from None
    return host.rstrip(".").lower(), port, scheme


def _reject_wildcard(host: str) -> None:
    if "*" in host:
        raise ScopeDerivationError(
            f"目标 {host!r} 含通配符；通配符会给出过宽的授权范围，拒绝派生"
        )


def _reject_bare_tld(host: str) -> None:
    """单标签主机：只有 localhost 系可接受，其余（尤其裸 TLD）一律拒绝。"""
    if "." in host or _is_ip(host):
        return
    if host in _LOCALHOST_NAMES:
        return
    if host in _KNOWN_TLDS:
        raise ScopeDerivationError(
            f"目标 {host!r} 是裸顶级域，派生会授权整个 TLD；拒绝派生，请显式提供 scope 文件"
        )
    raise ScopeDerivationError(
        f"目标 {host!r} 是单标签主机名，无法判定授权边界；拒绝派生，请显式提供 scope 文件"
    )


def _derive_ports(port: int | None, scheme: str | None) -> list[int]:
    """种子显式端口 → `ports: [port]`；默认端口 → 省略（空 = 不限，见模块 docstring）。"""
    if port is None:
        return []
    if scheme in _DEFAULT_PORTS and port == _DEFAULT_PORTS[scheme]:
        return []
    return [port]


def derive_scope(
    target: str,
    *,
    extra_domains: list[str] | tuple[str, ...] = (),
    extra_ports: list[int] | tuple[int, ...] = (),
) -> Scope:
    """从单个种子目标派生 scope。

    Parameters
    ----------
    target:
        种子目标，URL（带/不带 scheme）、`host:port`、裸域名或 IP 均可。
    extra_domains:
        附加授权域名（操作员显式补充，如目标依赖的 CDN/API 域）。逐条校验形态。
    extra_ports:
        附加授权端口（非默认端口场景）。逐条校验范围。

    Returns
    -------
    Scope
        与手写 YAML 同构的 `Scope` 实例。

    Raises
    ------
    ScopeDerivationError
        输入不可解析、或派生结果会过宽（通配符 / 裸 TLD / 全网段）。
    """
    seed = _normalize_seed(target)
    host, port, scheme = _extract_host_port(seed)
    _reject_wildcard(host)
    _reject_bare_tld(host)

    domains: list[str] = []
    networks: list[str] = []

    if _is_ip(host):
        # 单主机——只授权该地址本身。绝不放大成网段。
        addr = ipaddress.ip_address(host)
        prefix = _ALLOWED_HOST_PREFIX["ipv6" if addr.version == 6 else "ipv4"]
        network = f"{addr}/{prefix}"
        if network in _FORBIDDEN_NETWORKS:
            raise ScopeDerivationError(f"派生出的网段 {network} 等于全网授权，拒绝")
        networks.append(network)
    else:
        # localhost 系由 _reject_bare_tld 显式放行（本地靶场常用），
        # 但它们没有点，过不了 _DOMAIN_RE，故单独接受。
        if host in _LOCALHOST_NAMES:
            domains.append(host)
        elif not _DOMAIN_RE.match(host):
            raise ScopeDerivationError(
                f"目标主机 {host!r} 不是合法域名或 IP，拒绝派生"
            )
        else:
            domains.append(host)

    for raw in extra_domains:
        candidate = (raw or "").strip().rstrip(".").lower()
        if not candidate:
            continue
        _reject_wildcard(candidate)
        if _is_ip(candidate):
            addr = ipaddress.ip_address(candidate)
            prefix = _ALLOWED_HOST_PREFIX["ipv6" if addr.version == 6 else "ipv4"]
            net = f"{addr}/{prefix}"
            if net in _FORBIDDEN_NETWORKS:
                raise ScopeDerivationError(f"附加网段 {net} 等于全网授权，拒绝")
            if net not in networks:
                networks.append(net)
            continue
        if not _DOMAIN_RE.match(candidate):
            raise ScopeDerivationError(f"附加域名 {raw!r} 不是合法域名，拒绝派生")
        if candidate not in domains:
            domains.append(candidate)

    ports = _derive_ports(port, scheme)
    for raw_port in extra_ports:
        if not isinstance(raw_port, int) or not (1 <= raw_port <= 65535):
            raise ScopeDerivationError(f"附加端口 {raw_port!r} 不在 1..65535 内，拒绝派生")
        if raw_port not in ports:
            ports.append(raw_port)

    if not domains and not networks:
        # 理论不可达（上面的分支必产其一），留作不变的 fail-closed 兜底。
        raise ScopeDerivationError("派生结果为空 scope，拒绝（空 scope 会拒绝一切请求）")

    return Scope(domains=domains, networks=networks, ports=ports)


def derived_scope_marker(scope: Scope, *, target: str) -> dict:
    """派生 scope 的审计/落盘标记（`engagement.json` 与审计事件共用同一形态）。"""
    return {
        "scope_derived": True,
        "derived_from_target": target,
        "domains": list(scope.domains),
        "networks": list(scope.networks),
        "ports": list(scope.ports),
    }
