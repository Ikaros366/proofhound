"""M9a：从种子目标派生 scope 的单元测试。

派生是一个**授权范围生成器**，所以测试分三类，缺一不可：

1. **形态**：各种种子形态派生出预期结果（与 `Scope` 既有语义一致）。
2. **可用性（round-trip）**：派生结果必须真的放行种子目标本身——这是 M9a
   存在的意义（"只给一个目标就能跑"），派生出个不放行自己的 scope 就是废的。
3. **安全边界（最重要）**：派生只能收窄、不能放宽。必须证明它
   **不会**授权种子之外的主机、不会放大成网段、对可疑形态 fail-closed。
"""

from __future__ import annotations

import pytest

from proofhound.compliance.derive import (
    ScopeDerivationError,
    derive_scope,
    derived_scope_marker,
)
from proofhound.compliance.scope import Scope, check_scope


def _allowed(scope: Scope, argv: list[str]) -> bool:
    return check_scope(scope, argv).allowed


# ------------------------------------------------------------------ 1. 形态


@pytest.mark.parametrize(
    "seed,domains,networks,ports",
    [
        ("https://target.com", ["target.com"], [], []),
        ("http://target.com", ["target.com"], [], []),
        ("target.com", ["target.com"], [], []),
        ("https://target.com/some/path?a=1&b=2", ["target.com"], [], []),
        ("https://target.com:8443/admin", ["target.com"], [], [8443]),
        ("http://target.com:8080/", ["target.com"], [], [8080]),
        ("https://sub.deep.target.com/x", ["sub.deep.target.com"], [], []),
        ("https://target.com.", ["target.com"], [], []),  # 尾点归一化
        ("https://TARGET.com", ["target.com"], [], []),  # 大小写归一化
        ("http://127.0.0.1:8080/dvwa", [], ["127.0.0.1/32"], [8080]),
        ("127.0.0.1", [], ["127.0.0.1/32"], []),
        ("http://localhost", ["localhost"], [], []),
        ("http://localhost:3000/", ["localhost"], [], [3000]),
        ("http://[::1]:8080/", [], ["::1/128"], [8080]),
    ],
)
def test_shape(seed, domains, networks, ports):
    scope = derive_scope(seed)
    assert scope.domains == domains
    assert scope.networks == networks
    assert scope.ports == ports
    assert scope.session is None


def test_explicit_default_port_is_omitted():
    """显式 443/80 不写入 ports——空 ports = 不限端口（Scope 既有语义）。

    刻意不从 scheme 推 ports: [443]：那会把操作员已授权的同一主机挡在 8080
    之外，是"派生反而更严"的意外，与 M9a 降摩擦的意图相反。
    """
    assert derive_scope("https://target.com:443/x").ports == []
    assert derive_scope("http://target.com:80/x").ports == []
    # 非默认端口则必须写死，防止作用面意外扩大
    assert derive_scope("https://target.com:4443/x").ports == [4443]


def test_extra_domains_and_ports_are_merged():
    scope = derive_scope(
        "https://target.com", extra_domains=["cdn.example.net", "api.example.net"], extra_ports=[8443]
    )
    assert scope.domains == ["target.com", "cdn.example.net", "api.example.net"]
    assert scope.ports == [8443]


def test_extra_domain_may_be_ip():
    scope = derive_scope("https://target.com", extra_domains=["10.0.0.7"])
    assert scope.networks == ["10.0.0.7/32"]


def test_duplicates_are_collapsed():
    scope = derive_scope(
        "https://target.com", extra_domains=["target.com", "TARGET.com."], extra_ports=[8443, 8443]
    )
    assert scope.domains == ["target.com"]
    assert scope.ports == [8443]


# ------------------------------------------------------- 2. 可用性 round-trip


@pytest.mark.parametrize(
    "seed,argv",
    [
        ("https://target.com/a?x=1", ["httpx", "-u", "https://target.com/a?x=1"]),
        ("http://127.0.0.1:8080/dvwa", ["katana", "-u", "http://127.0.0.1:8080/dvwa"]),
        ("target.com", ["httpx", "-u", "https://target.com/"]),
        ("http://localhost:3000/", ["httpx", "-u", "http://localhost:3000/"]),
    ],
)
def test_derived_scope_allows_the_seed_itself(seed, argv):
    """M9a 的存在意义：派生结果必须放行种子目标，否则等于没派生。"""
    assert _allowed(derive_scope(seed), argv), f"{seed} 派生出的 scope 不放行自己"


def test_derived_scope_allows_other_ports_on_the_same_host():
    """空 ports 的既有语义 = 不限端口；种子只带 :443 时 8080 也应放行。"""
    scope = derive_scope("https://target.com/")
    assert _allowed(scope, ["httpx", "-u", "https://target.com:8080/x"])


# --------------------------------------------------- 3. 安全边界（不可放宽）


@pytest.mark.parametrize(
    "seed",
    [
        "",
        "   ",
        "https://*",
        "https://*.target.com",
        "https://com",          # 裸 TLD
        "https://cn",
        "https://notadomain!!",  # 非法字符
        "https://:8080",         # 无主机
        "http://target com",     # 主机含空格
        "https://target.com:99999",  # 端口越界
    ],
)
def test_suspicious_seeds_are_refused(seed):
    """可疑形态一律 fail-closed——宁可让操作员手写 scope，也不产出过宽授权。"""
    with pytest.raises(ScopeDerivationError):
        derive_scope(seed)


def test_single_label_host_other_than_localhost_is_refused():
    with pytest.raises(ScopeDerivationError, match="单标签|裸顶级域"):
        derive_scope("http://intranet")


@pytest.mark.parametrize(
    "argv",
    [
        ["httpx", "-u", "https://evil.example.com/"],
        ["httpx", "-u", "https://target.com.evil.example.com/"],  # 后缀伪装
        ["httpx", "-u", "https://othertarget.com/"],
        ["httpx", "-u", "http://127.0.0.1:8080/"],  # 同网段别的地址
        ["httpx", "-u", "http://10.0.0.8:8080/"],   # 私网邻址
    ],
)
def test_derived_scope_does_not_authorize_anything_else(argv):
    """核心安全属性：派生只授权种子主机，绝不扩张。"""
    scope = derive_scope("https://target.com/")
    assert not _allowed(scope, argv), f"{argv} 本不该被派生 scope 放行"


def test_derived_scope_never_widens_to_a_network():
    """IP 种子只产 /32（或 /128），绝不放大成网段。"""
    v4 = derive_scope("http://10.0.0.5/")
    assert v4.networks == ["10.0.0.5/32"]
    assert v4.domains == []
    assert not _allowed(v4, ["httpx", "-u", "http://10.0.0.6/"])

    v6 = derive_scope("http://[fe80::1]/")
    assert v6.networks == ["fe80::1/128"]


def test_extra_domain_that_is_not_a_domain_is_refused():
    with pytest.raises(ScopeDerivationError):
        derive_scope("https://target.com", extra_domains=["not a domain"])


def test_extra_wildcard_domain_is_refused():
    with pytest.raises(ScopeDerivationError):
        derive_scope("https://target.com", extra_domains=["*.example.com"])


@pytest.mark.parametrize("bad", [0, -1, 65536, "8080", None])
def test_extra_port_out_of_range_is_refused(bad):
    with pytest.raises(ScopeDerivationError):
        derive_scope("https://target.com", extra_ports=[bad])


def test_derived_scope_ports_restrict_when_seed_has_non_default_port():
    """种子带非默认端口时，派生 scope 会把端口锁死——收窄，符合纪律。"""
    scope = derive_scope("https://target.com:8443/")
    assert scope.ports == [8443]
    assert not _allowed(scope, ["httpx", "-u", "https://target.com:9443/"])


# ------------------------------------------------------------------ 标记


def test_marker_is_json_serializable_and_records_provenance():
    scope = derive_scope("http://127.0.0.1:8080/dvwa")
    marker = derived_scope_marker(scope, target="http://127.0.0.1:8080/dvwa")
    assert marker["scope_derived"] is True
    assert marker["derived_from_target"] == "http://127.0.0.1:8080/dvwa"
    assert marker["networks"] == ["127.0.0.1/32"]
    assert marker["ports"] == [8080]
    import json

    json.dumps(marker)  # 必须可序列化，落 engagement.json 用
