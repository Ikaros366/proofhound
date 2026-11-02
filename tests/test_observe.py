"""M26-a：观察点（``proofhound/verify/observe.py``）的单元测试。

这份文件钉住五件事（全部本机、**零真实外网**）：

1. **token 两形态**：内部 ``phfj_<hex>`` / 主机名 ``phfj<hex>``（DNS label 不能有下划线），
   两形态归一到同一 canonical，比较**全等**（同前缀不同 token 不算命中）；
2. **TCP 端口归因**：每个探针独占一个临时端口——连接到达该端口就是该探针的事实，
   包里的 token 只在**与端口归属一致**时才作佐证（M26-a 裁定 C3-P1）；
3. **只观察不投递**：回包是构造期写死的常量（缺省 ``b""``），断言不含任何类/referral 字节；
4. **DNSLog provider**：``allocate``/``poll`` 的 qname 全等匹配、未配置/非法响应一律
   ``ObserverError``（⇒ 调用方记 observer_unavailable，**绝不**当成"没命中"）；
5. **本机 stub**：demo 与单测共用的 ``getdomain``/``getrecords`` 形态，零外网。

时间相关的断言都留了余量（读超时压到 0.2~0.3s、轮询窗口 ≥1s），不靠"刚好赶上"。
"""

from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from proofhound.verify import observe


# --------------------------------------------------------------- 固件


def _ldap_bind(token: str) -> bytes:
    """一段**形态仿真**的 LDAP BindRequest：DN 里带 token（BER 外壳无关紧要）。"""
    return (
        b"\x30\x1d\x02\x01\x03\x04\x13cn="
        + token.encode("ascii")
        + b",dc=example\x80\x00"
    )


def _connect(port: int, *, host: str = "127.0.0.1", timeout: float = 2.0) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def _wait_for(predicate, *, timeout: float = 3.0, interval: float = 0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()


@pytest.fixture()
def tcp_observer():
    observer = observe.TcpObserver(read_timeout=0.3).start()
    try:
        yield observer
    finally:
        observer.stop()


@pytest.fixture()
def stub_server():
    server = observe.LocalStubDnsServer(domain="stub.local").start()
    try:
        yield server
    finally:
        server.stop()


# --------------------------------------------------------------- token


def test_new_token_shape():
    token = observe.new_token()
    assert token.startswith("phfj_")
    body = token[len("phfj_") :]
    assert len(body) == 32
    assert all(ch in "0123456789abcdef" for ch in body)
    assert observe.new_token() != token


def test_host_label_has_no_underscore():
    token = observe.new_token()
    label = observe.host_label(token)
    assert label.startswith("phfj")
    assert "_" not in label
    assert label == "phfj" + token[len("phfj_") :]


def test_canonical_token_accepts_both_forms():
    token = observe.new_token()
    hex_body = token[len("phfj_") :]
    assert observe.canonical_token(token) == token
    assert observe.canonical_token("phfj" + hex_body) == token
    assert observe.canonical_token(hex_body) == token
    assert observe.canonical_token("PHFJ_" + hex_body.upper()) == token


def test_canonical_token_rejects_junk():
    assert observe.canonical_token(None) is None
    assert observe.canonical_token("") is None
    assert observe.canonical_token("phfj_xyz") is None
    assert observe.canonical_token("nope") is None


def test_tokens_equal_is_exact_not_prefix():
    token = observe.new_token()
    other = observe.new_token()
    assert observe.tokens_equal(token, observe.host_label(token)) is True
    assert observe.tokens_equal(token, other) is False
    # 同前缀（32 位里前 31 位相同）也不算命中
    near = token[: len(token) - 1] + ("0" if token[-1] != "0" else "1")
    assert observe.tokens_equal(token, near) is False
    assert observe.tokens_equal(token, None) is False


def test_extract_token_from_raw_bytes():
    token = observe.new_token()
    assert observe.extract_token(_ldap_bind(token)) == token
    assert observe.extract_token(b"no token here") is None
    assert observe.extract_token(b"") is None
    # 主机名形态也要认出来
    assert observe.extract_token(observe.host_label(token).encode()) == token


def test_token_sha8_never_leaks_raw():
    token = observe.new_token()
    marker = observe.token_sha8(token)
    assert marker.startswith("sha256:")
    assert len(marker) == len("sha256:") + 8
    assert token not in marker
    assert observe.token_sha8(None) == ""


# --------------------------------------------------------------- TCP 观察点


def test_tcp_observer_records_token_attribution(tcp_observer):
    token = observe.new_token()
    probe = tcp_observer.allocate(token, kind="ldap")
    assert probe.port > 0
    assert probe.channel == "tcp-ldap"

    with _connect(probe.port) as sock:
        sock.sendall(_ldap_bind(token))
        assert sock.recv(16) == b""  # 只观察：对端立即关闭，无任何回包

    record = _wait_for(lambda: tcp_observer.records())
    assert record is not None, "没有收到连接记录"
    assert len(record) == 1
    item = record[0]
    assert item.channel == "tcp-ldap"
    assert item.token == token
    assert item.source == "127.0.0.1"
    assert item.port == probe.port
    assert item.detail["attribution"] == "token"
    assert item.detail["protocol"] == "ldap"
    assert len(item.detail["first_bytes_sha256"]) == 64
    assert item.detail["bytes"] > 0


def test_tcp_observer_port_attribution_without_payload(tcp_observer):
    """MySQL 是服务端先说话：客户端一个字节都不发，端口本身仍是事实。"""
    token = observe.new_token()
    probe = tcp_observer.allocate(token, kind="jdbc")
    with _connect(probe.port) as sock:
        assert sock.recv(16) == b""

    record = _wait_for(lambda: tcp_observer.records())
    assert record and len(record) == 1
    item = record[0]
    assert item.channel == "tcp-jdbc"
    assert item.token is None  # 读不到 token ⇒ 归因靠端口
    assert item.detail["attribution"] == "port"
    assert item.detail["bytes"] == 0
    assert item.detail["first_bytes_sha256"] == hashlib.sha256(b"").hexdigest()


def test_tcp_observer_ports_are_probe_scoped(tcp_observer):
    first = tcp_observer.allocate(observe.new_token(), kind="ldap")
    second = tcp_observer.allocate(observe.new_token(), kind="ldap")
    assert first.port != second.port
    with _connect(first.port):
        pass
    record = _wait_for(lambda: tcp_observer.records())
    assert record and len(record) == 1
    assert record[0].port == first.port
    assert record[0].detail["protocol"] == "ldap"


def test_tcp_observer_mismatched_token_is_not_attributed(tcp_observer):
    token = observe.new_token()
    other = observe.new_token()
    probe = tcp_observer.allocate(token, kind="ldap")
    with _connect(probe.port) as sock:
        sock.sendall(_ldap_bind(other))

    record = _wait_for(lambda: tcp_observer.records())
    assert record and len(record) == 1
    item = record[0]
    assert item.token is None
    assert item.detail["attribution"] == "mismatch"
    assert item.detail["extracted_token_sha8"] == observe.token_sha8(other)


def test_tcp_observer_refusal_is_constant_and_class_free():
    observer = observe.TcpObserver(read_timeout=0.2).start()
    try:
        token = observe.new_token()
        probe = observer.allocate(token, kind="ldap")
        with _connect(probe.port) as sock:
            sock.sendall(_ldap_bind(token))
            received = sock.recv(4096)
        assert received == b""
        # 回包是构造期写死的常量：长度有上限，且不含任何"可被加载"的字样。
        assert observer.refusal == b""
        assert len(observer.refusal) <= 32
        assert b"class" not in observer.refusal
        assert b"javaCodebase" not in observer.refusal
        assert b"javaFactory" not in observer.refusal
        record = _wait_for(lambda: observer.records())
        assert record is not None
    finally:
        observer.stop()


def test_tcp_observer_custom_refusal_frame_is_sent_verbatim():
    frame = b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x31\x04\x00\x04\x00"
    observer = observe.TcpObserver(read_timeout=0.2, refusal=frame).start()
    try:
        token = observe.new_token()
        probe = observer.allocate(token, kind="ldap")
        with _connect(probe.port) as sock:
            sock.sendall(_ldap_bind(token))
            received = sock.recv(4096)
        assert received == frame
        assert len(received) <= len(frame)
    finally:
        observer.stop()


def test_tcp_observer_read_is_capped():
    observer = observe.TcpObserver(read_timeout=0.3, max_bytes=256).start()
    try:
        token = observe.new_token()
        probe = observer.allocate(token, kind="jdbc")
        with _connect(probe.port) as sock:
            try:
                sock.sendall(b"A" * 8192)
            except OSError:  # 服务端读满上限即关闭，对端可能先收到 RST
                pass
        record = _wait_for(lambda: observer.records())
        assert record and len(record) == 1
        assert record[0].detail["bytes"] <= 256
    finally:
        observer.stop()


def test_tcp_observer_stop_releases_ports():
    observer = observe.TcpObserver(read_timeout=0.2).start()
    token = observe.new_token()
    probe = observer.allocate(token, kind="ldap")
    observer.stop()
    with pytest.raises(OSError):
        _connect(probe.port, timeout=0.5)


def test_tcp_observer_base_port_advances():
    """``base_port`` 非 0 ⇒ 依次尝试 base+i（远程靶需要可预期的端口区间）。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe_sock:
        probe_sock.bind(("127.0.0.1", 0))
        base = probe_sock.getsockname()[1]
    observer = observe.TcpObserver(base_port=base, read_timeout=0.2).start()
    try:
        first = observer.allocate(observe.new_token(), kind="ldap")
        second = observer.allocate(observe.new_token(), kind="ldap")
        assert (first.port, second.port) == (base, base + 1)
    finally:
        observer.stop()


def test_tcp_observer_excerpt_redacts_token(tcp_observer):
    token = observe.new_token()
    probe = tcp_observer.allocate(token, kind="ldap")
    with _connect(probe.port) as sock:
        sock.sendall(b"bind dn: " + token.encode() + b" end")
    record = _wait_for(lambda: tcp_observer.records())
    assert record is not None
    excerpt = record[0].detail["excerpt"]
    assert token not in excerpt
    assert observe.token_sha8(token) in excerpt
    assert "bind dn" in excerpt


def test_observation_to_dict_hides_token(tcp_observer):
    token = observe.new_token()
    probe = tcp_observer.allocate(token, kind="ldap")
    with _connect(probe.port) as sock:
        sock.sendall(_ldap_bind(token))
    record = _wait_for(lambda: tcp_observer.records())
    payload = record[0].to_dict()
    text = json.dumps(payload)
    assert token not in text
    assert payload["token_sha8"] == observe.token_sha8(token)
    assert payload["token_attributed"] is True


# --------------------------------------------------------------- provider：stub


def test_stub_provider_allocate_and_match(stub_server):
    provider = observe.LocalStubProvider(api_base=stub_server.url)
    token = observe.new_token()
    allocation = provider.allocate(token)
    assert allocation.qname == f"{observe.host_label(token)}.stub.local"

    stub_server.register(allocation.qname, ip="203.0.113.9")
    records = provider.poll(token)
    assert len(records) == 1
    item = records[0]
    assert item.token == token
    assert item.source == "203.0.113.9"
    assert item.detail["provider"] == "stub"


def test_stub_provider_rejects_prefix_lookalike(stub_server):
    """同前缀但不同 token（甚至把 qname 当**前缀**加后缀）都不算命中。"""
    provider = observe.LocalStubProvider(api_base=stub_server.url)
    token = observe.new_token()
    allocation = provider.allocate(token)
    stub_server.register(allocation.qname + ".evil.local", ip="203.0.113.9")
    stub_server.register(f"{observe.host_label(observe.new_token())}.stub.local")
    records = provider.poll(token)
    assert len(records) == 2
    assert all(item.token is None for item in records)


def test_stub_provider_requires_api_base():
    with pytest.raises(observe.ObserverError):
        observe.LocalStubProvider(api_base="")


def test_provider_from_env(stub_server):
    assert observe.provider_from_env(env={}) is None
    with pytest.raises(observe.ObserverError):
        observe.provider_from_env(env={observe.ENV_DNS_PROVIDER: "nope"})
    with pytest.raises(observe.ObserverError):
        observe.provider_from_env(env={observe.ENV_DNS_PROVIDER: "stub"})
    with pytest.raises(observe.ObserverError):
        observe.provider_from_env(env={observe.ENV_DNS_PROVIDER: "ceye"})
    provider = observe.provider_from_env(
        env={
            observe.ENV_DNS_PROVIDER: "stub",
            observe.ENV_DNS_API: stub_server.url,
        }
    )
    assert isinstance(provider, observe.LocalStubProvider)


def test_interactsh_is_explicitly_unavailable():
    provider = observe.provider_from_env(env={observe.ENV_DNS_PROVIDER: "interactsh"})
    assert isinstance(provider, observe.InteractshProvider)
    assert provider.available() is False
    with pytest.raises(observe.ObserverError):
        provider.allocate(observe.new_token())


# --------------------------------------------------------------- provider：真实形态（罐头字节）


class _CannedResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def read(self) -> bytes:
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _CannedOpener:
    """替换 urllib opener：按 URL 返回罐头字节（零网络）。"""

    def __init__(self, payloads: dict[str, bytes]):
        self.payloads = payloads
        self.requests: list[str] = []

    def open(self, url, timeout=None):  # noqa: A003 - 模仿 opener 接口
        self.requests.append(url)
        for key, payload in self.payloads.items():
            if key in url:
                return _CannedResponse(payload)
        raise urllib.error.URLError("no canned payload")


def _fake_get(canned: _CannedOpener):
    """把 ``observe._http_get`` 换成本地罐头（**不碰真实网络**）。"""

    def _get(url, *, timeout, opener=None):
        return canned.open(url, timeout=timeout).read()

    return _get


def test_dnslog_cn_parses_canned_records(monkeypatch):
    token = observe.new_token()
    opener = _CannedOpener(
        {
            "getdomain.php": b"example.dnslog.cn\n",
            "getrecords.php": json.dumps(
                [
                    {
                        "domain": f"{observe.host_label(token)}.example.dnslog.cn",
                        "ip": "198.51.100.7",
                        "time": "2026-11-02 10:00:00",
                    },
                    {
                        "domain": "someone-else.example.dnslog.cn",
                        "ip": "198.51.100.8",
                        "time": "2026-11-02 10:00:01",
                    },
                ]
            ).encode(),
        }
    )
    monkeypatch.setattr(observe, "_http_get", _fake_get(opener))
    provider = observe.DnslogCnProvider(base_url="http://dnslog.test")
    allocation = provider.allocate(token)
    assert allocation.qname == f"{observe.host_label(token)}.example.dnslog.cn"
    records = provider.poll(token)
    assert [item.token for item in records] == [token, None]
    assert records[0].source == "198.51.100.7"
    assert records[1].detail["other_host_sha8"]


def test_dnslog_cn_rejects_bad_domain(monkeypatch):
    opener = _CannedOpener({"getdomain.php": b"not a domain\n"})
    monkeypatch.setattr(observe, "_http_get", _fake_get(opener))
    provider = observe.DnslogCnProvider(base_url="http://dnslog.test")
    with pytest.raises(observe.ObserverError):
        provider.allocate(observe.new_token())


def test_ceye_parses_canned_events(monkeypatch):
    token = observe.new_token()
    opener = _CannedOpener(
        {
            "/api/v1/events": json.dumps(
                {
                    "data": [
                        {
                            "name": f"{observe.host_label(token)}.acct.ceye.io",
                            "remote_addr": "192.0.2.5",
                            "created_at": "2026-11-02 10:00:00",
                        }
                    ]
                }
            ).encode()
        }
    )
    monkeypatch.setattr(observe, "_http_get", _fake_get(opener))
    provider = observe.CeyeProvider(domain="acct.ceye.io", token="secret-token")
    allocation = provider.allocate(token)
    assert allocation.qname == f"{observe.host_label(token)}.acct.ceye.io"
    records = provider.poll(token)
    assert records[0].token == token
    assert records[0].source == "192.0.2.5"
    # 事件查询只用主机名形态做过滤，不把观察 token 当 API token 用
    assert observe.host_label(token) in opener.requests[-1]
    assert "secret-token" in opener.requests[-1]


def test_provider_malformed_json_is_observer_error(monkeypatch):
    token = observe.new_token()
    opener = _CannedOpener(
        {"getdomain.php": b"d.example", "/api/v1/events": b"<html>not json</html>"}
    )
    monkeypatch.setattr(observe, "_http_get", _fake_get(opener))
    provider = observe.CeyeProvider(domain="d.example", token="t")
    provider.allocate(token)
    with pytest.raises(observe.ObserverError):
        provider.poll(token)


def test_as_records_accepts_wrapped_lists():
    assert observe._as_records(b'[{"a": 1}]') == [{"a": 1}]
    assert observe._as_records(b'{"data": [{"a": 1}]}') == [{"a": 1}]
    with pytest.raises(observe.ObserverError):
        observe._as_records(b'{"data": "nope"}')


# --------------------------------------------------------------- collect_dns


def test_collect_dns_returns_matches_and_ignores_noise(stub_server):
    provider = observe.LocalStubProvider(api_base=stub_server.url)
    token = observe.new_token()
    allocation = provider.allocate(token)
    stub_server.register(f"{observe.host_label(observe.new_token())}.stub.local")
    stub_server.register(allocation.qname, ip="203.0.113.10")

    records = observe.collect_dns(
        provider, {token: allocation}, wait=1.0, interval=0.05
    )
    matched = [item for item in records if item.token is not None]
    assert [item.token for item in matched] == [token]
    assert any(item.token is None for item in records)


def test_collect_dns_waits_for_late_record(stub_server):
    provider = observe.LocalStubProvider(api_base=stub_server.url)
    token = observe.new_token()
    allocation = provider.allocate(token)

    def _late():
        time.sleep(0.3)
        stub_server.register(allocation.qname)

    thread = threading.Thread(target=_late, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        records = observe.collect_dns(
            provider, {token: allocation}, wait=2.0, interval=0.05
        )
        elapsed = time.monotonic() - started
    finally:
        thread.join(timeout=2.0)
    assert [item.token for item in records if item.token] == [token]
    assert elapsed >= 0.25


def test_collect_dns_empty_allocations_returns_nothing(stub_server):
    provider = observe.LocalStubProvider(api_base=stub_server.url)
    assert observe.collect_dns(provider, {}, wait=0.5) == []


# --------------------------------------------------------------- 本机 stub 服务


def test_stub_server_serves_provider_endpoints(stub_server):
    with urllib.request.urlopen(f"{stub_server.url}/getdomain.php", timeout=2) as resp:
        assert resp.read().decode().strip() == "stub.local"
    with urllib.request.urlopen(f"{stub_server.url}/getrecords.php", timeout=2) as resp:
        assert json.loads(resp.read().decode()) == []


def test_stub_server_register_and_reject_bad_payload(stub_server):
    request = urllib.request.Request(
        f"{stub_server.url}/register",
        data=json.dumps({"qname": "phfjabc.stub.local", "ip": "127.0.0.9"}).encode(),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=2) as resp:
        assert resp.status == 204
    records = stub_server.records
    assert len(records) == 1
    assert records[0]["domain"] == "phfjabc.stub.local"
    assert records[0]["ip"] == "127.0.0.9"

    bad = urllib.request.Request(
        f"{stub_server.url}/register", data=b"{}", method="POST"
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(bad, timeout=2)
    assert excinfo.value.code == 400
