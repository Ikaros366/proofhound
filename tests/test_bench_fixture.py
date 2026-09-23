"""M10a Step 1：中性基准 fixture 的「真可确认」与「离线不变式」回归网。

## 为什么需要这个文件

`scripts/bench_triage.py` 的 fixture 原先只是**模拟**特征（取值含引号 → 500），
只能测发现层。M10a 把它升级为**真可确认**（sqlite 拼接注入 / 不转义反射 /
身份归属），以便端到端跑真实确认链路拿 Confirmed 级数字。

这带来两个静默风险，本文件把它们钉死：

1. **可确认性**——真漏洞确实能被真实手段确认（sqlmap 看到真 sqlite 错误；
   无头浏览器看到未转义反射；双会话属性违反确实成立）；
2. **不变式**——端点表/参数名/爬行信号/粗筛长度裁定不变（否则基准数字不可比）。

第 2 类断言是**标定保护**：将来谁改 fixture 的响应体，只要碰到粗筛会读到的长度
关系就会红，而不是让基准数字悄悄漂移。

## 一个真实的坑（务必别再踩）

「A/B 两族行为同构」**不等于**「正文逐字节相同」。第一版升级把三族统一到同一份
正文上，结果 **katana 把正文重复的 URL 当重复响应丢弃**：16 个端点只有 9 个进入
crawler（sqli 5→1、xss 2→1、idor 3→1），live 臂的检出率被爬虫伪造成 25%。
故 `test_no_two_endpoints_share_a_body` 是**硬性回归网**：同构指的是**同一后端、
同一 vuln 语义、唯一变量是参数名**，而不是同字节。
"""

from __future__ import annotations

import importlib.util
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: 以文件路径加载基准脚本（scripts/ 不是包），并注册进 sys.modules——
#: 否则模块内的 ``@dataclass`` 在解析类型注解时取不到模块命名空间。
_spec = importlib.util.spec_from_file_location(
    "bench_triage", REPO_ROOT / "scripts" / "bench_triage.py"
)
bench = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = bench
_spec.loader.exec_module(bench)

from proofhound.verify.prefilter import with_query_param  # noqa: E402


@pytest.fixture(scope="module")
def base():
    """启动 fixture 应用（stdlib http.server，随机端口），模块级复用。"""
    server, url = bench.start_fixture()
    yield url
    server.shutdown()


def _get(url: str, token: str | None = None) -> tuple[int, str]:
    request = urllib.request.Request(url)
    if token:
        request.add_header("Cookie", f"phsess={token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _post(url: str, data: dict[str, str]) -> tuple[int, str]:
    body = urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _endpoint_urls() -> list[str]:
    urls = []
    for ep in bench.ENDPOINTS:
        urls.append(f"{ep.path}?{ep.param}=1" if ep.param else ep.path)
    return urls


# --------------------------------------------------------------- 可确认性


@pytest.mark.parametrize(
    ("path", "key"),
    [
        ("/a/sqli", "id"),
        ("/a/sqli2", "page"),
        ("/b/sqli", "article_id"),
        ("/b/sqli2", "bh"),
        ("/b/sqli3", "sku"),
    ],
)
def test_sqli_endpoints_are_really_injectable(base, path, key):
    """A/B 两族 sqli 端点走真 sqlite 拼接查询：正常取值出记录，注入触发真错误。

    这条是 M10a 的地基——若只是"引号 → 500"的模拟特征，sqlmap 的确认不成立，
    Confirmed 级数字就是假的。
    """
    status, body = _get(f"{base}{path}?{key}=1")
    assert status == 200, (path, status)
    assert "记录" in body

    status, body = _get(f"{base}{path}?{key}=" + urllib.parse.quote("1'"))
    assert status == 500, (path, status)
    assert "数据库错误" in body


def test_form_sqli_endpoints_are_really_injectable(base):
    """C 族（POST 表单）同样走真注入——M8a form_page 路径的可确认版。"""
    status, body = _post(f"{base}/c/form-sqli", {"bh": "1"})
    assert status == 200 and "记录" in body

    status, body = _post(f"{base}/c/form-sqli", {"bh": "1'"})
    assert status == 500 and "数据库错误" in body


@pytest.mark.parametrize(
    ("path", "key"),
    [("/b/sqli", "article_id"), ("/b/sqli2", "bh"), ("/b/sqli3", "sku")],
)
def test_ab_families_share_backend_but_differ_in_body(base, path, key):
    """A/B 两族**同构**：同一后端、同一 vuln 语义、唯一变量是参数名。

    但**不逐字节相同**——正文雷同会被 katana 当重复响应丢弃（见模块 docstring）。
    故这里同时断言"行为等价"与"正文不同"。
    """
    a_status, a_body = _get(f"{base}/a/sqli?id=1")
    b_status, b_body = _get(f"{base}{path}?{key}=1")
    assert (a_status, b_status) == (200, 200)
    # 行为等价：都查到了同一条记录（唯一变量是参数名）
    assert "记录 记录 1" in a_body and "记录 记录 1" in b_body
    # 注入等价
    a_err, _ = _get(f"{base}/a/sqli?id=" + urllib.parse.quote("1'"))
    b_err, _ = _get(f"{base}{path}?{key}=" + urllib.parse.quote("1'"))
    assert (a_err, b_err) == (500, 500)
    # 正文必须不同（否则爬虫丢 URL）
    assert a_body != b_body


@pytest.mark.parametrize(("path", "key"), [("/a/xss", "name"), ("/b/xss", "ref")])
def test_xss_endpoints_reflect_unescaped(base, path, key):
    """A/B 两族 xss **不转义**反射 → 无头浏览器 canary 可确认。"""
    payload = "<b>probe</b>"
    _, body = _get(f"{base}{path}?" + urllib.parse.urlencode({key: payload}))
    assert payload in body


def test_escaped_control_does_not_reflect_raw(base):
    """``/d/safe3`` 真安全：反射**已转义** → canary 不应执行。"""
    _, body = _get(
        f"{base}/d/safe3?" + urllib.parse.urlencode({"name": "<b>probe</b>"})
    )
    assert "<b>probe</b>" not in body
    assert "&lt;b&gt;" in body


@pytest.mark.parametrize(
    ("path", "key"),
    [("/a/idor", "id"), ("/b/idor", "no"), ("/b/idor2", "token")],
)
def test_idor_endpoints_leak_owner_object(base, path, key):
    """IDOR 端点**不做**授权校验：主会话（越权方）拿到与所有者相同的内容。"""
    _, attacker = _get(f"{base}{path}?{key}=1", bench.TOKEN)
    _, owner = _get(f"{base}{path}?{key}=1", bench.REFERENCE_TOKEN)
    assert "所有者" in attacker
    assert attacker == owner, "越权成立要求两会话看到同一份对象内容"


def test_safe4_control_enforces_authorization(base):
    """``/d/safe4`` 真安全：**做**授权校验，属性违反不成立。

    这是"真安全对照"的关键——原实现只对单一取值 403，其余取值两身份同内容，
    在 IDOR 判定器眼里就是成立的属性违反；升级后对所有取值都区分身份。
    """
    _, attacker = _get(f"{base}/d/safe4?no=1", bench.TOKEN)
    _, owner = _get(f"{base}/d/safe4?no=1", bench.REFERENCE_TOKEN)
    assert "无权查看" in attacker
    assert "所有者" in owner
    assert attacker != owner


def test_identity_mapping(base):
    """Cookie → 身份映射：主会话 attacker、第二会话 owner、未知值原样返回。"""
    assert bench.PRIMARY_IDENTITY == "attacker"
    assert bench.OWNER_IDENTITY == "owner"
    assert bench.REFERENCE_TOKEN != bench.TOKEN
    assert len(bench.REFERENCE_TOKEN) >= 16  # 与 TOKEN 同样的脱敏演练长度
    _, unknown = _get(f"{base}/d/safe4?no=1", "some-other-identity")
    assert "无权查看" in unknown


# --------------------------------------------------------------- 不变式


def test_no_two_endpoints_share_a_body(base):
    """**硬性回归网**：16 个端点的响应正文两两不同。

    理由：katana 会把正文重复的 URL 当**重复响应丢弃**，端点因此根本进不了
    crawler。第一版升级把 A/B/C 三族统一到同一份正文，实测 16 个端点只剩 9 个
    被爬到（sqli 5→1、xss 2→1、idor 3→1），live 臂检出率被伪造成 25%。

    因此"行为同构"必须理解为**同一后端 + 同一 vuln 语义 + 唯一变量是参数名**，
    而不是同字节。
    """
    bodies: dict[str, str] = {}
    for url in _endpoint_urls():
        status, body = _get(base + url)
        assert status == 200, (url, status)
        bodies[url] = body

    seen: dict[str, str] = {}
    duplicates = []
    for url, body in bodies.items():
        if body in seen:
            duplicates.append((seen[body], url))
        else:
            seen[body] = url
    assert not duplicates, (
        f"以下端点正文逐字节相同，会被 crawler 当重复响应丢弃：{duplicates}"
    )
    assert len(bodies) == len(bench.ENDPOINTS)


@pytest.mark.parametrize(
    ("url", "key", "length_should_change"),
    [
        # 真漏洞端点：取值影响响应长度 → 粗筛 PROMISING（保持原裁定）
        ("/a/sqli?id=1", "id", True),
        ("/b/sqli?article_id=1", "article_id", True),
        ("/a/xss?name=1", "name", True),
        ("/b/xss?ref=1", "ref", True),
        ("/d/safe3?name=1", "name", True),
        # 安全对照：取值不影响长度 → 粗筛 UNLIKELY（保持原裁定）
        ("/d/safe?id=1", "id", False),
        ("/d/safe2?article_id=1", "article_id", False),
        ("/d/safe4?no=1", "no", False),
    ],
)
def test_prefilter_length_invariants_preserved(base, url, key, length_should_change):
    """粗筛只比响应长度（``verify/prefilter.py::decide``）——故长度关系是**标定**。

    改 fixture 响应体只要碰到这些关系，基准的"粗筛后"数字就会漂移；
    这里把升级前的裁定逐条钉死。
    """
    _, baseline = _get(base + url)
    _, probed = _get(base + with_query_param(url, key, "999999"))
    assert len(baseline) >= 64, "响应体须 >= MIN_COMPARABLE_BYTES，否则长度无信息量"
    changed = len(probed) != len(baseline)
    assert changed == length_should_change, (
        f"{url} 长度关系变了：baseline={len(baseline)} probe={len(probed)}"
    )


def test_crawl_signals_unchanged(base):
    """确定性爬行的 Signal 语料不变：16 条、状态码全 200。

    端点表/首页链接/表单字段若被改动，这里会红——因为 triage 的输入变了，
    三臂消融就不再可比。
    """
    signals, _ = bench.crawl(base)
    assert len(signals) == 16
    assert {s.status_code for s in signals} == {200}
    kinds: dict[str, int] = {}
    for signal in signals:
        kinds[signal.kind] = kinds.get(signal.kind, 0) + 1
    assert kinds == {"param-endpoint": 14, "form_page": 2}


def test_endpoint_table_shape_unchanged():
    """ground truth 端点表形态不变：16 条、12 真漏洞 / 4 安全对照。

    误报率分母（对照端点数）与发现率分母（真漏洞数）一变，历史数字即不可比。
    """
    assert len(bench.ENDPOINTS) == 16
    assert sum(1 for e in bench.ENDPOINTS if e.vuln is not None) == 12
    assert sum(1 for e in bench.ENDPOINTS if e.vuln is None) == 4
    assert tuple(bench.OUT_OF_TABLE) == (
        "article_id", "sku", "ref", "bh", "no", "token", "product", "code",
    )
