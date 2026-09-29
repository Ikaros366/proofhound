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

## M15：E 族（真 SSRF）+ SSRF 形对照

SSRF 两步走的第一步只在基准上加**候选族**（`vuln_type` 白名单开 `ssrf`），
不建验证器、不动 `GATE_MATRIX`。本文件补两类断言：

1. **可确认性的前提——服务端真的代为发请求**：E 族端点必须真的按参数取值发起
   HTTP 请求，且非 http/https 取值被收敛成 200 + 错误文案（端点存在性不受取值
   影响）。第二步若建 `verify-ssrf`（回调服务器收到请求 = 二值事实），靠的就是
   这个行为；若这里只是“看起来像”，第二步的确认数字会是假的。
2. **不变式**：`/d/ssrf-like`（看着像 SSRF 但服务端不发起请求）必须与 D 族同款
   ——两个探测取值响应长度相同（粗筛只比长度），且**不回显取值**。
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


#: M15 之前（M10a/M11b/M11c）A/B/C/D 四族的 16 条端点路径。
#: 这四族是**历史数字的可比性基线**——它们的路径/参数名/行为一动，
#: 历史发现率与误报率就不再可比。故这里逐条列名，供下面的断言与冒烟测试用。
LEGACY_ENDPOINTS: tuple[str, ...] = (
    "/a/sqli", "/a/sqli2", "/a/xss", "/a/idor",
    "/b/sqli", "/b/sqli2", "/b/sqli3", "/b/xss", "/b/idor", "/b/idor2",
    "/c/form-sqli", "/c/form-sqli2",
    "/d/safe", "/d/safe2", "/d/safe3", "/d/safe4",
)


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


# ------------------------------------------------- 冒烟：端点全部可达


@pytest.mark.parametrize("url", _endpoint_urls())
def test_every_endpoint_is_reachable(base, url):
    """22 条端点全部可爬（200）——加族之后最容易踩的是新端点漏进 404。

    加这一条的理由：`test_no_two_endpoints_share_a_body` 是**带会话**取数，新端点若漏了路由会一起 404，而那条测试的失败信息会指向"正文重复"（404 页正文对多条端点相同），把根因误导成正文问题。这里用与爬行一致的视角（带会话）单独钉住可达性。
    """
    status, _body = _get(base + url, bench.TOKEN)
    assert status == 200, (url, status)


# ------------------------------------------------- M15：E 族（真 SSRF）


@pytest.mark.parametrize(
    ("path", "key"),
    [
        ("/e/fetch", "url"),
        ("/e/fetch2", "redirect"),
        ("/e/fetch3", "target"),
        ("/e/fetch4", "feed"),
        ("/e/fetch5", "avatar"),
    ],
)
def test_ssrf_endpoints_really_issue_server_side_requests(base, path, key):
    """E 族**真的**按参数取值发起服务端请求——SSRF 的行为本体。

    这条是第二步（建 `verify-ssrf`，确认手段 = 回调服务器收到请求）的地基：
    若端点只是“把取值回显出来”，回调判定永远收不到请求，第二步的数字就是假的。
    这里用 **fixture 自己的** `/e/list` 作目标（本地同源）：既真发了 HTTP 请求，
    又让基准零外部依赖、可离线复现。
    """
    status, body = _get(
        f"{base}{path}?" + urllib.parse.urlencode({key: f"{base}/e/list"})
    )
    assert status == 200
    assert "抓取成功" in body, "E 族端点没有真的代发请求"
    assert "状态码 200" in body


@pytest.mark.parametrize(
    ("path", "key"),
    [
        ("/e/fetch", "url"),
        ("/e/fetch2", "redirect"),
        ("/e/fetch3", "target"),
        ("/e/fetch4", "feed"),
        ("/e/fetch5", "avatar"),
    ],
)
def test_ssrf_endpoints_reject_non_url_values_without_lying(base, path, key):
    """非 http/https 取值：**端点仍存在**（200 + 失败文案），不是 404。

    两个理由：① 基准纪律——取值不该改变“端点存在”这件事，否则爬行状态码不变式
    会随探针漂；② 真实应用同款形态（“参数非法”与“端点不存在”是两回事）。
    """
    for bad in ("1", "file:///etc/passwd", "not a url"):
        status, body = _get(
            f"{base}{path}?" + urllib.parse.urlencode({key: bad})
        )
        assert status == 200, (path, bad, status)
        assert "抓取失败" in body, (path, bad)


def test_ssrf_endpoints_never_read_local_files(base):
    """`file://` 不被当作可取目标——fixture 的取样器只认 http(s)。

    这是**取样器的边界**，不是被测系统的边界（真实系统该不该允许 file:// 是
    verify-ssrf 的设计问题）；这里钉住的是“基准不隐藏这个事实”：取值非法时
    正文只是失败文案，绝不出现本地文件内容。
    """
    _, body = _get(
        f"{base}/e/fetch3?"
        + urllib.parse.urlencode({"target": "file:///etc/passwd"})
    )
    assert "抓取失败" in body
    assert "root:" not in body, "fixture 读取了本地文件"


def test_ssrf_like_control_never_issues_a_request(base):
    """`/d/ssrf-like` 真安全：参数只被登记，服务端**不发起任何请求**。

    交接文档点名的 D 族对照形态（“看起来像但不是 SSRF，例如参数只被记录、
    服务端不发起请求”）。判据用**行为**而非措辞：若它真去取了 fixture 自己的
    `/e/list`，正文会带“抓取成功”与目标路径——两条断言把它们排除掉。
    """
    _, probe = _get(
        f"{base}/d/ssrf-like?"
        + urllib.parse.urlencode({"callback": f"{base}/e/list"})
    )
    assert "抓取成功" not in probe
    assert "/e/list" not in probe, "对照端点回显了取值（那就成了反射，不再是纯对照）"
    _, other = _get(f"{base}/d/ssrf-like?callback=1")
    assert probe == other, "对照端点响应随取值变化——D 族定长性质被破坏"


# --------------------------------------------------------------- 不变式


def test_no_two_endpoints_share_a_body(base):
    """**硬性回归网**：全部 22 个端点的响应正文两两不同。

    理由：katana 会把正文重复的 URL 当**重复响应丢弃**，端点因此根本进不了
    crawler。第一版升级把 A/B/C 三族统一到同一份正文，实测 16 个端点只剩 9 个
    被爬到（sqli 5→1、xss 2→1、idor 3→1），live 臂检出率被伪造成 25%。

    因此"行为同构"必须理解为**同一后端 + 同一 vuln 语义 + 唯一变量是参数名**，
    而不是同字节。
    """
    bodies: dict[str, str] = {}
    for url in _endpoint_urls():
        # M11c：带**攻击者会话**取数——与 katana 爬行视角一致（IDOR 端点对匿名
        # 请求返回 403 通用页，匿名视角下它们会被误判为"正文重复"）
        status, body = _get(base + url, bench.TOKEN)
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
        # M15：SSRF 形对照——参数名像 SSRF，但服务端不发起请求、不回显取值
        ("/d/ssrf-like?callback=1", "callback", False),
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
    """确定性爬行的 Signal 语料：22 条、状态码全 200。

    端点表/首页链接/表单字段若被改动，这里会红——因为 triage 的输入变了，
    三臂消融就不再可比。

    M15 披露：计数 16 → 22、param-endpoint 14 → 20，是**加了 E 族（5 条真 SSRF）
    与 SSRF 形对照（1 条）**的必然结果，不是既有端点被动过——A/B/C/D 四族的
    16 条仍逐条在列（由 test_endpoint_table_shape_unchanged 的族分量断言钉死）。
    """
    signals, _ = bench.crawl(base)
    assert len(signals) == 22
    assert {s.status_code for s in signals} == {200}
    kinds: dict[str, int] = {}
    for signal in signals:
        kinds[signal.kind] = kinds.get(signal.kind, 0) + 1
    assert kinds == {"param-endpoint": 20, "form_page": 2}


def test_endpoint_table_shape_unchanged():
    """ground truth 端点表形态：22 条、17 真漏洞 / 5 安全对照。

    误报率分母（对照端点数）与发现率分母（真漏洞数）一变，历史数字即不可比——
    故 M15 的分母变化必须**显式**写在这里（16/12/4 → 22/17/5：新增 5 条真 SSRF
    + 1 条 SSRF 形对照），并由下面的族分量断言钉死“旧族一条没动”。
    """
    assert len(bench.ENDPOINTS) == 22
    assert sum(1 for e in bench.ENDPOINTS if e.vuln is not None) == 17
    assert sum(1 for e in bench.ENDPOINTS if e.vuln is None) == 5
    # M15：族分量——A/B/C/D 四族逐条不变，新增的只有 E 族与 SSRF 形对照
    families: dict[str, int] = {}
    for ep in bench.ENDPOINTS:
        families[ep.path.split("/")[1]] = families.get(ep.path.split("/")[1], 0) + 1
    assert families == {"a": 4, "b": 6, "c": 2, "d": 5, "e": 5}
    assert sum(1 for e in bench.ENDPOINTS if e.vuln == "ssrf") == 5
    # 族计数还不够——同族换一条也能骗过计数，故**逐条列名**断言旧 16 条仍在
    present = {ep.path for ep in bench.ENDPOINTS}
    missing = [path for path in LEGACY_ENDPOINTS if path not in present]
    assert not missing, f"既有端点被删改：{missing}"
    assert tuple(bench.OUT_OF_TABLE) == (
        "article_id", "sku", "ref", "bh", "no", "token", "product", "code",
    )

# ------------------------------------------------- M11b：fixture 控制面语义


def test_idor_endpoints_deny_unauthenticated(base):
    """M11b：IDOR 端点对**未认证**请求返回定长通用页（不泄漏对象内容）。

    动机：若匿名也能拿到对象页，"公开资源"与"B 的私有对象被 A 拿到"在未认证
    对照下**同形**，判据无法区分（这正是 Verifier 索要而拿不到的那个对照缺失的
    根因）。

    M11c 修正：**403 拒绝**（而非 200）。首版用 200 + 登录页，结果 M11b 的对照
    判据（只否定、不肯定）判 ``blocked`` 而非 ``protected``，真 IDOR 因此系统性
    测不到判定结果。403 是"未认证被拒"的明确表达，判据随之进入设计预期分支
    （302 亦被实测否决：会被 urllib 跟随到未注册的 /login → 404，语义模糊）。
    """
    for path, key in (("/a/idor", "id"), ("/b/idor", "no"), ("/b/idor2", "token")):
        status, body = _get(f"{base}{path}?{key}=1", None)  # 不带任何凭据
        assert status == 403, (path, status)
        assert "所有者" not in body, f"{path} 向未认证请求泄漏了对象归属"
        assert "未认证会话" in body


def test_idor_endpoints_still_leak_to_authenticated_attacker(base):
    """漏洞语义不变：已认证**非属主**仍拿到对象页（ground truth 未变）。"""
    _, attacker = _get(f"{base}/a/idor?id=1", bench.TOKEN)
    assert "所有者" in attacker
    assert "未认证会话" not in attacker


def test_footer_is_per_endpoint_not_credential(base):
    """M11b：footer 是 per-endpoint 标记，**不再回显任何凭据**。

    原实现硬编码 ``session=<主会话 token>``——页面在"谁在看"上说谎，且制造了
    A/B 正文逐字节相同的伪迹（M10a 的 Verifier 据此质疑"更像公开内容"）。
    """
    _, body_a = _get(f"{base}/a/idor?id=1", bench.TOKEN)
    _, body_b = _get(f"{base}/b/idor?no=1", bench.TOKEN)
    for body in (body_a, body_b):
        assert "<footer>ep=" in body
        assert bench.TOKEN not in body
        assert bench.REFERENCE_TOKEN not in body
    # 端点标记唯一 → 正文可区分（katana 不会当重复响应丢弃）
    assert body_a != body_b


def test_control_probe_basis_owner_and_attacker_see_object(base):
    """对照探测的判据基础：owner 与 attacker 都拿到对象页，**未认证拿不到**。"""
    _, owner = _get(f"{base}/a/idor?id=1", bench.REFERENCE_TOKEN)
    _, attacker = _get(f"{base}/a/idor?id=1", bench.TOKEN)
    _, anon = _get(f"{base}/a/idor?id=1", None)
    assert "所有者" in owner and "所有者" in attacker
    assert "所有者" not in anon
