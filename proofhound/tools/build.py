"""确定性命令构造器（§5.3 红线 1 的 M2b 落地形态）。

LLM 规划输出为结构化 JSON（action/tool/params），**不直接生成 shell 命令**；
argv 由本模块按工具名分派到确定性构造函数拼装，参数经 Pydantic 强校验。

- 产出 argv 列表（首元素为工具名），不经 shell 解释，无注入面；
- scope 校验仍在 ``SandboxRunner.run`` 内对 argv 强制执行（红线 5 不变）；
- restricted 出口模式下由调用方传入 ``egress_proxy_url``，构造函数负责
  注入显式代理参数（httpx 不读 proxy 环境变量）；
- M3b 预置会话：params 里只声明 ``with_session: true``，真实凭据由构造器
  从 ``session``（Scope 上的 SessionConfig）注入——LLM 永不接触凭据原文；
  ``with_session=True`` 而无 session 即校验失败（fail-closed）。
- **M16-b 请求量授权**：按字典**主动发请求**的工具（dirsearch）不自己定速率/并发/总量
  ——这些来自 ``Scope.request_budget``（未声明则用保守缺省值，审计记
  ``source="default"``）。构造器负责把预算翻成工具旗标，并据 ``max_requests``
  **截词表**（确定性硬闸）；同时提供 :func:`dirsearch_timeout_for` 把时间窗折算成
  沙箱超时，供调用方与硬上限 300s 取小。
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator, model_validator

from proofhound.compliance.scope import RequestBudget
from proofhound.compliance.session import SessionConfig


class UnknownToolError(ValueError):
    """没有命令构造器的工具。"""


class HttpxParams(BaseModel):
    """httpx 探活参数（对应 skills/web-scan SOP 的探活步骤）。"""

    target: str = Field(min_length=1)  # 单目标 URL 或 host
    rate_limit: int = Field(default=50, gt=0, le=1000)
    tech_detect: bool = True
    follow_redirects: bool = True
    with_session: bool = False  # M3b：注入预置会话（Cookie/额外请求头）

    @field_validator("target")
    @classmethod
    def _no_flag_injection(cls, value: str) -> str:
        if value.strip().startswith("-"):
            raise ValueError("target 不得以 - 开头（旗标注入防护）")
        return value.strip()


def _require_session(with_session: bool, session: SessionConfig | None) -> SessionConfig:
    """with_session=True 必须配会话，否则 fail-closed 校验失败。"""
    if not with_session:
        return SessionConfig()
    if session is None or not session.cookie_header():
        raise ValueError("with_session=True 要求 scope 配置预置会话（session.cookies）")
    return session


def _session_headers(session: SessionConfig) -> list[str]:
    """把预置会话渲染为 httpx ``-H`` 请求头列表。"""
    headers = [f"Cookie: {session.cookie_header()}"]
    headers.extend(f"{k}: {v}" for k, v in session.headers.items())
    return headers


def _build_httpx(
    params: dict,
    *,
    egress_proxy_url: str | None = None,
    session: SessionConfig | None = None,
) -> list[str]:
    p = HttpxParams.model_validate(params)
    argv = ["httpx", "-u", p.target]
    if egress_proxy_url:
        argv += ["-proxy", egress_proxy_url]
    if p.with_session:
        for header in _session_headers(_require_session(True, session)):
            argv += ["-H", header]
    argv += ["-status-code", "-title"]
    if p.tech_detect:
        argv.append("-tech-detect")
    if p.follow_redirects:
        argv.append("-follow-redirects")
    argv += ["-rate-limit", str(p.rate_limit), "-json", "-silent", "-no-color"]
    return argv


_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class SqlmapParams(BaseModel):
    """sqlmap 注入确认参数（对应 skills/verify-sqli SOP，L2 利用验证）。

    level/risk 设硬上限（3/2）：防规划或配置失误导致测试面失控；
    ``--batch``（禁交互）与 ``--flush-session``（禁陈旧会话缓存）恒由构造器
    强制，不接受参数覆盖。

    M8a：``forms=True`` 为 POST 表单页模式——sqlmap 自行解析页面内表单
    并测试其字段，**与 ``param`` 互斥**（不指定 ``-p``），且构造器永不产
    ``--data``（不手拼请求体，表单字段由目标页面自身决定）。
    """

    url: str = Field(min_length=1)  # 含注入参数的完整 URL（GET）或表单页 URL（forms）
    param: str | None = None  # 指定测试参数（-p），缺省测全部
    with_session: bool = False  # 注入预置会话（--cookie）
    level: int = Field(default=1, ge=1, le=3)
    risk: int = Field(default=1, ge=1, le=2)
    forms: bool = False  # M8a：POST 表单页模式（--forms；与 param 互斥）

    @field_validator("url")
    @classmethod
    def _valid_url(cls, value: str) -> str:
        value = value.strip()
        if value.startswith("-"):
            raise ValueError("url 不得以 - 开头（旗标注入防护）")
        if not re.match(r"^https?://[^\s/]+", value):
            raise ValueError("url 必须是 http(s) URL")
        return value

    @field_validator("param")
    @classmethod
    def _valid_param(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if value.startswith("-"):
            raise ValueError("param 不得以 - 开头（旗标注入防护）")
        if not _PARAM_NAME_RE.match(value):
            raise ValueError("param 只允许字母数字与 _ . -")
        return value

    @model_validator(mode="after")
    def _forms_excludes_param(self) -> "SqlmapParams":
        if self.forms and self.param is not None:
            raise ValueError("forms 模式与 param 互斥（--forms 自解析表单，不指定 -p）")
        return self


def _build_sqlmap(
    params: dict,
    *,
    egress_proxy_url: str | None = None,
    session: SessionConfig | None = None,
) -> list[str]:
    p = SqlmapParams.model_validate(params)
    argv = ["sqlmap", "-u", p.url]
    if egress_proxy_url:
        argv += ["--proxy", egress_proxy_url]
    if p.with_session:
        argv += ["--cookie", _require_session(True, session).cookie_header()]
    if p.forms:
        # M8a：POST 表单页模式——sqlmap 自解析页面内表单；永不手拼 --data
        argv.append("--forms")
    elif p.param:
        argv += ["-p", p.param]
    argv += [
        "--level", str(p.level),
        "--risk", str(p.risk),
        "--batch",  # 禁交互（硬编码，不可覆盖）
        "--flush-session",  # 禁陈旧会话缓存
        "--disable-coloring",  # 输出进证据文件，禁 ANSI 转义
    ]
    return argv


class KatanaParams(BaseModel):
    """katana 爬行参数（对应 skills/recon-crawl SOP，L1 发现类）。

    恒在项（构造器写死，不接受参数覆盖）：``-jsonl -silent -nc -fs rdn``
    （field-scope 限种子根域，三层 scope 纵深第一层）、
    ``-cos "(?i)(logout|logoff|signout|signoff|phpids)"``（爬行安全排除，
    v1.7.0 实测：katana 会把状态变更类 GET 链接当普通链接抓取——logout
    销毁服务端会话导致带认证爬行中途失效；DVWA ``security.php?phpids=on``
    会为该会话开启 PHPIDS、后续攻击载荷全被拦截。注意 -cos 值不能含
    逗号——旗标按逗号分片，``{m,n}`` 量词会被截断），以及
    **``-jc``（JS 文件内端点解析/爬行，M16-a）**——理由见下；
    **永不产 ``-o``**——输出只走 stdout → 容器日志 → 证据落盘（红线 3）。
    depth/concurrency/rate_limit 设硬上限，防爬行面失控；不暴露 headless。

    可选参数 ``jsluice``（``-jsl``，缺省 **关**，M16-a 实测后决定）：
    jsluice 用 AST 解析 JS，官方标注 memory intensive。实测（12MB 真实
    bundle、沙箱同档 512m 容器）峰值内存 447MiB vs 不开 248MiB，
    而**端点提取集合与 ``-jc`` 等价**（6 组 JS 形态 × 3~5 次重复，并集
    相同）⇒ 缺省不开：白付 ~200MiB 内存与 OOM 风险，换不到额外端点。
    已知唯一增量是拼接串的占位符形态（``-jc`` 出 ``?id=``、``-jsl`` 出
    ``?id=EXPR``），两者都过不了下游键名启发式，故不构成理由。
    需要更激进的 JS 解析时显式开 ``jsluice=True``。

    刻意**不暴露** ``-kf``/``-known-files``：官方要求 depth ≥ 3 才生效，
    而本构造器 depth 缺省 2、硬上限 5——给一个"开了也可能静默不生效"的
    参数容易误导；且它抓的是 robots.txt/sitemap.xml 这类已知文件，属
    字典/已知路径面（M16-b），不属本轮 JS 发现面。
    """

    target: str = Field(min_length=1)  # 单种子 URL
    depth: int = Field(default=2, ge=1, le=5)
    concurrency: int = Field(default=5, ge=1, le=10)
    rate_limit: int | None = Field(default=None, gt=0, le=150)  # -rl，缺省不限
    with_session: bool = False  # 注入预置会话（-H Cookie/自定义头）
    jsluice: bool = False  # -jsl：jsluice AST 解析（memory intensive，缺省关）

    @field_validator("target")
    @classmethod
    def _no_flag_injection(cls, value: str) -> str:
        if value.strip().startswith("-"):
            raise ValueError("target 不得以 - 开头（旗标注入防护）")
        return value.strip()


def _build_katana(
    params: dict,
    *,
    egress_proxy_url: str | None = None,
    session: SessionConfig | None = None,
) -> list[str]:
    p = KatanaParams.model_validate(params)
    argv = ["katana", "-u", p.target]
    if egress_proxy_url:
        argv += ["-proxy", egress_proxy_url]
    if p.with_session:
        for header in _session_headers(_require_session(True, session)):
            argv += ["-H", header]
    argv += ["-d", str(p.depth), "-c", str(p.concurrency)]
    if p.rate_limit is not None:
        argv += ["-rl", str(p.rate_limit)]
    # M16-a：JS 文件内端点解析/爬行。**恒在项**（同 -fs rdn/-cos 的地位）：
    # JS 里写死的接口路径是爬行面的一大块，不开等于整块看不见；
    # 实测对内存/耗时无可测影响（见 KatanaParams docstring）。
    argv.append("-jc")
    # M16-a：jsluice AST 解析（可选、缺省关）。实测与 -jc 提取集合等价而
    # 峰值内存近乎翻倍，故不写成恒在项——要更激进的解析须显式开。
    if p.jsluice:
        argv.append("-jsl")
    # 恒在项（写死）：-fs rdn 限种子根域；-cos 排除状态变更类 GET 链接
    # （logout 自毁会话、phpids 开关为目标开启 IDS）；值不含逗号
    # （-cos 旗标按逗号分片，量词 {m,n} 会被截断失效）
    argv += [
        "-jsonl", "-silent", "-nc", "-fs", "rdn",
        "-cos", "(?i)(logout|logoff|signout|signoff|phpids)",
    ]
    return argv


# M16-b：dirsearch 扩展名白名单（旗标注入防护——多个扩展名用逗号分隔，
# 只允许字母数字）。
_EXTENSIONS_RE = re.compile(r"^[A-Za-z0-9]+(?:,[A-Za-z0-9]+)*$")

# M16-b：沙箱超时硬上限（与既有默认一致；时间窗只会把它**收窄**，永不放宽）。
SANDBOX_TIMEOUT_CAP = 300


class DirsearchParams(BaseModel):
    """dirsearch 字典爆路径参数（M16-b，L1 主动发现类）。

    **请求量三维全部来自 scope，不由 LLM 给**：``rate_rps`` / ``concurrency`` /
    ``max_requests`` 由调用方从 ``Scope.request_budget`` 取（未声明即保守缺省值）
    传进来。理由：速率与请求总量是**授权语义**，不是规划参数——LLM 不参与
    （红线 1：命令由构造器按 manifest/scope 拼装）。

    恒在项（构造器写死，不接受参数覆盖）：

    - ``-q``（安静：进度条不进证据）、``--no-color``（证据里不留 ANSI 转义）；
    - ``-O json`` + ``-o /tmp/ds_report.json``——报告写进容器唯一可写处（tmpfs），
      wrapper 负责 ``cat`` 回 stdout（**rootfs 只读 + tmpfs 随容器销毁，不 cat 则
      报告蒸发**，红线 3 的证据就拿不到）；
    - ``-t <concurrency>`` / ``--max-rate <rate_rps>``——**授权语义的落点**；
    - ``--max-time <秒>``——仅在 scope 声明了时间窗时产（授权时间窗的落点）。

    **永不产** ``-r``/``--recursive``（递归爆破会成倍放大请求量，且越出面随重定向
    扩大）与 ``-F``/``--follow-redirects``（默认即不跟随，明确不放开）。
    ``--wordlists`` 恒指向容器内的内置字典（``/opt/tools/dicc.txt``）或显式挂载路径。
    """

    target: str = Field(min_length=1)  # 单目标 URL
    rate_rps: int = Field(ge=1, le=200)  # 来自 scope.request_budget
    concurrency: int = Field(ge=1, le=20)  # 来自 scope.request_budget
    max_requests: int = Field(ge=1, le=50000)  # 来自 scope.request_budget
    window_seconds: int | None = Field(default=None, ge=1, le=1440 * 60)
    extensions: str = "php,asp,aspx,jsp,html,htm"
    wordlist: str = "/opt/tools/dicc.txt"
    with_session: bool = False  # 注入预置会话（-H Cookie）

    @field_validator("target")
    @classmethod
    def _no_flag_injection(cls, value: str) -> str:
        if value.strip().startswith("-"):
            raise ValueError("target 不得以 - 开头（旗标注入防护）")
        return value.strip()

    @field_validator("extensions")
    @classmethod
    def _valid_extensions(cls, value: str) -> str:
        value = value.strip()
        if not _EXTENSIONS_RE.match(value):
            raise ValueError("extensions 只允许字母数字，逗号分隔")
        return value

    @field_validator("wordlist")
    @classmethod
    def _valid_wordlist(cls, value: str) -> str:
        value = value.strip()
        if value.startswith("-") or not value:
            raise ValueError("wordlist 非法（旗标注入防护）")
        return value


def dirsearch_wordlist_head(params: "DirsearchParams") -> int:
    """按请求总量上限算出**允许读入的词条数**（确定性硬闸）。

    dirsearch 会把每个词条与 ``-e`` 的每个扩展名各拼一个路径，故按
    ``max_requests // (1 + len(extensions))`` 反推允许的词条数。

    **这是保守上界，不是精确请求计数**：实现期实测 ``dicc.txt``（9681 词条）+
    默认 6 扩展，靶侧实际只收到 **12308** 次请求——远低于 ``9681 * 7 = 67767``
    这个朴素上界（dirsearch 1.7.0 的扩展名展开与去重行为未完全逆向）。因此该公式
    只会**截得更狠**，方向是 fail-closed（宁可少发请求），符合授权语义。
    反之，工具在重定向/校准等场景下仍可能发出词表之外的少量请求，故
    ``max_requests`` 是**词表侧硬闸**，不是逐请求的精确配额。
    """
    n_ext = len([e for e in params.extensions.split(",") if e]) if params.extensions else 0
    per_word = 1 + n_ext
    return max(1, params.max_requests // per_word)


def build_dirsearch_params(
    target: str,
    budget: RequestBudget,
    *,
    wordlist: str = "/opt/tools/dicc.txt",
    extensions: str = "php,asp,aspx,jsp,html,htm",
    with_session: bool = False,
) -> dict:
    """组装 dirsearch 的入参 dict（**含**从预算来的四要素）。

    预算必须**显式传入**（调用方用 ``scope.resolved_request_budget()``）——不给
    缺省值，避免"忘了传就静默用别的值"。
    """
    return {
        "target": target,
        "rate_rps": budget.rate_rps,
        "concurrency": budget.concurrency,
        "max_requests": budget.max_requests,
        "window_seconds": budget.max_seconds(),
        "extensions": extensions,
        "wordlist": wordlist,
        "with_session": with_session,
    }


#: 工具自限时占授权时间窗的比例。实测（M16-b 验收）：`--max-time 60` 在
#: 1 分钟窗口上**未触发**自截——扫描一直跑到沙箱超时（61.4s）才被杀；
#: 而 `--max-time 8` 是能触发的。故留 30% 余量让 dirsearch 自己收尾并落报告，
#: 避免"第一道没赶上、报告也没写出来"的双输形态。
_TOOL_SELF_LIMIT_RATIO = 0.7


def _tool_self_limit_seconds(window_seconds: int) -> int:
    """把授权时间窗折算成**工具自限时**秒数（至少 1 秒，且不超过窗口本身）。"""
    return max(1, min(window_seconds, int(window_seconds * _TOOL_SELF_LIMIT_RATIO)))


def dirsearch_timeout_for(scope) -> int:
    """本次 dirsearch 执行的沙箱超时：``min(300, 时间窗)``。

    M16-b：授权时间窗是**用户意图**，工具自限时（``--max-time``）是**第一道**；
    沙箱超时是**第二道**（容器层面强杀）。两道取小，**时间窗只会收窄超时、永不放宽**。
    """
    seconds = scope.resolved_request_budget().max_seconds()
    if seconds is None:
        return SANDBOX_TIMEOUT_CAP
    return max(1, min(SANDBOX_TIMEOUT_CAP, seconds))


def _build_dirsearch(
    params: dict,
    *,
    egress_proxy_url: str | None = None,
    session: SessionConfig | None = None,
) -> list[str]:
    p = DirsearchParams.model_validate(params)
    argv = ["dirsearch", "-u", p.target]
    if egress_proxy_url:
        argv += ["--proxy", egress_proxy_url]
    if p.with_session:
        for header in _session_headers(_require_session(True, session)):
            argv += ["-H", header]
    argv += [
        "-t", str(p.concurrency),
        "--max-rate", str(p.rate_rps),
    ]
    # 授权时间窗 → 工具自限时（第一道；沙箱超时是第二道，见 dirsearch_timeout_for）。
    # 取窗口的 70%（见 _tool_self_limit_seconds 的实测理由）：让工具**先于**沙箱超时
    # 自己收尾并落报告；沙箱超时仍用完整窗口秒数兜底硬杀。
    if p.window_seconds is not None:
        argv += ["--max-time", str(_tool_self_limit_seconds(p.window_seconds))]
    argv += [
        "--wordlists", p.wordlist,
        "-e", p.extensions,
        "-q", "--no-color",
        "-O", "json",
        "-o", "/tmp/ds_report.json",
    ]
    # 恒在项缺席声明（写死在下方注释，不产旗标）：
    #   -r/--recursive        递归爆破成倍放大请求量 —— 永不产
    #   -F/--follow-redirects 默认即不跟随重定向 —— 永不产
    return argv


_BUILDERS = {
    "httpx": _build_httpx,
    "sqlmap": _build_sqlmap,
    "katana": _build_katana,
    "dirsearch": _build_dirsearch,
}

_PARAMS_MODELS = {
    "httpx": HttpxParams,
    "sqlmap": SqlmapParams,
    "katana": KatanaParams,
    "dirsearch": DirsearchParams,
}


def build_command(
    tool: str,
    params: dict,
    *,
    egress_proxy_url: str | None = None,
    session: SessionConfig | None = None,
    request_budget: RequestBudget | None = None,
) -> list[str]:
    """按工具名构造 argv；未知工具抛 :class:`UnknownToolError`。

    ``request_budget``（M16-b）：**主动按字典发请求**的工具（dirsearch）用它落请求量
    授权语义。未传时取保守缺省值；对不消费预算的工具**刻意报错**——静默忽略会让
    "以为授了限速、其实没生效"成为可能（fail-closed 方向）。
    """
    builder = _BUILDERS.get(tool)
    if builder is None:
        raise UnknownToolError(f"工具 {tool} 没有命令构造器")
    if tool == "dirsearch":
        # M16-b：请求量预算的**单一真相源是 request_budget 参数**。调用方必须显式传
        # ``scope.resolved_request_budget()``（未声明 scope 时它返回保守缺省值）。
        # **不**在 params 里静默接受这四个键——静默忽略授权值会让"以为授了限速、
        # 其实没生效"成为可能，故此处 fail-closed 报错。
        if request_budget is None:
            raise ValueError(
                "dirsearch 必须显式传 request_budget"
                "（用 scope.resolved_request_budget()；未声明 scope 时它返回保守缺省值）"
            )
        smuggled = [k for k in ("rate_rps", "concurrency", "max_requests",
                                "window_seconds") if k in params]
        if smuggled:
            raise ValueError(
                f"dirsearch 的请求量预算不得放进 params（发现 {smuggled}）"
                "——请改传 request_budget 参数，避免静默覆盖授权值"
            )
        merged = {
            **params,
            "rate_rps": request_budget.rate_rps,
            "concurrency": request_budget.concurrency,
            "max_requests": request_budget.max_requests,
            "window_seconds": request_budget.max_seconds(),
        }
        return builder(merged, egress_proxy_url=egress_proxy_url, session=session)
    if request_budget is not None:
        raise ValueError(f"工具 {tool} 不消费 request_budget（该参数仅 dirsearch 使用）")
    return builder(params, egress_proxy_url=egress_proxy_url, session=session)


def known_tools() -> list[str]:
    """已有命令构造器的工具清单。"""
    return sorted(_BUILDERS)


def params_schema(tool: str) -> dict | None:
    """工具的 params JSON Schema（供规划器注入 prompt，防 LLM 瞎猜字段名）。"""
    model = _PARAMS_MODELS.get(tool)
    return model.model_json_schema() if model is not None else None
