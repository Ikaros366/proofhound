# 更新日志

本文件记录 ProofHound 的所有显著变更。格式基于
[Keep a Changelog 1.1.0](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

M9a / M9b / M9c / M9d / M10a / M11a / M11b / M11c-pre / M11c / M15 / M16 / M16-a / M16-b（内部消化，按维护者要求**不 bump 版本号**：`0.2.0` 保持不变）。

### 变更（M16-b dirsearch 接入 + 速率/并发/时间窗授权语义）

**做了什么**：把 dirsearch 接进发现链路，**并先补上"本次允许发多少请求"的授权语义**——
无差别字典爆破在没有这一维授权之前不应上线（实测：dirsearch 在 `-t 25` 下的**自然吞吐是
836 rps**，自带 9681 词词表全量 12308 请求仅需 15s）。

**先做的前置件：请求量授权语义（`Scope.request_budget`）**

- 既有 scope 只表达"允许打哪些目标"（域名/IP/端口），**不表达"本次允许发多少请求"**。
  新增四个维度：`rate_rps` / `concurrency` / `max_requests` / `window_minutes`。
- **缺省是保守值**（50 rps / 5 并发 / 5000 请求）——**维护者裁定的"开箱即用但保守"**，
  **刻意不采用 fail-closed 的"缺省即拒绝"**，理由与残余风险见 AGENTS.md 限制 54。
- **缺省放行不等于无痕放行**：`Scope.request_budget_source()` 返回
  `"explicit"` / `"default"`，审计与调用方可分辨是谁给的授权。
- **非法值一律显式抛错**（越界即 `ValidationError`），绝不静默回落到放宽值。

**dirsearch 构造器（`DirsearchParams` / `_build_dirsearch`）**

- 速率/并发/时间窗**只从 scope 预算来**：`build_command("dirsearch", params,
  request_budget=scope.resolved_request_budget())`。
- **预算不得夹带在 params 里**——夹带即报错（实现期踩到的真缺陷：`params` 里的显式
  2 rps 曾被构造器自己的缺省静默覆盖成 50，正是"以为授了限速、其实没生效"）。
- 给**不消费**预算的工具传预算也报错（不假装限速生效）。
- **永不产** `-r`（递归）/ `-F`（跟随重定向）/ `-l`（目标文件）⇒ 请求面与越界面结构性收敛。
- 恒在项：`-q` / `--no-color` / `-O json` / `-o /tmp/ds_report.json`；wrapper 负责把报告
  `cat` 回 stdout（沙箱 rootfs 只读、`/tmp` 是随容器销毁的 tmpfs，不 cat 则报告蒸发，
  红线 3 的证据就拿不到）。

**时间窗是"两道"**：① 工具自限时 `--max-time = floor(窗口×0.7)`；
② 沙箱超时 `min(300, 窗口秒数)`。**两道都不放宽授权窗口**。
**为何只给 70%**：实测 `window_minutes=1` ⇒ `--max-time 60` **未触发**自截（扫描跑到
沙箱超时 61.4s 才被杀），而 `--max-time 8` 能触发；取 70% 后 1 分钟窗口实测 wall 43.4s
且工具自报 `Runtime exceeded the maximum`。

**解析器（`parsers/dirsearch_json.py`）——零新增 Signal kind**

- 产既有 `kind="web-probe"`，走 M3a 起就在的 `web-exposure` 映射（**零 triage 改动**）。
- **判据字段 vs 证据字段分离**（M16-a 的教训）：`results[].url`/`status` 决定候选；
  `contentLength`/`contentType`/`elapsed`/`redirect` 只进 `note`，**不参与任何判定**。
- fail-closed 容错：坏 JSON / 结构不符 / 非 http(s) URL（含 `file://`）一律丢弃并计数，
  绝不猜、绝不造候选。

**依赖闭包（installer 扩展 + manifest `closure`）**

- dirsearch 是本项目**第一个依赖闭包非空**的 pip 工具（sqlmap 零依赖）。旧 pip 配方跑
  `--no-deps`，**装了也跑不起来**（缺 requests/cryptography 等）。
- manifest 新增 `closure`（26 条依赖，逐条 `==` 钉版 + sha256），installer 新增闭包安装
  路径：逐条下载并重算哈希 → 写 `--require-hashes` requirements → `--no-index` 安装。
- **交叉选平台**：沙箱镜像 `python:3.12-alpine` 是 musllinux，宿主是 glibc，必须
  `--platform musllinux_1_2_x86_64 --only-binary=:all:`（见限制 55）。
- 向后兼容：`closure` 缺省 `None` ⇒ `sqlmap` 等旧配方**行为不变**。

**离线预置（不入库）**：`scripts/make_dirsearch_preset.py` 一次性生成
`tools.d/dirsearch/`（wrapper + `lib/`，**20.6 MiB / 834 文件**，含自带 `db/dicc.txt`
143573 bytes / 9681 词）。`tools.d/*` 被 `.gitignore` 整片排除（运行时状态，与
httpx/katana/sqlmap 同待遇），故依赖闭包**不进公开仓库**；`--wheels DIR` 可完全离线重建。

**实测（真靶 + 真沙箱，产物 `evidence/demo_dirsearch/<ts>/`）**

| 项 | 实测 |
|---|---|
| 限速是否落到行为 | 缺省(50)=**836.7 rps** vs 显式(2)=**2.1 rps**，**比值 402×** |
| 时间窗（1 分钟） | wall **43.4s**，工具自报 `Runtime exceeded the maximum` |
| 峰值内存 | **35~56 MiB** = `mem_limit=512m` 的 **7~11%** |
| 对照 M16-a katana | `-jc` 248MiB / `-jc -jsl` 447MiB ⇒ dirsearch 属**轻量档** |
| 解析管道 | 30 词小词表 → 5 条 `web-probe` Signal → **5 条 `web-exposure` 候选**（坏条目 0） |
| scope 兜底 | 靶侧 42 条请求 Host **全部**授权地址（外域 0）；注入 2 条外域记录全被拒 + 留 `triage_out_of_scope` 审计，**外域候选 0** |

**明确不做（诚实边界）**：判定通道（M16-c）、`GATE_MATRIX` / 状态机铁律 / Verifier 输入
边界 / 红线 3 / 红线 4 的**任何**改动、httpx/katana 回填同一套授权语义、`sqlmap` 的 pip
路径改造、`request_budget` 写入 `command_executed` 审计（**本轮未做**，见下）。

**未做/未验证（如实标注）**：① **`request_budget` 尚未写进 `command_executed` 审计**——
授权语义目前落在 argv（`--max-rate`/`-t`/`--max-time`）与 `scope.request_budget_source()`
上，未改 `sandbox.py`；② 未系统扫描时间窗自限时的触发边界（70% 是单点实测得出的经验值）；
③ 未在 DVWA 真实前端上跑 dirsearch（本轮回合验收用的是自建单页靶）；④ `window_minutes > 5`
时实际生效的是 300s 沙箱上限，与"授权 8 分钟"存在口径差（限制 56）。

**测试**：新增 `tests/test_dirsearch.py` / `test_dirsearch_parser.py` /
`test_dirsearch_manifest.py` 共 **83** 个；全量 **1219 passed / 0 skipped**。
**披露的旧测试改动 1 处**：`tests/test_build.py::test_known_tools` 的期望清单加入
`dirsearch`——断言**意图不变**（仍是逐字面量锁死已注册构造器清单），只是把新条目纳入锁定；
不加这一项，该测试就锁不住 dirsearch 构造器是否被后续改动误删。其余旧测试**零改动**。

### 变更（M16-a katana 从 JS 里翻接口 —— 只做发现侧）

**做了什么**：给 katana 构造器开 JS 端点解析，让「JS 文件里写死的接口路径」进入发现链路。

- **恒在项加 `-jc`**（JS 文件内端点解析/爬行）：与 `-fs rdn` / `-cos` 同级写死，
  **不接受参数覆盖**——JS 里写死的接口是爬行面的一大块，不开等于整块看不见。
- **`-jsl`（jsluice AST 解析）做成可选参数且缺省关**：官方标注 memory intensive，
  实测**提取集合与 `-jc` 等价**而峰值内存近乎翻倍（见下），恒在开它等于白付内存换零增量。
  需要更激进的解析时显式 `jsluice=True`。
- **刻意不暴露 `-kf`**：官方要求 depth ≥ 3 才生效，而构造器 depth 缺省 2 ⇒ 给了也是
  「开了可能静默不生效」；且它抓的是 robots.txt / sitemap.xml（字典/已知路径面，属 M16-b）。
- **零新增解析器 / 零新增 Signal kind**：实测 katana 把 JS 里翻出的接口当**普通爬行记录**
  输出，字段与静态链接**逐字段同形**（`request.endpoint` / `request.method` /
  `response.status_code`）⇒ 现有 `parsers/katana_jsonl.py` 以「GET 且 URL 含 query」为判据
  **直接吃下**，落成 `param-endpoint` Signal（M3d 起就在的通道）。
- **triage 接线不动**：JS 端点走既有 `param-endpoint` 通道进 sqli/xss/idor 提示表，
  命中即产候选（零提示表改动）。
- **判定面一律不碰**：`GATE_MATRIX`、状态机铁律、Verifier 输入边界、红线 3/4 **零改动**；
  这类端点若落 `web-exposure` 仍不可 Confirmed（不在矩阵内，铁律：纯 status-code 证据永不 Confirmed）。

**为什么这样做**：维护者裁定的三条方向里，「JS 翻接口」是发现侧成本最低、收益最直接的一条
（katana 本体就支持、请求量小、有据可依），故先切这一段交付；字典爆路径（M16-b）与
「未授权访问」判定通道（M16-c）本轮**刻意不碰**。

**实测（真靶 + 真沙箱，产物 `evidence/demo_katana_js/<ts>/`）**：JS 里写死 17 条接口路径的
目标上，4 轮 katana 共提取 **16 条** JS 接口（每轮 13~14 条）→ 解析出 **13 条 `param-endpoint`
Signal**（坏行 0）→ triage 产 **19 条候选**（sqli 11 / idor 7 / xss 1）；**加 `-jc` 前同一靶
0 条 JS 接口**（只有 3 条静态链接）。

**资源**（12MB 真实 bundle：vue/three/echarts/monaco/mermaid/chart.js；容器参数与沙箱硬化档
逐项一致：512m / 1 CPU / `nobody` / 只读 rootfs / 64m tmpfs / `pids_limit=512`）：

| 配置 | wall | docker-stats 峰值内存 | OOM |
|---|---|---|---|
| `-jc` | ~13~16s | **248MiB** | 否 |
| `-jc -jsl` | ~13~16s | **447MiB** | 否 |

⇒ **`mem_limit=512m` 够用但余量薄**（`-jsl` 已用掉 87%），**300s 超时充裕**（katana 有 ~13s
固定开销地板，与本轮旗标无关）；`-jsl` **无可测耗时增量**。

**scope 兜底（本轮最重要安全回归）**：JS 里含 3 个外域绝对 URL 时——katana stdout **68 条
记录里 `request.endpoint` 含外域 = 0、`request.raw` 含外域 = 0**（外域只出现在 `response.body`
的 JS 原文回显里，那是证据、不是候选来源）；靶侧访问日志 **68 条请求 Host 全部是种子域、
外域 0 条**；再把 2 条外域记录**直接注入**解析器 + triage，两条均被判「域名不在授权列表内」
丢弃、**新增外域候选 0 条**，并留 `triage_out_of_scope` 审计。
另针对 AGENTS.md 限制 30 点名的「`-fs rdn` 对 **IP 型种子**不收敛」单独复测（本轮验收
demo 用的正是 IP 型种子）：IP 种子 + `-jc -jsl` 跑 3 轮共 **21 条 endpoint**，
`request.endpoint` / `request.raw` 含外域**均 0**、靶侧 21 条请求 Host 全为种子地址、
外域 0 条 ⇒ 该不收敛面**本轮未复现**（限制 30 按原样保留，不作结论性修订）。

**测试**：新增 `tests/test_katana_js.py` **9** 个（构造器 3 / jsluice 输出容错 3 / scope 兜底 3）；
旧 1125 全绿（共 **1134 passed / 2 skipped**）。**披露的旧测试改动 1 处**：
`test_katana.py::test_katana_argv_golden` 的期望 argv 插入 `-jc`——断言**意图不变**
（仍是逐字面量锁死默认 argv 形态），只是把新增恒在旗标纳入锁定；不加这一项，golden 测试
就锁不住 `-jc` 是否被后续改动误删。

**如实记录的既有行为缺陷 1 处**（katana 1.7.0，非本轮引入，见 AGENTS.md 限制 53）：
JS 爬取在 `-c 5` 下**每轮只吐 1~2 条**该 JS 里的接口，`-c 1` / `-d 3` 重测**不收敛**
（6 种参数组合 × 3~5 次重复，命中随运行漂移）⇒ 单次 crawl 的 JS 发现**必然是子集**，
报告里不得把「本轮没翻到」读作「不存在该接口」。模板串形态（`` `/api/x?id=${id}` ``）在
`-jc`/`-jsl` 下**均 0 提取**。

**明确不做（诚实边界）**：dirsearch 接入（M16-b）、任何判定通道（M16-c）、新增 triage 提示表、
`GATE_MATRIX` / 状态机铁律 / Verifier 输入边界 / 红线 3 / 红线 4 的**任何**改动、
「AI 判定」的任何预埋。

### 变更（M16 SSRF 两步走·第二步：verify-ssrf 垂直切片）

**做了什么**：把 M15 放开候选的 SSRF 建成**第 4 类可确认漏洞**——确认手段只有一个：
**回调 listener 收到请求**（带外二值事实）。

- **新模块** `proofhound/verify/ssrf.py`（first-party 纯 stdlib，定位同 `verify/idor.py`）：
  `CallbackListener`（宿主进程内，缺省只绑回环）+ 判定纯函数 `judge` + 交付证明
  `token_delivered` + token/nonce 与回调 URL 构造。
- **确认铁律**：目标响应里的 callback URL 反射、状态码、耗时一律**不是**证据——SSRF 的
  答案不在目标给我们的响应里。reflected 的 callback URL 只是反射。
- **三道防伪**：每探针唯一 token（128 位随机 + 常量时间比对；路径不含 token 的请求记
  `ssrf_callback_ignored`，不计命中）· 交付证明（回取探测 URL，正文须含 token/nonce）·
  随机地址对照探针（`<hex>.invalid`，命中只证明「服务端会代发请求」，**不确认**）。
- **判定分界（宁漏勿滥）**：命中 → confirmed；干净未命中 + 交付证明成立 → rejected（确定性
  真阴性，零 LLM 成本）；探针出错 / 交付证明不成立 / 前置不全 / listener 不可用 → blocked。
- **走既有链路、无旁路**：`GATE_MATRIX` 加 ssrf 项（method 「与既有三类**互不染指**」，逐条断言
  互斥）→ `skills/verify-ssrf/SKILL.md`（L2）→ `skills/profiles.py` 登记（L2 + mutating=False）→
  编排层 `_verify_ssrf` → 证据门 → Verifier 终审（只收确定性结论 + 锚点，回调原文不进 prompt）→
  CVSS 代码算分 → 四段式证据。红线零放松；listener **不常驻**（phase 收尾释放）。
- **远程靶**：`PROOFHOUND_SSRF_CALLBACK_HOST`（告知目标的地址）与 `PROOFHOUND_SSRF_CALLBACK_BIND`
  （本机绑定地址）**解耦**——两者混用会让 listener 直接绑不上（实弹踩到）。

**为什么这样做**：M15 的第一步数据回答"发现侧够格、筛除侧不够格"——模型对 SSRF 语义识别
稳定且零方差，但会把"参数名像 SSRF 而服务端并不取数"的端点误报。这类误报**恰是行为验证
能确定性回答、纯语义判断回答不了**的（回调收没收到请求）。故第二步不是"锦上添花"，而是
让 M15 那批候选**有可能离开 Hypothesis** 的唯一合法门径。

**测试**：新增 `tests/test_ssrf.py` **47** 个（纯函数 20 / 真 listener 11 / 编排层 16），
其中 confirmed 路径由**真 listener 收到真请求**驱动；旧 1076 全绿（共 **1125 passed / 2 skipped**）。
**披露的旧测试改动 1 处**：`test_ssrf_is_hypothesis_only_no_confirmed_channel` 随第二步落地
**意图反转**并更名 `test_ssrf_confirmed_requires_callback_method_only`（原断言"ssrf 不在矩阵内、
过门恒不过"，现断言"矩阵内有且仅有回调确认这一条 method，且缺行为证据/缺 verification 一律
不过门"；原意图由后者加强承接）。

**实弹验收** `scripts/demo_verify_ssrf.py`：目标 = 基准 fixture 的 E 族，**跑在容器里**、端口
发布到宿主（目标必须网络上真实可达，不能是同进程替身）。两条真 SSRF 端点 → **CONFIRMED**
（method=`ssrf-callback-confirmed`、CVSS 5.3 代码算分、refs 3、四段式 4 步；回调源 IP 为容器
网段 `172.17.0.6`）；形对照 `/d/ssrf-like` → **不被确认**（交付证明不成立 ⇒ blocked）。
**一处如实说明的接缝**：baseline 走沙箱 httpx，而沙箱在 internal 出口网络里够不到宿主发布的
端口，故实弹脚本用预制 httpx 输出提供 baseline，其余步骤全部真实（已写在脚本 docstring 与
AGENTS.md 限制 52，不得读作"全链路无接缝"）。

**实现期发现并修掉的 4 个真实缺陷**（都只在"用真 listener 驱动 confirmed"的测试下才暴露，
已全部记入 `docs/design.md` §7.12）：① **注册的 token 与注入 URL 里的 token 不是同一个**
（循环外生成 value、循环内另生成 token）⇒ confirmed 分支**在生产里永不触发**；② `_ssrf_listener`
**没用注入的 listener 工厂** ⇒ token 注册与回调落在两个对象上；③ 对照探针的失败被计入 errored ⇒
每次干净未命中都判 blocked、rejected 分支不可达；④ **注入的回调 URL 被 `check_scope` 当作目标**
（端口不在授权范围）⇒ 每个探针都被 scope 拒掉，改为"asset 过 scope + 探针同源自检"。

**明确不做（诚实边界）**：POST/表单 SSRF（`form_page` 候选直接判 blocked）、header/JSON body
注入、无回调的盲 SSRF、协议/编码绕过变体（`gopher`/`dict`/`@`/十进制 IP 等）、listener 鉴权、
给沙箱配到宿主的出口。


### 变更（M15 SSRF 两步走·第一步：只放开候选 + 基准加 SSRF 端点族）

**做了什么**：给系统加上**第 4 类漏洞候选（SSRF）**，但**只到候选层**——先测模型候选质量，再由数据决定要不要投入建验证器。

- **白名单**：`proofhound/llm/triage.py::ALLOWED_VULN_TYPES` 加 `ssrf`，并**同步改 prompt 正文**（原文写死"只能取这三个之一"——漏改这处模型永远不会产 ssrf，且**不会报错**，属静默失效）。同时补 ssrf 判断线索，并把"看着像但不成立"的负例写进提示词。
- **确认通道刻意不开**：`verify/gate.py::GATE_MATRIX` **不加** ssrf 项，也不建 `skills/verify-ssrf`、不在 `skills/profiles.py` 登记 ⇒ 证据门对 ssrf 恒 fail-closed，`ssrf` **永远不可能 Confirmed**。新增测试三条断言把该形态钉死。
- **规则表刻意不加** SSRF 提示表：要测的正是"规则表盲区上模型能否发现"。
- **中性基准加 E 族**（`scripts/bench_triage.py`）：5 条**真 SSRF**端点——服务端**真的**按参数取值发起 HTTP 请求（`_fetch_remote`：只认 http/https、1.5s 超时、任何失败收敛成 200 + 文案，fixture 自己绝不 500）；参数名 `url`/`redirect` 在提示表内（规则表锚点），`target`/`feed`/`avatar` 在表外（关键词盲区）。另加 **D 族形对照 `/d/ssrf-like`**：参数名 `callback` 像 SSRF，但服务端**只登记、不发起请求、不回显取值**（定长）。

**为什么这样做**：发现层已不是瓶颈（模型在本基准上发现率 100%），瓶颈是**可确认的漏洞类别数**。选 SSRF 而非 LFI：SSRF 的确认手段是**二值事实**（回调服务器收到请求），LFI 靠回显 canary 文件、受目标环境与路径知识影响更易含糊。而**分两步走**的理由是避免"先建验证器再给它找活干"——先拿到候选质量数据，再决定投资。

**实测（真实 T1 `deepseek-flash`，4 次独立运行，22 端点 = 17 真漏洞 + 5 对照）**：

| 指标 | 结果 |
|---|---|
| SSRF 发现率（E 族 5 条，正确类型 = ssrf） | **5/5 = 100%，4/4 次一致（σ=0）** |
| 其中表外盲区 3 条（`target`/`feed`/`avatar`） | **3/3，4/4 次一致** |
| 规则表对同 5 条 SSRF 端点 | **0 候选**（表内两条只产出 xss） |
| 无规则表提示时模型能否产出 ssrf 候选 | **能，且稳定**——这正是第二步的前提 |
| 形对照 `/d/ssrf-like` 被误报 ssrf | **3/4 次**（prompt 已明写该类不要报） |
| `model` 臂对照误报率（4 次） | 60% / 60% / 0% / 20% —— 区间重叠，**不可判** |
| 单题成本 | 5.3k~8.9k token / 2 次 T1 调用 |

**结论与第二步建议**：**发现侧够格，筛除侧不够格**。模型对 SSRF 的语义识别稳定且零方差（含全部表外盲区参数名），但会把"参数名像 SSRF 而服务端并不取数"的端点误报为 ssrf——这类误报**恰恰是行为验证能确定性回答、纯语义判断回答不了**的（回调服务器收没收到请求，是二值事实）。故建议**进入第二步**（建 `verify-ssrf`，回调判定），判据与形态见 `docs/design.md` §7.12；且第一步的候选**必须**经该验证器才能离开 Hypothesis。

**明确不做（诚实边界）**：`GATE_MATRIX` 的 ssrf 项、`skills/verify-ssrf/`、`skills/profiles.py` 登记、规则表 SSRF 提示表、`--live` 的 SSRF 臂（无验证器 ⇒ 跑出来只会全是"未能判定"）。

**测试影响**：新测试 **36** 个；旧 1040 全绿（共 **1076 passed / 2 skipped**，2 skip = 企业模板缺失，公开仓库固有形态）。**披露的旧测试改动 4 处**（逐条理由写在文件内）：① `test_allowed_types_are_exactly_the_verified_ones` → `..._declared_ones`，白名单断言加 ssrf——原意图"无验证器的类型不得有确认通道"由新增的 `test_ssrf_is_hypothesis_only_no_confirmed_channel` 承接并加强；② `test_crawl_signals_unchanged` 16→22 条（加族必然结果）；③ `test_endpoint_table_shape_unchanged` 16/12/4→22/17/5（分母变化必然结果，并新增族分量断言钉死 A/B/C/D 四族逐条未动）；④ 粗筛长度不变式参数化表加 `/d/ssrf-like` 一行（断言本体零改动）。

**附带披露（提交 `7cbf700` 的组成）**：该提交除上列 M15 改动外，还**连带提交了两处上轮第三方评审**
**插入的 README 文档改动**（提交信息未提及，此处补记）：① 《路线图与已知限制》一节补齐 **M10~M11** 与 
**M12~M14** 两张里程碑表；② 修正已过期的状态行（原文写"M9a~M9d 尚未提交"，实为 M9a~M14 **均已提交**、
当时有 4 个提交未推送）。两处均为**纯文档**、不涉及任何代码或判定语义，属上一轮工作的收尾，随本轮一并入库。

**另需说明的时点**：本节的 M15 里程碑行（AGENTS.md）、已知限制 46/47 与本节全部内容，是**本轮（评审后）**
**补写**的——首次提交 M15 时 AGENTS.md 尚未包含这些记录。补写只增不改，未修改 `7cbf700` 的任何代码或历史。

### 变更（M14 API 认证：HTTP Basic 单账户，deny-by-default）

**做了什么**：控制台/API 从"无认证"改为 **HTTP Basic 单账户认证**，且 `create_app` **缺省启用**：

- 新模块 `proofhound/api/auth.py`；凭据优先级 **环境变量 > `.env` > 仓库默认值**；
- 中间件覆盖**全路径**（含控制台首页与静态资源），401 带 `WWW-Authenticate` → 浏览器原生登录框，
  **前端零改动**（同源 `fetch` 会用浏览器认证缓存自动带凭据）；
- 默认账户 **`shangyun` / `123456`**（公开写在仓库里），可在 `.env` 用
  `PROOFHOUND_API_USER` / `PROOFHOUND_API_PASSWORD` 覆盖；
- `GET /api/health` 增 `auth` 块，控制台顶栏显示当前账户，仍在默认口令时提示改掉
  （原顶栏写死的"本机实例 · 无认证"同步删除——加了认证之后那句话是假的）。

**关键护栏：默认口令 + 非回环绑定 = 拒绝启动（rc=2）。** 因为默认口令是公开的固定值，
安全性不能建立在它之上。`--host 0.0.0.0` 且未改口令时进程直接退出，并给出三条出路
（改回 127.0.0.1 / 换口令 / 前置反向代理）；换成自定义口令才放行并打印告警。这把
"忘了改默认口令还对外监听"从一句告警变成不可能。

**明确不做（诚实边界，见 AGENTS.md 限制 23）**：无 TLS（Basic 是 Base64 明文，故默认口令
只许回环）、无多用户与权限分级（单账户即全部权限）、无登录失败锁定、无会话过期/登出。

**为什么这样做**：维护者裁定"简单优先、不做密码复杂度"。在此前提下，唯一能站得住的做法是
把安全性从口令转移到**边界**上——公开口令只在本机可用，对外必须先换口令。

**实测**：真实 uvicorn 子进程 + curl：匿名 `401` + `www-authenticate: Basic realm="ProofHound"`；
错口令 401；默认口令 `GET /`、`/static/app.js`、`/api/health` 全 200；401 体不回显提交的口令。
**Playwright 带 `http_credentials` 打开控制台**：标题「ProofHound 控制台」，
顶栏「认证：shangyun · 默认口令（公开，建议改）· 勿暴露局域网/公网」；
换自定义口令后顶栏变为「认证：custom-op · 勿暴露局域网/公网」。
`--host 0.0.0.0` + 默认口令 ⇒ `rc=2` 且打印拒绝原因。

**实现期踩坑（已修，并写进 demo 断言）**：`scripts/demo_console.py` Step 1 原本假设"端口已被主服务占用 ⇒ uvicorn 绑不上 ⇒ 不会真暴露局域网"。该假设在 Linux 上**不成立**——`SO_REUSEADDR` 允许 `0.0.0.0:X` 与 `127.0.0.1:X` 共存（M14 用纯 `bind()` 实测：两者都成功），且该步原先只看输出文本、不检查进程如何退出 ⇒ 旧版会在 `0.0.0.0` 上真起一个控制台、直到 20s 超时被杀，而断言照样通过。现改为："拒绝启动"那条走子进程（在 `uvicorn.run` 之前 return，零监听），"告警"那条**只调纯函数**断言文案，彻底不起非回环监听。

**测试影响**：新测试 24 个；旧测试**零改动**（`tests/conftest.py` 新增 autouse fixture 固定凭据
环境变量并给 `TestClient` 注入 `Authorization` 头——**如实带凭据，不是绕过校验**）；
`scripts/` 11 个验收脚本 20 处 client 构造带凭据。

### 变更（M13 可复现安装 + CI）

**做了什么**：① `requirements.txt` 从"只锁 API 层三项 + playwright"改为**完整依赖锁**
（36 个包，含传递依赖；生成方式与沿革写在文件头）；② 新增 `.github/workflows/ci.yml`，
两道门——`unit`（Python 3.12，无 Docker / 无浏览器，`pytest -m "not docker and not browser"`）
与 `integration`（`playwright install --with-deps chromium` + 预拉 `alpine:3.20` /
`python:3.12-alpine` / `vulnerables/web-dvwa`，跑全量）；两道门都**从锁安装**
（`pip install -r requirements.txt` + `pip install -e . --no-deps --no-build-isolation`）；
③ 新增 `tests/test_release_hygiene.py`（8 个），把"锁不漂移 / 锁可复现 / CI 形态 /
CI 解释器落在 `requires-python` 内"钉成断言。

**为什么**：原先只有 `pyproject.toml` 的 `>=` 区间，实际解析结果随时间漂移——实测
`requirements.txt` 里写死的 `uvicorn==0.52.1`、`playwright==1.62.0` 与真正装到的
`0.54.0`、`1.63.0` 已不一致（两者都仍满足 pyproject，故**不会报错、只会静默不一致**），
而仓库没有任何 CI，也没有人在干净环境执行过文档里的测试命令。第三方评审把"干净环境
`python -m pytest` 43 个模块收集失败"列为 P0——该**归因**是错的（README §Quickstart 本来
就写了装依赖的命令，`pip install -e ".[dev]"` 后 1010 测试全绿），但**缺口是真的**：
没有锁、没有 CI，"全绿"这件事在任何别的机器上都不可复现。M13 补的正是这一块。

**实证（干净环境，非本机 venv）**：新建 venv 只按锁安装、跳过 `pip install -e ".[dev]"`
→ `pip freeze` 与锁**逐行一致（36 包）**；默认门 `986 passed / 2 skipped / 30 deselected`
（13.2s）；全量 `1016 passed / 2 skipped`（116s；浏览器用例因 `~/.cache/ms-playwright`
按用户共享而真实执行，非 skip）。

**只跑 Python 3.12**：`requires-python` 是 `>=3.12`，但只有 3.12 经过本仓库全量验证；
加 3.13 属能力扩张，须先在本地跑绿再进矩阵，不靠 CI 试错。守护测试断言 CI 的 Python
版本落在 `requires-python` 内，防止一边放宽区间、一边 CI 仍停在旧解释器。

**不改**：任何运行时代码与测试语义；`requirements.txt` 原先四个版本 pin 的**语义**
（API 层直接依赖）在文件头注释里保留沿革说明。

### 变更（M12 沙箱隔离硬化：容器内降权 + 只读 rootfs + capability 归零）

**做了什么**：沙箱工具容器的隔离从"容器化执行"提到"强隔离执行"——`SandboxConfig` 新增
隔离硬化档并**缺省生效**：容器内降权为 `nobody(65534)`、容器 rootfs 只读（仅 `/tmp` 为
64m tmpfs 可写，`mode=1777`、`nosuid`）、`cap_drop=["ALL"]`、`security_opt=["no-new-privileges:true"]`、
`pids_limit=512`、`RLIMIT_NOFILE=4096`；`$HOME`/`TMPDIR`/`working_dir` 指向该 tmpfs，
使 sqlmap 这类要往 `~/.sqlmap` 写会话与输出的有状态工具在只读 rootfs 下仍可用。

**为什么**：原先只有 CPU/内存配额 + 工具目录只读挂载，容器内仍是 root 且带默认 capability
集合，"写满宿主磁盘"只能靠 `mem_limit` 间接约束。硬化后该路径在容器内**结构性不存在**。

**可审计**：`command_executed` 增 `sandbox` 字段，逐项记录本次执行的隔离档（放宽档记
`{"mode": "relaxed"}`）——隔离强度与证据同源可查，不只写在文档里。

**逃生阀**：`PROOFHOUND_SANDBOX_HARDENING=strict|relaxed`（缺省 `strict`；非法值 fail-closed
抛错，与 `PROOFHOUND_SANDBOX_EGRESS` 同纪律）。`relaxed` 逐字节回到旧容器参数。

**不改**：scope 五层校验、证据门判定语义、状态机铁律、闸门矩阵、出口白名单、脱敏与预算硬闸。

**实测**：容器内探针 `uid=65534 / home=WRITABLE / rootfs=READONLY / tools=READONLY /
docker_sock=ABSENT / pids_max=512 / cap_eff=0000000000000000`；fork 炸弹被 pids 上限截断且
容器零残留；真实 T1/T2 + DVWA 全链路验收脚本在硬化档下通过（`sqlmap-confirmed`，
`deepseek-v4-pro` confirm，证据 3 项）。

### 变更（M11c 重复测量：方差已量化，`PROOFHOUND_TRIAGE_MODEL` 建议默认开启）

**做了什么**：4 臂 × 3 遍 = **12 次臂运行**（`scripts/bench_triage.py --live`，真实 T1/T2 +
Docker + Chromium），用最保守的**区间重叠法**判臂间差异可判性（TP 区间重叠即视为不可判）。

| 臂 | 检出率 | TP 各遍 | 精确率 | FP | 未能判定 | token 各遍 |
|---|---|---|---|---|---|---|
| `rules` | 33.3% (σ=0.000) | [4, 4, 4] | 100% | 0 | 0 | 33,684 / 25,975 / 32,648 |
| `rules+model` | **66.7%** (σ=0.000) | [8, 8, 8] | 100% | 0 | 1 | 58,526 / 59,697 / 63,704 |
| `rules+prefilter` | 33.3% (σ=0.000) | [4, 4, 4] | 100% | 0 | 0 | 31,221 / 31,643 / 32,033 |
| `rules+model+prefilter` | 72.2% (σ=0.048) | [9, 8, 9] | 100% | 0 | 1 | 59,669 / 88,819 / 74,787 |

**结论**

- **`PROOFHOUND_TRIAGE_MODEL`：唯一可判且增益巨大的开关，建议默认开启**（现为缺省关闭）。
  `rules` → `rules+model` 的 TP 区间 `[4,4,4]` → `[8,8,8]` **不重叠 ⇒ 差异可判**，且两者
  **标准差均为 0** ⇒ **+4 个 Confirmed（33.3%→66.7%，翻倍）**在三遍里完全稳定；代价
  **1.97× token**。`rules+prefilter` 对照臂复现同一结论，属两条独立路径互证。
- **`PROOFHOUND_VERIFY_PREFILTER`：效应落在噪声内，建议保持缺省关闭**。`rules` 下
  `[4,4,4]→[4,4,4]`（零效应）；`rules+model` 下 `[8,8,8]→[9,8,9]`（**区间重叠 ⇒ 不可判**，
  方向偏正但 3 样本不足定论）；代价在大模型臂达 **1.23× token**。即：开它等于**用确定成本
  换不可判的收益**。
- **12 次运行精确率全 100%、FP 全 0**——4 个安全对照端点在每一次运行里都未被误确认。
- **M10a 记录的"同一真 IDOR 在 4 臂出现 4 种结果"不再复现**：`/a/idor` 在**全部 12 次**运行
  里都是 confirmed。这与 M11b 的诊断吻合——原方差是**判据规格歧义**（叠加 harness 缺陷），
  判据定死后消失。残余方差收窄到**单端点**（`/b/sqli2 [sqli]`，`rules+model+prefilter` 臂的
  confirmed/无候选/confirmed 是该臂 σ=0.048 的唯一来源），其余 15 个端点终态 12 次全一致。

> ⚠️ **断代声明**：本批 **T2 档指向 DeepSeek（`deepseek-v4-flash`，与 T1 同模型）**——测量
> 期间 Kimi 账户余额耗尽被停用。红线 4（M9b 重定义）**明确允许** T1/T2 同模型（独立性由
> agent 隔离 + 输入边界 + 输出强校验保证，不靠模型身份，同模型时记 `llm_tiers_share_model`
> 审计），故判定语义有效；但**本批数字与 M9a~M11b 的 `kimi-k3` 实测不可直接比较**。另：测量
> 前停掉了宿主机上抢占 CPU 的无关容器，故 **wall 时间亦不可比**。

### 修复（M11c-pre 基准 harness：让 M11b 判据在基准里真正生效）

> 两条都是**测量 harness 的配置缺陷**，不是生产判据缺陷。它们使 M11b 新增的 IDOR 判据在
> 基准里**无法进入设计预期状态**，真 IDOR 被系统性判成"未能判定"或被"缺归属证据"驳回
> ——基准测到的因此不是判据行为，而是配置错误的副作用。

- **匿名拒答 `200` → 改 `403`**：M11b 的对照判据是**只否定、不肯定**（2xx 且内容既不逐字节
  相同、相似度也不达阈值 → `blocked`）。实测 `/a/idor` 对照相似度 0.747 < 0.9 → 判 `blocked`
  → Finding 停 Hypothesis → **4 臂的 IDOR 真阳性全部被丢弃**。改 403 后判 `protected`。
  **302 经实测否决**（`urllib` 会跟随重定向到未注册的 `/login` → 404，语义模糊，且跟随后的
  404 正文在多个端点间相同，破坏正文唯一性不变式）。
- **补声明 `reference_identity`**：对象页展示 `所有者 owner`，而 reference 会话凭据是
  `bench0reference0token`——两者**不同源**，未声明则归属判 `mismatched` → 真 IDOR 被
  "缺归属证据"驳回。补声明后判 `matched`。

**对基准数字的影响（实测，非估算）**：修复后 `rules` 臂 **33.3%（4/12，FP 0，未能判定 0）**、
`rules+model` 臂 **75.0%（9/12，FP 0）**——后者显著高于 M10a published 的 58.3%，差额主要来自
此前被上述缺陷压制的 IDOR 项。**M10a 的 4 臂表因此降级为"历史数字"**。

> ⚠️ **方差量化仍未完成**：M11c 的 3 遍 × 4 臂只跑完 1 遍（且该遍后两臂被 `LLM HTTP 429`
> 污染——**T2 账户余额耗尽**，外部阻塞）。故"臂间 1~2 条 TP 差异是否可区分于采样噪声"与
> "`PROOFHOUND_VERIFY_PREFILTER` 效应是否落在噪声内"**仍无答案**；上述新基线亦**只有 1 次
> 采样，不可用于臂间比较**。另注意 `verify_blocked` 同时承载"覆盖不全"与"账户/配额故障"，
> 读汇总表时须先排除故障污染（否则 pass 2 那样的全 0 会被误读成模型能力骤降）。

### 变更（M11b IDOR 判据收紧）

- **IDOR 确认判据收紧：新增未认证对照探测 + 确定性归属证据**。M10a 实测同一个真 IDOR
  在 4 个配置臂里出现 **4 种结果**（confirmed / rejected / 未能判定 / rejected），当时的
  归因是「Verifier 判定随机」。逐条复核 4 臂全部 11 条 IDOR 终审原文后，归因**修正为规格
  歧义**：11 条里 7 条 reject 有 **6 条判得正确**（那些是对 `/a/sqli`、`/b/sqli2`、`/d/safe`
  之类**非 IDOR 端点**的类型误报），真 IDOR 的驳回理由则**逐字同构**——① 无对象归属证据；
  ② 两份响应 sha256 完全相同，更平凡的解释是"公开内容"；③ 缺一个能排除公开端点的对照。
  决定性证据：同一 `/b/idor2` 在**同一次运行**的两个臂里被判了两种标准。

  维护者裁决并落地的三条：

  - **未认证对照探测**：对同 URL 追加一次**不带任何凭据**的请求（新增只读 GET），
    用纯确定性代码判定该资源是否"公开/与会话无关"。对照三态——`public`（未认证即拿到与
    对象属主基准逐字节相同或相似度 ≥0.9 的内容）/ `protected`（未认证被非 2xx 拒）/
    `blocked`（对照请求失败，或 2xx 但既不逐字节相同也不相似）。**只否定、不肯定**：
    只有"相同/高度相似"才是可据此**否定**违反的硬证据；"不同但不相似"同样符合"两个身份
    看到不同数据"这一**合法**形态，判 `blocked` 而非 `protected`（不猜）。
  - **要求归属证据**：仅"对象属主可访问 + 攻击者拿到等价响应"**不足以**构成属性违反。
    归属判定要求**两族同时命中**——响应里存在归属字段名（`owner`/`所有者`/`created_by`/...，
    且不在 `current_user`/`session_user` 这类"当前登录者"排除表内）**且**该字段的**值**
    等于 reference 身份标识；三态 `matched`/`mismatched`/`absent`。身份标识缺失时一律
    `absent`（**不做"有 owner 字段就算证据"的放松**）。
  - **判据由代码给结论，Verifier 只收结论 + 行号锚点**：三种负面形态（对照 `public`、
    对照 `blocked`、归属非 `matched`）在**编排层确定性定终态**（`public`/归属非 matched →
    `REJECTED(actor=verify-idor)`；`blocked` → Finding 停 `Hypothesis`），**零额外 LLM 成本**
    ——这正是消除 M10a 方差的机制：不给模型自由裁量的空间。仅"对照 `protected` **且** 归属
    `matched`"才进证据门与 Verifier 终审。

- **`reference_identity`（新可选字段，API/session.json）**：归属比对用的**声明式**身份标识。
  真系统的对象页展示的是用户名/所有者名，而会话凭据往往是随机 session id——两者**不同源**，
  只从凭据推会让归属判定一律 `absent`（本仓库 demo fixture 实测即如此：正文 `属主：b`
  vs 凭据 `8071f6e5d4c3b2a1`）。故允许操作员显式声明；未声明时回退到凭据值（向后兼容）。
  **给出它不放宽任何判据**——归属字段名与字段值仍须同时命中。

- **`Scope.session_third`（新可选字段）**：第三身份会话，用于对照探测。**未配置时对照用
  完全不发凭据的匿名请求**——匿名已足以否定"公开资源"，故本字段是可选增强；链路不会因
  缺第三身份而 blocked。

### 修复（M11b）

- **基准 fixture：页面 footer 硬编码主会话凭据**。原 `_page()` 固定输出
  `session=<主会话 TOKEN>`，两个后果：① 页面在"谁在看"上说谎（对象属主会话的响应回显的
  是攻击者的凭据）；② **三个 IDOR 端点的可见文本实际相同**，仅靠这行硬编码标记才逐字节
  可区分——于是 M10a 的 Verifier 反复援引的"A/B 两份响应 sha256 完全相同 → 更像公开内容"
  **部分是该缺陷制造的伪迹**。现改为 **per-endpoint 标记**（`ep=<路径去斜杠>`）：差异来自
  端点身份、不依赖任何凭据、长度稳定。**脱敏演练随之取消**——凭据脱敏由生产链路自身测试
  覆盖，不该由基准 fixture 承担，尤其当它需要**伪造**正文差异时。

- **基准 fixture：IDOR 端点原先不拒匿名**，使"公开资源"与"私有对象被越权读取"在未认证
  对照下**同形**——这正是 Verifier 索要却拿不到那个对照的根因。现未认证请求得定长通用页
  （**刻意用 200 而非 403**：旧系统常见"登录页 200"形态，保留"匿名也能拿到 200"这一最不利
  情形，迫使判据在正文层面工作）。攻击者（已认证**非**属主）**仍拿到对象页**，故 ground
  truth 与漏洞语义不变。

### 变更（连带影响，如实披露）

- **基准「粗筛后」两列数值变化**：`verify/prefilter.py` 的探测**不带凭据**，IDOR 端点拒匿名后，
  粗筛对它们的两个探测取值都只能看到同一份"请先登录"页 → 判 `UNLIKELY`。故 `rules`
  33.3%→25.0%、`model` 91.7%→75.0%、`rules+model` 100%→75.0%。**主指标（发现率/误报率）
  逐格不变**（33.3%/50.0%、91.7%/0.0%、100%/50.0%）。**不是功能回归**：`ScreenResult.passed`
  恒为 True、`advisory` 只增一个审计计数，粗筛**从不丢弃候选**。同时它暴露一条**真实限制**
  ——粗筛在"需认证目标"上只能看到登录/拒绝页，判别力下降（已记入已知限制）。

### 新增（M11a 成本可见性）

- **单题成本口径落地：按「调用方 + 阶段」归属，含修复重试**。此前「单题成本」只有基准脚本
  算得出来，且**同一份数据能得出三组互不相同的数字**（M10a 记录：5,897/4,270、4,197/11,349
  等，连大小关系都反）。根因是两件事：口径未定，以及 `llm_call` 审计事件**根本不带归属信息**
  ——连「Verifier 花了多少」都算不出来。M11a 把这两件事一起解决：

  - `llm_call` 审计新增 `caller`（调用方：triage/planner/verifier/narrative）、
    `finding_id`（该次调用服务的 Finding，仅 Verifier 逐 Finding 有值）、`retry`
    （True = M6a 修复重试的那一次）；
  - 新增 `proofhound/llm/cost.py`：纯确定性聚合，维度 = 调用方 / 阶段 / Finding / 档位，
    **四个维度各自求和都等于总数**（单一口径，不存在第二套算法）；
  - 修复重试**计入主口径**（它是真实成本），同时因带 `retry=True` 而可**确定性单列**
    `retry_calls`/`retry_tokens`，可见抖动成本；
  - `estimated=True` 的事件（响应无 usage、按 4 字符≈1 token 估算）**单列计数**，
    估算与真实不混算；
  - **旧数据容忍**：M11a 之前的 `llm_call` 缺 `caller`/`finding_id`，一律归入 `unknown`
    桶并计入总数——**绝不静默丢弃**（丢弃会让总量对不上，正是"数字不可复现"的来源）。
    报告同时给出**可归属比例**（1 − unknown 占比），避免局部数字被误读成全量。

- **`python -m proofhound.cost --dir <engagement_dir>`**（新增 CLI）：打印按四个维度的
  成本摘要；`--json` 供脚本消费；`--finding F-xxxx` 只看单条 Finding 的确认成本。

- **`GET /api/engagements/{id}/cost`**（新增只读端点）：返回同一聚合结果；
  `include_calls=false` 只回聚合值（供控制台轮询）。响应体不含任何凭据。

- **控制台新增只读成本面板**：按调用方/阶段/档位/Finding 展示调用数、token、重试与估算
  计数，并在可归属比例 < 100% 时显式提示「其余为 M11a 之前的审计事件」。

- **内部口径统一**：`tokens_used`（engagement 列表/详情）与 `/cost` 总数现在**必然同源同值**
  ——`_tokens_used()` 原先自己遍历审计求和，属第二套口径；现改用同一个聚合函数。数值语义与
  改造前**逐字节等价**（缺失/None 字段按 0 计），仅消除"两份数字打架"的可能。

- **归属元数据对旧代码兼容**（M11a）：`ModelRouter.complete` 的三个新参数均为**可选关键字**，
  且经 `llm/callmeta.py` 做**确定性签名分派**——不接受这些 kwargs 的既有测试替身/旧实现
  自动退化为旧调用形态（逐字节等价于 M11a 之前），既不报错也不被重复调用。

### 变更

- **架构红线 4 重定义：模型身份 → 校验独立性**（M9b）。原表述「Verifier 与发现端必须用
  不同模型」在实现上只是启动时一句警告（非硬约束），且管错了维度——"不同模型"并不等于
  "不同盲点"（同家族不同尺寸的模型盲点高度相关）。红线 4 现改为约束三件**可测试**的事：
  ① 输入边界（只收结构化摘要与证据包索引，不喂原始输出）；② 独立 agent + 独立 system
  prompt；③ 输出 Pydantic 强校验（非法 verdict 一律拒收）。**T1/T2 允许配置同一模型**，
  同模型时记 `llm_tiers_share_model` 审计而非警告。

  > **对使用者的影响**：原先依赖「同模型会触发 UserWarning」来做配置校验的脚本/CI 需要
  > 改为读取 `ModelRouter.shared_model_across_tiers` 或审计事件 `llm_tiers_share_model`。
  > 功能上无破坏——同模型本来就能跑，只是会被告警。

- **沙箱出口默认改为 `restricted`**（M9a）。`default_phases_factory` 原先硬编码
  `network_mode="host" + egress=mode:"open"`（演示取向）。现在默认接入
  `proofhound-egress`（internal，无网关/NAT），HTTP(S) 强制经白名单正向代理出站，
  白名单 = engagement 的 scope + 工具安装源。逃生阀：`PROOFHOUND_SANDBOX_EGRESS=open`。

  > **对使用者的影响**：容器内不再能直连任意地址。依赖"沙箱可直连内网任意主机"的既有
  > 脚本会失败——这属于预期收紧。受限 Docker 环境可显式设 `PROOFHOUND_SANDBOX_EGRESS=open`。

- **`scope_paths` 变为可选**（M9a）。`POST /api/engagements` 不再强制要求 scope 文件：
  留空时系统从 `target` 自动派生授权范围。**显式提供 scope 文件时行为完全不变**。

  > **对使用者的影响**：既有调用方（总是传 `scope_paths`）零改动。新增的
  > `acknowledge_authorization` 字段仅在**未提供 scope 文件**时才需要置 true。

### 新增

- **从种子目标自动派生 scope**（M9a）：新增 `proofhound/compliance/derive.py`——
  从目标派生 `domains` / 单主机 `networks`（IP 恒 `/32`、`/128`）+ 显式非默认端口。
  纯确定性、零 LLM、零网络。**安全纪律**：只从种子 host 派生，不跟随重定向、不解析页面
  链接、不并入爬到的域名；通配符、裸 TLD、全网段、单标签主机、不可解析形态一律
  `ScopeDerivationError` fail-closed。派生与授权**拆开**：派生是技术动作，授权由
  `acknowledge_authorization` 显式确认，两者分别落审计 `scope_derived` 与
  `authorization_acknowledged`。

- **派生范围持久化并集生效**（M9a）：派生结果落盘 `api.json` 的 `derived_scope`，
  `load_scope` 将其与 scope 文件并集。因此 **5 层 `check_scope` 与出口白名单零改动**
  即自动覆盖派生范围，重启后依然生效。

- **`tests/test_verifier_independence.py`**（M9b）：把 Verifier 校验独立性从
  "不可验证的配置事实"变成"锁死的工程属性"。四组断言：A 输入白名单（发现端过程字段
  state/confidence/source_signal_refs/dedup_key/rejection_reason/narrative、原始工具输出、
  凭据原文以哨兵串断言全部不得进入裁判 prompt）；B 超限 fail-closed（超字符上限抛
  `ContextOverflowError`，且**调用模型之前**抛出，禁静默截断）；C 输出契约（坏 JSON /
  非法 verdict / 空 reason / confirm 缺合法 CVSS 向量一律 `VerifierError`）；
  **D 同模型配置下 A/B/C 依然成立**——这是 M9b 的核心主张。

- **`scripts/demo_derived_scope.py`**（M9a）：六步验收 demo（确定性，无需 DVWA/Docker/LLM）——
  未确认授权 403 且零副作用 → 派生并打印 → 审计双留痕 → 重建 manager 后派生范围仍在并仍通过
  重校验 → 边界未被放宽（放行自身、拒绝兄弟域/后缀伪装域/范围外 IP）→ 出口白名单随 scope。
  `--live` 附加模式真实调用 `default_phases_factory`，断言生产栈 `egress.mode=restricted`、
  接入 `proofhound-egress`、白名单来自该 engagement 的 scope。

- **控制台**（M9a）：创建表单以 target 为主输入，scope 下拉改标注「可选」，新增「我确认已获得
  书面测试授权」勾选框（未选 scope 文件时必填）。

- **模型驱动假设生成（T1 档）**（M9c①）：新增 `proofhound/llm/triage.py`。补上
  `llm/router.py` 早已规划、却从未接线的 T1 档 triage——原先 triage 是纯规则表，参数键
  **精确匹配**约 20 个英文键名，参数名不在表内（`article_id` / `sku` / `token` / `ref` / `no`
  / 中文站 `bh` 等）的真实漏洞端点**根本不产生候选**："不是验证失败，是看不见"。四条纪律：
  ① 只推理（不生成命令、不发请求）；② `vuln_type` 白名单硬编码 `{sqli,xss,idor}`
  （= `GATE_MATRIX` 覆盖类型，模型不得发明无验证器的类型）；③ 输入边界（prompt 只含 URL path、
  参数名、状态码、表单字段名与响应长度，**响应体零进入**）；④ 输出 Pydantic 强校验 + 接地性
  （`param` 必须在送审摘要真实出现过）+ `llm/repair.py` 一次修复重试，**非法输出零候选**
  （fail-closed，不降级为"当作合法候选"）。候选归属由送审摘要确定性回填（模型不回 URL）。

  > **对使用者的影响**：**默认关闭**。置 `PROOFHOUND_TRIAGE_MODEL=1` 开启。既有部署不设该
  > 变量则行为与 M9c 之前逐字节等价（旧 21 个 triage 测试零改动全绿）。

- **中性基准基座**（M9c Step 0）：新增 `scripts/bench_triage.py`。三臂消融
  （`rules` / `model` / `rules+model`）量化发现层，产出**发现率 / 误报率 / 单题成本**。
  自建 stdlib fixture 的理由：DVWA 的参数名全是 `id`/`name`，**恰好落在提示表内**，
  拿它测关键词盲区必然测不出来；基座让 A/B 两族端点行为同构、**唯一变量是参数名是否命中
  提示表**，故发现率差异只可能来自 triage 的关键词匹配。确定性 in-process 爬行，零 Docker 零 LLM。

  > **实测（12 真漏洞 / 4 安全对照）**：`rules` 发现率 **33.3%**、误报率 50.0%；
  > `rules+model` **100.0%**（经廉价粗筛后误报率 0%）。纯规则表漏掉 8/12 条真实漏洞，
  > 其中 6 条是参数名不在提示表的盲区。
  >
  > **真实 T1 档实测**（`--model`）：`rules+model` 发现率 **100.0%**、`model` 臂 **91.7%**
  > （与理想模型上界替身持平），成本 10,028 token/轮。模型沿语义线索把安全端点
  > `/d/safe4` 也判成候选，故**候选级**误报率高于替身——这类误报由确认链路
  > （L2 闸门 + 行为验证 + 证据门 + Verifier）消化，不靠发现侧保守到看不见漏洞。

- **廉价粗筛层 + cap 移到贵验证档**（M9c②）：新增 `proofhound/verify/prefilter.py`。
  零 LLM、纯 httpx、确定性、只读 GET；在此基础上 cap 从「候选生成侧」移到「贵验证档」
  （`_TRIAGE_EXPENSIVE_CAP`），发现侧随之放开。

  > **实现期实测到的负结果（诚实披露）**：初版把粗筛的 `UNLIKELY`（两个语义不同取值产出
  > 逐字节等长响应）当作"不进贵验证档"，在本仓库基座上实测为**负收益**——`rules+model` 臂
  > 发现率被从 100% 砍到 83.3%，而误报率**一点没降**。原因是差分假设不成立：「两个取值等长」
  > 同样出现在 blind 注入、定长模板里，**不是**漏洞的负面证据。故本层收窄为**建议性信号
  > （永不丢弃候选）**，并修掉一处方法感知缺陷（POST 表单候选不做 GET 差分，判 `UNKNOWN`
  > 而非 `UNLIKELY`）。修好后实测：候选级误报率 50% → **0%**，且不损失任何真漏洞。

  > **对使用者的影响**：**默认关闭**。置 `PROOFHOUND_VERIFY_PREFILTER=1` 开启。


- **人工闸细分：只读验证可自动 / 写操作留人工**（M9c③）。原先 `autonomy.py` 按 L0/L1/L2
  一刀切：semi_auto 下**所有** L2 动作都进确认队列。但 L2 里混着两类性质不同的动作——
  「只读验证」（sqlmap 确认、浏览器 canary 探测、双会话 GET 对比）不改变目标状态，
  「写操作」会。`_GATE_MATRIX` 因此扩为「模式 × 等级 × 是否改变状态」，**唯一差异格 =
  semi_auto × L2**（只读 → auto、写操作 → confirm）；supervised 一律 confirm（细分级
  **不放宽最严格档**），unattended 本就全自动。`mutating` 来自 skill manifest 新增可选字段
  **`mutating`（缺省 `true` = fail-closed）**：未声明的 skill 一律按"会改变目标状态"对待。
  内置 `verify-sqli`/`verify-xss`/`verify-idor` 声明 `mutating: false`（三者都是只读验证），
  `web-scan`/`recon-crawl` 声明 `true`（会向目标发真实请求，保守声明）。

  > **对使用者的影响**：**默认不变**——`decide(risk_level)` 缺省 `mutating=True`，即写操作
  > 行，既有调用方与既有部署行为逐字节一致。只有**显式声明 `mutating: false` 的 skill**
  > 才会在 semi_auto 下自动执行 L2。`GET /health` 的 `autonomy_gate` 字段形态**未变**
  > （仍为扁平字符串，控制台按字符串渲染不受影响）；只读行另经
  > `proofhound.autonomy.gate_matrix_read_only()` 导出。自定义 skill 若确实是只读验证，
  > 需在 `SKILL.md` 显式加 `mutating: false` 才能享受自动执行；不加则保持"需人工确认"。

  > **为什么这一刀安全**：它区分的是"是否改变目标状态"，而非放宽任何硬闸——scope 强校验、
  > token 预算、凭据脱敏、append-only 审计在任何裁定下一律照旧。只读自动执行会落审计
  > `action_read_only_auto`（含 mode 与理由），便于事后归因"为什么这次没人被问"。

- **撤下 Skill 用户导入面 + 风险画像单一真相源**（M9d）。本系统**不开放用户自写 skill**
  （维护者裁定），skill 库全部内置、随仓库交付。据此删除：导入安全闸
  （`proofhound/skills/gate.py`：静态扫描外来 skill 脚本的网络外联/文件删除/权限提升/
  动态执行）、registry 的高危确认流程（`risk_report`/`confirmed`/`confirm()`）、
  API 侧 `GET/POST/PUT/DELETE /api/skills` 五个端点与 `SkillUpdateRequest`、
  `management.py` 的 skill CRUD（zip 上传 / copy-on-edit / 符号链接本地化）、
  控制台「技能」上传编辑视图与导航项。同时新增 `proofhound/skills/profiles.py` 作为
  内置 skill 风险画像（`risk_level` + 是否只读）的**运行时唯一真相源**——此前该事实同时
  写在 `SKILL.md` frontmatter 与各处 Python 里，**没有任何机制保证一致**，改一处忘一处
  即静默不一致，且落在安全语义上（闸门裁定、是否需人工确认）。

  > **对使用者的影响（破坏性）**：`/api/skills` 相关端点**已移除**（调用将得到 404），
  > 控制台不再有「技能」视图。此前通过 API 上传/编辑/删除 skill 的脚本与流程需要改为
  > 直接修改仓库内 `skills/<name>/SKILL.md` 并走代码评审。**`SKILL.md` 的 frontmatter
  > 不再是运行时真相源**：改它的 `risk_level` / `mutating` 不会改变闸门行为（改的是
  > `profiles.py`）；两者不一致会**测试失败**而非静默生效。自定义扫描/验证逻辑改为
  > 在 `proofhound/` 内实现（编排器链路本就是确定性 Python，不经 skill 扩展）。

  > **保留**：`SKILL.md` 解析与校验、skill registry、`enable()`/`disable()`
  > （planner「skill 未启用即拒」依赖）、五个内置 skill 本身。
  >
  > **测试账（实测复核）**：新增 `tests/test_skill_profiles.py` 16 个；移除
  > `tests/test_skill_gate.py`（19）与 `tests/test_skill_admin.py`（23）——两者只测
  > 被删功能。863 − 42 + 16 = **853 全绿**，其余 18 个引用 `SkillRegistry` 的测试文件
  > **零改动**（registry 接口保留，只删了它内部的安全闸与确认流程）。

- **中性基准升级为「真可确认」+ 端到端 `--live` 模式**（M10a）：`scripts/bench_triage.py`
  原先的 fixture 只是**模拟**特征（取值含引号 → 500），只能测发现层。M10a 把后端换成真的：
  sqli 走 sqlite 拼接查询（sqlmap 可真确认，A/B/C 三族同后端）、xss 保持不转义反射
  （无头浏览器 canary 可确认）、idor 引入身份归属（`PRIMARY_IDENTITY` / `OWNER_IDENTITY` +
  `REFERENCE_TOKEN`，双会话属性违反可确认）、D 族换成真安全（`/d/safe2` 去掉模拟 SQL 错误；
  `/d/safe4` 改为对**所有**取值做真授权校验，非所有者得定长通用页）。**不变式全部保持**：
  端点表/参数名、首页链接、表单字段、爬行状态码、D 族「两个探测取值响应长度相同」（粗筛只比
  长度）、响应体 ≥64 字节——故**离线三臂与真实 T1 档数字逐格不变**。

  **`--live` 为附加模式**（不改变离线确定性）：4 臂 = 两个生产开关的 2×2 组合，走真实编排栈
  （Docker 沙箱 + Chromium + T2），semi_auto 下只读 verify 自动执行、无人工闸。**口径（维护者
  裁定）**：粒度 = **(端点路径, vuln_type)**、类型错配计误报；`verify_blocked`（T2 超时 / 缺第二
  会话）**单列一行、不计入 precision/recall 分母**。

  **Confirmed 级实测**（12 条真漏洞 + 4 个安全对照）：

  | 臂 | 检出率 | 精确率 | 误报率 | TP | FP | 未能判定 | token |
  |---|---|---|---|---|---|---|---|
  | `rules` | 33.3% | 100.0% | 0.0% | 4 | 0 | 0 | 26,557 |
  | `rules+model` | 58.3% | 100.0% | 0.0% | 7 | 0 | 0 | 59,052 |
  | `rules+prefilter` | 25.0% | 100.0% | 0.0% | 3 | 0 | 1 | 22,662 |
  | `rules+model+prefilter` | **66.7%** | 100.0% | 0.0% | **8** | 0 | 0 | 59,858 |

  即**确认链路（证据门 + 独立 Verifier）在 4 臂上误报率全 0**——4 个安全对照端点的全部候选
  （含"公开资源被 IDOR 判定器误判"的陷阱）都被驳回，且理由是实质性的（"无证据证明该对象确属
  reference 身份私有"）；`PROOFHOUND_TRIAGE_MODEL` 有 **+3~+5 个 Confirmed** 的明确增益，
  代价约 2.2× token / 2.1× 时长。

  > **明示限制（未解决）**：每臂仅**单次采样**，而单条 Confirmed 的判定本身随机——同一个真
  > IDOR（`/a/idor`）在 4 臂里出现 **4 种结果**（confirmed / rejected / 未能判定 / rejected），
  > 分歧点是 Verifier 对「对象私有性」证据够不够的判定标准（它只收结构化摘要、看不到响应体，
  > 该要件在摘要下**欠定**，属规格歧义）。故臂间 1~2 条 TP 的差异**无法区分开关效应与采样
  > 噪声**。重复测量与 Verifier 的 IDOR 判据收紧均未做。

### 修复

- **前沿推理档读超时 60s 压在模型延迟线上**（M10a 实现期发现）：`TierConfig.timeout`
  缺省 60s，而 T2（Verifier 终审）实测延迟落在 **55~65s**——正压线上，导致**间歇性**
  `verify_blocked`（fail-closed，语义正确，但把"未能判定"混进了 Confirmed 级指标）。
  基线实测：单臂 12 条真漏洞里 **3 条**纯因超时丢失（检出率 50%，本可 75%），而同一次运行里
  其它 T2 调用均正常返回——即**逐次随机**，不是环境不可用。已修：新增分档缺省表
  `DEFAULT_TIMEOUTS`（T0/T1 保持 60s、**T2 放宽到 180s**）并支持 `PROOFHOUND_<TIER>_TIMEOUT`
  覆盖。修复后 4 臂合计 48 条配对只剩 1 条超时（≈2%）。由 `tests/test_tier_timeout.py`（9 个）
  锁死分档缺省、env 覆盖与非法值 fail-closed。

  > **对使用者的影响**：T2 调用失败会等更久才被判定失败——`urllib` 的 timeout 是**单一读
  > 超时**（连接与读取共用），放宽同时抬高了故障发现延迟，属刻意取舍；需要更快失败可在
  > `.env` 显式设回 `PROOFHOUND_T2_TIMEOUT=60`。

- **基准 fixture 正文雷同会让爬虫丢端点**（M10a 实现期发现）：Step 1 首版把 A/B/C 三族统一到
  同一份响应正文（以为"更同构"），结果 **katana 把正文重复的 URL 当作重复响应丢弃**——16 个
  端点只有 **9 个**进入 crawler（sqli 5→1、xss 2→1、idor 3→1），live 臂的 Confirmed 级检出率
  因此被伪造成 25%。已修：每个端点带自己的 label + 参数名，形态仍同构（同一后端、同一 vuln
  语义、唯一变量是参数名）但正文逐端点不同；并由
  `test_no_two_endpoints_share_a_body` 作为硬性回归网锁死。
  **教训：「行为同构」≠「逐字节相同」。**

- **两处文档错误修正**（M10a 复核发现）：① `AGENTS.md` M9d 行的被删用例数写为
  `test_skill_gate.py`（19）/ `test_skill_admin.py`（23）、实收 −42；实测为 **7 / 19**、
  实收 **−26**（原式 `863 − 42 + 16 = 853` 本身就不成立，= 837）。② `AGENTS.md` 已知限制 33
  称「fixture demo 走 host + open egress」——实测 `scripts/` 下无任何脚本设置
  `PROOFHOUND_SANDBOX_EGRESS`，demo 走的是 M9a 之后的默认 **`restricted`**，正是它经白名单代理
  打通了宿主 loopback。已就地修正。

- **`Engagement._persist()` 会抹掉 `derived_scope`**（M9a 实现期发现）：该方法原先硬编码
  要写入 `api.json` 的 key 白名单，任何一次状态迁移写回都会丢掉派生范围，导致 `start()`
  重校验到一个空 scope——授权范围静默消失（表现为拒绝一切）。已修，并由
  `test_derived_scope_survives_state_transition_persist` 与
  `test_derived_scope_survives_manager_restart` 两条测试锁死。

### 文档

- `docs/design.md`：新增 §7.5 M9 落地注记（含实现期踩坑记录）；§3 红线 4 重写；
  §8 路线图补 M9a/M9b 两行；§9 开放问题 5 相应收窄（既然已解除「必须不同模型」，
  问题转为**模型家族多样性**与 agent 隔离各自对对抗效果的边际贡献）。
- `AGENTS.md`：里程碑表补 M9a/M9b 两行（含验收标准）；架构红线 4 重写；
  已知限制 24（API 沙箱网络为演示取向）标记为**已还清**并记录逃生阀。
- `AGENTS.md` / `docs/design.md`（M9c）：里程碑表/路线图补 M9c 行；新增 §7.6 落地注记
  （含粗筛负结果的完整披露）；已知限制 8（triage 仅规则表覆盖两类）标记为**已还清**；
  环境变量表补 `PROOFHOUND_TRIAGE_MODEL` / `PROOFHOUND_VERIFY_PREFILTER`。
- `docs/design.md` / `README.md`（M9c③）：新增 §7.6.3 人工闸细分注记（含闸门矩阵两行与只读声明契约）；README 自主模式三档表补只读验证行。
- `README.md`：架构红线 4 与差异化段落改为"校验独立性"表述；Quickstart 说明最短路径
  只需一个目标（无需手写 scope 文件）；前提说明 T1/T2 可同模型。
- `docs/design.md`（M10a）：新增 §7.7 落地注记（含两处实现期踩坑、指标口径与两处诚实性
  说明）；§8 路线图补 M10a 行。
- `README.md`（M10a）：「发现效果基准」节补 Confirmed 级 4 臂表与口径，并**修正**离线
  「接入模型 100%」的解读（离线 model 臂是"能力上界"替身，真实 T1 有运行间方差）；
  「下一步」节第 1 项标记完成并列出两项残留。
- `AGENTS.md`（M10a）：里程碑表补 M10a 行（含验收标准）；环境变量表补
  `PROOFHOUND_<TIER>_TIMEOUT`；已知限制补 34~37（单一读超时取舍、基准单次采样方差、
  fixture 自报对象归属、身份无关端点会被 IDOR 判定器判为属性违反）。

## [0.2.0] - 2026-08-15

### 新增

- **POST 表单发现自动化**（M8a）：katana 解析器产出 `form_page` 信号（页面
  裸 URL + 表单字段名并集，action 跨源 fail-closed 跳过），triage 自动产出
  POST 表单类 SQL 注入候选，验证侧走 `sqlmap --forms` 模式（与 `-p`/`--data`
  互斥 fail-closed）；DVWA security=medium 实靶验收通过。
- **XSS 无头浏览器行为确认**（M8b）：新增 verify-xss 验证器——无头 Chromium
  加载带 canary 探针的唯一 token payload，XSS 的 Confirmed 只来自脚本真实
  执行事件（反射不算证据）；scope 双层防线（加载前校验 + 跨源请求一律
  abort）；Finding 验证信息升级为四段式结构（claim/method/expected/actual）。
- **IDOR 双会话属性验证**（M8c）：新增 verify-idor 验证器——支持预置第二
  身份会话（reference/victim），同一 URL 换身份重放，按响应相似度/JSON 键
  重叠写死阈值判定水平越权属性违反，判定依据全量结构化落盘；单会话异常
  响应不能确认 IDOR。
- **Killer Demo 一键三漏洞演示**（M8d）：`scripts/demo_killer.py` 单
  engagement 覆盖 DVWA（sqli + xss_r）与内置 IDOR fixture（含不误报对照组）
  双目标，一键跑出"一份报告、三个 Confirmed、每条带四段式证据"的完整证据
  链，终端打印证据链摘要表；README 新增「三分钟看清 ProofHound」展示区。

## [0.1.0] - 2026-08-10

首次公开发布（Apache-2.0）。

### 新增

- **工具底座**：Tool Manifest、白名单源 + 强制 SHA256 校验的安装器、Docker
  沙箱执行（隔离/配额/网络出口策略）、scope 授权校验（无授权拒绝启动，
  越界命令拒绝 + 审计）、append-only 审计日志。
- **Skill 系统**：Agent Skills 开放规范（SKILL.md）registry 与导入安全闸；
  内置 web-scan / recon-crawl / verify-sqli skill。
- **编排器**：任务树/DAG 状态机、结构化计划双层校验的规划器、失败预算；
  LLM 三档模型路由（T0/T1/T2）、Run 级 token 预算硬闸、上下文确定性压缩
  与字符硬上限。
- **Finding 生命周期**：Signal→Hypothesis→Reproduced→Confirmed/Rejected
  状态机（铁律硬编码：版本匹配型与纯状态码型证据永远不能 Confirmed）、
  去重指纹、证据包组装与离线调出、确定性 triage（零 LLM 调用）。
- **验证执行层**：证据门（各漏洞类型最低验收标准，fail-closed）、预置会话
  凭据脱敏（审计/证据只记 sha256 标记）、sqlmap 接入、独立模型 Verifier
  对抗终审、verify-sqli 垂直切片（DVWA 实靶 Confirmed）。
- **发现自动化**：katana 爬行发现带参端点，triage 启发式自动产出 SQL 注入
  Hypothesis（宁漏勿滥 + 每 engagement 上限）。
- **报告引擎**：docxtpl 模板渲染（数据与表现分离，StrictUndefined +
  autoescape）、T1 叙述润色（段落锚定 Finding ID，无锚拒收）、叙事事实
  守卫（状态措辞/计数断言确定性校验）、误报附录中文归因、CVSS v3.1 官方
  公式代码确定性算分（Confirmed 严重级不再是种子数据）。
- **Web API 与本地控制台**：FastAPI 本机后端（只绑 localhost）、自主模式
  三档动作闸门（supervised/semi_auto/unattended，L2 默认需确认）、动作
  确认队列（持久化可恢复、超时默认拒绝）、纯静态零依赖 Web 控制台
  （任务/Findings 看板/证据包审阅/审计流/报告下载）、skill 与 scope
  管理面。
