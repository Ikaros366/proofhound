# AGENTS.md

> 面向 AI 编码 Agent 的项目指南。本文件基于仓库当前实际内容编写；项目已完成 M1（工具底座）、M2a（Skill 系统 + M1 遗留补强）、M2b（编排器核心）与 M2c（模型路由与成本治理）。

## 项目概述

本项目是 **ProofHound**（暂定名，发布前需复查 GitHub/PyPI/Docker Hub/域名占用）——一个**自动化渗透测试 Agent 系统**。仓库包含设计文档与 M1 实现：

- `docs/design.md` —— 设计文档 v0.7（草案，状态：待评审），是整个仓库的权威输入，用途为"作为 Kimi Code 开发输入，指导从零实现"。
- `proofhound/` —— M1 工具底座（L0+L1）：Tool Manifest、安装器、Docker 沙箱、scope 校验、append-only 审计日志；M2a：L2 Skill 系统（registry + 导入安全闸）+ 两项 M1 遗留补强（文件目标 scope 解析、沙箱网络出口白名单）；M2b：L3 编排器核心（`proofhound/core/`：任务树/状态机、规划器、失败预算）+ 最小 LLM 客户端（`proofhound/llm/`）+ 确定性命令构造器（`tools/build.py`）+ 首个输出解析器（`tools/parsers/httpx_json.py`）+ Signal 模型（`findings/signal.py`）；M2c：模型路由三档 T0/T1/T2（`llm/router.py`）+ 用量计量与 Run 级 token 预算硬闸（`llm/usage.py`）+ 上下文治理（`core/context.py`：确定性压缩 + prompt 字符硬上限）+ live 演示脚本（`scripts/demo_live.py`）；其余分层（verify/report/infra）仅有占位目录，属后续里程碑。
- `skills/` —— 内置 skill 库，目前已有 `web-scan`（httpx SOP）。

系统针对现有编排型 AI 渗透工具（以 PentAGI 为代表）的三大痛点设计：误报泛滥、速度慢、成本高。核心设计哲学是"**证据为王、验证驱动**"：一切候选发现默认为假，必须通过验证层状态机和证据门才能进入报告。

三大功能目标（F1~F3）：

1. **可导入 Skill**：采用 Agent Skills 开放规范（SKILL.md），支持本地目录、Git 仓库、内部 registry 三种导入来源。
2. **工具自管理**：本地预置工具优先；缺失工具按配方自动安装（白名单源 + 强制 SHA256 校验）；全程 Docker 沙箱执行。
3. **模板化报告**：用户提供 docx/html 模板自动出报告；事实性内容全部来自结构化数据，LLM 只做叙述润色。

## 仓库现状与开发阶段

- **M1（2026-08-06）、M2a、M2b、M2c（2026-08-07）已完成**：`pyproject.toml`、pytest 测试套件已就位；M2a 交付 L2 Skill 系统（`proofhound/skills/`：manifest 强校验、registry、导入安全闸）、scope 文件目标解析（`httpx -l targets.txt` 逐行校验，任一行越界即拒）、no_targets 默认拒绝、沙箱网络出口白名单（`proofhound/tools/egress.py`，默认 restricted）；M2b 交付 L3 编排器核心（任务树/DAG + 节点状态机、规划器——结构化 JSON 计划经 Pydantic schema + 语义双层校验、失败预算 + 规则表失败分类、最小 LLM 客户端，OpenAI 兼容、配置走 .env）并打通"web-scan → 计划 → 沙箱 httpx → Signal 落盘 → 全链路审计"最小链路；M2c 交付模型路由（三档 T0/T1/T2 独立配置、规划走 T1、T1==T2 同模型启动警告——红线 4）、用量计量（`llm_call` 审计；响应无 usage 按字符估算并标 estimated）与 Run 级 token 预算硬闸（调用前检查，超限停止规划循环、节点 blocked、记 `llm_budget_exceeded`，与 scope 同级不可绕过）、上下文治理（Signal 摘要按 kind 聚合压缩、计数不丢；prompt 字符硬上限，超则任务 failed 记 `context_overflow`，禁静默截断）；尚未实现 CLI、成本仪表盘/模型自动降级（M2c 仅有审计事件）及 M3 之后的模块，也没有 CI、lint 配置。
- 一切实现工作都应以 `docs/design.md` 为准。修改设计决策时，同步更新该文档。
- 开发路线图（文档 §8）：

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| M0 流程验证（1~2 周） | 不写平台代码：把 recon/scan/verify/report 5 个 skill 装进 Kimi Code，手工编排跑通一个靶场 | 全流程 SOP 跑通，skill 划分定型 |
| M1 工具底座（2 周）——已完成（2026-08-06） | L0+L1：manifest、安装器、Docker 沙箱、scope 校验、审计日志；打通 httpx 一条工具链 | 离线镜像可用；越界命令被拒且有日志 |
| M2 编排器（2~3 周）——M2a、M2b、M2c 已完成（2026-08-07） | skill registry（M2a ✅）、任务 DAG + 规划器 + 失败预算 + 最小 LLM 客户端（M2b ✅）、模型路由 + 预算硬闸 + 上下文治理（M2c ✅；成本仪表盘未做，仅有 llm_call 审计事件）；M1 遗留补强（M2a ✅）：文件目标 scope 解析、沙箱网络出口白名单 | 单目标 recon+扫描全自动；上下文体积有上限；成本仪表盘可见 |
| M3 验证层（3 周） | 状态机、baseline 对照、3 个 verify skill（sqli/xss/lfi）、Verifier Agent、去重、误报库 | XBEN/DVWA 上 Confirmed 发现 100% 带证据；误报率达标 |
| M4 报告引擎（1~2 周） | docxtpl 管线、叙述润色、误报附录 | 给定模板一键出报告，事实字段零手写 |
| M5 产品化（按需） | 本机 Web 控制台、MCP 暴露、持续监测、增量复测 | — |

**注意 M0 的特殊性**：第一阶段刻意不写平台代码，只做 skill（SKILL.md 目录）并用 Kimi Code 手工编排验证流程。

## 技术选型（设计已定，实现时遵循）

| 层 | 选型 |
|---|---|
| 语言 | Python 3.12 |
| 数据校验 | Pydantic v2（Finding/Signal/Manifest schema 强校验） |
| 存储 | SQLite（单文件归档；后期可升 PostgreSQL，选型已预留） |
| 沙箱 | Docker SDK for Python（隔离、配额、只读挂载、网络策略） |
| 浏览器/代理 | Playwright（Chromium）+ mitmproxy（不自研浏览器） |
| LLM 接入 | OpenAI 兼容协议统一封装（Kimi / DeepSeek / 本地 Ollama） |
| 报告 | docxtpl + Jinja2；PDF 走 Jinja2 → HTML → Paged.js/weasyprint |
| 接口 | FastAPI（本机 Web 控制台，只监听 localhost）+ MCP Server（可选） |
| 测试 | pytest + 公开漏洞靶场（DVWA、Vulhub、XBEN） |

## 计划中的代码组织（文档 §7）

实现时按以下结构建目录；模块边界即分层架构 L0~L5：

```
proofhound/
├── proofhound/
│   ├── core/          # L3 编排器、状态机、DAG 调度
│   ├── skills/        # L2 Skill registry、loader、导入安全闸
│   ├── tools/         # L1 Tool manifest、安装器、沙箱、解析器（解析器集中在 tools/parsers/）
│   ├── infra/         # L0 engagement 基础设施：浏览器容器、代理容器、HTTP 日志库
│   ├── verify/        # L4 证据门、baseline、Verifier Agent、去重、误报库
│   ├── findings/      # Finding 数据模型、SQLite 存储
│   ├── report/        # L5 模板渲染管线
│   ├── llm/           # 模型路由（T0 廉价/T1 中档/T2 前沿）、预算、上下文治理
│   └── compliance/    # 授权、scope 校验、审计日志
├── skills/            # 内置 skill 库（recon-*、web-scan、baseline-check、dir-bruteforce、verify-*、report）
├── tools.d/           # 用户预置工具（离线场景）
├── templates/         # 报告模板
├── evidence/          # 运行时证据归档（原始输出 100% 落盘于此）
├── tests/
└── docs/
```

## 架构红线（不可妥协，文档 §3）

实现任何模块时与以下五条冲突的，以红线为准：

1. **LLM 只做推理**：确定性动作（端口扫描、目录爆破、模板渲染）由调度器直接执行；LLM 规划输出为结构化 JSON，**不直接生成 shell 命令**（命令由工具管理器按 manifest 模板拼装）。
2. **发现 ≠ 漏洞**：候选发现默认是假的；版本匹配型 CVE、纯状态码型发现永远只能是 Signal，必须经行为验证晋级 Confirmed。
3. **上下文只进结构化摘要**：工具原始输出一律落盘 `evidence/`，LLM 上下文只有结构化数据 + 文件引用路径。
4. **模型按任务分级**：解析/分类/去重/润色用廉价模型；仅漏洞假设与利用链规划用前沿模型；**Verifier 与发现端必须用不同模型**。
5. **授权前置**：无 scope 授权文件系统拒绝启动；每条拟执行命令先提取目标过 scope 校验，越界拒绝 + 记审计日志。

## 关键开发约定

- **Skill 职责隔离**（写入 skill 开发规范）：发现类 skill 只能产出 Signal/Hypothesis，**Confirmed 必须经 verify-\* skill 产出**。
- **失败预算**：子任务同类失败默认重试上限 2 次，命中即停止并升级；失败信号须分类（凭证错误/验证码/限流/锁定/网络异常），禁止"一律重试"。验证码、MFA、WAF 人机校验属硬阻塞，不作为自动攻克目标。
- **工具安装纪律**：白名单源 + 强制 SHA256 校验；常用工具构建期烘焙进 Docker 镜像；规则库/字典放 named volume 跨任务复用；**绝不每任务重复下载**；更新走显式动作（`proofhound tools update <name>`）。
- **报告数据与表现分离**：模板渲染只读结构化字段；LLM 叙述段落必须关联 Finding ID，叙述文字只存 `narrative` 字段，不回写事实字段。
- **文档语言为中文**：现有设计文档全文中文，新增文档、commit 信息、用户可见说明沿用中文；代码标识符保持英文。
- **去重指纹**：`sha256(资产 + 漏洞类型 + 参数/路径)`，同指纹证据归并到同一条 Finding。

## 测试策略（设计已定，实现时遵循）

- 框架：**pytest**，配合公开漏洞靶场（DVWA、Vulhub、XBEN）做回归与指标测量。
- 解析器（`tools/parsers/`）配版本快照与回归测试，防工具输出格式随版本漂移。
- 质量验收指标（文档 §2.2）：人工复核误报率 < 5%；验证通过率 30%~70% 健康区间；单目标成本 ≤ PentAGI 同任务 1/10；单目标时长 ≤ 1/3；证据完备率 100%。

## 安全与合规（产品级红线，文档 §5.8、§11）

- **授权门槛**：启动必须加载 scope 文件（授权域名/IP/端口白名单）+ 用户显式确认；任何自治模式（Supervised / Semi-auto / Unattended）都不可绕过 scope 强制校验、预算帽、append-only 审计日志。
- **审计日志 append-only**：每条命令、每段输出、每次 LLM 调用、每次状态迁移全部落盘，兼作报告证据链。
- **危险动作分级**：L0 被动 / L1 主动扫描 / L2 利用验证；L2 skill 默认每次执行需确认。
- **沙箱**：每 engagement 独立容器；工具目录只读挂载；网络出口限速+白名单；CPU/内存配额。
- **网络暴露红线**：Web 控制台只绑定 localhost/内网/VPN；多人访问需反向代理（nginx + TLS）+ 登录认证；**严禁无认证直接暴露公网**。
- **无害 PoC 为限**：不内置武器化 exploit 库；开源发布纪律：不附带武器化 exploit 模块、不附带任何真实目标数据；发布前 gitleaks 全量扫密钥。
- 生成或修改代码时，不得削弱上述机制（如添加绕过 scope 校验的开关、把审计日志改成可写覆盖等）。

## 构建与运行

环境搭建与测试命令：

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest            # 全量（含 Docker 沙箱与 httpx 端到端）
.venv/bin/python -m pytest -m "not docker"   # 无 Docker 环境时只跑纯单元测试
```

沙箱/端到端测试需要可用的 Docker 守护进程（自动探测，不可用则 skip）；httpx 端到端测试需能访问 github.com（不可达时自动 skip）。设计确定的交付形态（文档 §5.9）：

- 核心引擎 = 本地 CLI（M1~M4 唯一交互方式）。
- 产品化 = 本机 Web 控制台（FastAPI 监听 localhost）+ 一键启动脚本；**不打包 exe**（强依赖 Docker 沙箱、Kali 工具链、本地证据目录）。
- 服务器部署：Docker Compose；引擎容器挂载 `/var/run/docker.sock` 以兄弟容器方式拉起沙箱。
- 涉敏环境支持全离线：本地模型（Ollama）+ 预烘焙工具镜像 + `tools.d/` 预置目录。

### .env 配置项（M2c）

环境变量与 .env 同名，已有环境变量优先；M2c 起 LLM 走三档分配置：

| 变量 | 含义 |
|---|---|
| `PROOFHOUND_T0_BASE_URL` / `PROOFHOUND_T0_API_KEY` / `PROOFHOUND_T0_MODEL` | T0 档（解析/分类/去重/润色）端点、密钥、模型；可选 `PROOFHOUND_T0_TEMPERATURE`、`PROOFHOUND_T0_MAX_TOKENS` |
| `PROOFHOUND_T1_*`（同构五变量） | T1 档（规划/triage/摘要）；规划器固定走此档 |
| `PROOFHOUND_T2_*`（同构五变量） | T2 档（漏洞推理/Verifier 终审，M3 接入）；与 T1 同模型会触发启动警告（红线 4） |
| `PROOFHOUND_MAX_TOKENS_PER_RUN` | Run 级 token 预算硬闸：未设 = 不限；0 = 拒绝一切调用；超限停止规划、节点 blocked、记 `llm_budget_exceeded` |
| `PROOFHOUND_MAX_TOKENS_PER_RUN_T0` / `_T1` / `_T2` | 分档预算上限（可选） |
| `PROOFHOUND_CONTEXT_MAX_SIGNALS`（默认 20） | Signal 摘要超过该条数即按 kind 聚合压缩 |
| `PROOFHOUND_CONTEXT_KEEP_LATEST`（默认 5） | 压缩时每类保留的最新条数（total_counts 完整保留） |
| `PROOFHOUND_CONTEXT_MAX_CHARS`（默认 32000） | prompt 字符硬上限：超限先压缩，仍超则任务 failed 记 `context_overflow`，禁静默截断 |
| `PROOFHOUND_LLM_BASE_URL` / `_API_KEY` / `_MODEL` | M2b 单模型旧路径（`LLMConfig.from_env`）；M2c 起规划走 T1 分档，此组仅供旧调用 |

live 演示（真实 key，不进 pytest，产物落 `evidence/demo_live/`）：

```bash
.venv/bin/python scripts/demo_live.py                 # 正常链路：T1 真实调用 + 沙箱 httpx 打本地靶标
.venv/bin/python scripts/demo_live.py --max-tokens 0  # 演示预算硬闸：首次调用前即被闸（llm_budget_exceeded）
```

## 项目纪律与环境

1. 里程碑纪律：一次只实现当前里程碑的内容，未经用户确认不提前实现后续里程碑的模块。
2. 环境注记：开发环境为 WSL（Linux），项目根 `~/proofhound`，Docker 为 WSL 内引擎，`/var/run/docker.sock` 原生可用；镜像拉取走 daemon 级代理（systemd drop-in 已配置），容器不继承任何代理。
3. 仓库卫生：.env、API 密钥、evidence/ 目录内容永不入库，.gitignore 必须包含 .env 和 evidence/。

## 已知限制（M2a/M2c 遗留，后续里程碑处理）

1. **目标文件不挂进容器**：`httpx -l targets.txt` 的目标文件只在 scope 校验阶段于宿主侧读取；把目标文件（只读）挂载进容器属编排器职责，M2 后续切片处理。
2. **出口白名单仅覆盖 HTTP(S)**：restricted 模式下 HTTP(S) 流量经宿主机白名单正向代理强制出站；非 HTTP 原始 TCP 被 internal 网络整体阻断（fail-closed）；完整协议覆盖待 §5.10 mitmproxy 代理链。不读 proxy 环境变量的工具（如 httpx）须显式传代理参数（沙箱 `egress_proxy_url`）；工具级代理参数声明待 Tool Manifest 扩展。
3. **输出文件名误判**：形如 `out.json` 的参数会被裸域名正则误判为目标（fail-closed 方向，最多误拒，不会误放）； `-l` 消费的目标文件名已不受影响。
4. **构造器仅支持单目标**：`tools/build.py` 的 httpx 构造器只产 `-u <target>` 单目标 argv；`-l` 批量列表依赖"目标文件挂载进容器"（限制 1），M2 后续切片接入。
5. **预算并发精度**：token 预算为调用前检查（check-then-call），并行子任务间不互斥，最多超出一个在途调用的用量；不追求 token 级精确互斥。
6. **token 估算为启发式**：响应无 usage 字段时按 4 字符≈1 token 估算并标 `estimated`，以服务商 usage 为准。
7. **成本仪表盘与自动降级未做**：M2c 的成本可观测仅有 `llm_call` 审计事件；§5.3"超额自动降级模型或挂起请示"与 §5.6 成本仪表盘待后续里程碑。
