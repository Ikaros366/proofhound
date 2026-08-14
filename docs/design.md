# 自动化渗透测试 Agent 系统 —— 设计文档

| 项 | 内容 |
|---|---|
| 文档版本 | v0.7（草案；定名 ProofHound，新增 §11 开源策略） |
| 日期 | 2026-08-06 |
| 状态 | 待评审 |
| 项目名称 | ProofHound（暂定，发布前复查 GitHub/PyPI/Docker Hub/域名占用） |
| 文档用途 | 作为 Kimi Code 开发输入，指导从零实现 |

---

## 1. 背景与问题陈述

现有编排型 AI 渗透工具（以 PentAGI 为代表）在实际使用中存在三大结构性痛点：

1. **误报泛滥**：LLM 直接阅读工具输出并自由下结论，无强制验证环节。表现为：仅看回显状态码就报漏洞、输出需要特定前置条件才能成立的"漏洞"、产生无价值发现乃至幻觉漏洞。
2. **速度慢**：每一步动作（包括确定性的扫描执行）都要经过 LLM 决策，长链路串行；工具原始输出直接塞入上下文，会话越往后 prompt 越大，越跑越慢。
3. **成本高**：解析、分类、去重等粗活与漏洞推理等细活使用同一前沿模型；多 Agent 之间传递大段叙述文本，token 被反复复制。

## 2. 设计目标

### 2.1 功能目标

- **F1 可导入 Skill**：采用 Agent Skills 开放规范（SKILL.md），支持从本地目录、Git 仓库、内部 registry 导入第三方 skill，与 Kimi Code / Claude Code 生态兼容。
- **F2 工具自管理**：本地预置工具优先使用；缺失工具按配方自动下载安装（白名单源 + 哈希校验）；全程在 Docker 沙箱中执行。
- **F3 模板化报告**：用户提供 docx/html 模板，系统按模板自动输出渗透报告；事实性内容全部来自结构化数据，LLM 只做叙述润色。

### 2.2 质量目标（验收指标）

| 指标 | 目标值 | 测量方式 |
|---|---|---|
| 人工复核误报率 | < 5% | Confirmed 发现中被人工标记为误报的比例 |
| 验证通过率 | 30%~70%（健康区间） | Confirmed ÷ Signal 总数；过低说明发现端太飘，过高说明验证端太松 |
| 单目标成本 | ≤ PentAGI 同任务的 1/10 | 相同靶标、相同模型供应商下的 token 账单对比 |
| 单目标时长 | ≤ PentAGI 同任务的 1/3 | 端到端 wall-clock 对比 |
| 证据完备率 | 100% | Confirmed 发现中带完整证据链（请求/响应/复现步骤）的比例 |

### 2.3 非目标

- 不做无授权目标的任何主动测试；不内置武器化 exploit 库（验证以无害 PoC 为限）。
- 全自动无人值守作为**可选模式**提供（见 §5.9），默认半自动；任何模式下 scope 强制与预算帽不可绕过。
- 第一版不覆盖复杂业务逻辑漏洞（此类发现以 Signal 形式提交人工）。

## 3. 架构红线（不可妥协的设计原则）

以下五条是整个系统的地基，任何模块设计与之冲突时以红线为准：

1. **LLM 只做推理**：确定性动作（端口扫描、目录爆破、模板渲染）由调度器直接执行，LLM 只负责制定计划、解读结构化结果、决定下一步。
2. **发现 ≠ 漏洞**：一切候选发现默认是假的，必须通过验证层的状态机和证据门才能进入报告。
3. **上下文只进结构化摘要**：工具原始输出一律落盘，进入 LLM 上下文的只有解析后的结构化数据与文件引用。
4. **模型按任务分级**：解析/分类/去重/润色用廉价模型，仅漏洞假设与利用链规划使用前沿模型。
5. **授权前置**：无 scope 授权文件系统拒绝启动；每条拟执行命令的目标先过 scope 校验。

## 4. 总体架构

### 4.1 分层视图

```
┌────────────────────────────────────────────────────┐
│ L5 报告引擎    模板渲染（docxtpl/Jinja2）· 叙述润色     │
├────────────────────────────────────────────────────┤
│ L4 验证层      状态机 · 证据门 · PoC 验证 · Baseline     │
│                对照 · Verifier Agent · 去重 · 误报库     │
├────────────────────────────────────────────────────┤
│ L3 编排器      任务树/DAG · 规划器 · 模型路由 · 预算控制  │
├────────────────────────────────────────────────────┤
│ L2 Skill 系统  SKILL.md 规范 · Registry · 导入安全闸    │
├────────────────────────────────────────────────────┤
│ L1 工具管理器  Tool Manifest · 安装器 · Docker 沙箱 ·    │
│                输出解析器 · 浏览器服务 · 流量代理         │
├────────────────────────────────────────────────────┤
│ L0 基础设施    Docker · SQLite · 审计日志 · 授权/Scope   │
└────────────────────────────────────────────────────┘
```

### 4.2 核心数据流

```
授权文件 → 编排器加载 recon skill → 工具管理器执行（沙箱）
  → 原始输出落盘 + 解析器产出结构化 Signal
  → LLM（中档模型）triage：Signal → Hypothesis（提出验证计划）
  → 调度 verify-* skill 执行 PoC（沙箱）→ 证据落盘
  → Verifier Agent 对抗校验 → Confirmed / Rejected
  → 去重合并 → Finding 库（SQLite）
  → 报告引擎读取 Finding 库 + 用户模板 → 渲染 docx/pdf
```

## 5. 模块设计

### 5.1 Skill 系统（L2）

**规范**：直接采用 Agent Skills 开放规范。一个 skill 是一个目录：

```
verify-sqli/
├── SKILL.md          # 必需：YAML frontmatter + 正文 SOP
├── scripts/          # 可选：验证脚本
└── references/       # 可选：参考材料（payload 字典、判定规则）
```

SKILL.md frontmatter 字段：

```yaml
---
name: verify-sqli
description: 对疑似 SQL 注入点执行无害化验证并产出证据
version: 1.0.0
required_tools: [sqlmap]
risk_level: L2            # L0 被动 / L1 主动扫描 / L2 利用验证
inputs: [hypothesis]      # 输入：结构化假设
outputs: [evidence_pack]  # 输出：证据包
---
```

正文写 SOP：前置检查 → 执行步骤 → 判定标准 → 什么情况停下来请示人工。

**Registry 设计**：
- 扫描 skills 目录 → 解析并校验 manifest → 注册（含版本管理、启用/禁用）。
- 导入来源三种：本地目录、Git 仓库 URL、内部 registry。
- **渐进式披露**：编排器默认只加载各 skill 的 name + description，命中时才读全文，控制上下文体积。

**导入安全闸**（必须实现）：
- 静态检查：扫描 skill 内脚本的危险调用（网络外联、文件删除、权限提升等），输出风险清单。
- 用户显式确认后才启用；`risk_level: L2` 的 skill 默认每次执行都需确认（可配置）。

**内置 Skill 规划（第一版）**：

| 类别 | Skill |
|---|---|
| 侦察 | recon-passive、recon-active、fingerprint |
| Web 测试 | web-scan、baseline-check、dir-bruteforce |
| 验证 | verify-sqli、verify-xss、verify-ssrf、verify-lfi、verify-rce、verify-idor、verify-cve |
| 报告 | report（内含模板文件 + 写作规范，换模板 = 换 skill） |

职责隔离规则：**发现类 skill 只能产出 Signal/Hypothesis，Confirmed 必须经 verify-* skill 产出**——此规则写进 skill 开发规范。

### 5.2 工具管理器（L1）

**Tool Manifest**（每个工具一份 YAML）：

```yaml
name: nuclei
version: "3.x"
check: "nuclei -version"          # 安装检测命令
install:                           # 安装配方，按优先级
  - type: local                    # 1. 用户预置目录（离线场景）
    path: ./tools.d/nuclei
  - type: binary                   # 2. 官方 release 二进制
    url: "https://.../nuclei_linux_amd64.zip"
    sha256: "<必填，强制校验>"
  - type: go                       # 3. 包管理器兜底
    package: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
parser: nuclei_json                # 输出解析器标识
tags: [scanner, web]
```

**执行策略**：
1. 本地优先：依次检查 PATH → `./tools.d/` → 预构建 Docker 镜像（Kali 基础镜像 + 常用工具，支持完全离线）。
2. 缺失才装：仅从白名单源下载，强制 SHA256 校验，安装后记录版本快照。
3. 沙箱执行：每个测试任务（engagement）独立容器；工具目录只读挂载；网络出口限速+白名单；CPU/内存配额。
4. Scope 强制：命令执行前，从命令参数中提取目标（host/IP/URL），与授权 scope 比对，越界直接拒绝并记审计日志。

**工具持久化策略**（针对"PentAGI 每任务重复下载"问题的硬性设计）：

- **镜像烘焙**：常用工具在**构建期**写入工具镜像（Dockerfile 分层：kali-base → pentagent-tools），任务容器从该镜像秒级启动，运行期零下载。
- **命名卷持久化**：规则库/字典/模板类数据（nuclei-templates、SecLists 等）放 named volume 跨任务复用；工具目录只读挂载保证一致性，任务数据走独立可写卷。
- **安装即缓存**：运行期确需安装的新工具，结果落入持久卷或 commit 为新镜像层，并更新 manifest 版本快照；版本匹配直接跳过，**绝不重复安装**。
- **更新显式化**：工具更新是手动/定时动作（`proofhound tools update <name>`）：校验哈希 → 重建受影响镜像层 → 记录版本快照；不做"每任务隐式检查更新"，也不容忍"从不更新"（可配 TTL 到期提示）。

**输出解析器**：每个工具配确定性解析器（regex/JSON，非 LLM），将原始输出转为统一 Signal 结构；原始输出全文落盘至 `evidence/`，上下文中只保留引用路径。

**可选扩展**：工具层封装为 MCP Server，使 Kimi Code 及任意 MCP 客户端可直接调用本工具集。

### 5.3 编排器（L3）

- **任务模型**：树/DAG 混合。阶段间串行（recon → 扫描 → 验证 → 报告），阶段内独立子任务（不同子域、不同端点、不同验证项）DAG 并行。
- **规划器**：LLM 基于当前结构化状态 + 命中 skill 的 SOP 生成下一步计划；规划输出为结构化 JSON（动作类型、工具、参数、预期产出），不直接生成 shell 命令——shell 命令由工具管理器按 manifest 模板拼装，便于审计和 scope 校验。
- **模型路由**：每次 LLM 调用声明任务类型，路由器按类型选模型（见 §5.6 路由表）。
- **预算控制**：每 engagement 设 token/金额/时长三帽；超额自动降级模型或挂起请示。
- **提前终止**：某假设验证置信度达标即停，不做无信息量的重复尝试。

> **M2b 落地注记**（2026-08-07）："按 manifest 模板拼装命令"的落地形态为代码级确定性命令构造器 `proofhound/tools/build.py`（按工具名分派、参数 Pydantic 强校验、产出 argv 列表），原因是 httpx 等工具需条件性注入参数（如 restricted 出口下的 `-proxy`），纯 YAML 模板表达条件逻辑代价过高；manifest 仍是工具身份/版本/安装配方的权威来源。任务状态机、失败预算、规则表式失败分类分别见 `core/tasks.py`、`core/failures.py`；规划器（含 schema + 语义双层校验）见 `core/planner.py`。模型路由/预算帽/上下文治理留 M2c。

**失败预算与阻塞升级**（防"验证码死循环"类问题）：

- **失败预算**：每个子任务设重试上限（同类失败默认 2 次）；编排器维护结构化失败计数，命中上限即停止重试并升级，从机制上消灭无限重试。
- **失败信号分类**：解析执行结果，区分凭证错误 / 验证码失败 / 限流 / 账号锁定 / 网络异常，不同类别走不同策略，禁止"一律重试"。
- **硬阻塞升级**：验证码、MFA、WAF 人机校验属人机区分机制，不作为自动攻克目标。命中后按自治模式处理——半自动：弹出人工接管请求（人工完成登录，系统注入会话 Cookie/Token 继续）；全自动：记录阻塞、跳过该路径、报告注明。
- **认证旁路优先**：auth skill 的 SOP 固定顺序——① scope 配置中的预置会话（Cookie/Token）→ ② API 直登获取 Token → ③ 协调目标方为测试环境关闭验证码或提供测试账号 → ④ 专用识别服务兜底（有限重试）。

### 5.4 验证层（L4）—— 本系统的核心差异化模块

#### 5.4.1 发现生命周期状态机

```
Signal ──(triage 通过)──> Hypothesis ──(PoC 复现)──> Reproduced ──(证明安全边界被突破)──> Confirmed
   │                          │                          │
   └──(triage 驳回)──> Rejected <──(验证失败)──────────────┘
```

铁律：**版本匹配型 CVE、纯状态码型发现，永远只能是 Signal**，必须经行为验证才能晋级。

> **M3a 落地注记**（2026-08-07）：状态机实现于 `proofhound/findings/finding.py`（`Finding.transition` + `_TRANSITIONS` 表；非法迁移抛 `InvalidTransitionError`，Confirmed/Rejected 为终态）。铁律**硬编码在状态机层**（非 prompt 层）：`vuln_type` 命中版本匹配型集合（`VERSION_MATCH_VULN_TYPES`，当前含 `version-cve`）、或证据种类标签（`evidence_kinds`）中没有任何非 `status-code` 的种类（空列表同拒，fail-closed）的 Finding 迁入 Confirmed 即抛 `IronRuleViolationError`；Confirmed 另须携带 `verification.evidence_refs`（证据完备率 100%）。每次迁移记审计 `finding_state{finding_id, from, to, actor, reason}`。triage 为确定性规则表（`Orchestrator.run_triage_phase()`，零 LLM 调用）：`web-probe` 且状态码 ∈ {2xx/301/302/307/308/401/403} → `web-exposure` 建/并 Finding 置 Hypothesis，不可映射保持 Signal；LLM triage（T1 档）与 Reproduced 之后的 verify-\* skill 接入留 M3 后续切片。
>
> **M3d 落地注记**（2026-08-08）：发现自动化切片——katana（projectdiscovery，v1.7.0 binary 配方：GitHub release zip + 强制 sha256，装 `tools.d/katana/`，默认 alpine:3.20 运行，https CA 实测正常）经新 skill `recon-crawl`（L1）接入 scan 阶段；`OrchestratorPhases.scan_skills`（web-scan + recon-crawl）逐 skill 过自主模式闸门（确认/审计粒度到 skill），旧式单 skill phases 经 `getattr(phases, "scan_skills", None)` 回退、零改动。katana 解析器（`tools/parsers/katana_jsonl.py`）对带查询串 GET 端点产 `kind="param-endpoint"` Signal；**分支 B**：katana 默认不自动填充表单（v1.7.0 实测 `-aff` 会真实提交含 logout/security 的 POST 表单，副作用不可控，不采用），GET 表单由解析器从 `response.body` 用 html.parser 确定性提取并合成查询 URL（零副作用，不提交任何表单；无 value 字段统一填占位 "1"——空值参数会让下游行为验证失去 baseline 可比，DVWA 实靶实测空 id 被 sqlmap 判 not injectable、填 1 即确认）。triage 重构为 `_triage_candidates`：web-probe 规则逐字段不变；param-endpoint 按 query 参数键精确匹配 `_SQLI_PARAM_HINTS`（约 20 个，小写比对）展开 sqli 候选（severity=medium、evidence_kind=`crawl-endpoint`、param=键），dedup_key 补 param 分量（同 URL 不同 param 不合并）；**防确认洪泛**：每 engagement 新建 sqli Hypothesis 上限 20 条（确定性顺序，超出记 `triage_capped`，被丢弃候选重跑时确定性重判再丢，建侧幂等）；**三层 scope 纵深**：`-fs rdn` 恒在（v1.7.0 实测对 IP 型种子不收敛、外域会混入输出，故后两层必不可少）+ triage 建/并前对 asset 过 check_scope（丢弃记 `triage_out_of_scope`）+ 沙箱逐命令强校验。katana 构造器恒在项：`-jsonl -silent -nc -fs rdn -cos "(?i)(logout|logoff|signout|signoff|phpids)"`（katana 会把状态变更类 GET 链接当普通链接抓取：logout 销毁服务端会话，DVWA `security.php?phpids=on` 为该会话开启 PHPIDS 致后续攻击载荷全被拦截——均为实靶实测，须排除；该旗标按逗号分片，值禁含逗号）——**永不产 `-o`**，输出只走 stdout 落盘；凭据只经 `with_session` 声明由构造器注入 `-H`（LLM 不碰原文）。本切片**只覆盖 GET 查询参数端点**：POST 表单、Submit 类按键不进（POST 表单 verify 切片与 verify-xss/lfi 同属后续里程碑）。`triage_completed` 审计新增 `created_by_type`/`merged_by_type` 分桶计数，`kept_signal` 语义为零产出信号数（旧值不变）。
>
> **M8a 落地注记**（2026-08-14）：POST 表单发现自动化（sqlmap `--forms` 模式，不引入浏览器）。① **解析器**（`tools/parsers/katana_jsonl.py`）：`_GetFormExtractor` 重构为全表单提取（method 原始三态/action/有 name 的 input|select|textarea 字段），GET 分支 B 合成语义逐字节不变；新增 `kind="form_page"` Signal——asset 为**页面 URL 本身**（不拼参数），字段名并集存 Signal 新字段 `form_fields`（纯增量，旧 signals.jsonl 回放无碍）。合格规则：A）method 显式 post（大小写不敏感）且 ≥1 个有 name 字段；B）method 缺省 + 非空 action + 有 name 的密码/文本字段（登录类表单常缺省 method）；**同源防线（fail-closed）**：action 解析后须与页面同 scheme/host/port（空 action=页面自身）——forms 模式 sqlmap 实际 POST 的目标是表单 action，跨域会脱离 `-u` 的 scope 校验覆盖面，故跨域一律不产候选（端口显式比对，宁漏勿放）。去重键从 asset 改为 `(kind, asset)`（同 URL 两 kind 共存）。② **triage**：form_page 按字段名小写精确匹配同一张 `_SQLI_PARAM_HINTS` 展开候选（每命中字段一条，param=字段名，evidence_kind 新常量 `crawl-form`），零命中回退页面路径提示 `_SQLI_PATH_HINTS`（sqli/sql/login/signin/search，path 段去扩展名精确匹配，param=None）；与 get_param 共享同一 20 上限、dedup param 分量与 check_scope 层；`triage_completed` 增 `created_by_source`/`merged_by_source`（web_probe/get_param/form_page 分桶）。③ **构造器**：`SqlmapParams.forms`（缺省 False）——forms 模式 argv 含 `--forms`、不产 `-p`、**永不产 `--data`**（表单由 sqlmap 自解析页面决定，不手拼请求体）；forms 与 param 互斥（model_validator fail-closed）。④ **verify**：`_verify_sqli` 按 `crawl-form ∈ evidence_kinds` 切 forms 模式（发现方式确定性决定验证方式，Finding schema 零改动），`verification.method` 仍 `sqlmap-confirmed`（证据门/Verifier/铁律全不变），复现步骤按模式渲染命令行。⑤ **实靶形态**：DVWA security=low 时 sqli 系页面是 GET 表单（M3d 已覆盖）；**medium 时渲染 `POST + select name="id"`**（从镜像源文件坐实），故 demo 翻转 security=medium cookie 验收。旧测试触碰 2 处（均为罐头数据对齐、断言零改动，完成报告逐条披露）：test_katana_parser.py 的 POST 表单罐头改为无 name 字段、首个合成罐头补显式 `method="get"`。

#### 5.4.2 证据门：各漏洞类型最低验收标准

| 漏洞类型 | Confirmed 最低标准（不达标即降级或驳回） |
|---|---|
| SQL 注入 | sqlmap 明确判定 vulnerable；或布尔/时间盲注的对照差异（真假响应内容差或稳定时延差） |
| XSS | headless 浏览器中实际触发弹窗/DOM 变化（dalfox 类确认） |
| LFI/文件读取 | 响应中出现目标文件特征内容（`root:x:0:0`、`[boot loader]`） |
| SSRF | 带外回调（interactsh 类）证明真实出网 |
| RCE | 无害命令（`id`/`whoami`）回显或带外回调 |
| 版本型 CVE | 非破坏性 payload 行为验证；无法安全验证的标"疑似未验证"进附录 |
| 越权/IDOR | 双角色对照：A 凭证访问 B 资源，响应对比证明越权 |
| 暴露面板/敏感路径 | baseline 对照后仍存在可归因内容差异 |

> **M3b 落地注记**（2026-08-07）：证据门实现于 `proofhound/verify/gate.py`——每 `vuln_type` 在 `GATE_MATRIX` 声明 `verification.method` 白名单与行为类 `evidence_kinds` 标签要求（当前仅落 sqli：method ∈ {sqlmap-confirmed, boolean-diff, time-blind-diff} 且含 `behavioral` 标签）；`check(finding) -> GateResult{passed, missing}` 产出缺项清单，未知 `vuln_type` fail-closed。编排层（`run_verify_phase`）在 `transition(CONFIRMED)` 前必过本门，与 M3a 状态机铁律构成**双层防守**；门不过记审计 `verify_gate_failed`，Finding 停于 Reproduced。XSS/LFI 等其余类型随对应 verify-* skill 扩展矩阵项。
>
> **M6b 落地注记**（2026-08-08，CVSS 评分真实化）：Confirmed 的严重级不再用 triage 种子值——改为 **CVSS v3.1 向量 + 代码确定性算分**。分工与理由：**LLM（T2 Verifier）只产向量字符串**（`cvss_vector` + 逐项理由 `cvss_rationale`），分数与严重级由 `proofhound/verify/cvss.py` 按 FIRST 官方公式（含官方 roundup）计算——分数必须确定性可复现、防 LLM 编数字、审计可按向量重算复核，故模型不接受 LLM 给的任何分数字段（verdict schema 无此键，多余键忽略）。契约 fail-closed：**confirm 缺失/非法向量 = 整个 verdict 非法**（走 M6a repair 一次后仍失败则 VerifierError，编排层停 Reproduced，无"无分数确认"降级路径）；reject 不得携带向量。向量解析严格（8 个 base 指标各恰好一次，缺/重/未知/temporal 指标、非法值、错版本一律拒绝；顺序宽容）。置态：编排层 confirm 分支在 `transition(CONFIRMED)` 前写入 `Finding.cvss_vector`/`cvss_score`（字段取代 §5.5 曾预留的 `cvss` 标量占位）并以算分严重级覆盖 triage 种子 severity——种子值仅为过渡态，历史 Finding 不回填（append-only 哲学）。对抗 SOP 增补 CVSS 指导：按证据定指标、不按漏洞类型套模板（如 sqlmap 仅布尔盲注确认未拖数据 → C 至多为 L；拖出库名/表名 → C 可为 H）。报告层（`report/data.py`）仅 Confirmed 桶透传 `cvss_vector`/`cvss_score`（非 Confirmed 不展示分数，旧数据容忍 None），默认模板详细发现章加条件渲染 CVSS 行。

#### 5.4.3 Baseline 对照

任何判定前先探测目标默认行为：请求随机不存在路径、发送无效参数值，建立 baseline 档案（通配路由、自定义 404、全 200 站点等）。payload 响应与 baseline 存在可归因差异才计为信号。

#### 5.4.4 Verifier Agent（对抗校验）

- 独立 Agent，唯一职责是**攻击结论**：证据是否支持？是否存在更平凡的解释？前置条件当前是否满足？
- 与发现端使用不同模型，避免同源偏见。
- 输出结构化裁定：`confirm / downgrade / reject + 理由`。

> **M3b 落地注记**（2026-08-07）：实现于 `proofhound/verify/verifier.py`，走 **T2 档**（红线 4：与发现端 T1 异模型，同模型启动警告沿用 M2c 机制）。输入严守红线 3：Finding 结构化摘要 + 证据包索引（文件名/sha256/行号锚点）+ baseline diff 摘要，**不喂原始输出**；prompt 超字符硬上限抛 `ContextOverflowError`。输出 Pydantic 强校验 `{"verdict": confirm|reject, "reason"}`（本刀不收 downgrade），任何非法输出抛 `VerifierError`——**非法 verdict 拒收**，编排层 fail-closed 停于 Reproduced 并记 `verify_blocked`。裁定落 `Finding.verifier`，记审计 `verifier_verdict{finding_id, model, verdict, reason}`。Confirmed 迁移条件 = 行为证据存在 ∧ 证据门通过 ∧ Verifier confirm，三者缺一不得确认；reject → `REJECTED(actor=verifier)`。

#### 5.4.5 去重与误报库

- 去重指纹 = sha256(资产 + 漏洞类型 + 参数/路径)；同指纹合并，证据归并到同一条 Finding。
- 人工标记的误报入误报库（模式 + 上下文特征），后续同类 Signal 自动降权或拦截；误报库随使用持续积累，是长期准确率壁垒。

### 5.5 Finding 数据模型

```json
{
  "id": "F-2026-0001",
  "state": "confirmed",
  "title": "登录接口 username 参数 SQL 注入",
  "vuln_type": "sqli",
  "severity": "high",
  "cvss": 8.6,
  "asset": {"host": "example.com", "url": "/api/login", "param": "username"},
  "preconditions": ["未认证"],
  "confidence": "confirmed",
  "verification": {
    "method": "sqlmap-confirmed",
    "verified_by": "verify-sqli@1.0.0",
    "verified_at": "2026-08-06T10:00:00Z",
    "evidence_refs": ["evidence/F-2026-0001/request.txt", "evidence/F-2026-0001/response.txt"],
    "baseline_diff": "真条件响应 1,203B / 假条件响应 217B，稳定可复现",
    "reproduction_steps": ["..."]
  },
  "verifier": {"model": "...", "verdict": "confirm", "reason": "..."},
  "dedup_key": "sha256:...",
  "rejection_reason": null,
  "narrative": "（报告阶段由 LLM 生成的叙述文字，仅存于此，不回写事实字段）"
}
```

存储：SQLite（单文件，便于归档与移交）；所有证据文件按 Finding ID 归档于 `evidence/`。

**出处可调出（溯源为一等公民）**：任何 Finding 可通过 CLI/API 一键调出完整证据包（请求/响应原文、baseline 对照、复现步骤、关联审计记录）；报告正文中每条 Finding 附证据包索引。（M3 实现）

> **M3a 落地注记**（2026-08-07）：字段已按本 Schema 落地（`proofhound/findings/finding.py`），两点偏差——① `asset` 暂为字符串（Signal 原样）+ 独立可选 `param` 字段，结构化 `asset{host,url,param}` 延后；② 存储暂为 `findings.jsonl`（append-only，全量快照追加 + 按 id 回放 last-wins），SQLite 延后；另新增 `source_signal_refs`、`created_at`/`updated_at` 字段。去重指纹实现于 `proofhound/findings/dedup.py`：规范化（资产小写去尾斜杠、漏洞类型小写、参数缺省与空串等价）后 NUL 连接取 sha256，同指纹合并记审计 `finding_deduplicated`。"出处可调出"已落地：证据包组装（`proofhound/findings/evidence.py`，`<evidence_dir>/findings/<finding_id>/`：证据原文整文件拷贝 + 含 sha256 的 `manifest.json` + `finding.json` 快照 + `reproduction_steps.md`）与 `python -m proofhound.findings show <id> --dir <evidence_dir>`（离线打印全字段 + 证据索引 + `#L` 行号锚点原文，纯文件查询，不碰网络/LLM）。

### 5.6 成本与性能工程

**模型路由表**：

| 档位 | 任务类型 | 建议模型 |
|---|---|---|
| T0 廉价/本地 | 输出解析兜底、分类、去重判定、报告润色 | DeepSeek / Kimi K2 级 API，或本地 Qwen（数据不出内网，合规友好） |
| T1 中档 | triage、摘要、假设生成 | 中档商用模型 |
| T2 前沿 | 漏洞推理、利用链规划、Verifier 终审 | 前沿推理模型（Verifier 与发现端必须用不同模型） |

**上下文治理**：
- 工具原始输出 100% 落盘，上下文只进结构化摘要 + 引用路径。
- 每阶段结束做滚动摘要，丢弃中间细节；skill 按需加载（渐进式披露）。
- 目标：任一时刻上下文体积有硬上限，杜绝"越跑越慢越贵"。

**并行与缓存**：
- 阶段内独立子任务 DAG 并行（不同资产/端点/验证项）。
- recon 结果与指纹按资产缓存，复测只跑增量（持续监测场景的数量级优化）。

**成本可观测**：每次 LLM 调用记录 tokens/费用/耗时，按 engagement 出成本仪表盘；超预算自动降级或挂起。

> **M2c 落地注记**（2026-08-07）：模型路由落地为 `proofhound/llm/router.py`——Tier 枚举 + TierConfig，三档独立环境变量 `PROOFHOUND_T0/T1/T2_{BASE_URL,API_KEY,MODEL[,TEMPERATURE,MAX_TOKENS]}`，HTTP 复用 `llm/client.py`，router 只做选路与计量；T1==T2 同模型启动即警告（红线 4）。用量计量与预算硬闸落地为 `proofhound/llm/usage.py`：每次调用记 tier/model/prompt_tokens/completion_tokens/耗时（响应无 usage 时按 4 字符≈1 token 估算并标 `estimated`），追加审计 `llm_call`；`PROOFHOUND_MAX_TOKENS_PER_RUN`（及可选分档 `..._T0/T1/T2`）为 Run 级硬闸，调用前检查，超限即停止规划循环、节点 blocked 并记 `llm_budget_exceeded`——与 scope 同级，任何自治模式不可绕过。上下文治理落地为 `proofhound/core/context.py`：Signal 摘要超 `PROOFHOUND_CONTEXT_MAX_SIGNALS`（默认 20）条按 kind 聚合、每类留最新 `PROOFHOUND_CONTEXT_KEEP_LATEST`（默认 5）条并保留 total_counts；prompt 字符硬上限 `PROOFHOUND_CONTEXT_MAX_CHARS`（默认 32000），超限先压缩、仍超则任务 failed 并记 `context_overflow`，禁止静默截断。未做：成本仪表盘（现仅有 `llm_call` 审计事件）、"超额自动降级模型或挂起请示"（当前策略为超限即 blocked 升级）。

### 5.7 报告引擎（L5）

- **数据与表现分离**：模板渲染只读 Finding 库的结构化字段；LLM 仅生成叙述性段落（概述、风险分析、修复建议），且每段必须关联 Finding ID，可回溯、可审计。
- **模板方案**：docx 用 docxtpl（Jinja2 语法，用户直接在其 Word 模板中写 `{{target}}`、`{% for f in confirmed_findings %}` 循环）；PDF 走 Jinja2 → HTML → Paged.js/weasyprint。
- **报告固定章节**：测试概述 → 授权范围 → 方法论 → 发现汇总表（按严重级）→ 详细发现（每条附证据与复现步骤）→ **已排除误报及原因附录**（提升报告可信度）→ 修复建议。
- 按条件分桶呈现："可直接利用" / "需特定条件（已注明）" / "疑似未验证（附录）"。

> **M4 落地注记**（2026-08-07）：报告引擎落地为 `proofhound/report/`——① `data.py`：findings.jsonl + 证据包 manifest → `ReportContext`（confirmed / conditional（Reproduced 未 Confirmed）/ hypothesis / rejected 四桶，桶内 severity→id 排序；每条携带结构化字段 + 证据包索引（pack_dir + 含 sha256 的 entries 清单）+ narrative 槽位；engagement 元信息走可选 `engagement.json`，缺字段派生——target 取资产最高频 host、时间窗取 audit.jsonl 首/末条 ts）；② `narrative.py`：T1 档叙述生成，输入仅结构化摘要（红线 3），输出 Pydantic 强校验 `{finding_id 或 overview/remediation: 段落}`——未知键（无锚文字）/坏 JSON/空段落全量拒收零落盘；finding 段落只写 `Finding.narrative`（不回写事实字段），固定章节段落写 `narrative_sections.json`，逐段记审计 `narrative_generated{finding_id|section, model, tokens}`，BudgetExceededError 上抛；③ `render.py`：docxtpl + Jinja2 StrictUndefined（变量未定义清晰报错）+ autoescape（替换值 XML 转义，防 `&` 伪实体被 docx recover 解析静默吞字）；④ CLI `python -m proofhound.report build --dir <evidence_dir> --out <docx> [--template] [--no-llm]`；⑤ `scripts/make_default_template.py` 生成 `templates/default_template.docx`（全标签参考模板，尾部附变量契约说明页；docxtpl 布局纪律：`{%tr %}/{%p %}` 标签须独占表格行/段落）。确定性：context 不含报告生成时刻 wall-clock，narrative 固定后同输入渲染出相同 `word/document.xml`（docx zip 字节级时间戳不保证）。偏差：PDF 管线未做（留后续）；Rejected 附录直接用结构化 rejection_reason 不经 LLM；证据包索引字段名用 `entries`（dict 的 `.items` 方法会遮蔽 Jinja 属性解析）。验收 `scripts/demo_report.py`：DVWA 产物（Confirmed sqli + Rejected version-cve + Hypothesis web-exposure）出真实报告，汇总分桶/证据索引 sha256/误报附录/叙述回溯/no-llm 对照逐项读回自检通过。
>
> **M4.5 落地注记**（2026-08-07，模板适配与叙述结构化，驱动自定义企业模板）：① engagement extras 透传——`EngagementMeta` 开 `extra="allow"`，engagement.json 任意额外键（company_name/system_name/report_date 等）原样透传进渲染上下文（只进模板、不进 prompt），已知字段校验不变，`_load_engagement` 改就地补派生以保 extras；② `FindingReport.severity_cn` 中文档位映射（critical→严重/high→高/medium→中/low→低/info→提示，未知原样）；③ 叙述结构化——finding 键段落升级为 `NarrativeParts` 三段对象（description/impact/remediation，`Finding.narrative_parts` 落盘，extra=forbid、字段空白拒收），单段 `narrative` 由三段确定性拼接派生（`\n` 连接，单一事实源；旧字符串段落格式仍兼容、章节键必须为字符串，锚定与全量拒收规则不变）；④ `FindingReport.repro_text` 编号拼接复现文本（`\n` 连接，无步骤为空串）；⑤ `cn_date` Jinja 过滤器注册进渲染环境（ISO → 「2026年8月7日」不补零，空值 → 空串，非 ISO 原样返回）；⑥ `ReportContext.evidence_index` 扁平证据索引（confirmed+conditional 全部条目，{finding_id, file, sha256, source_ref, line_anchor}，confirmed→conditional 桶序 + manifest 原序，稳定确定）。渲染层 `{{r }}` 适配：docxtpl 0.20.2 把 `{{r }}` 的值插到 run 之外，纯字符串会整个丢失（实测）——渲染前扫描模板 `{{r }}` 标签、把 context 对应键的字符串值自动包装成 `docxtpl.RichText`（自带 `__html__` 与内部转义，autoescape 下安全），数据层 context 保持纯 JSON。验收 `scripts/demo_report_enterprise.py`：DVWA 产物 + engagement.json 补 extras，自定义企业模板出真实报告，封面/时间/系统名、风险项 Heading 4 循环连续、附录 A == 证据包 manifest、附录 B 含 version-cve、1.4 流程章与源模板逐段一致、default_template 对照回归，逐项读回自检通过；M4 demo 全量回归通过。
>
> **M6c 落地注记**（2026-08-08，叙事事实守卫 + 误报中文归因）：① **叙事事实守卫** `proofhound/report/factguard.py`——纯确定性代码（正则/词表/计数比对，零 LLM 参与判断），语料 = overview/remediation 章节 + 各 finding 段落 + reasons_cn 归因，三道守卫任一违规即 NarrativeError（写明 F-ID/声称词/真实状态/计数明细，随 M6a 修复指令携带，守卫在 parse callable 内执行故修复重试一次自然生效，二次仍败零写入语义不变）：**F-ID 存在性**（`F-\d{4}-\d{4,}` 引用必须真实存在，幻觉防护）；**状态词共现**（每 F-ID 取所在句——句号/分号/换行切分：确认/证实/confirm 仅许 Confirmed、误报/排除/rejected 仅许 Rejected、假设/待验证/hypothesis 仅许 Signal/Hypothesis、有效验证/行为复现/reproduced 仅许 Reproduced，英文词大小写不敏感；无状态词的中性列举放行；**否定前缀豁免**——紧邻前缀为未/不/无/非/未能/无法/没有时该次出现不计入共现，"未确认注入"不是确认表述）；**计数断言**（共确认 N / 确认（了|的|（…））N 个条项 / N 个条项…被确认 的 N 须 == Confirmed 桶数，误报计数三形态同理对 Rejected 桶；N 支持阿拉伯数字与中文数字一~十，按 span 去重，否定豁免同适用）；② **附录 B 误报中文归因**：narrative 输出扩展可选顶层键 `reasons_cn`（缺失容忍——旧回复格式仍合法；键 ⊆ Rejected id 集合、多余键按无锚拒收、值非空白；归因文本同过事实守卫），落衍生文件 `rejected_reasons_cn.json`（恒写防陈旧），非空逐条记 `narrative_generated{finding_id, kind="reason_cn"}`；data.py `FindingReport.reason_cn` 仅 Rejected 桶透传（缺文件/坏 JSON 容忍 None，与 cvss 同款纪律）；默认模板附录 B 排除原因列改 `{{ f.reason_cn or f.rejection_reason or '—' }}`（None 回退原文，旧数据兼容），**自定义企业二进制模板本里程碑不碰**（附录 B reason_cn 列待建筑师另行同步）；③ **提示词加固**：SYSTEM_PROMPT 增措辞纪律（状态词按清单、计数与 stats 一致、一句一状态类别）+ 归因任务，payload 增 `state_roster`（全量 id→state）与 `rejected_reason_ids`；④ 唯一旧测试触碰：`tests/test_repair.py` 罐头 overview「共确认 1 个」与 fixture Confirmed=2 矛盾，按 M6b 先例改为「共确认 2 个」（断言零改动），其余旧罐头逐条核对自然过守卫。验收：新测试 `tests/test_factguard.py` 96 用例全绿 + 旧 501 全绿（共 597）；`scripts/demo_factguard.py` 对 eng-20260808T161941Z-ab7ca89a（M6c 背景案例）就地重建——初测综述 F-2026-0004/0005 改述"经行为复现归入条件性状态"、确认计数表述 == 1、附录 B 五条中文归因、factguard 离线复验零违规、仓库自定义企业模板 sha256 不变（验收用 python-docx 打临时副本模拟建筑师同步）。启发式边界：同句混排多状态类别会被拒（prompt 纪律 + 修复重试兜底）、计数冷门变体宁漏勿滥。

### 5.8 安全与合规（L0 横切）

| 机制 | 说明 |
|---|---|
| 授权门槛 | 启动必须加载 scope 文件（授权域名/IP/端口白名单）+ 用户显式确认 |
| Scope 强制 | 每条命令执行前提取目标比对 scope，越界拒绝 + 记日志 |
| 危险动作分级 | L0 被动 / L1 主动扫描 / L2 利用验证；各级自动或需确认的行为由自治模式决定（见 §5.9） |
| 审计日志 | append-only：每条命令、每段输出、每次 LLM 调用、每次状态迁移全部落盘，兼作报告证据链 |
| 数据边界 | 支持全本地模型模式，渗透数据不出内网 |

### 5.9 交付形态与人机交互

#### 5.9.1 交付形态：本地引擎 + 本机 Web 控制台

- **核心引擎 = 本地 CLI**：M1~M4 阶段的唯一交互方式，开发、调试、脚本化集成均走 CLI。
- **产品化 = 本机 Web 控制台**：FastAPI 监听 localhost，浏览器打开本地地址使用；**不是公网网站**，不对外暴露，不打包 exe。
- **不做 exe 的理由**：系统强依赖 Docker 沙箱、Kali 工具链与本地证据目录，exe 封装只带来打包与兼容性负担；交付形态为"一键启动脚本（启动引擎 + 自动打开浏览器）"，使用体验等同桌面软件。
- 与 PentAGI / Strix / HexStrike 同形态；渗透数据全程不出本机，配合本地模型可全离线运行。

#### 5.9.2 自治模式（Autonomy Mode，核心人机开关）

三档，按 engagement 设置，启动时选定、运行中可切换：

| 模式 | 行为 | 适用场景 |
|---|---|---|
| 监督 Supervised | L1/L2 动作逐条弹确认 | 学习磨合期、高敏感目标 |
| 半自动 Semi-auto（默认） | L0/L1 自动执行；L2 利用验证需人工确认；报告发布前人工终审 | 日常授权测试 |
| 全自动 Unattended | 全流程无打扰；**启动时一次性签署本次授权**（含 scope、L2 许可、预算帽）；完成后通知 | 夜间批量、持续监测 |

约束与规则：

- **任何模式不可绕过**：scope 强制校验、预算帽、append-only 审计日志。
- 切换规则：向更严格模式切换立即生效；向更宽松模式切换需当次显式确认。
- 双入口：Web 控制台提供模式切换按钮 + 确认队列界面；CLI 提供 `--autonomy supervised|semi|full` 启动参数。

> **M5a 落地注记**（2026-08-07，Web API 与自主模式闸门）：① 自主模式引擎 `proofhound/autonomy.py`（独立于 API，CLI 后续可复用）——`AutonomyMode` 三档（supervised/semi_auto 默认/unattended）+ `AutonomyGate`：动作风险等级（L0/L1/L2，与 skill manifest `risk_level` 同源；`RISK_ORDER` 定义于本模块，planner 层无此常量）→ 裁定 auto/confirm/forbidden，矩阵代码化（supervised：L0 auto、L1/L2 confirm；semi_auto：L0/L1 auto、L2 confirm；unattended：全 auto；未知等级一律 forbidden，fail-closed）；模式切换单向收紧自由、放宽须显式 `operator`，落审计 `autonomy_mode_changed{from,to,operator,note}`；模块 docstring 与测试双重声明**不可旁路**——任何模式下 scope 校验、token 预算硬闸、cookie 脱敏、审计追加永远生效，闸门只决定"是否停下来问人"；② 本机 Web API `proofhound/api/`（FastAPI，仅后端无前端，前端属 M5b）：`create_app(workspace_root)` 应用工厂 + `EngagementRunner` 后台执行器（一 engagement 一线程，状态机 created→scanning→triaging→verifying→confirming（可往返）→done/failed 全量写审计 `engagement_state`）——API 层只是编排器薄壳，不含命令构造/旁路逻辑，阶段复用 `run_scan_phase/run_triage_phase/run_verify_phase`；动作确认队列：内存态 + engagement 目录 `confirmations.jsonl` 追加持久化（重启可恢复，重跑复用既有批准记 `action_resumed`），confirm 裁定阻塞等待（超时可配，超时默认拒绝记 `action_rejected` operator=system），拒绝的 L2 verify 使对应 Hypothesis 终态 rejected（reason=operator_rejected，归报告 rejected 桶）；③ 端点清单：`POST/GET /api/engagements`（201 创建：target/scope_paths/cookie?/autonomy_mode?/budget?）、`GET /api/engagements/{id}`（状态+findings 统计+token 用量）、`POST .../run`（202 异步启动/推进）、`POST .../autonomy`（切换模式）、`GET .../findings`（含 rejected）、`GET .../findings/{fid}/evidence`（证据包内容+sha256，等价 findings show）、`POST/GET .../report`（构建：template?/narrative bool；下载 docx）、`GET .../audit?tail=N`、`GET .../confirmations` + `POST /api/confirmations/{cid}/approve|reject`（operator 必填，审计 action_approved/action_rejected）、`GET /api/health`；错误统一 403 scope_violation / 402 budget_exceeded / 409 invalid_state / 404 not_found（`{"detail":{"error","message"}}`），非法模式名 422；④ 安全纪律：创建时 scope 违规 403 且**零目录零审计**；run 前目标重新过 `check_scope`（创建后改 scope 文件是合法运维，记 `scope_recheck`）；cookie 只写 `session.json`（0600），任何响应体不回显（detail 只给 `with_session: true`）；模板路径限制在 workspace `templates/` 内（越界 403）；engagement 级 `budget` 直接构造 `TokenBudget`（0 = 拒绝一切 LLM 调用，run 直接 402，无人值守也不例外）；⑤ 偏差：engagement 落 `<workspace>/engagements/<id>/`（非 evidence/ 树，gitignore 已加）；API 沙箱网络沿用 demo 取向（host+open），restricted 出口硬化留后续；API 本身无认证（只绑 localhost/内网，§5.9.3 红线不变）；测试 328+37=365 全绿（`tests/test_autonomy.py` + `tests/test_api.py`，TestClient + fake 阶段执行器，不碰 Docker/真模型）；验收 `scripts/demo_api.py`（Part A：semi_auto 对 DVWA 全流程零确认自动出报告——本仓库工具执行强制 Docker 沙箱，故无"不经过 docker"形态，本步不需要的是 sqlmap 镜像与 T2 模型；Part B：L2 阻塞→API 批准→sqlmap→Verifier T2→Confirmed，`--skip-l2` 可单独跳过）。
>
> **M5b 落地注记**（2026-08-08，本地 Web 控制台）：① 纯静态零依赖前端 `proofhound/api/static/`（手写 index.html + app.css + api.js + app.js，原生 ES2020+/fetch/hash 路由，**无 npm 构建链、无 CDN/外部字体/外部框架**，完全离线可用——与证据链离线可调出同级纪律；测试代码化守卫：静态目录零 `http(s)://` 外链、JS 零 HTML 字符串拼接渲染）；FastAPI 挂载 `GET /`（FileResponse index.html）+ `/static/*`（StaticFiles，注册于全部 API 路由之后，未知路径仍 404 不被吞）；② 三视图单页应用：任务列表/创建（target、scope_paths 多行、cookie password 框、autonomy 三档各带中文说明默认 semi_auto、budget 可选、创建可立即启动）、任务详情（顶部状态条：阶段徽标 + tokens/预算 + 自治模式切换器——收紧直接切、放宽弹 operator 确认框并提示写审计；确认队列面板 pending 时置顶警示 + 超时倒计时（取 health 的 confirm_timeout）；Findings 看板全状态卡片含 rejected 灰显归因；证据包查看器——文件清单/sha256/全文行号渲染/锚点行高亮滚动，"出处可调出"的 Web 呈现；审计流 tail 轮询按事件类型着色，command_executed 显脱敏命令与 stdout sha256；报告区模板下拉 + narrative 开关 + 下载链接）、健康页（闸门矩阵 3×3 + 版本 + confirm_timeout）；数据全走轮询（2.5s，`document.hidden` 暂停），不上 WebSocket；③ 安全纪律：前端只是 API 消费者（零业务逻辑/零命令构造，风险等级/闸门矩阵/状态全来自后端响应）；一切动态文本经 textContent；cookie 只在创建提交时流向 `POST /api/engagements`，不缓存/不回显/不写 Web 存储、提交即清空输入框；`python -m proofhound.api` 绑非回环地址时 stderr 打印醒目警告（不阻断启动，§5.9.3 红线提示）；④ 后端附加式新增（旧契约零改动，366 旧测试全绿）：`GET /api/engagements/{eid}/findings/{fid}/evidence/{filename}` 证据文件全文（只读；manifest items 白名单精确匹配 + resolve 防穿越双保险；>2MiB 截断带 `X-ProofHound-Truncated` 头——证据查看器需全文，原 evidence 端点只回单行锚点文本；响应行尾归一化 `\r\n`/裸 `\r`→`\n`，与 anchor_line_text 的 read_text 行为同款，锚点严格对齐，证据完整性以 manifest sha256 对磁盘字节核验为准）、`GET /api/templates` 模板清单（报告区下拉数据源，写死两份会随模板增删失真）、`/api/health` 加 `version`/`confirm_timeout` 两键（健康页版本展示 + 确认倒计时需服务端真实超时值）；⑤ 验收 `scripts/demo_console.py`：真实 uvicorn 子进程（非 TestClient）+ DVWA——Step0 静态面 200、Step1 非回环告警（复用主服务端口使绑定失败即退，零真实局域网暴露）、Part A semi_auto 带 cookie 全流程零确认出报告、Part B L2 阻塞→批准→Confirmed→证据逐文件 sha256+锚点行核对、Step C 全程响应体（含 docx 字节）无 PHPSESSID 原值（脚本化等价 devtools 网络面板检查），`--serve` 保持服务供浏览器手动验收；新测试 `tests/test_console.py` 15 个，全量 381 绿。

>
> **M6a 落地注记**（2026-08-08，稳定性加固 + 控制台管理面）：① **LLM 结构化输出修复重试** `proofhound/llm/repair.py`——`complete_structured(router, tier, messages, parse, ...)` 统一助手接入 T1 规划（core/planner.py）/ T1 叙述（report/narrative.py）/ T2 Verifier（verify/verifier.py）三处结构化输出调用点：JSON 解析或校验失败时携带原始输出（assistant 轮次）+ 错误描述追问一次，要求仅输出修正后的 JSON；全程最多 1 次重试，重试仍走 router.complete（token 照常计量、Run 级预算硬闸覆盖重试、中途超限照旧 BudgetExceededError）；第二次仍失败抛第二次的异常（同类型），原失败语义逐字保留（plan_rejected / NarrativeError 零写入 / VerifierError fail-closed）；修复调用本身 LLMError 记 `llm_repair_attempt{result=error}` 并回退抛首次错误，其余异常静默回退（首次校验失败已是确定性结论）；修复消息超 max_chars 记 `skipped_overflow` 不发起重试；审计 `llm_repair_attempt{tier, caller, error_type, result}`；② **Skill 管理面**：`GET/POST /api/skills`、`GET/PUT/DELETE /api/skills/{name}`（proofhound/api/management.py + server.py 薄壳端点）——zip 上传 ≤1MiB、防路径穿越、单顶层目录、必含 SKILL.md、frontmatter schema 全量校验、`required_tools ⊆ 构造器注册表`（未知工具拒绝）、解压总量 ≤8MiB（防 zip 炸弹）、目录名须 == manifest name；编辑保存即校验；**全部校验 all-or-nothing，拒绝即零写入**（临时目录 + rename）；**内置判定 = skill 目录 resolve 后落在 workspace 之外**（演示 workspace 的 skills 是指向仓库的符号链接）：内置 skill 经 API 只读（DELETE 409），PUT 走 **copy-on-edit**——先把顶层符号链接本地化为真目录 + 逐 skill 符号链接，再复制实体副本进 workspace 应用修改，**绝不顺符号链接写仓库文件**（`--workspace .` 时 workspace 即仓库，无内外之分，skill 一律按用户 skill 处理；copy-on-edit 后副本转为 workspace 实体 builtin=false，可再编辑/删除，删除后仓库内置不再透出）；registry 热重载 = 管理面按请求新建 SkillRegistry 重新 discover（engagement 运行时 registry 本就逐 run 新建），新 skill 无需重启即可被创建任务使用；③ **Scope 文件管理面**：约定目录 `workspace/scopes/`（不存在则创建），`GET/POST /api/scopes`、`GET/PUT/DELETE /api/scopes/{name}` 只管理该目录内文件（文件名白名单 `^[A-Za-z0-9_.-]+\.ya?ml$` + resolve 后必须在目录内双保险，目录外 scope 一律 404/422）；校验：YAML 可解析 + 键集合 ⊆ {domains, networks, ports}（**session 键显式拒绝**——凭据只走创建任务 cookie 入口，防管理面落盘与 GET 全文回显泄漏；未知键拒绝）+ networks 逐条 ipaddress CIDR + ports 1-65535 整数 + Scope.model_validate 锁步；④ **管理审计通道**：`workspace/management.jsonl`（append-only，与 engagement 审计同级纪律）——`skill_imported/skill_updated（含新旧 sha256）/skill_deleted/scope_created/scope_updated（含新旧 sha256）/scope_deleted` 全进它；⑤ 控制台新增技能/授权两视图（纯 textarea 编辑纪律，零依赖不变；保存失败原样展示校验错误；删除带 name+sha256 确认框；缺工具/未知工具黄色标记），创建任务表单的 scope_paths 从手填路径改为下拉多选（数据源 GET /api/scopes，前端映射为 scopes/<name> 提交，API 契约不变）；⑥ `scripts/seed_finding.py` 退役标记（M3d 起发现已自动化，仅供旧演示复现 verify 路径，demo_verify_dvwa.py 仍依赖）。验收：新测试 55 个（test_repair.py 12 + test_skill_admin.py 19 + test_scope_admin.py 24，含参数化展开）+ 旧 402 全绿；`scripts/demo_management.py`（TestClient，无需 DVWA/Docker/LLM）全链路通过。

#### 5.9.3 服务器部署

架构全容器化，天然支持部署到自有服务器（推荐 Linux + Docker Compose）：

- **部署单元**：引擎容器 + 工具镜像（Kali 基础镜像预置 tools.d）+ SQLite/evidence 数据卷；引擎通过挂载 `/var/run/docker.sock` 以兄弟容器方式拉起沙箱（也可选 rootless Docker / 远程 Docker host）。
- **网络暴露红线**：控制台只绑定内网/VPN 地址；多人访问需反向代理（nginx + TLS）+ 登录认证；**严禁无认证直接暴露公网**——这相当于把攻击工具的遥控面板公开。
- **出网合规**：从服务器发起扫描前，确认服务器侧允许外发测试流量（部分云厂商默认禁止、会触发滥用投诉），且授权书覆盖该出口 IP；必要时走自有 IDC 或专线。
- **模型接入**：服务器需能访问所选模型 API；涉敏环境改用 GPU 服务器跑本地模型（Ollama），维持全离线。
- **多人使用**：按需增加用户体系与 engagement 隔离；数据量大时 SQLite 升 PostgreSQL（选型已预留）。

### 5.10 Engagement 基础设施：内置浏览器与流量代理

每个 engagement 启动一套共享基础设施：代理容器 + 浏览器容器；沙箱内全部 HTTP(S) 流量**强制**经代理出站。

**浏览器服务**（Playwright + Chromium，不自研浏览器）：

- **headless 模式**：Agent 驱动——导航、点击、填表、DOM 提取、截图、Cookie/会话导出。用于 SPA/JS 重站点爬取与表单发现、XSS 证据门验证（§5.4.2）、登录态获取、报告截图证据。
- **交互模式**：noVNC/CDP 投屏到 Web 控制台，供人工接管登录（对接 §5.3 硬阻塞升级），人工完成后系统导出会话继续。
- 浏览器流量同样强制走代理，人工操作产生的请求一并入库。

**流量代理**（mitmproxy 为核心；是 HTTP 拦截代理，非原始抓包）：

- 全部请求/响应结构化落库（HTTP 日志库），作为 Agent 观察面与证据链；Finding 的 evidence_refs 直接引用代理日志条目。
- 支持重放/改包（Repeater 式）：Agent 基于真实流量改参数重放，禁止凭空构造请求。
- CA 证书注入浏览器与工具容器；nuclei 等工具的代理参数在 Tool Manifest 中声明。
- 上下文治理不变：代理日志只建索引 + 查询 API，摘要进上下文，原始报文不进。
- 后期可叠加 OWASP ZAP 被动扫描作为信号增强。
- 原始抓包（tcpdump/tshark）仅作普通工具进 manifest，用于非 HTTP 协议、DNS 带外验证等场景，不进核心链路。

## 6. 技术选型

| 层 | 选型 | 理由 |
|---|---|---|
| 语言 | Python 3.12 | 安全工具生态最丰富，Kimi Code 生成质量高 |
| 数据校验 | Pydantic v2 | Finding/Signal/Manifest schema 强校验 |
| 存储 | SQLite（后期可升 PostgreSQL） | 单文件归档，零运维 |
| 沙箱 | Docker SDK for Python | 隔离、配额、只读挂载、网络策略 |
| 浏览器/代理 | Playwright（Chromium）+ mitmproxy | 不自研浏览器；流量即证据与观察面 |
| LLM 接入 | OpenAI 兼容协议统一封装（Kimi / DeepSeek / 本地 Ollama） | 模型路由只需切换 endpoint |
| 报告 | docxtpl + Jinja2 | 用户 Word 模板直接可用 |
| 接口 | FastAPI（本机 Web 控制台）+ MCP Server（可选） | 控制台只是本地引擎的壳；Kimi Code 可直调 |
| 测试 | pytest + 公开漏洞靶场（DVWA、Vulhub、XBEN） | 回归与指标测量 |

> M2c 注记（2026-08-07）："模型路由只需切换 endpoint" 已落地——三档 TierConfig 各自指向独立 base_url/api_key/model（`PROOFHOUND_T0/T1/T2_*`），路由层 `llm/router.py` 不绑定具体厂商，本地 Ollama 与商用 API 可混用。

## 7. 项目目录结构

```
proofhound/
├── proofhound/
│   ├── core/          # 编排器、状态机、DAG 调度
│   ├── skills/        # Skill registry、loader、导入安全闸
│   ├── tools/         # Tool manifest、安装器、沙箱、解析器
│   ├── infra/         # engagement 基础设施：浏览器容器、代理容器、HTTP 日志库
│   ├── verify/        # 证据门、baseline、Verifier Agent、去重、误报库
│   ├── findings/      # 数据模型、存储
│   ├── report/        # 模板渲染管线
│   ├── llm/           # 模型路由、预算、上下文治理
│   ├── compliance/    # 授权、scope 校验、审计日志
│   └── api/           # 本机 Web API（M5a：FastAPI 应用工厂、后台执行器、确认队列）
├── skills/            # 内置 skill 库（§5.1 清单）
├── tools.d/           # 用户预置工具（离线）
├── templates/         # 报告模板
├── evidence/          # 运行时证据归档
├── tests/
└── docs/
```

## 8. 开发路线图

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| M0 流程验证（1~2 周） | 不写平台代码：把 recon/scan/verify/report 5 个 skill 装进 Kimi Code，手工编排跑通一个靶场 | 全流程 SOP 跑通，skill 划分定型 |
| M1 工具底座（2 周）——已完成（2026-08-06） | L0 + L1：manifest、安装器、Docker 沙箱、scope 校验、审计日志；打通 httpx 一条工具链（nuclei 链并入 M2 一并验收） | 离线镜像可用；越界命令被拒且有日志 |
| M2 编排器（2~3 周） | skill registry、任务 DAG、模型路由、预算帽、上下文治理；补齐 M1 遗留：① 从文件读取目标（如 `httpx -l targets.txt`）的 scope 解析与校验，消除 no_targets 放行口子；② 沙箱网络出口白名单 | 单目标 recon+扫描全自动；上下文体积有上限；成本仪表盘可见 |
| M3 验证层（3 周） | 状态机、baseline 对照、3 个 verify skill（sqli/xss/lfi）、Verifier Agent、去重、误报库——**M3a 已完成（2026-08-07）**：状态机（铁律硬编码）+ 证据包/离线 show + 去重 + 确定性 triage；**M3b 已完成（2026-08-07）**：证据门 + 预置会话（凭据脱敏）+ sqlmap 接入 + Verifier（T2）+ verify-sqli 垂直切片，DVWA 实靶 Confirmed | XBEN/DVWA 上 Confirmed 发现 100% 带证据；误报率达标 |
| M4 报告引擎（1~2 周） | docxtpl 管线、叙述润色、误报附录 | 给定模板一键出报告，事实字段零手写 |
| M5 产品化（按需）——M5a 已完成（2026-08-07） | **M5a ✅**：本机 Web API（FastAPI 后端，无前端）+ 自主模式三档闸门（矩阵代码化）+ 动作确认队列（持久化 + operator 审计）；待做：M5b 前端控制台（自治模式切换、确认队列、证据浏览）、MCP 暴露、持续监测、增量复测 | — |

## 9. 风险与开放问题

1. **解析器维护成本**：工具输出格式随版本漂移 → 解析器集中在 `tools/parsers/`，配版本快照与回归测试。
2. **复杂业务逻辑漏洞**仍是 LLM 短板 → 第一版以 Signal 形式交人工，不硬做。
3. **供应链安全**：工具下载源被投毒 → 白名单 + 强制哈希校验 + 优先离线镜像。
4. **法律责任**：工具仅限授权测试，scope 机制是产品级红线，不是可选项。
5. **开放问题**：Verifier 与发现端的模型组合如何选型以最大化对抗效果；误报库的模式泛化粒度——均在 M3 以实验定案。

## 10. 参考项目（借鉴，不重复造）

| 项目 | 借鉴点 |
|---|---|
| PentAGI (github.com/vxcontrol/pentagi) | 多 Agent 分工、Docker 沙箱；同时作为慢/贵/误报的反面基线 |
| Strix (github.com/usestrix/strix) | PoC 验证驱动、误报学习机制 |
| PentestGPT (github.com/GreyDGL/PentestGPT) | 推理/生成/解析三模块分工 |
| HexStrike AI | 工具 MCP 化封装 |
| CAI (github.com/aliasrobotics/cai) | 廉价模型 + 高密度工具调用的成本路线 |
| Agent Skills 规范（agentskills.io） | SKILL.md 格式与渐进式披露 |

## 11. 命名与开源策略

### 11.1 命名

- 定名 **ProofHound**（暂定）：契合"证据为王、验证驱动"的设计哲学；原占位名 PentAgent 与已有开源项目 PentestAgent 过于接近，弃用。
- 备选：Probatio / Evidentia。
- 发布前复查四件套：GitHub 仓库名、PyPI 包名、Docker Hub 镜像名、域名（如 proofhound.dev）。

### 11.2 开源可行性

GitHub 对双用途安全工具有成熟生态（Metasploit、sqlmap、nuclei、PentAGI 均在此列）。本项目的设计红线（授权前置、scope 强制、无害 PoC、审计日志）恰好符合平台对善意安全工具的要求。两条纪律：**不附带武器化 exploit 模块；不附带任何真实目标数据**。

### 11.3 发布清单（M3 完成后执行）

- **协议**：Apache-2.0（含专利授权条款，企业采用友好）。
- **仓库卫生**：README（用途定位 + 授权测试法律声明 + 靶场演示 GIF）、LICENSE、SECURITY.md（漏洞上报渠道）、CONTRIBUTING；gitleaks 全量扫密钥；清理内部 skill、客户报告模板、误报库真实数据。
- **API 安全**（M5a）：确认队列持久化（confirmations.jsonl 追加、重启可恢复）+ operator 审计（action_approved/action_rejected/autonomy_mode_changed）已落地；API 默认只绑 localhost，发布前复查暴露面与认证缺口。
- **社区飞轮**：引擎与 skill 库分仓（`proofhound` + `proofhound-skills`），参照 nuclei-templates 模式接受社区贡献 verify skill——skill 生态是项目的长期护城河。
- **发布节奏**：M3 验证层跑通 + DVWA/XBEN 靶场 demo 后再公开发布；渠道 GitHub + 安全社区。

> **M7 落地注记**（2026-08-09，开源准备）：① 协议定 Apache-2.0（LICENSE 全文入库，pyproject `license = "Apache-2.0"` SPDX 对齐）；② 仓库卫生——README（定位 + 法律免责声明前置 + 十分钟复现 + 工具/skill/模板/安全模型指南）、SECURITY.md（GitHub Security Advisories 渠道 + 信任模型 + 无认证部署警告）、CONTRIBUTING.md 简版、.env.example；③ 客户报告模板清除——git filter-repo 将模板二进制从全部历史抹除、全历史文本引用改写为中性表述（"自定义企业模板"），提交信息同步清洗，模板本机保留于 `templates/custom_enterprise_template.docx`（.gitignore 排除，相关测试/演示缺失自动 skip，公开/本机两态各自全绿）；④ gitleaks 全历史扫描 + 人工密钥复核（结论：零泄漏，.env/evidence/engagements 从未入库）；⑤ 演示 GIF（docs/demo.gif）嵌入 README；⑥ **分仓决策：proofhound-skills 本里程碑不拆**——skill 随主仓库发布，社区成形后再行拆分（§11.3 社区飞轮条目目标不变，仅节奏后移）；⑦ 打 v0.1.0 标签后公开。
