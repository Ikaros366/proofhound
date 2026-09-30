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

- ~~**F1 可导入 Skill**：采用 Agent Skills 开放规范（SKILL.md），支持从本地目录、Git 仓库、内部 registry 导入第三方 skill，与 Kimi Code / Claude Code 生态兼容。~~ **已于 M9d 撤回**（维护者裁定不开放用户自写 skill）：skill 库全部内置、随仓库交付，仍用 SKILL.md 作为组织格式与人类可读文档，但不再是外部扩展面；导入安全闸与上传端点一并移除。详见 §7.6.4。
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
4. **模型按任务分级 + 校验独立性**：解析/分类/去重/润色用廉价模型，仅漏洞假设与利用链规划使用前沿模型；**校验独立性**（M9b 重定义）——Verifier 必须在独立 agent、独立上下文中运行，输入仅限结构化摘要与证据索引（看不到发现端的推理链），**模型身份不作约束**，T1 与 T2 允许配置同一模型。独立性由 agent 隔离与输入边界保证，而非模型差异——"不同模型"并不等于"不同盲点"（同家族不同尺寸的模型盲点高度相关）。
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
3. 沙箱执行：每个测试任务（engagement）独立容器；工具目录只读挂载；网络出口限速+白名单；CPU/内存配额。**隔离硬化档**（M12，缺省严格）：容器内非 root（`nobody`）+ rootfs 只读（仅 `/tmp` 为 tmpfs 可写）+ `cap_drop=ALL` + `no-new-privileges` + `pids_limit` + `RLIMIT_NOFILE`；隔离档逐项写入 `command_executed` 审计，逃生阀 `PROOFHOUND_SANDBOX_HARDENING=relaxed`。
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
>
> **M8b 落地注记**（2026-08-14，verify-xss 无头浏览器行为确认）：上表 XSS 行从"dalfox 类确认"落地为 first-party 浏览器验证器 `proofhound/verify/browser.py`（定位同 `verify/cvss.py`，**不走** tools/manifests 外部二进制注册体系；playwright 锁版本 `1.62.0`，Chromium 二进制经 `playwright install chromium` 安装，懒导入——无浏览器环境其余链路不受影响）。① **canary 探针机制**：每次 probe 生成唯一 token（`phxss_<12hex>`），`add_init_script` 先于页面脚本 hook alert/confirm/prompt 双信道（对话框钩子 + `window[token]` 标记位）捕获执行事件；payload 集为代码常量 ≤6 条（script 标签 / img onerror / svg onload 三类载体 × 两信道），URL 由 `payload_url()` 确定性构造（query 键替换 + urlencode，缺参 ValueError）——LLM 零介入（红线 1）。**确认铁律：仅 canary 执行事件可确认，"响应反射输入"永远不是证据**。② **scope 防线（红线 5，双层）**：加载任何 URL 前编排层 `check_scope`；页面加载后 `page.route` 拦截全部子请求，`allow_request()` 双重判定（同源归一化 ∧ `Scope.check_target`），跨 origin/越 scope 一律 abort 并记入请求链。③ **证据 100% 落盘（红线 3）**：每次尝试落 canary 事件 JSON + 执行后 DOM 快照 + console 记录 + 请求/响应链（含状态码，**不记请求头**——从源头杜绝 Cookie 落证据），全部经 `redact_bytes` 字节级脱敏。④ **编排**（`Orchestrator._verify_xss`）：带会话 baseline（复用 httpx 可达性对照）→ 逐 payload probe（按次记 `xss_probe_attempt` 审计，上限 = 模板条数，任一 canary 即停）→ 命中则 method=`browser-confirmed` + behavioral 标签 + **四段式证据结构**（`Verification` 增 `claim`/`expected`/`actual` 可选字段，`method` 复用现有字段；旧数据 null，报告层 `is not none` 判空跳过）→ REPRODUCED → 证据门（`GATE_MATRIX` 增 xss 项：method ∈ {browser-confirmed}）→ Verifier 终审 + CVSS 代码算分（M6b 机制不变）；全部 payload 干净完成无 canary → REJECTED，任一次尝试出错且未命中 → blocked（覆盖不全不驳回，fail-closed）；REPRODUCED 后的"证据门→Verifier→终态"收尾抽为 `_gate_and_review()` 两 handler 共用（sqli 链路行为不变）。⑤ **triage**：param-endpoint 另按 `_XSS_PARAM_HINTS`（name/q/search/query/keyword/comment/msg/message/text/redirect/url，保守小表）展开 xss 候选，独立上限 `_TRIAGE_XSS_CAP=10` 与独立 `triage_capped{vuln_type:"xss"}` 事件；两表交集参数同产 sqli+xss 两类候选（dedup 按 vuln_type 分量区分）。⑥ **API 接线**：`OrchestratorPhases.verify_skills` 多 verify skill 清单 + `EngagementRunner._verify` 逐 skill 过闸（沿用 M3d scan_skills 的 getattr 回退先例，旧 FakePhases 零改动）；verify-xss 未注册/未启用记 `verify_skill_skipped` 跳过（增强项不阻塞主链路）。⑦ **边界**：仅覆盖 reflected/GET 查询参数场景；stored/DOM 型与 POST 表单 XSS、JS 驱动交互属后续里程碑；浏览器是验证器不是爬虫（发现侧仍靠 katana）。旧测试**零改动**（新增 27 个测试：browser.py 纯函数/FakePage 单测 + browser marker 真实 Chromium e2e 自动 skip 先例 + triage/门/全链/多 skill 接线/四段式报告）。DVWA security=low xss_r 页实靶验收通过（`scripts/demo_xss_dvwa.py`：零种子 → canary marker 命中 → kimi-k3 confirm → Confirmed 5.4，凭据脱敏自检通过）。
>
> **M8c 落地注记**（2026-08-15，verify-idor 双会话属性验证）：上表"越权/IDOR"行落地——**Security Property 验证第一刀**（§9.1 北极星呼应）：属性 ="身份 A 不可访问身份 B 的私有对象"，验证 = 双会话对比。① **会话模型**：`SessionConfig` 自嵌套可选 `reference`（reference/victim 第二身份，字段与主会话同构），`secret_values()` 递归并入两会话全部秘密值——沙箱/浏览器/编排三处脱敏口子零改动自动覆盖（红线 5：脱敏是两个会话都要）；缺省 None 与单会话模型逐字节等价。② **判定器** `proofhound/verify/idor.py`（first-party 纯 stdlib，定位同 cvss.py/browser.py，零新依赖）：stdlib fetch（GET、不跟随重定向——3xx 以状态码暴露，"重定向登录页"是判定不成立的关键形态；异常只置 error 字段不抛出）+ 纯函数判定（红线 1：状态码分类、difflib 正文相似度、JSON 键集合 Jaccard 重叠、实质数据判定全部确定性可单测）；阈值写死——B 基准 = 2xx 且含实质数据（≥32 字节非空 JSON），A 同 URL 2xx 且（相似度 ≥ 0.9 或键重叠 ≥ 0.8）→ 属性违反成立；判定依据（双状态码/相似度数值/键重叠/阈值快照/reasons）全量结构化落判定 JSON。③ **编排** `_verify_idor`（对齐 `_verify_xss` 结构）：缺主会话/缺 reference/runner 无 scope → `verify_blocked`（reason 明写"需要配置第二身份会话"）；check_scope → B 基准请求 → A 对比请求（按次记 `idor_probe_attempt{role,status,error}`，响应体脱敏落盘）→ judge：**语义分界——A 侧真阴性（403/404/重定向/数据不相似）才 REJECTED(actor=verify-idor)；B 基准不成立与网络错误属覆盖不全 → blocked 不驳回**；违反成立 → Verification(method=`dual-session-confirmed` + behavioral + 四段式 claim/expected/actual，复现步骤两身份 Cookie 各写 sha256 marker)→ REPRODUCED → `_gate_and_review` 原样复用（证据门 `GATE_MATRIX` 增 idor 项 method ∈ {dual-session-confirmed} + Verifier T2 + CVSS 代码算分，prompt 确认手段段同步）。④ **triage**：param-endpoint 另按 `_IDOR_PARAM_HINTS`（id/uid/user/userid/user_id/account/order/invoice/doc/document/record/file，12 键保守表——刻意不收 name 等泛化键收窄爆炸半径）展开 idor 候选，独立上限 `_TRIAGE_IDOR_CAP=10` 与独立 `triage_capped{vuln_type:"idor"}`；与 sqli 表交集参数（id 等）同产两类候选是**设计行为**（既可能注入也可能越权，各自经独立 verify skill 行为验证）。⑤ **API/控制台**：`CreateEngagementRequest.reference_cookie`（同 parse_cookie 校验、422 纪律），session.json 增 `reference` 嵌套结构（0600、旧格式回放兼容），响应回显 `with_reference_session`（值永不进响应体）；`OrchestratorPhases.verify_skills` 增第三槽位（未注册/未启用记 `verify_skill_skipped`）；控制台创建表单加第二组可选 password 字段（提交即清零存储）。⑥ **实弹形态**：不用 DVWA（无 IDOR 页面）——`scripts/demo_idor_fixture.py` 以 stdlib http.server 起双身份发票 fixture（1001 无授权判断=漏洞、1002 有授权判断=对照组、首页列链接供 katana 带 A 会话发现、无 cookie 302 登录页；发票页回显会话 token 演练脱敏路径）。⑦ **边界**：仅水平越权 GET 对象场景（同 URL 换身份重放）；垂直越权/多步业务流/写操作越权属后续；需操作员提供双身份会话。旧测试触碰 5 处（test_triage_param.py 4 个 + test_forms_mode.py 1 个，均为罐头 `id` 同产 idor 候选所致——断言原意图保留、补 idor 维度，完成报告逐条披露）。fixture 实弹验收通过（1001 Confirmed 判定 JSON 含相似度数值、1002 对照 REJECTED、双会话脱敏自检通过）。

>
> **M8d 落地注记**（2026-08-15）：Killer Demo 一键三漏洞全证据链演示入口 `scripts/demo_killer.py`——单 engagement 覆盖 DVWA（sqli + xss_r）与 IDOR fixture（1001 漏洞 / 1002 对照）双目标（fixture 门户页追加 DVWA 深链供 katana 单种子跨端口爬行、合并 Cookie 头承载双站会话，均为 demo 层对既有机制的复用）；配套增量：`_verify_sqli` 的 `Verification` 补 `claim`/`expected`/`actual` 四段式字段（纯增量可选字段，证据门/Verifier/判定语义零改动，三条链路四段式自此齐整，旧数据 null 容忍），其余编排/证据门/构造器零改动。

> **M11a IDOR 判据裁决规格（2026-09-23 裁决；**M11b 已实现**，落地注记见 §7.9）**：M10a 实测同一真
> IDOR 在 4 臂出现 4 种结果（已知限制 35），当时归因为「Verifier 判定随机」。M11a 逐条复核
> 4 臂全部 11 条 IDOR 终审原文后**修正该归因**：11 条里 7 条 reject 有 **6 条判得正确**
> （它们是对 `/a/sqli`、`/b/sqli2`、`/d/safe` 之类**非 IDOR 端点**的类型误报，见限制 37），
> 真 IDOR 的驳回理由则**逐字同构**——① 无对象归属证据；② A/B 响应 sha256 完全相同，更平凡的
> 解释是"公开内容"；③ 缺一个能**排除公开端点**的对照。**分歧点因此是单一且明确的**：Verifier
> 是否把"B 是 reference/victim ⇒ 对象属 B"当作**方法论已定义的前提**接受。决定性证据：同一
> `/b/idor2` 在同一次运行的 `rules+model` 臂被 reject（"无证据建立属主关系"）、在
> `rules+model+prefilter` 臂被 confirm（"属主由方法论定义"）——**同一模型、同一数据、两种标准**。
>
> 维护者裁决三条（**本里程碑只落规格，不实现**）：
>
> 1. **增加「未认证 / 第三身份」对照探测**：对同 URL 追加一次无凭据（或第三身份）请求，若其
>    响应与 B 基准等价，则判定为**公开资源**并驳回。这是**纯确定性代码判定**（不新增 LLM
>    调用、零额外 token），直接消掉 Verifier 反复索要的那个对照（其原话：
>    "缺少第三对照（未认证请求、A 请求自有对象、或响应中含可归属 B 的私有字段的证据）
>    来排除此解释"）。
> 2. **要求归属证据**：「reference 可访问 + 攻击者拿到等价响应」**不足以**构成属性违反，
>    必须有对象归属证据。
> 3. **归属由确定性代码提取，Verifier 只收结论 + 行号锚点**：归属事实（如响应中的
>    「所有者/owner/uid」类字段及归属判定）由**纯函数**从响应中提取并归一化，写入送审摘要的
>    **结论 + 证据文件#行号锚点**；**响应体原文一行不进 prompt**——红线 3 的输入边界**零放松**
>    （这是"要求归属证据"与"红线 3 不喂原始输出"之间唯一自洽的落法：红线 3 管的是**LLM 上下文**
>    不得含原始输出，不是禁止代码读取磁盘上的证据文件）。
>
> **落地形态（M11b 已实现）**：判据落在**新模块** `proofhound/verify/idor_control.py`
> （`judge_control` 三态 + `judge_ownership` 三态，纯函数），`_verify_idor` 据此在**编排层**
> 直接定终态（public → REJECTED、blocked → blocked、归属非 matched → REJECTED、protected +
> matched → 进 Verifier），零额外 LLM 成本；`Scope.session_third` 为**可选**第三身份，未配时
> 对照用完全不带凭据的匿名请求；`Verifier.review` 增**可选** `extra_summary`（仅 verify-idor
> 传，sqli/xss 载荷逐字节不变），SOP 写入三条硬性复核要点。详见 §7.9。
> **基准 fixture 的既有弱点（限制 36）在方案 2 下会显性化**：`_object_page` 正文含
> 「所有者 owner」，故归属证据可被提取 → 当前 fixture 在收紧后仍能 Confirmed；但真靶场若不
> 自报归属，则按此规格会被驳回（宁漏勿滥），该取舍已由维护者确认保留。

#### 5.4.3 Baseline 对照

任何判定前先探测目标默认行为：请求随机不存在路径、发送无效参数值，建立 baseline 档案（通配路由、自定义 404、全 200 站点等）。payload 响应与 baseline 存在可归因差异才计为信号。

#### 5.4.4 Verifier Agent（对抗校验）

- 独立 Agent，唯一职责是**攻击结论**：证据是否支持？是否存在更平凡的解释？前置条件当前是否满足？
- 在独立 agent、独立上下文中运行（M9b：不约束模型身份，改由 agent 隔离 + 输入边界避免同源偏见）。
- 输出结构化裁定：`confirm / downgrade / reject + 理由`。

> **M3b 落地注记**（2026-08-07）：实现于 `proofhound/verify/verifier.py`，走 **T2 档**（红线 4 于 M9b 重定义为 **校验独立性**：独立 agent + 输入边界，**不约束模型身份**，T1/T2 允许同模型）。输入严守红线 3：Finding 结构化摘要 + 证据包索引（文件名/sha256/行号锚点）+ baseline diff 摘要，**不喂原始输出**；prompt 超字符硬上限抛 `ContextOverflowError`。输出 Pydantic 强校验 `{"verdict": confirm|reject, "reason"}`（本刀不收 downgrade），任何非法输出抛 `VerifierError`——**非法 verdict 拒收**，编排层 fail-closed 停于 Reproduced 并记 `verify_blocked`。裁定落 `Finding.verifier`，记审计 `verifier_verdict{finding_id, model, verdict, reason}`。Confirmed 迁移条件 = 行为证据存在 ∧ 证据门通过 ∧ Verifier confirm，三者缺一不得确认；reject → `REJECTED(actor=verifier)`。

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
| T2 前沿 | 漏洞推理、利用链规划、Verifier 终审 | 前沿推理模型；Verifier 与发现端**须为独立 agent、独立上下文**（M9b：模型身份不作约束，可与 T1 同模型） |

**上下文治理**：
- 工具原始输出 100% 落盘，上下文只进结构化摘要 + 引用路径。
- 每阶段结束做滚动摘要，丢弃中间细节；skill 按需加载（渐进式披露）。
- 目标：任一时刻上下文体积有硬上限，杜绝"越跑越慢越贵"。

**并行与缓存**：
- 阶段内独立子任务 DAG 并行（不同资产/端点/验证项）。
- recon 结果与指纹按资产缓存，复测只跑增量（持续监测场景的数量级优化）。

**成本可观测**：每次 LLM 调用记录 tokens/费用/耗时，按 engagement 出成本仪表盘；超预算自动降级或挂起。

> **M2c 落地注记**（2026-08-07）：模型路由落地为 `proofhound/llm/router.py`——Tier 枚举 + TierConfig，三档独立环境变量 `PROOFHOUND_T0/T1/T2_{BASE_URL,API_KEY,MODEL[,TEMPERATURE,MAX_TOKENS]}`，HTTP 复用 `llm/client.py`，router 只做选路与计量；T1==T2 同模型记 `llm_tiers_share_model` 审计（M9b：红线 4 已重定义为 agent 独立性，不再是启动警告）。用量计量与预算硬闸落地为 `proofhound/llm/usage.py`：每次调用记 tier/model/prompt_tokens/completion_tokens/耗时（响应无 usage 时按 4 字符≈1 token 估算并标 `estimated`），追加审计 `llm_call`；`PROOFHOUND_MAX_TOKENS_PER_RUN`（及可选分档 `..._T0/T1/T2`）为 Run 级硬闸，调用前检查，超限即停止规划循环、节点 blocked 并记 `llm_budget_exceeded`——与 scope 同级，任何自治模式不可绕过。上下文治理落地为 `proofhound/core/context.py`：Signal 摘要超 `PROOFHOUND_CONTEXT_MAX_SIGNALS`（默认 20）条按 kind 聚合、每类留最新 `PROOFHOUND_CONTEXT_KEEP_LATEST`（默认 5）条并保留 total_counts；prompt 字符硬上限 `PROOFHOUND_CONTEXT_MAX_CHARS`（默认 32000），超限先压缩、仍超则任务 failed 并记 `context_overflow`，禁止静默截断。未做：成本仪表盘（现仅有 `llm_call` 审计事件）、"超额自动降级模型或挂起请示"（当前策略为超限即 blocked 升级）。

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
- **网络暴露红线**：控制台只绑定内网/VPN 地址；多人访问需反向代理（nginx + TLS）+ 登录认证；**严禁无认证直接暴露公网**——这相当于把攻击工具的遥控面板公开。**M14 注记**（2026-09-29）：控制台已加 HTTP Basic 单账户认证（deny-by-default，覆盖静态资源；默认口令 + 非回环绑定**拒绝启动**），但 Basic 不经 TLS 加密、且无多用户/RBAC/失败锁定——**本红线不因此放宽**。
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

## 7.5 M9 落地注记（2026-09-22：scope 零摩擦化 + 校验独立性重定义）

**M9a 从种子目标派生 scope**（`proofhound/compliance/derive.py`）。动机：M9a 之前创建
engagement 必须手写 scope YAML，摩擦高到促使操作员想直接删掉 scope 校验——而 scope 不只是
授权声明，它同时是**出口白名单的数据源**（`tools/egress.py`：白名单 = scope + 安装源），
删掉等于要么全阻要么开全放。故 M9a 采取"降摩擦但不放宽"：

1. **派生是纯确定性动作**（零 LLM 零网络）：从种子 host 产 `domains` / 单主机 `networks`
   （IP 恒 `/32`、`/128`）+ 显式非默认端口。**只从种子 host 派生，不跟随重定向、不解析页面
   链接、不并入爬到的域名**——扩张授权范围是安全事故，不是便利。
2. **授权是人的确认**：两者此前混在一起，M9a 拆开——无 scope 文件时由目标派生，此时必须显式
   `acknowledge_authorization=true`，否则 403 且零副作用；确认落审计 `authorization_acknowledged`，
   派生落 `scope_derived`，两条并行留痕便于事后归因。
3. **fail-closed 纪律**：通配符、裸 TLD、`0.0.0.0/0`、单标签主机（localhost 除外）、不可解析
   形态一律 `ScopeDerivationError`。宁可让操作员手写 scope，也不产出一个过宽的授权。
4. **`ports` 语义沿用既有约定**（空 = 不限端口）。显式默认端口（http→80 / https→443）**不写入**
   `ports`——刻意不从 scheme 推 `ports: [443]`，那会把操作员已授权的同一主机挡在 8080 之外，
   属"派生反而更严"的意外，与降摩擦意图相反。
5. **派生结果持久化**为实际生效的那一份（`api.json` 的 `derived_scope`），而非每次扫描现算——
   否则"操作员看到的"与"实际生效的"会漂移，审计也追溯不了。`load_scope` 把派生范围与 scope
   文件**并集**，**5 层 `check_scope` 与出口白名单因此零改动自动覆盖**。

> **实现期真实踩到的坑**：`Engagement._persist()` 原先硬编码 key 白名单，会把 `derived_scope`
> 抹掉——每次状态迁移写回后 `start()` 就重校验到一个空 scope，授权范围静默消失。已修，并由
> `test_derived_scope_survives_state_transition_persist` / `..._survives_manager_restart` 锁死。

**M9a 附带还债**：`default_phases_factory` 的沙箱出口从演示取向的 `open` 改为默认 `restricted`
（AGENTS.md 已知限制 24 由此还清）。

**M9b 红线 4 重定义：模型身份 → 校验独立性**。原表述"Verifier 与发现端必须用不同模型"，实现上
只是 `ModelRouter` 启动时一句 `warnings.warn`（非硬约束），且**本就管错了维度**——"不同模型" ≠
"不同盲点"（同家族不同尺寸的模型盲点高度相关）。Verifier 的独立性实际由三处保证，且全都与模型
身份无关：① 输入边界（红线 3：只收结构化摘要 + 证据包索引 + diff 摘要，不喂原始输出）；
② 独立 agent + 独立 system prompt（对抗校验员视角）；③ 输出 Pydantic 强校验（非法 verdict 一律
拒收）。故 M9b 把红线 4 改为约束这三条——从不可验证的配置事实，变成**可测试的工程属性**，
并以 `tests/test_verifier_independence.py` 锁死（含"同模型下依然成立"一条，这是 M9b 的核心主张）。
同模型配置保留 `llm_tiers_share_model` 审计，提示共享盲点风险。

## 7.6 M9c 落地注记（2026-09-22：发现层去锁）

**问题定位**。M3d 起 triage 是纯规则表（`core/orchestrator.py::_triage_candidates`）：参数键
**精确匹配**约 20 个英文键名。一个参数叫 `article_id` / `sku` / `token` / `ref` / `no`，或中文站点
的 `bh`（编号），系统**根本不产生候选**——不是验证失败，是看不见。而 `llm/router.py` 的档位定义
里 T1 档写的就是「triage、摘要、假设生成、规划」，triage 却从未用过 LLM。

**为什么先测基线**。参照系缺失时，所有架构增益都悬空——无法分辨「新 triage 有效」与「模型本来
就能干、脚手架在拖后腿」。故 M9c 的硬前置是中性基座（`scripts/bench_triage.py`）：

- **为什么不用 DVWA**：DVWA 的参数名全是 `id`/`name`，**恰好落在提示表内**——拿它测关键词盲区
  必然测不出来。基座因此自建 stdlib fixture，A/B 两族端点**行为同构、唯一变量是参数名是否命中
  提示表**，故任何发现率差异只可能来自 triage 的关键词匹配，不可能来自靶场难度差。
- **三臂消融**：`rules`（现状）/ `model`（纯模型，对标"裸模型"参照线）/ `rules+model`（目标形态）。
- **实测**（12 真漏洞 / 4 安全对照，确定性、零 Docker 零 LLM）：

  | 臂 | 发现率 | 误报率 | 粗筛后 |
  |---|---|---|---|
  | `rules`（现状） | **33.3%** | 50.0% | 33.3% / 0.0% |
  | `model`（纯模型） | 91.7% | 0.0% | 91.7% / 0.0% |
  | `rules+model`（目标） | **100.0%** | 50.0% | **100.0% / 0.0%** |

  纯规则表**漏掉 8/12 条真实漏洞**，其中 6 条正是参数名不在提示表的盲区。这就是"发现层被锁死"
  的第一个可复现数字。

- **真实 T1 档实测**（`bench_triage.py --model`，替换「能力上界」替身）：

  | 臂 | 发现率 | 误报率 | 粗筛后 |
  |---|---|---|---|
  | `rules` | 33.3% | 50.0% | 33.3% / 25.0% |
  | `model`（真实 T1，5,516 token） | **91.7%** | 50.0% | 91.7% / 25.0% |
  | `rules+model`（真实 T1，10,028 token） | **100.0%** | 75.0% | 100.0% / 25.0% |

  即：**真实 T1 档的发现率与理想模型上界几乎持平**（91.7% vs 91.7%），但模型沿提示词的
  语义线索把对照组 `/d/safe4`（有授权判断的安全端点）也判成了候选，故**候选级**误报率高于
  替身。这正是扫描结果必须过 L2 闸门 + 行为验证 + 证据门 + Verifier 才成 Confirmed 的原因
  （红线 2）——发现侧的误报由确认链路消化，而不是靠发现侧保守到看不见漏洞。


**① 模型驱动假设生成**（`proofhound/llm/triage.py`，T1 档）。四条纪律：

1. **只推理**（红线 1）：产出结构化候选（`vuln_type` + `param` + 理由 + 置信度），不生成命令、
   不发请求；
2. **不发明漏洞类型**：`vuln_type` 白名单硬编码为 `{sqli, xss, idor}`（= `GATE_MATRIX` 覆盖类型）。
   未知类型虽被证据门 fail-closed 拒绝，但放行只会污染 `findings.jsonl`；
3. **输入边界**（红线 3）：prompt 只含 URL path、参数名、状态码、表单字段名与**响应长度**；
   响应体一行不进（HTTP 响应体是最典型的不可信输入），原文落 `evidence/`、prompt 只给文件引用；
4. **fail-closed**：Pydantic 强校验 + 白名单 + **接地性**（`param` 必须在该批摘要真实出现过）+
   `llm/repair.py` 一次修复重试；非法输出**零候选**，不降级为"当作合法候选"。

**归属确定性回填**：模型只回参数名与类型、**不回 URL**，候选归属由送审摘要回填——模型无法把
候选挪到别的资产上（红线 5 面）。**送审集合 = 通过 `check_scope` 的 Signal**，越界信号在到达模型
之前就已丢弃。

**② 接线**（`core/orchestrator.py`）。候选两来源由 `triage_rules`（缺省 True）与 `triage_model`
（**缺省 False**）开关控制，两者**汇入同一套** dedup / 上限 / scope 校验 / 证据包逻辑——故 5 层
`check_scope` 纵深与出口白名单零改动即覆盖模型候选。模型只提出候选，**不改变任何确认路径**
（仍须过 L2 闸门 → 行为验证 → 证据门 → Verifier）。规则路径经 `_ingest_candidates` 机械抽出后
**逐字节等价**，旧 21 个 triage 测试零改动全绿。

**③ 廉价粗筛**（`proofhound/verify/prefilter.py`）。动机：原先 `_TRIAGE_*_CAP`（20/10/10）是在
**发现侧**设卡防确认洪泛，等于用"少发现"换"不洪泛"；本层加入后 cap 移到**贵验证档**
（`_TRIAGE_EXPENSIVE_CAP`），发现侧随之放开。判定依据是**参数影响力差分**（两个语义上应产生不同
结果的取值，比响应长度）。

> **实现期实测到的负结果（重要，已锁进代码注释与测试）**：初版把 `UNLIKELY`（两个取值响应逐字节
> 等长）当作"不进贵验证档"，在本仓库基座上实测为**负收益**——`rules+model` 臂发现率被从 100%
> 砍到 83.3%，而误报率**一点没降**。原因是差分假设不成立：「两个取值等长」同样出现在 blind 注入、
> 定长模板、参数不影响输出等大量情形里，它**不是**漏洞的负面证据。故本层收窄为
> **建议性信号（永不丢弃候选）**：只产出 `decision` 供贵验证档排序与人工参考。
> 另修一处方法感知缺陷：POST 表单候选的 asset 是页面 URL（无 query），对它发 GET 探测在语义上
> 不成立（两个取值必然等长），原先误判 `UNLIKELY`，现判 `UNKNOWN`（宁漏勿滥）。
> 修好后的实测：粗筛把候选级误报率从 50% 降到 **0%**，且**不再损失任何真漏洞**（发现率保持 100%）。

**开关与残余**：`PROOFHOUND_TRIAGE_MODEL` / `PROOFHOUND_VERIFY_PREFILTER` 均**缺省关闭**，
默认行为与 M9c 之前逐字节等价。残余：模型输出质量取决于档位模型（基座内 `model` 臂用的是
"能力上界"离线替身，**不代表真实模型表现**——真实数字须 `bench_triage.py --model` 跑 T1 档）；
粗筛只处理 GET 型候选，POST 表单候选一律放行；候选级误报率不等于 Confirmed 级误报率
（后者须跑真实 verify 链路）。

### 7.6.3 M9c③ 人工闸细分（只读验证可自动 / 写操作留人工）

**动因**。`autonomy.py` 原先按 L0/L1/L2 一刀切：semi_auto 下**所有** L2 动作都进确认
队列。但 L2 里混着两类性质完全不同的动作——「只读验证」（sqlmap 确认、浏览器 canary
探测、双会话 GET 对比）与「写操作 / 状态变更」。前者不改变目标状态，后者会。代码里
`katana` 的 `-cos` 状态变更排除清单（logout/ids 类端点）说明维护者早已在意这个区分。

**改动面只有一格**。`_GATE_MATRIX` 从「模式 × 等级」扩为「模式 × 等级 × 是否改变状态」：

| 模式 | L0 | L1 | L2 写操作 | L2 只读验证 |
|---|---|---|---|---|
| supervised | auto | confirm | confirm | confirm |
| semi_auto | auto | auto | confirm | **auto** |
| unattended | auto | auto | auto | auto |

- **supervised 一律 confirm**：细分级只在"要不要问人"上做区分，**不放宽最严格档**；
- **unattended 本就全自动**：细分不改变其裁定；
- **唯一差异格 = semi_auto × L2**，有参数化测试逐格核对，防止误放宽其他档。

**mutating 从哪来**：skill manifest 新增可选字段 `mutating`（**缺省 `true` =
fail-closed**）。未声明的 skill 一律按"会改变目标状态"对待。内置声明：
`verify-sqli` / `verify-xss` / `verify-idor` = `false`（三者都是只读验证——sqlmap 构造
器硬禁 `risk>2` 的 OR 型注入与任何写操作，浏览器只加载 payload 页，idor 只发 GET 对比）；
`web-scan` / `recon-crawl` = `true`（会向目标发起真实请求，保守声明）。

**不改 API 契约**：`gate_matrix()` 仍返回扁平「模式 → 等级 → 裁定字符串」——
`GET /health` 的 `autonomy_gate` 字段与控制台 `app.js`（按字符串渲染）依赖该形态，
故不因新增维度改形；只读行另经 `gate_matrix_read_only()` 导出。

**为什么这一刀安全**：它区分的是"是否改变目标状态"，而**不是**放宽任何硬闸——
scope 强校验、token 预算、凭据脱敏、append-only 审计在任何裁定下一律照旧；且只读声明
是 skill 的显式契约，未声明即按写操作处理。命中细分级自动执行的 L2 会落审计
`action_read_only_auto`，便于事后归因"为什么这次没人被问"。

**验证**：`tests/test_gate_sublevels.py`（39 个：矩阵两行逐格 / 未知等级两行都
fail-closed / 导出形态与只读导出差异面 / manifest 缺省与显式声明 / 编排层映射与
fail-closed 回退）+ `tests/test_readonly_e2e.py`（2 个端到端：semi_auto 下只读验证
**零确认队列**且 Finding 仍走完行为验证到 Confirmed、写操作仍进队列）。


### 7.6.4 M9d skill 收敛（撤下用户导入面 + 单一真相源）

**动因（维护者裁定）**：本系统**不打算让用户自己写 skill**。这条裁定直接抹掉了
skill 机制在本项目里的两个真实价值：

1. **不可信输入的校验边界**——导入安全闸（`skills/gate.py` 静态扫描外来脚本的网络外联/
   删除/提权/动态执行 + 高危默认禁用 + 人工 `confirm()`）的前提是"skill 可以是外来文件"，
   而 zip 上传端点（M6a）服务的是"用户交付 skill"这一场景；
2. **扩展不需要改仓库**——用户可加扫描过程，同样以上传为前提。

两者前提都不成立时，剩下的就是纯开销，且其中一项是**可验证的正确性风险**。

**① 单一真相源**（`proofhound/skills/profiles.py`）。「某条内置 skill 是 L2 还是 L1、
是否只读」原先同时存在于 SKILL.md frontmatter 与各 Python 处（闸门槽位、`mutating_by_skill`
映射）——**没有任何机制保证两者一致**，改一处忘一处即静默不一致，而这类不一致恰好落在
安全语义上（闸门裁定、是否需人工确认）。M9d 起该表是**运行时唯一真相源**，闸门只读它；
`SKILL.md` 降级为人类可读文档，由 `tests/test_skill_profiles.py` 断言逐条一致——
**文档可以读，但不能与代码矛盾**（不一致即测试失败，而不是静默生效）。
表内未登记的名字走 fail-closed（`profile_for` 抛错），非内置名字回退 manifest 声明值以保持
对外语义不变。

> 其中一条测试刻意写成「诚实记录」：断言编排路径上 `manifest.risk_level` 已**不再作为
> 判定值被读**（只作为 `_builtin_risk_level` 的回退实参出现）。这是为了防止后来者误以为
> 改 Markdown 里的 `risk_level` 能改变闸门行为。

**② 撤下用户导入面**（净删约 600 行）。删除面：
`skills/gate.py`（206 行）、`registry` 的 `risk_report`/`confirmed`/`confirm()`、
API 侧 `GET/POST/PUT/DELETE /api/skills` 五个端点与 `SkillUpdateRequest`、
`management.py` 的 skill CRUD（zip 上传 / copy-on-edit / 符号链接本地化，441→207 行）、
控制台「技能」上传编辑视图（`app.js` −158 行）与导航项。**保留**：SKILL.md 解析校验、
registry（编排器仍需按名查 skill 与正文 SOP）、`enable()`/`disable()`
（planner 的「skill 未启用即拒」仍依赖它，有测试覆盖）。

**③ 撤回公开承诺**。F1「可导入 Skill（本地目录 / Git 仓库 / 内部 registry 三种导入来源）」
标记为**已撤回**——它曾是对外承诺，故按 M9a 撤回已知限制 24 的先例显式记明，而非静默删除。

**代价与披露**：删除两个测被删功能的测试文件（`test_skill_gate.py`、`test_skill_admin.py`）。
其余 18 个引用 `SkillRegistry` 的测试文件**零改动**——因为 registry 接口本身保留，
只删了它内部的安全闸与确认流程。

## 7.7 M10a 落地注记（2026-09-23：Confirmed 级基线）

**动因**。M9c 的三臂消融只到**候选级**——它回答"发现层的门开多大"，回答不了"这些候选里
有多少真能被确认为漏洞、有多少误报会穿过确认链路"。而 M9c 的两个生产开关（`TRIAGE_MODEL`
/ `VERIFY_PREFILTER`）要不要默认开启，恰恰取决于后者。

**Step 1：fixture 升级为「真可确认」**。原 fixture 的"真漏洞"端点只是**模拟**特征
（取值含引号 → 500），只能测发现层。M10a 把后端换成真的：sqli 走 sqlite 拼接查询
（sqlmap 可确认，A/B/C 三族同后端）、xss 保持不转义反射（canary 可确认）、idor 引入
身份归属（`PRIMARY_IDENTITY`/`OWNER_IDENTITY` + `REFERENCE_TOKEN`，双会话属性违反可确认）、
D 族换成真安全（`/d/safe2` 去掉模拟 SQL 错误；`/d/safe4` 改为对**所有**取值做真授权校验，
非所有者得**定长**通用页）。**不变式全部保持**：端点表/参数名、首页链接、表单字段、爬行
状态码、D 族"两个探测取值响应长度相同"（粗筛只比长度，见 §7.6③）、响应体 ≥64 字节——
故**离线三臂与真实 T1 档数字逐格不变**，历史结论可比。

> **实现期踩坑（重要，已锁进测试）**：首版把 A/B/C 三族统一到**同一份正文**（以为"更同
> 构"），结果 **katana 把正文重复的 URL 当作重复响应丢弃**——16 个端点只有 **9 个**进入
> crawler（sqli 5→1、xss 2→1、idor 3→1，算术精确吻合），live 臂的 Confirmed 级检出率因此
> 被伪造成 25%。修法是每个端点带自己的 label + 参数名。**教训：「行为同构」必须理解为
> 「同一后端 + 同一 vuln 语义 + 唯一变量是参数名」，而不是「逐字节相同」。** 硬性回归网：
> `tests/test_bench_fixture.py::test_no_two_endpoints_share_a_body`。

**Step 2：`--live` 端到端确认链路**。作为**附加模式**接入（不改变离线确定性）。4 臂 =
两个生产开关的 2×2 组合；走真实编排栈（Docker 沙箱 + Chromium + T2）；semi_auto 下三条
verify-* 均为只读（§7.6.3），闸门直接放行、不进确认队列——**这正是要测的"无人过滤"形态**。

指标口径经维护者裁定：**粒度 = (端点路径, vuln_type)**，类型错配计误报；`verify_blocked`
（T2 超时 / 缺第二会话 / 基准不成立）**单列一行，不计入 precision/recall 分母**——超时是
"未能判定"，不是"确证不成立"。

**T2 读超时修复**（实现期发现，`llm/router.py`）：`TierConfig.timeout` 缺省 60s，而 T2
（Verifier 终审）实测延迟落在 **55~65s**、正压线上，导致**间歇性** `verify_blocked`——
单臂 12 条真漏洞里 **3 条**纯因超时丢失（检出率 50%，本可 75%），而同一次运行里其它 T2 调用
均正常返回。新增 `DEFAULT_TIMEOUTS`（T0/T1 60s、**T2 180s**）+ `PROOFHOUND_<TIER>_TIMEOUT`
覆盖。修复后 4 臂合计 48 条配对只剩 1 条超时（≈2%）。注意 `urllib` 的 timeout 是**单一读
超时**（连接与读取共用），放宽同时抬高故障发现延迟，属刻意取舍。

**Confirmed 级实测**（12 条真漏洞 + 4 个安全对照）：

| 臂 | TRIAGE_MODEL | VERIFY_PREFILTER | 检出率 | 精确率 | 误报率 | TP | FP | 未能判定 | token |
|---|---|---|---|---|---|---|---|---|---|
| `rules` | 0 | 0 | 33.3% | 100.0% | 0.0% | 4 | 0 | 0 | 26,557 |
| `rules+model` | 1 | 0 | 58.3% | 100.0% | 0.0% | 7 | 0 | 0 | 59,052 |
| `rules+prefilter` | 0 | 1 | 25.0% | 100.0% | 0.0% | 3 | 0 | 1 | 22,662 |
| `rules+model+prefilter` | 1 | 1 | **66.7%** | 100.0% | 0.0% | **8** | 0 | 0 | 59,858 |

即：**确认链路（证据门 + 独立 Verifier）在 4 臂上误报率全 0**——4 个安全对照端点的全部候选
都被驳回，且理由是实质性的（"无证据证明该对象确属 reference 身份私有"、"A/B 两份响应
sha256 相同，更符合与会话无关的公开内容"）。`PROOFHOUND_TRIAGE_MODEL` 有 **+3~+5 个
Confirmed** 的明确增益，代价约 2.2× token / 2.1× 时长。

**两处诚实性说明（不许含糊）**：

1. **离线 `model` 臂的"100%"是能力上界，不是模型实测**。该臂用的是按 ground truth 回候选的
   **替身**（构造上必然接近满分）；`--model` 那次的 12/12 也是单次采样。live 实测显示真实
   T1 每次只捞到 6 条表外端点里的 ~3 条，**且每次不是同样 3 条**。故"33.3% → 100%"回答的是
   **发现层的门开多大**，不能读作模型的稳定能力。
2. **每臂仅单次采样，而单条 Confirmed 的判定本身随机**。同一个真 IDOR（`/a/idor`）在 4 臂
   出现 **4 种结果**：confirm / reject / 未能判定 / reject。拒收与确认双方争论的是
   **「对象私有性」证据够不够**——红线 3 决定 Verifier 只收结构化摘要、看不到响应体，该要件
   在摘要下**欠定**，每次由模型自定标准。**这是规格歧义，不是模型能力问题。**
   **后果：臂间 1~2 条 TP 的差异无法区分开关效应与采样噪声**（`rules+prefilter` 的 25.0%
   实为 `/a/idor` 那次超时，而非粗筛负作用）。**重复测量与 Verifier 的 IDOR 判据收紧均未做，
   留给后续里程碑**（后者属产品语义裁决：必须先定"什么才算 IDOR 成立"）。

**不改**：确认链路、证据门判定语义、状态机铁律、闸门矩阵、两个开关的缺省值
（`PROOFHOUND_TRIAGE_MODEL` / `PROOFHOUND_VERIFY_PREFILTER` 仍缺省关闭）。

## 7.8 M11a 落地注记（2026-09-23：成本可见性）

**动因**。M10a 之后，两个生产开关要不要默认开启取决于「单题成本」，但**成本数字根本不可
复现**：同一份数据实测得出 5,897/4,270、4,197/11,349 等三组不同值（连大小关系都反）。根因
经查是两件事叠加——① **口径未定**（按臂？含修复重试？按批次？）；② `llm_call` 审计事件
**根本不带归属信息**（只有 tier/model/tokens/耗时），连「Verifier 花了多少」都算不出来。
故本里程碑先定口径、再补归属，最后才出口。

**口径（维护者裁决）**：按**调用方 + 阶段**归属、**含修复重试**。

**Step 1：归属元数据**。`llm_call` 审计新增三个字段：

| 字段 | 含义 | 取值 |
|---|---|---|
| `caller` | 调用方 | `triage` / `planner` / `verifier` / `narrative`（未登记 → 聚合归 `unknown`） |
| `finding_id` | 该次调用服务的 Finding | **仅 Verifier 有值**（唯一逐 Finding 的贵调用；其余三处是批次/engagement 级） |
| `retry` | 是否 M6a 修复重试那一次 | `True` 仅重试 |

阶段映射：`triage→discovery`、`planner→planning`、`verifier→verification`、
`narrative→report`。`retry` 由 `repair.py` 在重试调用上显式置位——**不发散推断事件顺序**
（首轮与重试在审计上可确定性区分）。

**Step 2：纯函数聚合**（`proofhound/llm/cost.py`，零 LLM 零网络）。维度 = 调用方 / 阶段 /
Finding / 档位，**四个维度各自求和都等于总数**（单一口径，不存在第二套算法）。三条口径纪律：

- **修复重试计入主口径**（它是真实成本），同时因带 `retry=True` 而可**确定性单列**
  （`retry_calls`/`retry_tokens`）——既不含糊也不丢信息；
- **`estimated` 单列计数**：响应无 usage 时按 4 字符≈1 token 估算（已知限制 6），估算与真实
  **不混算**；
- **旧数据归 `unknown` 桶而非丢弃**：M11a 之前的 `llm_call` 缺 `caller`，若丢弃则总量对不上
  ——这正是"数字不可复现"的来源。另出**可归属比例**（1 − unknown 占比），把"这个数字覆盖了
  多少调用"一并说清（旧 engagement 会是 0%，属**诚实的可见降级**）。

**Step 3：三处出口**。CLI `python -m proofhound.cost --dir <eng> [--json] [--finding F-x]`；
API `GET /api/engagements/{id}/cost`（只读、`include_calls` 可选、响应零凭据）；控制台**只读**
成本面板。**口径统一**：`tokens_used` 与 `/cost` 改为同源同值（原先 `_tokens_used()` 自己遍历
审计求和，属第二套口径），数值语义与改造前逐字节等价。

> **实现期踩坑（重要，省后来者时间）**：
>
> 1. **降级逻辑必须放在 repair 层，而不只是 router 层**。首版只在 `ModelRouter.complete` 内
>    做「目标不接受 kwargs 就不传」的判定，但 `complete_structured`（repair.py）**直接调用**
>    `router.complete(tier, messages, caller=...)`，绕过了那层判定——57 个既有测试当场
>    `TypeError`。修法是把判定抽成 `llm/callmeta.py` 的共享助手，**两个调用点都走它**。
>    教训：**判定要放在所有调用路径的共同必经点上**，否则"已兼容"是假的。
> 2. **`call_with_meta` 的参数顺序会静默错位**。首版签名是 `(func, messages, meta, *extra)`，
>    调用写成 `call_with_meta(router.complete, messages, meta_dict, tier)` 时，`tier` 落进了
>    `meta` 槽位、`messages` 只收到一个参数——症状是替身拿到 `(messages,)` 后报
>    `TypeError: string indices must be integers`（因为把 `tier` 字符串当 dict 下标）。
>    修法是把 messages 固定为「最后一个位置参数」（`func(*leading, messages, **meta)`），
>    **meta 变关键字专用**，物理上不可能再错位。回归网：`test_cost.py` 的
>    `test_callmeta_leading_args_forwarded`。
> 3. **既有测试替身有 ~20 处 `def complete(self, tier, messages)`**（无 `**kwargs`）。选
>    「签名判定 + 确定性降级」而非「改 20 个替身」，既守住"旧测试尽量零改动"纪律，又把
>    降级语义锁进测试（`test_old_style_client_still_works_and_audits_none`）。
> 4. **审计字段的诚实性 > 数字好看**。旧数据无法归属是事实，故选择「归 unknown + 报可归属
>    比例」而不是摊派或丢弃；`finding_id` 只给 Verifier（其余调用点是批次级，按比例摊派到
>    单条 Finding 是编造）——已记为限制 38。

## 7.9 M11b 落地注记（2026-09-23：IDOR 判据收紧）

**动因**。M10a 的 Confirmed 级 4 臂表显示同一个真 IDOR（`/a/idor`）在 4 个臂里出现
**4 种结果**（confirmed / rejected / 未能判定 / rejected），当时归因为「Verifier 判定
随机、判据欠定」（已知限制 35）。M11a 逐条复核 4 臂**全部 11 条 IDOR 终审原文**后把
归因**修正为规格歧义**：7 条 reject 里 **6 条判得正确**（那些是对 `/a/sqli`、
`/b/sqli2`、`/d/safe` 之类**非 IDOR 端点**的类型误报），真 IDOR 的驳回理由则**逐字
同构**——① 无对象归属证据；② A/B 响应 sha256 完全相同，更平凡的解释是"公开内容"；
③ 缺一个能排除公开端点的对照。决定性证据：同一 `/b/idor2` 在**同一次运行**的两个臂里
被判了两种标准（`rules+model` reject"无证据建立属主关系"、`rules+model+prefilter`
confirm"属主由方法论定义"）。

**维护者裁决三条**（M11a 落规格、M11b 实现；§5.4.2 有同一份裁决记录）：

1. **加未认证对照探测**：对同 URL 追加一次不带凭据的请求，公开资源即驳回；
2. **要求归属证据**：仅"reference 可访问 + 攻击者拿到等价响应"不足以构成属性违反；
3. **归属由确定性代码提取**，Verifier 只收「结论 + 行号锚点」，红线 3 零放松。

### 实现（本里程碑只改判据，不动证据门/状态机铁律/闸门矩阵）

**① 新模块 `proofhound/verify/idor_control.py`**（纯函数、零网络零 LLM）：两个
**否定性**判据。

- `judge_control(baseline, control)`：未认证对照的**三态**判定——
  - `public`：未认证 2xx **且**（与 B 基准正文**逐字节相同** 或 相似度 ≥ 0.9）
    → 公开/与会话无关的资源，属性违反不成立；
  - `protected`：未认证非 2xx（3xx/4xx/5xx）→ 资源与会话相关，解释成立；
  - `blocked`：对照请求网络错误，或 2xx 但既不逐字节相同、相似度也低于阈值
    → **判定不了**（覆盖不全）。
  **为什么"不同但不相似"判 blocked 而不是 protected**：那同样符合"两个身份看到
  不同数据"这一**合法**形态，把它当越权证据是会误报的方向。本层**只否定、不肯定**
  ——只有"相同/高度相似"才是可据此**否定**违反的硬证据。
- `judge_ownership(baseline, victim_identity)`：从 B 基准提取对象归属，**两族同时
  命中**才算证据——① 字段名像归属字段（`owner`/`所有者`/`created_by`/...，且不在
  `current_user`/`session_user` 这类"当前登录者"排除表内）；② 该字段的**值**等于
  reference 身份标识。三态：`matched` / `mismatched`（指向他人）/ `absent`。
  **`victim_identity` 缺失时一律 `absent`**——没有期望值就无法把字段值认定为归属
  证据（**不做"有 owner 字段就算证据"的放松**，那会把任意第三方归属也当证据）。

**② 编排层（`_verify_idor`）——确定性判据进代码，不交给 LLM**。这是消除方差的
关键：三种形态在编排层**直接定终态并落审计**（零额外 LLM 成本），不给模型"自由
裁量"的空间。

| 形态 | 终态 | 依据 |
|---|---|---|
| 对照 `public` | `REJECTED(actor=verify-idor)` | 公开资源，属性违反不成立 |
| 对照 `blocked` | `blocked`（停 Hypothesis） | 覆盖不全，**既不驳回也不确认** |
| 对照 `protected` + 归属 `absent`/`mismatched` | `REJECTED(actor=verify-idor)` | 裁决第 2 条：缺归属证据 |
| 对照 `protected` + 归属 `matched` | 进证据门 → Verifier 终审 | 常规路径 |

结论同时落盘 `idor_{id}_control.json`（三态枚举 + 行号锚点 + **两份响应 sha256**），
并计入 `verification.evidence_refs`；审计增 `idor_control_judged`。

**③ 第三身份可选**。`Scope.session_third`（可选）——未配置时对照用**完全不发凭据**
的匿名请求（`SessionConfig()`）。**匿名已足以否定"公开资源"**（未认证都能拿到，当然
不是私有对象），故第三身份是**可选增强**而非必需，链路不会因缺它而 blocked。

**④ Verifier 只收结论 + 锚点**。`Verifier.review(..., extra_summary=...)`——这是
**可选关键字**，仅 verify-idor 传，sqli/xss 两条链路的 prompt 载荷**逐字节不变**
（新键仅在给定时并入）。摘要里只有三态枚举、数值、字段名/匹配字面量/行号，**没有
响应体原文**：红线 3 的输入边界零放松。SOP 同时写入三条硬性复核要点（对照 public /
blocked / 归属非 matched 一律 reject，**不得自行放宽**）。

### 实现期踩坑（诚实记录，省后来者时间）

1. **基准 fixture 的 footer 是缺陷，且它冒充了端点差异**。`_page()` 硬编码
   `session=<主会话 TOKEN>`——两个后果：① 页面在"谁在看"上说谎（owner 会话的响应
   回显 attacker 的 token）；② **三个 IDOR 端点的可见文本实际相同**，仅靠这行硬编码
   标记才逐字节可区分，于是 M10a 的 Verifier 反复援引的"A/B 两份响应 sha256 完全
   相同 → 更像公开内容"**部分是该缺陷制造的伪迹**。M11b 把 footer 改为
   **per-endpoint 标记**（`ep=<路径去斜杠>`）：正文差异来自端点身份、不依赖任何凭据、
   长度稳定（同端点恒定）。**脱敏演练随之取消**——凭据脱敏由生产链路自身测试覆盖，
   不该由基准 fixture 承担，尤其当它需要**伪造**正文差异时。
2. **IDOR 端点原先不拒匿名**，使"公开资源"与"私有对象被 A 拿到"在未认证对照下**同形**
   ——这正是 Verifier 索要却拿不到那个对照的根因。改为未认证得定长通用页（**刻意用
   200 而非 403**：旧系统常见"登录页 200"形态，保留"匿名也能拿到 200"这一最不利情形，
   迫使判据在正文层面工作）。attacker（已认证非属主）**仍拿到对象页**，故 ground
   truth 与漏洞语义不变。
3. **一个连带后果（已在基准中如实体现，不掩盖）**：`verify/prefilter.py` 的探测是
   **不带凭据**的（`_http_get` 无 session），故 IDOR 端点拒匿名后，粗筛对它们的两个
   探测取值都只能看到同一份"请先登录"页 → 判 `UNLIKELY`。于是基准的「粗筛后」两列
   变了：`rules` 33.3%→25.0%、`model` 91.7%→75.0%、`rules+model` 100%→75.0%。
   **主指标（发现率/误报率）逐格不变**（33.3% / 50.0%、91.7% / 0.0%、100% / 50.0%）。
   **这不是功能回归**：`ScreenResult.passed` 恒为 True，`advisory` 只增一个审计计数，
   粗筛**从不丢候选**（M9c② 已实测丢弃是负收益）。同时它暴露一条**真实限制**——
   粗筛在"需认证目标"上只能看到登录/拒绝页，判别力下降（已记入已知限制 41）。
4. **归属提取的两处实现缺陷（靠实测而非推理发现）**：首版文本正则包含 `属主`/`所属`
   这类**泛化叙述词**，把散文 `（属主 B）` 抓成字段 `属主=B）`，且它先于真正的
   `owner=` 出现，于是 `mismatched` 取到了散文；修法是①从正则里剔除泛化叙述词、
   ②先扫 **JSON 形态**再扫文本形态（结构化字段更可信）、③空格分支的字符类**必须
   排除全角标点**（实测 `所有者 owner，金额 800` 会被吃成值 `owner，金额`——前两次
   修法都以为 strip 能解决，实际标点已被正则吃掉，strip 已太晚）。
5. **测试罐头的正文契约很敏感**。`test_idor.py` 的 `_padded_body` 依赖"A/B 正文主体
   逐字节相同、只在尾部标记不同"来维持相似度 > 0.9。我把 owner 字段插在**中段**时，
   B 的填充区整体右移约 50 字符、与 A 的 token 注释错位，相似度实测掉到 **0.8725**，
   于是在"双会话判定"这步就驳回、根本走不到 Verifier。修法是让**差异区等长**
   （token 注释定长 + 3 字符差异标记），相似度回到 0.99+。

### 7.9.1 M11c-pre：测量 harness 修正（2026-09-23）

**性质：这是测量 harness 的配置缺陷，不是生产判据缺陷。** 第一遍重复测量一跑起来就暴露：
M11b 新增的判据在基准里**完全无法进入设计预期状态**，真 IDOR 被系统性判成"未能判定"或
"缺归属证据"驳回——基准测到的不是判据行为，而是配置错误的副作用。两处缺陷：

| # | 缺陷 | 机制 | 后果（实测） |
|---|---|---|---|
| 1 | 匿名拒答用 **200** | 对照判据**只否定、不肯定**：2xx 且既不逐字节相同、相似度也不达阈值 → `blocked` | `/a/idor` 对照相似度 0.747 < 0.9 → `blocked` → Finding 停 Hypothesis → **4 臂 IDOR 真阳性全丢** |
| 2 | 未声明 `reference_identity` | 对象页展示 `所有者 owner`，reference 凭据是 `bench0reference0token`，两者**不同源** → 归属判 `mismatched` | 真 IDOR 被"缺归属证据"驳回 |

**修法与否决记录**（三种形态都试过）：

- 缺陷 1 改 **403**。**302 经实测否决**——`urllib`（测试与部分工具）会**跟随**重定向到
  未注册的 `/login` → 404，语义模糊，且跟随后的 404 正文在多个端点间**相同**，会破坏
  `test_no_two_endpoints_share_a_body`（该不变式防的是 katana 把正文重复的 URL 当重复响应
  丢弃）。403 是 `verify/prefilter.py` 文档自己点名的"被拒"形态，语义清晰且 `HTTPError`
  会带出被拒正文而不跟随。
- 缺陷 2 在建 engagement 时补 `reference_identity=OWNER_IDENTITY`（与 `demo_killer` /
  `demo_idor_fixture` 同一处理）。

**为什么这是修 harness 而不是放宽判据**：`idor_control.py` 对"200 的含糊对照"判 `blocked`
而不去猜，是**正确行为**（只否定、不肯定）。修 harness 是让被测系统进入其**设计预期状态**。

**修复后验证（实测）**

- 单臂 sanity（`evidence/bench_triage/20260923T150346Z`）：`/a/idor` → **confirmed**；
  对照 = `protected`（403，similarity 0.747）；归属 = **`matched`**（字段 `所有者`，值 `owner`，
  行锚点 1）——M11b 判据首次在基准里跑通 `protected + matched` 正向路径。
- 新基线（各 1 次采样）：`rules` **33.3%（4/12，FP 0，未能判定 0）**；
  `rules+model` **75.0%（9/12，FP 0）**——后者显著高于 M10a published 的 58.3%，
  差额主要来自此前被上述缺陷压制的 IDOR 项。
- **M10a 的 4 臂表因此降级为"历史数字"**（其 IDOR 项受缺陷 1 压制）。

> **未完成**：**方差量化**。M11c 的 3 遍 × 4 臂只跑完 1 遍（且该遍后两臂被 `LLM HTTP 429`
> 污染——T2 账户余额耗尽，属外部阻塞）。故"臂间 1~2 条 TP 差异是否可区分于采样噪声"
> 与"`VERIFY_PREFILTER` 效应是否落在噪声内"**仍无答案**，上述新基线亦**不可用于臂间比较**。

## 7.10 M11c 落地注记（2026-09-24：重复测量与方差结论）

**动因**。M10a 的 Confirmed 级基线是**每臂单次采样**，而它记录的"同一个真 IDOR 在 4 个臂里
出现 4 种结果"使臂间 1~2 条 TP 的差异**无法区分开关效应与采样噪声**。M11b 把那个方差归因
修正为**规格歧义**（判据没定死）并收紧了判据、M11c-pre 修掉了让判据在基准里失效的两处
harness 缺陷，本里程碑负责回答那个悬而未决的问题：**方差到底有多大，臂间差异可判吗？**

**方法**。4 臂 × 3 遍 = **12 次臂运行**（`scripts/bench_triage.py --live`，真实 T1/T2 +
Docker + Chromium，semi_auto 无人过滤）。判据可判性用最保守的**区间重叠法**：两臂的 TP
实测区间若重叠，则其差异**不可判**（可能纯属采样噪声）。

**⚠️ 断代声明（读数字前必看）**：本批运行的 **T2 档指向 DeepSeek（`deepseek-v4-flash`），
与 T1 同模型**（原为 `kimi-k3`）——因测量期间 Kimi 账户余额耗尽被停用。红线 4（M9b 重定义）
**明确允许** T1/T2 同模型（独立性由 agent 隔离 + 输入边界 + 输出强校验保证，不靠模型身份），
故判定语义有效；但**本批数字与 M9a~M11b 的 kimi-k3 实测不可直接比较**，属断代。另：测量前
停掉了宿主机上无关的 pentagi 栈（原在抢占 CPU），故 **wall 时间也不宜与旧数据比**。

### 实测结果（3 遍，验证了区间重叠法之外的稳定性）

| 臂 | 检出率 | TP 各遍 | 误报率 | FP 各遍 | 未能判定 | token 各遍 |
|---|---|---|---|---|---|---|
| `rules` | **33.3%** (σ=0.000) | [4, 4, 4] | 0% | [0, 0, 0] | [0, 0, 0] | [33,684, 25,975, 32,648] |
| `rules+model` | **66.7%** (σ=0.000) | [8, 8, 8] | 0% | [0, 0, 0] | [1, 1, 1] | [58,526, 59,697, 63,704] |
| `rules+prefilter` | **33.3%** (σ=0.000) | [4, 4, 4] | 0% | [0, 0, 0] | [0, 0, 0] | [31,221, 31,643, 32,033] |
| `rules+model+prefilter` | **72.2%** (σ=0.048) | [9, 8, 9] | 0% | [0, 0, 0] | [1, 1, 1] | [59,669, 88,819, 74,787] |

**四条结论**（每条都有实测支撑）：

1. **`PROOFHOUND_TRIAGE_MODEL` 是**唯一**可判且增益巨大的开关**：`rules` 与 `rules+model`
   的 TP 区间 **[4,4,4] vs [8,8,8] 不重叠** → 差异**可判**；两者**标准差都是 0**，即该增益
   （**+4 个 Confirmed，33.3%→66.7%，翻倍**）在三遍里**完全稳定**。两条独立路径
   （`rules+prefilter` 对照）复现同一结论。
2. **`PROOFHOUND_VERIFY_PREFILTER` 的效应落在噪声内**：`rules` → `rules+prefilter` 是
   **[4,4,4] → [4,4,4]**（完全相同，零效应）；`rules+model` → `rules+model+prefilter` 是
   **[8,8,8] → [9,8,9]**，区间**重叠** → **不可判**。方向虽偏正（均值 +0.5 个 TP），但
   3 个样本不足以定论，且其 token 代价在大模型臂上达 **1.23×**（60,642 → 74,425）。
3. **M10a 的"同一真 IDOR 4 臂 4 结果"不再复现**：`/a/idor` 在**全部 12 次运行里都是
   confirmed**（M10a 当时是 confirmed/rejected/未能判定/rejected）。这与 M11b 的诊断一致
   ——原方差是**判据规格歧义**（叠加 harness 缺陷），判据定死后消失。
4. **方差并未归零，但已收窄到"具体端点"级别**：唯一波动格是 `rules+model+prefilter` 臂的
   `/b/sqli2 [sqli]`（confirmed / 无候选 / confirmed），即整臂 σ=0.048 的**唯一来源**。
   其余 15 个端点终态 12 次运行**全一致**。M10a 记录的发现层方差（"两个 model 臂各漏 3 条
   表外端点但漏的不是同一条"）在本批未复现为整体差异。

**精确率与误报率的稳定性（最强的一条）**：**12 次运行、四臂，精确率全 100%、FP 全 0**、
4 个安全对照端点在每次运行里都未误确认。即**确认链路（证据门 + 独立 Verifier）的零误报
在重复测量下稳如常数**——这是 M8c 起"候选默认为假、必须行为验证 + 证据门 + 独立终审"这条
主线的第三次独立验证（M3b DVWA、M10a 4 臂、本次 12 次）。

### 开关默认值的证据化建议（本里程碑的直接产出）

| 开关 | 建议 | 依据 |
|---|---|---|
| `PROOFHOUND_TRIAGE_MODEL` | **建议默认开启**（当前缺省关闭） | 差异**可判**、三遍**零方差**、增益 **+4 个 Confirmed（翻倍）**，代价 **1.97× token**。这是全部实测里证据最强的单项改进 |
| `PROOFHOUND_VERIFY_PREFILTER` | **保持缺省关闭**；若要开，需先补样本 | 区间重叠 → **不可判**；`rules` 下**零效应**，`rules+model` 下方向偏正但代价 **1.23× token**。开它等于**用确定成本换不可判的收益** |

> **成本口径**（M11a 的 `proofhound.cost`）：`rules` 均值 30,769 token 为基准 1.00×；
> `rules+model` 1.97×；`rules+prefilter` 1.03×；`rules+model+prefilter` 2.42×。

### 实现期踩坑（诚实记录）

1. **测量被 T2 账户余额耗尽中断过一次**：第 1 轮 pass 1 后两臂起撞 `LLM HTTP 429
   exceeded_current_quota_error`（账户停用，非限流），pass 2 四臂全为 429 → **整遍作废**。
   有效数据边界靠**首次 429 的时刻**（UTC 15:21:12）划定。教训：`verify_blocked` 同时承载
   "覆盖不全"与"账户/配额故障"，**只看汇总表会把故障读成模型能力骤降**（已记限制 44）。
2. **宿主机上有无关容器在抢 CPU**：pentagi 栈（`unless-stopped`，会自我重启）使 wall 时间
   膨胀约 40%（每遍 19 分 vs 停掉后的 11~13 分）。停用需 `compose down` 而非 `stop`
   （否则 `unless-stopped` 会把它拉起来）。**TP/FP 不受影响，仅 wall**。
3. **`.env` 备份会泄露密钥到未跟踪列表**：为改 T2 配置而备份 `.env` 时，`.env.bak-<stamp>`
   未被 `.gitignore` 覆盖，`git status` 直接暴露（任何 `git add -A` 都会带进提交）。已补
   `.env.bak-*` 规则（**不能改成 `.env*`**——那会把入库的 `.env.example` 变成"被忽略但仍
   跟踪"的迷惑状态）。

## 7.11 M15 落地注记（2026-09-29：SSRF 两步走·第一步 —— 只放开候选 + 基准加 SSRF 端点族）

> **本节的定位**：记录"第 4 类漏洞"如何在不削弱任何红线的前提下**只放开候选层**，以及"先测候选质量、再决定建不建验证器"这个顺序在代码里的落地形态与实测数据。**第二步（建 `verify-ssrf`）已于 M16 交付**，判据与形态见本文件 §7.12。

### 施工点（四处，一处都不能漏）

| 位置 | 动作 | 漏了会怎样 |
|---|---|---|
| `llm/triage.py::ALLOWED_VULN_TYPES` | 加 `ssrf` | ssrf 候选整批被 schema 拒（fail-closed，看得见） |
| `llm/triage.py::SYSTEM_PROMPT` 第 3 条 | "只能取**这三个**之一" → **四个**，并补 ssrf 判断线索 | **模型永远不会产 ssrf，且不报错**——静默失效，本轮最危险的一处 |
| `verify/gate.py::GATE_MATRIX` | **刻意不动**（不加 ssrf 项） | 若加了：ssrf 立刻获得 Confirmed 通道，而确认手段（回调服务器）尚未实现 ⇒ 假确认 |
| `scripts/bench_triage.py::ENDPOINTS` | 加 E 族 5 条真 SSRF + 形对照 1 条 | 没有 SSRF 端点就测不出候选质量，第二步无从裁决 |

**规则表也刻意不动**（不加 `_SSRF_PARAM_HINTS`）：要测的正是"**规则表盲区上**模型能否发现"。加了提示表，测出来的就只是"规则表能不能匹配关键词"——那是已经知道的答案。

### 两段式的安全形态：候选有通道，确认无通道

`ssrf` 在**模型白名单**内但**不在 `GATE_MATRIX`** 内，这个"不对称"是刻意的，且由三条断言钉死（`tests/test_llm_triage.py::test_ssrf_is_hypothesis_only_no_confirmed_channel`）：
白名单有 ssrf / 矩阵无 ssrf / 任意 ssrf Finding 过证据门恒不通过。第二条断言的作用是**防止将来有人"顺手"在矩阵里补一项**——那会让 ssrf 绕过验证器建设直接拿到 Confirmed 通道。代价是 ssrf 候选目前只能停在 Hypothesis 并堆积在 findings.jsonl（已记 AGENTS.md 限制 46），这是分两步走的**明示代价**，不是缺陷。

### 基准端点族的形态（E 族 + SSRF 形对照）

- **E 族 5 条真 SSRF**：服务端**真的**按参数取值发起 HTTP 请求（`_fetch_remote`）。参数名 `url`/`redirect` **在提示表内**（规则表锚点，用于对照），`target`/`feed`/`avatar` **在表外**（关键词盲区，第一步要测的正是在这里）。行为由 path 决定、参数名不参与行为分支——与 A/B 族同一条基准纪律，故 E 族内部的发现率差异只可能来自"参数名在不在表里"。
- **抓取目标由 fixture 自身提供**（`/e/list*`，同源）：于是既有"服务端代取"的真实语义，又**零外部依赖、可离线复现**（这是把 SSRF 放进中性基准的关键取舍——若指向真外网，基准就再也不是确定性的了）。超时 1.5s、只认 http/https、失败一律收敛成 200 + 文案（端点存在性不受取值影响，否则爬行状态码不变式会随探针漂）。
- **形对照 `/d/ssrf-like`**：参数名 `callback` 像 SSRF，但服务端**只登记、不发起请求、不回显取值**（定长）。刻意不回显的理由是硬的：回显会让响应长度随取值变化，而 D 族不变式要求"两个探测取值响应长度相同"（粗筛只比长度）。

**不变式保持**：A/B/C/D 四族 16 条端点逐条未动（由族分量断言钉死）；22 个端点正文两两不同（footer 端点标记）、字节数 132–275、全部 ≥ 64 字节；D 族四个对照端点两探测取值**字节级等长**。

### 实测（真实 T1 `deepseek-flash`，4 次独立运行，22 端点 = 17 真漏洞 + 5 对照）

| 指标 | `rules`（离线） | `model`（真实 T1） | `rules+model`（真实 T1） |
|---|---|---|---|
| 总发现率 | 23.5%（4/17） | 94.1%（16/17） | **100.0%**（17/17） |
| **SSRF 发现率（E 族 5 条）** | **0/5** | **5/5**（4/4 次一致，σ=0） | **5/5** |
| 其中表外盲区 3 条 | 0/3 | **3/3**（4/4 次一致） | 3/3 |
| 对照误报率（4 次） | 40%（确定） | 60/60/0/20% | 80/80/60/80% |
| 形对照 `/d/ssrf-like` 被误报 ssrf | 从不 | **3/4 次** | 3/4 次 |
| 单题 token | 0 | 5.7k~8.9k（2 次调用） | 5.3k~8.0k |

**读法（这是本轮最重要的一段）**：

1. **发现侧够格**——表外三条 SSRF 端点在 4 次独立运行里**全部命中且零方差**，而规则表对同 5 条**一个候选都没有**（表内两条只产出 xss）。"没有规则表提示时模型能否产出高质量 ssrf 候选"的答案是**能，且稳定**。
2. **筛除侧不够格**——形对照 `/d/ssrf-like`（参数名像 SSRF、服务端却不取数）被误报 ssrf **3/4 次**，尽管 prompt 已明写"参数只是被回显/写日志/存库则不是，这类不要报"。对照误报率在 4 次运行间区间重叠 ⇒ **该差异不可判**（同 M11c 的区间重叠法口径）。
3. **这个"不够格"正好指向行为验证**——"服务端到底发没发请求"是**二值事实**，调用方 listener 收没收到回调可以确定性回答；而纯语义判断**回答不了**（这正是选 SSRF 而非 LFI 的同一条理由，也是下一步该建验证器的直接依据）。

### 实现期踩坑（诚实记录，省后来者时间）

1. **prompt 正文与白名单是两处，漏改一处即静默失效**——`ALLOWED_VULN_TYPES` 是**校验**，prompt 第 3 条是**告知**。只改前者，模型不会产 ssrf，而且**不报任何错**（校验器只会拒绝它没见过的类型，不会抱怨"你没告诉我可以产 ssrf"）。故本轮把这一条写进施工点表并加了测试。
2. **D 族对照端点不能回显取值**——首版 `/d/ssrf-like` 把 `callback` 转义后回显，结果两个探测取值（`1` / `999999`）响应**不等长**，直接破坏 D 族不变式（粗筛只比长度）。改为"只登记、不回显"的定长页后恢复。**教训**：对照端点的"真安全"必须同时满足"行为上不成立"与"不扰动既有不变式"。
3. **字节数 vs 字符数的坑（诊断时踩的，非实现缺陷）**：用 `len(body.decode(...))` 量响应长度得到的是**字符数**，而响应头 `Content-Length` 与粗筛的 `len(response.read())` 是**字节数**；中文页面上两者相差可观（实测 131 字符 = 171 字节），一度看起来像"同一 URL 两次请求返回不同长度的正文"。**量 HTTP 正文长度一律用字节。**

### 本里程碑明确不做

- `GATE_MATRIX` 的 ssrf 项、`skills/verify-ssrf/`、`skills/profiles.py` 登记（属第二步，待裁决）；
- 规则表的 SSRF 提示表（刻意不加，见上）；
- `--live` 的 SSRF 臂（没有验证器 ⇒ 跑出来只会全是"未能判定"，是浪费与误导）；
- 其他形似 SSRF 的对照形态（"参数被回显""参数被写日志""参数被存库"）——当前只有"只登记"一种，已记 AGENTS.md 限制 47 的残余。

## 7.12 M16 落地注记（2026-09-29：verify-ssrf —— SSRF 的带外回调确认）

> **本节的定位**：记录"第 4 类可确认漏洞"如何在不削弱任何红线的前提下落地，以及
> **实现期被测试抓出的 4 个真实缺陷**——它们都只在"用真 listener 驱动 confirmed"时暴露。

### 为什么必须是带外事实

SSRF 与 sqli/xss/idor 的判定形态不同：它**没有可观测的响应差异**。目标是否替我们发了请求，
答案**不在目标给我们的响应里**——响应里出现 callback URL 只是**反射**。故确认手段只能是
带外二值事实：我们自己起的 listener **收到了**那次请求。这与 verify-xss 用"canary 执行事件"、
verify-idor 用"双会话属性违反"是同一种纪律。

### 三道防伪（缺一不可）

| 机制 | 作用 |
|---|---|
| 每探针唯一 token（128 位随机 + `hmac.compare_digest`） | 伪造不可能；路径不含 token 的请求记 `ssrf_callback_ignored`，**不计命中** |
| 交付证明（回取探测 URL，正文须含 token/nonce） | 证明目标当时收到的**就是**我们报告里那个地址 |
| 随机地址对照探针（`<hex>.invalid`） | 命中只证明"服务端会代发请求"，**不确认**——防"目标自己访问了别的地址" |

### 实现期被测试抓出的 4 个真实缺陷（都记在这里，省后来者）

1. **注册的 token 与注入 URL 里的 token 不是同一个**（最严重）：循环外 `probe =
   callback_url(..., new_token())` 生成 value，循环内又 `token = new_token()` 拿去注册 ⇒
   "注册的"与"URL 里的"永远对不上，**confirmed 分支在生产里永不触发**。修法：token 从**实际
   注入的字符串**里解析（单一真相源），取不到即 fail-closed。
2. **`_ssrf_listener` 没用注入的 listener 工厂**：构造时存了 `ssrf_listener_factory` 却直接
   `CallbackListener(...)`，导致测试注入的 listener 与实际使用者不是同一对象（token 注册在 A、
   回调打到 B）。与 `browser_factory`/`idor_fetch` 的既有契约不一致。
3. **对照探针的失败被计入 errored**：对照打的是**必须不可解析**的随机地址，它失败是**预期**
   行为；计入 errored 后**每次**干净未命中都判 blocked，rejected 分支形同虚设。
4. **注入的回调 URL 被 `check_scope` 当作目标**：`check_scope` 会从参数里提取所有 URL 形态目标，
   于是把我们的回调地址（临时端口）按"端口不在授权范围"整条拒掉——scope 只授权 8080 时
   **每个探针**都被拒。修法：进入前对 **asset** 过一次 scope（授权前置零放松），每个探测 URL
   再做**同源自检**（scheme/host/port 必须与 asset 一致），对照探针豁免（它刻意指向随机主机）。

**共同点**：这四处都**只在"真 listener 收到真请求"的测试下才暴露**——用替身判定时四条全部
静默通过。这是"confirmed 路径必须由真回调驱动"这条测试纪律的直接价值。

### 远程靶形态：告知地址与绑定地址解耦

回调 listener 缺省只绑回环（本地靶够用）。目标是容器/远程主机时，**告知目标的地址**
（如宿主 LAN IP）与**本机绑定地址**必须分开：混用会让 listener 直接 `gaierror` 绑不上
（实弹踩到）。故 `PROOFHOUND_SSRF_CALLBACK_HOST`（告知）+ `PROOFHOUND_SSRF_CALLBACK_BIND`
（绑定，缺省保守推断：名字可解析就绑该名、回环仍只绑回环；不可解析才退 `0.0.0.0` 并告警）。
**另一处实测事实**：本机 dockerd 上 `host.docker.internal` **不解析**（`wget: bad address`），
只能用宿主真实 IP（容器经 NAT 可达，实测回调源 IP `172.17.0.6`）。

### 实弹验收（`scripts/demo_verify_ssrf.py`）

目标 = 基准 fixture 的 E 族，**跑在容器里**、端口发布到宿主——目标必须是网络上真实可达的服务，
不能是同进程替身。结果：两条真 SSRF 端点 → **CONFIRMED**（method `ssrf-callback-confirmed`、
CVSS 5.3 代码算分、refs 3、四段式 4 步、回调源 IP 为容器网段）；形对照 `/d/ssrf-like` →
**不被确认**（交付证明不成立 ⇒ blocked）。

**一处如实说明的接缝**：baseline 走沙箱 httpx，而沙箱在 `proofhound-egress`（internal）里
**够不到**宿主发布的端口，故脚本用预制 httpx 输出提供 baseline，其余步骤全部真实。
要让 baseline 也走真沙箱，需给沙箱配到宿主的出口（属 M12/M13 部署面，见 AGENTS.md 限制 52）。

### 本里程碑明确不做

POST/表单 SSRF、header/JSON body 注入、无回调的盲 SSRF、协议/编码绕过变体、listener 鉴权、
沙箱到宿主的出口配置。

## 7.13 M16-a 落地注记（2026-09-29：katana 从 JS 里翻接口 —— 只做发现侧）

维护者就「**未授权访问 / 接口暴露**」（JS 翻接口、字典爆路径 → 不用登录就能拿到信息）
裁定三条方向，切成三段交付，本里程碑是第①段：

| # | 决定 | 状态 |
|---|---|---|
| ① | **JS 翻接口：开**——katana 1.7.0 本体就支持（`-jc` / `-jsl` / `-kf`） | **M16-a（本次）** |
| ② | **字典爆路径：用 dirsearch 接入**（`tools.d/` 本地预置 + manifest + 自带 `db/dicc.txt`） | M16-b（未开工） |
| ③ | **判定「不需要登录就能拿到信息」：交 AI**——形态 B：独立 AI 判定器产结构化结论 + 行号锚点，**Verifier 仍只收结论与锚点** | M16-c（未开工） |

③ 之所以不选「让 Verifier 直接看响应体」：红线 4 的独立性论证建立在**输入边界**上，
让 Verifier 看响应体等于它与发现端共享输入，那条论证会失效；而形态 B 有现成先例
（M9c 模型驱动 triage、M11b 确定性归属提取、M16 verify-ssrf 都是「独立件产结构化证据，
Verifier 只收结论 + 锚点」）。

### 施工点（三处；判定面一处未动）

1. **`proofhound/tools/build.py` 的 katana 构造器**：恒在项加 **`-jc`**（JS 文件内端点
   解析/爬行），与 `-fs rdn` / `-cos` 同级**写死、不接受参数覆盖**——JS 里写死的接口是
   爬行面的一大块，不开等于整块看不见；实测对内存/耗时无可测影响（`-jc` 峰值 248MiB，
   与不开 JS 解析同量级）。
2. **`KatanaParams` 加可选参数 `jsluice`（`-jsl`），缺省关**：官方标注 memory intensive，
   实测**提取集合与 `-jc` 等价**而峰值内存 248MiB → **447MiB**（12MB 真实 bundle、
   沙箱同档 512m 容器）⇒ 恒在开它是**白付内存换零增量**。唯一实测增量是拼接串的
   占位符形态（`-jc` 出 `?id=`、`-jsl` 出 `?id=EXPR`），两者都过不了下游键名启发式。
   需要更激进的 JS 解析时显式 `jsluice=True`。
3. **刻意不暴露 `-kf`/`-known-files`**：官方要求 depth ≥ 3 才生效，而构造器 depth 缺省 2
   ⇒ 给了也是「开了可能静默不生效」，容易误导；且它抓的是 robots.txt / sitemap.xml
   （字典/已知路径面），属 M16-b 而非本轮 JS 发现面。

**未动**：`proofhound/tools/manifests/katana.yaml`（旗标属构造器、不属 manifest）；
`proofhound/core/orchestrator.py` 的 triage 规则表与各类型上限；`GATE_MATRIX`；状态机铁律；
Verifier 输入边界；红线 3 / 红线 4。

### 零新增解析器：JS 端点与静态链接在输出里**逐字段同形**

施工前的侦察结论（`katana -h` 只是旗标存在性，不足以推出解析结论）：在真靶上跑
`-jc -jsonl`，JS 里翻出的接口以**普通爬行记录**出现，字段与静态链接完全一致——
`request.method` / `request.endpoint` / `response.status_code`，同样带 `response.body`。
⇒ 现有 `parsers/katana_jsonl.py` 以「GET 且 URL 含非空 query」为判据**直接吃下**，
落成 M3d 起就在的 `param-endpoint` Signal，**无需新增解析器、无需新增 Signal kind**；
triage 也走既有 `param-endpoint` 通道进 sqli/xss/idor 提示表，**零提示表改动**。

实测（真靶 + 真沙箱，产物 `evidence/demo_katana_js/<ts>/`）：JS 里写死 17 条接口路径的
目标上，4 轮 katana 共提取 **16 条** JS 接口 → 解析出 **13 条 `param-endpoint` Signal**
（坏行 0）→ triage 产 **19 条候选**（sqli 11 / idor 7 / xss 1）；**加 `-jc` 前同一靶
0 条 JS 接口**（只有 3 条静态链接）。旗标本身不产生候选，**是"JS 里的接口进了发现链路"
这一步**产生了候选。

### 资源实测：`-jsl` 贴近 512m 上限，但耗时无可测增量

容器参数与 M12 沙箱硬化档**逐项一致**（`mem_limit=512m` / 1 CPU / `nobody` /
只读 rootfs / 仅 `/tmp` 64m tmpfs / `cap_drop=ALL` / `no-new-privileges` /
`pids_limit=512` / `nofile=4096`），输入为 12MB 真实 bundle：

| 配置 | wall | docker-stats 峰值内存 | OOMKilled |
|---|---|---|---|
| `-jc` | ~13~16s | **248MiB** | 否 |
| `-jc -jsl` | ~13~16s | **447MiB** | 否 |

结论：**512m 够用但余量薄**（`-jsl` 已用掉约 87%）；**300s 超时充裕**——katana 有约
13s 的固定开销地板，与本轮旗标无关，故不存在「JS 解析撑爆超时」的问题，也就**不需要**
去动失败预算或写死更长的超时。

### scope 兜底实测（本轮最重要的一条安全回归）

JS 提取最危险的是**把范围带出去**（JS 里常写外域绝对 URL）。实测形态：靶面 JS 里放
3 个外域绝对 URL（`evil.example.com` × 2、`cdn.evil-other.example.org` × 1），跑完核对：

- **层①（`-fs rdn` 恒在）**：katana stdout **68 条记录里 `request.endpoint` 含外域 = 0、
  `request.raw` 含外域 = 0**；外域主机名**只出现在 `response.body`**（katana 把 JS 原文
  回显在记录里，那是证据、不是候选来源）。靶侧访问日志 **68 条请求的 Host 全部是种子域，
  外域 0 条** ⇒ 外域**根本没被请求过**。
  ⚠️ 记录一处**判据陷阱**（本里程碑实测踩到）：用「整行文本含外域主机名」当判据会**假阳性**
  ——命中的是 `response.body` 的回显。判据必须落在**决定候选的字段**（`request.endpoint`）
  与**实际发出的请求行**（`request.raw`）上。
- **层②（`check_scope`）**：把 2 条外域记录**直接注入**解析器 + triage（模拟"万一越界记录
  还是进来了"），两条均被判「域名不在授权列表内」丢弃、**新增外域候选 0 条**，
  并留 `triage_out_of_scope` 审计。

⇒ 两层都仍然成立，**JS 提取没有把范围带出去**。

**并针对限制 30 单独复测**：AGENTS 限制 30 明写「`-fs rdn` 对 **IP 型种子**不收敛
（v1.7.0 实测外域混进输出）」，而上面这轮验收用的正是 IP 型种子（`http://127.0.0.1:<port>/`）
⇒ 必须把这个已知不收敛面单独测清楚，否则「scope 兜底成立」会被限制 30 直接反驳。
实测：IP 型种子 + `-jc -jsl` 跑 3 轮共 **21 条 endpoint**，`request.endpoint` 含外域 **0**、
`request.raw` 含外域 **0**（外域只出现在 3 条记录的 `response.body` 回显里）、
靶侧 **21 条请求 Host 全为种子地址、外域 0 条**。即**该不收敛面本轮未复现**。
限制 30 **按原样保留、不作结论性修订**——本轮换的是靶形态（DVWA 链接结构 vs 单页 JS），
不足以否定限制 30 记录的观测，只说明本轮这条路径上两层兜底是成立的。

### 实现期发现并如实记录的行为缺陷 1 处（katana 1.7.0，非本轮引入）

JS 爬取在 `-c 5` 下**每轮只吐 1~2 条**该 JS 里的接口（17 条调用里），`-c 1`（串行）与
`-d 3`（加深）重测**不收敛**——6 种参数组合 × 3~5 次重复，每次命中的接口**随运行漂移**，
并集才逐步覆盖；`-jsl` 亦然。**含义**：单次 crawl 的 JS 发现**必然是子集**，报告里不得把
「本轮没翻到」读作「不存在该接口」；要提全覆盖需多轮重爬取并集（成倍增加请求量与耗时）。
模板串形态（反引号模板串 `/api/x?id=${id}`）在 `-jc` / `-jsl` 下**均 0 提取**。
**未定位**：属 katana 内部调度行为，本轮只如实记录、不修（不属发现侧参数能解决的面）。
详见 `AGENTS.md` 限制 53。

### 测试与披露

新增 `tests/test_katana_js.py` **9** 个：构造器 3（`-jc` 恒在 / `-jsl` 缺省关且可显式开 /
永不产 `-kf`）、jsluice 输出容错 3（`EXPR` 占位符照常收下、字段缺失不炸、JS 端点落成
`param-endpoint`）、scope 兜底 3（解析器不把外域改写成种子域、`check_scope` 拒外域、
端到端「外域不产生候选」）。旧 1125 全绿（共 **1134 passed / 2 skipped**）。

**披露的旧测试改动 1 处**：`test_katana.py::test_katana_argv_golden` 的期望 argv 插入
`-jc`——断言**意图不变**（仍是逐字面量锁死默认 argv 形态），只是把新增恒在旗标纳入锁定；
不加这一项，golden 测试就锁不住 `-jc` 是否被后续改动误删。

### 本里程碑明确不做

dirsearch 接入（M16-b）、任何判定通道（M16-c）、新增 triage 提示表、
`GATE_MATRIX` / 状态机铁律 / Verifier 输入边界 / 红线 3 / 红线 4 的**任何**改动、
「AI 判定」的任何预埋。

## 7.14 M16-b 落地注记（2026-09-29：dirsearch 接入 + 速率/并发/时间窗授权语义）

**方向来源**：维护者就「未授权访问 / 接口暴露」裁定的三条方向之②（字典爆路径用 dirsearch
接入），`tools.d/` 本地预置 + manifest + 自带 `db/dicc.txt`。①（JS 翻接口）已在 §7.13 交付；
③（`unauth-exposure` 判定通道）属 M16-c，本轮**不碰**。

### 7.14.1 施工点

| 位置 | 动作 |
|---|---|
| `proofhound/compliance/scope.py` | 新增 `RequestBudget`（`rate_rps`/`concurrency`/`max_requests`/`window_minutes`）+ `Scope.request_budget` + `resolved_request_budget()` / `request_budget_source()` |
| `proofhound/tools/build.py` | 新增 `DirsearchParams` / `_build_dirsearch` / `dirsearch_wordlist_head` / `dirsearch_timeout_for`；`build_command` 增 `request_budget` 参数 |
| `proofhound/tools/parsers/dirsearch_json.py` | 新增解析器（`parser: dirsearch_json`），产既有 `web-probe` |
| `proofhound/tools/manifests/dirsearch.yaml` | 新增（`local` → `pip` + **`closure` 26 条**，`image: python:3.12-alpine`） |
| `proofhound/tools/installer.py` | 新增闭包安装路径（`--require-hashes` + 交叉选 musllinux wheel）；`closure=None` 时旧路径不变 |
| `scripts/make_dirsearch_preset.py` | 新增：生成离线预置 `tools.d/dirsearch/`（不入库） |
| `scripts/demo_dirsearch.py` | 新增：真靶 + 真沙箱验收 |

### 7.14.2 授权语义是"新维度"，不是"还旧账"

实现前核对过：AGENTS.md **限制 5 是"预算并发精度"（LLM token 预算的 check-then-call）**，
与请求速率无关；全仓 `速率` 出现 0 次、`时间窗` 仅 2 次且都指**报告时间窗**（限制 18/19）；
`爆破` 唯一一处出现在**红线 1**（"确定性动作（端口扫描、**目录爆破**、模板渲染）由调度器
直接执行"）。故本维度是**本轮新增**，据此登记为新限制（54~56），而非修订限制 5。

### 7.14.3 缺省值：维护者裁定"保守缺省"，刻意非 fail-closed

`RequestBudget` 缺省 `None` → 构造器替换为 **50 rps / 5 并发 / 5000 请求**，并记
`source="default"`。**这与本仓库既有纪律有意不同**（`PROOFHOUND_SANDBOX_EGRESS` /
`_HARDENING` / `with_session` / `verify-xss` 懒导入都是"缺省即最严、非法值抛错"）：
后者防的是"把危险方向打开"，这里维护者要的是"开箱即用"。四道阻尼仍然成立且都不放宽：
① `max_requests` 的**词表硬闸**（构造器按 `1 + len(extensions)` 反推允许词条数，
**确定性截词表**，不靠工具自觉）；② 逐条 `check_scope`（triage 前拦越界并记
`triage_out_of_scope`）；③ 出口白名单代理**逐连接**判定；④ 非法值显式抛错。
**"缺省放行"在审计里不等于"无痕放行"**——`request_budget_source()` 可分辨 `default`/`explicit`。

### 7.14.4 时间窗的"两道"，以及 70% 的来历

`window_minutes` 同时翻成 ① 工具自限时 `--max-time = floor(窗口×0.7)`；
② 沙箱超时 `min(300, 窗口秒数)`。**两道都只收窄、绝不放宽**。

**为何是 70%**（实现期实测的边界失效）：`window_minutes=1` ⇒ `--max-time 60` **未触发**
自截，扫描一直跑到沙箱超时（wall **61.4s**）才被杀——即"第一道没赶上、且报告也没写出来"
的双输形态；而 `--max-time 8` 是能触发的。取 70% 后同一 1 分钟窗口 wall **43.4s** 且工具
自报 `Runtime exceeded the maximum`。**残余**：70% 是单点实测的经验值，未系统扫描触发边界；
且窗口 > 5 分钟时沙箱 300s 上限先生效（`window_minutes=8` ⇒ 工具自限时 336s 但沙箱 300s）。

### 7.14.5 依赖闭包：installer 从"单发行件"扩到"闭包"

dirsearch 是本项目**第一个依赖闭包非空**的 pip 工具。旧 pip 配方跑 `pip install --no-deps`
——**装了也跑不起来**。manifest 因此新增 `closure`（26 条依赖，逐条 `==` + sha256），
installer 新增 `_install_pip_with_closure`：逐条按 sha256 从 PyPI 元数据定位 wheel →
下载并**重算哈希比对**（不符即拒装）→ 写 `--require-hashes` 的 requirements →
`--no-index --find-links` 安装 → 生成 wrapper。

**两条纪律**：① **哈希不符即拒装**，不回落"先装上再说"；② 显式声明 `closure` 才走闭包路径
（`closure=None` ⇒ 旧行为，`sqlmap` 不受影响）。

**闭包按 musllinux 解析**：沙箱镜像是 `python:3.12-alpine`，宿主是 glibc——直接
`pip install --target` **找不到** musllinux wheel（实测 `No matching distribution found
for MarkupSafe`，根因是宿主 `sys_tags()` 里一个 musllinux 都没有），故必须
`--platform musllinux_1_2_x86_64 --only-binary=:all:` 交叉选择。**该常量与沙箱镜像耦合**，
换基础镜像必须同步改（见限制 55）。

**闭包内容的一个实测教训**：`cryptography` 最初被判为"声明但未使用"（`pyopenssl` 拉它，
而 dirsearch 源码里 `OpenSSL`/`cryptography` 零导入）——但**实际跑起来直接崩**：
`requests-ntlm → spnego → spnego._ntlm_raw.crypto → cryptography.hazmat.backends`。
**即"静态扫描源码导入"不足以下结论，必须真跑**。这是本轮最有价值的一条方法论记录。

### 7.14.6 判定面零改动

新解析器产既有 `kind="web-probe"`，走 M3a 起就在的 `_triage_candidates` 映射
（`web-probe` + 状态码 ∈ `_EXPOSED_STATUSES` ⇒ `web-exposure` 候选）。**零新增 Signal kind、
零 triage 改动、零 `GATE_MATRIX` 改动**。`web-exposure` 仍不在 `GATE_MATRIX` ⇒ 这类候选
**仍不可 Confirmed**（属 M16-c）——本轮的收益**只在发现面**。

### 7.14.7 实测（真靶 + 真沙箱，产物 `evidence/demo_dirsearch/<ts>/`）

| 项 | 实测 | 含义 |
|---|---|---|
| 限速是否落到行为 | 缺省(50)=**836.7 rps** vs 显式(2)=**2.1 rps**，**402×** | 授权不只是写进 argv |
| 时间窗（1 分钟） | wall **43.4s**，自报 `Runtime exceeded the maximum` | 第一道真赶上 |
| 峰值内存 | **35~56 MiB**（512m 的 **7~11%**） | 对照 katana `-jc` 248 / `-jc -jsl` 447 MiB ⇒ 轻量档 |
| 解析管道 | 30 词 → 5 条 `web-probe` → **5 条 `web-exposure` 候选**（坏条目 0） | 零新增 kind 成立 |
| scope 兜底 | 靶侧 42 条请求 Host 全授权（外域 0）；注入 2 条外域全拒 + `triage_out_of_scope`×2，外域候选 **0** | 主动发请求的越界面被两层挡住 |
| 自然吞吐（对照） | `-t 25` 全量 dicc.txt 12308 请求 **15s ≈ 820 rps** | **这就是"无差别爆破"的实物** |

**实现期抓到并修掉的真缺陷 2 个**：① `params` 里显式给的 2 rps 曾被构造器自己的缺省
**静默覆盖成 50**（"以为授了限速、其实没生效"）⇒ 改为预算**单一真相源** + params 夹带即报错；
② `window_minutes=1` 的 `--max-time 60` 未触发自截 ⇒ 改为窗口 ×0.7。

### 7.14.8 本里程碑明确不做

判定通道（M16-c）· `GATE_MATRIX` / 状态机铁律 / Verifier 输入边界 / 红线 3 / 红线 4 的
任何改动 · httpx/katana 回填同一套授权语义 · `sqlmap` 的 pip 路径改造 ·
**`request_budget` 写入 `command_executed` 审计（本轮未做）** · 在 DVWA 真实前端上验 dirsearch。

## 7.15 M16-c 落地注记（2026-09-29：`unauth-exposure` 判定通道 —— 形态 B + 确定性前置门）

### 7.15.1 流程：裁定先行

判定通道属「判定通道的形态变更（尤其红线 3/4）」，按 AGENTS 项目纪律第 9 条**必须先拿
维护者裁定**。故先出裁定文档（含「能否行为确认」正反论证 + 三方案 B1/B2/B3 对比），
维护者裁定选 **B1**，然后才动代码。

### 7.15.2 核心区分：把「能否行为确认」拆成两半

| 半 | 内容 | 判据性质 | 能否作证据 |
|---|---|---|---|
| **可复现** | 同一 URL，**匿名**客户端与**已认证**客户端得到**等价响应** | 响应**字节**（二值事实） | ✅ 是（唯一证据） |
| 不可复现 | 这份内容**本来就该**要求登录 | 内容语义（无二值观测量） | ❌ 否（只作报告分类） |

后半不可作证据有双重依据：① **实测**——M15 已证语义判断不稳（形对照误报 3/4 次、
`model` 臂 60/60/0/20% 区间重叠 ⇒ 不可判）；② **铁律 2**——`findings/finding.py`
硬性要求 `evidence_kinds` 含非 `status-code` 标签，而「AI 说敏感」是**结论**不是证据；
把它当证据等于打开「疑似即确认」的降级路径，撞 README「定位与边界」。

⇒ `GATE_MATRIX` 的 `behavioral_kinds` **只认前置门产物**，故**判定器判错不可能造成
误确认**（`tests/test_unauth_judge.py::test_confirmed_even_when_judge_says_not_sensitive`
把这条主张做成可执行断言）。

### 7.15.3 确定性前置门（`verify/unauth_control.py`）

三态，零 LLM：

- `exposed`：匿名 **2xx** 且（与已认证基准**逐字节相同** ‖ 相似度 ≥ 0.9）→ 暴露成立；
- `requires_auth`：匿名**非 2xx** → 资源本就要求认证 → 编排层 **Rejected**；
- `blocked`：匿名请求失败，或匿名 2xx 但内容既不同也不像 → 停 Hypothesis（不驳回不确认）。

**为什么 `blocked` 不驳回**（继承 `judge_control` 的推理）：内容「不同但不像」同样符合
「两视图不同」这一**合法且常见**形态（匿名看精简版、已认证看完整版）——把它当暴露证据是
**误报方向**。故本模块**只做「字节级肯定」与「状态码否定」**，不做任何语义肯定。

**与 `judge_control` 的方向相反（最容易踩的一处）**：两者判据形态同构（都是"已认证基准
vs 匿名对照"），但语义方向相反——`public` 在 idor 下**否定**越权（驳回）、`exposed` 在
exposure 下**肯定**暴露（确认）。**同一份响应、两个漏洞类型、结论相反**。故两者独立成模块，
且 `test_unauth_control.py::test_direction_is_opposite_to_judge_control` 用同一份输入
**显式钉住方向相反**——若后人图省事合并两处逻辑，那条测试会立刻失败。

### 7.15.4 独立敏感度判定器（`verify/unauth_judge.py`，T1）

- **输入**：**仅**过了门的响应正文，经**脱敏**（复用 `SessionConfig.secret_values()`）+
  **截断**（`MAX_JUDGE_BODY_CHARS = 8000` 字符）；送审文本落
  `unauth_judge_<id>_sent.txt`，**「判定器看到了什么」可离线复核**；
- **输出**：`{sensitive, category(枚举白名单), anchors(L<行号>), reason, confidence}`
  Pydantic 强校验；**非法即 fail-closed**（抛 `UnauthJudgeError`，调用方判 blocked；
  **注意：判定器失败是「覆盖不全」，不是「没暴露」**）；
- **红线 3 的边界（如实标注）**：判定器**读**响应正文（这是形态 B 的定义——"只看过了
  第 1 关的响应（脱敏+截断）"），但它的**输出只有结论与锚点**；
  **Verifier 的输入边界一字未改**（`extra_summary` 里只有枚举/数值/锚点，
  `test_verifier_summary_has_no_response_body` 断言响应体原文不进 prompt）。

### 7.15.5 `GATE_MATRIX` 与铁律 2 的衔接

```python
"unauth-exposure": GateRequirement(
    methods=frozenset({"unauth-equivalence-confirmed"}),
    behavioral_kinds=frozenset({"unauth-response-equivalence"}),
),
```

**为何行为类标签要具名**（而非复用笼统的 `behavioral`）：铁律 2 只要求"存在任一非
`status-code` 标签「，两者都满足；但具名让」这条 Confirmed 靠的是响应字节等价"在**证据层
可分辨**（报告与审计能据此区分来源）。既有四类的标签**不受影响**。

**`web-exposure` 仍不可 Confirmed**：它的证据是 `status-code`（`web-probe` + 状态码产出），
`GATE_MATRIX` **刻意不含**它——`test_web_exposure_still_not_confirmable` 钉住这条。

### 7.15.6 实测与未做

**已实测（替身 fetch + 替身判定器的全链路测试）**：等价 ⇒ Confirmed（四段式 + CVSS 代码
算分）；判定器判 `sensitive=false` ⇒ **仍 Confirmed**；判定器非法 ⇒ blocked；匿名被拒 ⇒
确定性 Rejected 且**零判定器调用**；匿名 2xx 不等价 ⇒ blocked；**判据陷阱**——正文含
`password` 但两视图不等价 ⇒ blocked（证明判据不落在关键词上）；两视图等价但正文无任何
敏感词 ⇒ 仍 exposed（证明不做关键词判断）。

**真靶实测（`scripts/demo_verify_unauth.py`）**：真实 `ThreadingHTTPServer` + **真实
stdlib HTTP**（靶侧日志核对 6 次请求，每端点 1 带会话 + 1 匿名）：① 有无会话同内容 ⇒
Confirmed（CVSS 7.5、4 件证据）；② 匿名 302 ⇒ Rejected（零判定器调用）；③ 匿名公开页
vs 已认证敏感 JSON（相似度 0.085）⇒ 停 Hypothesis + `verify_blocked` 审计。**中心主张
复验**：判定器判 `sensitive=false` 时真暴露照样 Confirmed。**红线 3 核查**：
`*_control.json` 均不含响应体原文，`*_sent.txt` 按设计含原文（判定器输入的可复核留痕，
非 prompt）。

**仍存的边界**：「匿名看到部分敏感内容」这类真实暴露仍不可 Confirmed（维护者裁定的
覆盖取舍，见限制 57）；POST/JSON body 型接口不在本轮范围；判定器的**真实模型行为**
未验（只验了契约：schema/fail-closed/脱敏/截断）——但它不构成证据，故不影响确认正确性。

### 7.15.6b 🔴 事后核实（2026-09-29，发布后）：本类型在生产链路不可达

第三方评审提出、独立复核确认：**`unauth-exposure` 缺生产者**。详见 AGENTS.md 已知限制 58。
要点：生产期 `vuln_type` 只由 `_triage_candidates`（`web-exposure`/`sqli`/`xss`/`idor`）
与模型通道（`ALLOWED_VULN_TYPES`）产出，**两条路都不产该类型**；全仓唯一产出点是 demo 的
**手写 seed**。故 §7.15.6 的「真靶实测」验的是**判定通道自身**，**未验「发现→验证」接通**。

**§7.15.1~§7.15.6 的设计与实测数字仍然有效**——缺的是入口那一端，不是判定端。

**修复方向**：① `web-probe` 信号确定性派生 `unauth-exposure` 候选（待决策：与
`web-exposure` 重复候选 vs 取代；scope 无会话时是否回退）；② 收敛注册点为
`VULN_REGISTRY` 单一真相源 + 守护测试「每个注册类型必须有生产者」与「发现→确认」冒烟
测试。**同批**修正了 `llm/triage.py` 里「白名单与 `GATE_MATRIX` 唯一区别是 `ssrf`」
这句过期注释（M16-c 后已是两处方向相反的差异）。

### 7.15.7 本里程碑明确不做

`web-exposure` 进 `GATE_MATRIX` · 把 AI 判定器结论当证据（撞铁律 2）· 关键词/正则敏感表
（既漏又误，且与「发现侧不靠关键词表」的既有立场冲突）· POST/表单 SSRF 式的扩展 ·
红线 3/4 的任何放松 · 既有四类的 method/证据标签改动。

### 7.16 落点守护：把「有没有接上」变成自动化断言（M17-a，2026-09-30）

§7.15.6b 记的缺陷（`unauth-exposure` 在生产链路不可达）暴露的不是一处漏写，
而是一类**结构性失效**：类型注册在六个落点（`GATE_MATRIX` / `verify-*` skill /
`profiles.py` / `Orchestrator._verify_handlers` / API 生产栈槽位 / **生产期 producer**），
**只有前五个有测试看着，第六个没有**——于是「一切都齐了、就是没接上」可以全绿通过。

**断言对象必须是生产链路，不是手写 Finding。** 本里程碑的守护测试
（`tests/test_vuln_registry.py`）就此写成两条互补的路径：

1. **生产者可达**：只写 **Signal**，让**生产代码**建 Finding——走真实 `run_triage_phase`，
   输入域穷举 `web-probe` × 全部状态码、三张提示表的**并集**每个键、`form_page` 三形态；
   可达集 = 该产出 ∪ `ALLOWED_VULN_TYPES`。**每个 `GATE_MATRIX` 键都必须落在其中。**
   这条直接对应「每个已注册类型至少有一个生产期 producer」。
2. **生产栈接线**：verify handler 名必须出现在 `OrchestratorPhases.__init__` 的
   **真实源码**（`inspect.getsource`）里——覆盖 §7.15 那个「有 handler、有 skill、
   有 profiles 登记，却没有第 5 个槽位」的出口端缺口（AGENTS.md 限制 59）。

**§7.16 的失败语义**：两个缺口在测试里是 `xfail(strict=True)`。选 strict 而非 `skip`
的理由是**修复后必须回来删标记**——若只写 `skip`，修好了也不会有人记得删，
断言就此永久失效（这正是缺陷 58 的成因之一）。

**落点清单 `VULN_LANDINGS` 的定位**：它不是第七个真相源，而是**加类型时的同步清单**
（人类可读的 producer 描述仅供失败信息定位；判定一律走真实代码），并与 `GATE_MATRIX`
键集**双向**校验。已知的非门禁类型（`web-exposure`：有产出、刻意不在矩阵、进报告
hypothesis 桶）以显式常量登记，**不做隐式豁免**——隐式豁免会让下一个类型悄悄漏掉守护。

### 7.17 `unauth-exposure` 接生产：把 §7.15 的设计真正接上（M17-b，2026-09-30）

§7.15.6b 的缺口（缺生产者）与 §7.16 新增的出口端缺口（API 生产栈无槽位）在本节一并闭合。
维护者四次裁定：**并存** · **仅 2xx** · **独立上限 10** · **无会话不派生不回退**。

**① 派生点**：`core/orchestrator.py::_triage_candidates(signal, *, session_available=False)`。
新参数**缺省 False**，故所有既有调用方（含 `tests/test_dirsearch_parser.py` 的三处直接调用）
行为逐字节不变——「能不能派生」是**策略**，由编排层按 scope 传入，纯函数不读 scope。
生产期取 `session_available = scope.session 存在且能渲染 Cookie 头`，与
`_verify_unauth` 的前置判据**同一谓词**（避免"能派生但必然 blocked"的不一致）。

**② 为什么并存**：`web-exposure`（纯 status-code 观察，铁律 2 禁止 Confirmed，进报告
hypothesis 桶）与 `unauth-exposure`（响应字节等价，可 Confirmed）**语义不同、不冗余**。
且前者是**无会话 engagement 下「哪些端点可达」的唯一记录**——取代它等于让这类扫描
丢掉全部信息类观察。两类型 `vuln_type` 分量不同 ⇒ dedup 指纹不同 ⇒ 同一端点两条 Finding。

**③ 为什么只取 2xx**：见 `_UNAUTH_EXPOSED_STATUSES` 的注释——401/403 的匿名被拒是
「要求认证」的**确定性**结局（直接 Rejected），3xx 因不跟随重定向多半 blocked，
两者都只产噪声；该类型的立论「匿名直接拿到内容」只对应 2xx。**刻意不复用**
`_EXPOSED_STATUSES`：那个集合服务的是 web-exposure 的「端点有反应」语义。

**④ 贵验证配额诚实化**：`_verify_unauth` / `_verify_ssrf` 的前置（可用预置会话）是
**结构上**的——缺它则每条候选都立刻 blocked，但旧实现在 `_prefilter_or_cap` 里
**每条各消耗一次贵验证配额**。现在 `verify_precondition_blocked()` 在配额判定**之前**
整类拦下：零配额消耗、逐条 `verify_blocked`（文案与 handler **逐字同源**）+
收尾聚合 `verify_type_unavailable` / `verify_precondition_gate`。**终态零变化**：
凡被拦者 handler 内也必然立刻 blocked。

**⑤ 验收纪律**：`scripts/demo_unauth_zero_seed.py` **零 seed**——只写 Signal，Finding 由
`run_triage_phase()` 建，再走真 `run_verify_phase()` 打真靶。这是 §7.15.6b 那条教训的
制度化落地（交接单项目纪律第 11 条）：**验收脚本若自己 seed Finding，就只验了判定端**。
原 `demo_verify_unauth.py` **保留不动**——它验的是判定通道自身，仍然有效、仍然必要。

### 7.18 `VULN_REGISTRY`：把「加一个漏洞类型」从多点同步变成一次登记（M17-c，2026-09-30）

§7.16 的守护测试解决的是「有没有接上**能被发现**」，本节解决的是「**事实**不再散落」。
两者互补：前者是断言，后者是结构。

**收敛前**：一个 `vuln_type` 的关键事实散在三处手工维护、互不校验的地方——
`GATE_MATRIX`（确认门，**兼任**类型清单）、`ALLOWED_VULN_TYPES`（模型白名单）、
`_VERIFY_PRECONDITIONS`（验证前置）。§7.15.6b 的缺陷正是这种散落的代价。

**收敛后**：`verify/gate.py::VULN_REGISTRY`（`dict[str, VulnSpec]`）是唯一真相源，
三处**全部由它派生**。落在 `gate.py` 是刻意的——它是依赖树的**叶**（只依赖
`findings` + `verify.*`），故 `llm/triage.py` 可以安全地反向 import 而不成环。

**为什么 `producer` 不进登记表**：它是**规则表**（`_triage_candidates`）的属性，
随规则表演进；同一个类型可以只走模型通道（M15 的 `ssrf`）、只走规则表
（`unauth-exposure`）、或两者都走（`sqli`/`xss`/`idor`）。把「某类型由哪个 kind
产出」记进「类型事实表」，等于把规则表的形状复制一份——那就是第二个真相源，
正是本轮要消除的东西。故生产者可达性仍由 §7.16 的**穷举守护**断言。

**机制仍在原处**（守护测试兜，限制 60 如实披露边界）：`_verify_handlers` 的
handler 方法对象、`SKILL_PROFILES` 画像、API 生产栈槽位。登记表把「加类型漏登记」
从**静默不一致**变成**测试失败**，但没有变成**编译期不可能**——这条链唯一的防线
就是那几条守护测试，**不得被削弱或跳过**。

## 8. 开发路线图



| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| M0 流程验证（1~2 周） | 不写平台代码：把 recon/scan/verify/report 5 个 skill 装进 Kimi Code，手工编排跑通一个靶场 | 全流程 SOP 跑通，skill 划分定型 |
| M1 工具底座（2 周）——已完成（2026-08-06） | L0 + L1：manifest、安装器、Docker 沙箱、scope 校验、审计日志；打通 httpx 一条工具链（nuclei 链并入 M2 一并验收） | 离线镜像可用；越界命令被拒且有日志 |
| M2 编排器（2~3 周） | skill registry、任务 DAG、模型路由、预算帽、上下文治理；补齐 M1 遗留：① 从文件读取目标（如 `httpx -l targets.txt`）的 scope 解析与校验，消除 no_targets 放行口子；② 沙箱网络出口白名单 | 单目标 recon+扫描全自动；上下文体积有上限；成本仪表盘可见 |
| M3 验证层（3 周） | 状态机、baseline 对照、3 个 verify skill（sqli/xss/lfi）、Verifier Agent、去重、误报库——**M3a 已完成（2026-08-07）**：状态机（铁律硬编码）+ 证据包/离线 show + 去重 + 确定性 triage；**M3b 已完成（2026-08-07）**：证据门 + 预置会话（凭据脱敏）+ sqlmap 接入 + Verifier（T2）+ verify-sqli 垂直切片，DVWA 实靶 Confirmed | XBEN/DVWA 上 Confirmed 发现 100% 带证据；误报率达标 |
| M4 报告引擎（1~2 周） | docxtpl 管线、叙述润色、误报附录 | 给定模板一键出报告，事实字段零手写 |
| M9a 从目标派生 scope（零手写 YAML）+ API 运行栈 restricted 出口（2026-09-22 已完成） | `compliance/derive.py` 纯确定性派生（只从种子 host、不扩张；通配符/裸 TLD/全网段 fail-closed）；`scope_paths` 变可选 + `acknowledge_authorization`（派生与授权拆开）；派生结果落盘并集生效，5 层 check_scope 与出口白名单零改动覆盖；`default_phases_factory` 默认 restricted（还清已知限制 24） | 只给 target 即可跑通；派生范围放行目标、拒绝兄弟域/后缀伪装域/范围外 IP；无授权确认 403 且零副作用；重启后派生范围仍在；出口白名单随 scope |
| M9c 发现层去锁：模型驱动假设生成 + 廉价粗筛 + 中性基准（2026-09-22 已完成） | ① 中性基准基座 `scripts/bench_triage.py`（自建 stdlib fixture，A/B 两族行为同构、唯一变量是参数名是否命中提示表；三臂消融 rules/model/rules+model；确定性 in-process 爬行，零 Docker）；② `proofhound/llm/triage.py` T1 档模型假设生成（白名单 `{sqli,xss,idor}` + 输入边界 + 接地性 + fail-closed + M6a 一次修复重试）；③ 接线 `triage_rules`/`triage_model` 双开关（model 缺省关闭，规则路径逐字节等价）；④ `proofhound/verify/prefilter.py` 廉价粗筛 + cap 移到贵验证档；⑤ M9c③ 人工闸细分（`mutating` 声明 + 闸门矩阵「模式 × 等级 × 是否改变状态」，唯一差异格 = semi_auto × L2） | 基准实测：纯规则表发现率 33.3%（漏 8/12，其中 6 条为关键词盲区）→ `rules+model` **100%**，粗筛后误报率 **0%**；新测试 87 个 + 旧 776 全绿（共 863，旧测试零改动）；粗筛实测负结果（丢弃式筛选是负收益）已收窄为建议性并锁进测试 |
| M9b 红线 4 重定义：模型身份 → 校验独立性（2026-09-22 已完成） | 删除 T1==T2 同模型启动警告（改记 `llm_tiers_share_model` 审计）；红线 4 改约束「独立 agent + 独立上下文 + 输入边界」，不约束模型身份；新增独立性锁死测试 | T1/T2 同模型下功能全通且无警告；输入白名单/超限 fail-closed/输出契约三条在同模型下依然成立；「必须用不同模型」表述全树零残留 |
| M10a 基线数字补完：真可确认 fixture + 端到端 `--live` + T2 读超时修复（2026-09-23 已完成） | ① `scripts/bench_triage.py` fixture 换真后端（sqlite 拼接注入 / 不转义反射 / 身份归属 / 真安全对照），**离线数字逐格不变**；② `--live` 附加模式跑 4 臂真实确认链路，口径 = (端点×类型)、类型错配计误报、`verify_blocked` 单列不计入分母；③ `llm/router.py` 增 `DEFAULT_TIMEOUTS`（T2 180s）+ `PROOFHOUND_<TIER>_TIMEOUT` | Confirmed 级 4 臂：精确率 **100%**、误报率 **0%**、检出率 33.3%/58.3%/25.0%/**66.7%**；T2 超时丢失从单臂 3/12 降到 4 臂合计 1/48；新测试 37 个 + 旧 853 全绿（共 890，旧测试零改动）；**明示限制**：单次采样、方差未量化（同一真 IDOR 4 臂 4 结果） |
| M11a 成本可见性：单题成本口径 + 归属（2026-09-23 已完成） | ① `llm_call` 审计补 `caller`/`finding_id`/`retry`（`llm/callmeta.py` 确定性签名分派，旧替身零改动）；② `proofhound/llm/cost.py` 纯函数聚合（调用方/阶段/Finding/档位四维各自求和 == 总数；修复重试计入主口径且可确定性单列；`estimated` 单列；旧事件归 `unknown` 不丢弃 + 出可归属比例）；③ 三处出口 CLI/API/控制台只读面板；④ `tokens_used` 与 `/cost` 口径统一 | 新测试 39 个 + 旧 890 全绿（共 **929**，旧测试零改动）；对 M10a 已产出 engagement 独立复算出与 published 表**完全相同**的数字（59,052 token / 17 次调用 / t1 12,956 + t2 46,096）；**不含** IDOR 判据实现（已裁决留 M11b，见限制 40） |
| M11b IDOR 判据收紧：未认证对照 + 确定性归属（2026-09-23 已完成） | ① 新模块 `verify/idor_control.py`（纯函数）：`judge_control` 三态（public/protected/blocked，**只否定不肯定**）+ `judge_ownership` 三态（matched/mismatched/absent，要求"归属字段名 + 值等于 reference 身份"两族同时命中，身份未知一律 absent）；② `_verify_idor` 确定性定终态（public→REJECTED、blocked→blocked、归属非 matched→REJECTED，**零额外 LLM**）并落 `idor_{id}_control.json`（三态 + 行号锚点 + 两份响应 sha256）；③ `Scope.session_third` 可选第三身份（未配则匿名对照）；④ `Verifier.review(extra_summary=...)` 只传结论 + 锚点（sqli/xss 载荷逐字节不变）；⑤ fixture：footer 改 per-endpoint 标记（**修掉硬编码凭据回声及其制造的 A/B 逐字节相同伪迹**）、IDOR 端点拒匿名（200 定长通用页） | 新测试 **40** 个（`test_idor_control.py` 28 纯函数 + `test_idor.py` M11b 编排 8 + `test_bench_fixture.py` 控制面 4）+ 旧 929 全绿（共 **969**；`test_idor.py` **披露式修正**——双会话罐头补归属字段与等长差异区、识别新对照角色，断言意图不变）；离线基准**主指标逐格不变**（33.3%/50.0%、91.7%/0.0%、100%/50.0%），「粗筛后」两列按实变化并已记录成因（新增已知限制 41） |
| M11c 重复测量与方差量化（2026-09-24 已完成） | 4 臂 × 3 遍 = 12 次臂运行（真实 T1/T2 + Docker + Chromium）→ 每臂检出率/精确率/误报率/未能判定/单题成本的分布；用**区间重叠法**判可判性 | `TRIAGE_MODEL`：TP [4,4,4]→[8,8,8]**区间不重叠 ⇒ 差异可判**，三遍**零方差**，+4 Confirmed（翻倍），代价 1.97× token ⇒ **建议默认开启**；`VERIFY_PREFILTER`：`rules` 下零效应、`rules+model` 下 [8,8,8]→[9,8,9] **区间重叠 ⇒ 不可判**，代价 1.23× token ⇒ **保持缺省关闭**；**12 次运行精确率全 100%/FP 全 0**；M10a 的"同一真 IDOR 4 臂 4 结果"不再复现（`/a/idor` 12/12 confirmed）；残余方差收窄为单端点（`/b/sqli2`）；**断代**：本批 T2=DeepSeek（与 T1 同模型），与 kimi-k3 数据不可直接比 |
| M5 产品化（按需）——M5a 已完成（2026-08-07） | **M5a ✅**：本机 Web API（FastAPI 后端，无前端）+ 自主模式三档闸门（矩阵代码化）+ 动作确认队列（持久化 + operator 审计）；待做：M5b 前端控制台（自治模式切换、确认队列、证据浏览）、MCP 暴露、持续监测、增量复测 | — |

## 9. 风险与开放问题

1. **解析器维护成本**：工具输出格式随版本漂移 → 解析器集中在 `tools/parsers/`，配版本快照与回归测试。
2. **复杂业务逻辑漏洞**仍是 LLM 短板 → 第一版以 Signal 形式交人工，不硬做。
3. **供应链安全**：工具下载源被投毒 → 白名单 + 强制哈希校验 + 优先离线镜像。
4. **法律责任**：工具仅限授权测试，scope 机制是产品级红线，不是可选项。
5. **开放问题**：Verifier 与发现端的模型组合如何选型以最大化对抗效果——M9b 已解除「必须不同模型」的硬约束（红线 4 改约束 agent 独立性），因此该问题收窄为：**模型家族多样性**与 **agent 角色/输入隔离**各自对对抗效果的边际贡献如何，以及是否需要刻意要求不同**家族**（而非仅不同型号）；误报库的模式泛化粒度——均在 M3 以实验定案。

### 9.1 远期方向（北极星，非当前里程碑承诺）

- **Security Property / Graph**：把"验证"从单条 Finding 的行为确认，升级为跨
  Finding 的安全属性推理与证据图谱——验证语义图谱化、属性级不变量校验
  （"该参数的任何输入都不得进入执行上下文"）、利用链证据关联。这是验证层的
  北极星方向。**M8b 不做任何 Graph 重构**：四段式证据结构
  （claim/method/expected/actual）只是朝向属性化验证的最小一步，且仅落在
  xss 链路（sqli 链路不动）；图谱化的数据模型与推理引擎留待后续里程碑
  单独评审。**M8c 落第二块属性化拼图**：IDOR 的双会话属性违反（属性 =
  "身份 A 不可访问身份 B 的私有对象"）已落地为写死阈值的确定性判定
  （§5.4.2 M8c 注记），仍不做任何 Graph 重构。

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
