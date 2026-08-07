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

#### 5.4.3 Baseline 对照

任何判定前先探测目标默认行为：请求随机不存在路径、发送无效参数值，建立 baseline 档案（通配路由、自定义 404、全 200 站点等）。payload 响应与 baseline 存在可归因差异才计为信号。

#### 5.4.4 Verifier Agent（对抗校验）

- 独立 Agent，唯一职责是**攻击结论**：证据是否支持？是否存在更平凡的解释？前置条件当前是否满足？
- 与发现端使用不同模型，避免同源偏见。
- 输出结构化裁定：`confirm / downgrade / reject + 理由`。

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
│   └── compliance/    # 授权、scope 校验、审计日志
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
| M3 验证层（3 周） | 状态机、baseline 对照、3 个 verify skill（sqli/xss/lfi）、Verifier Agent、去重、误报库 | XBEN/DVWA 上 Confirmed 发现 100% 带证据；误报率达标 |
| M4 报告引擎（1~2 周） | docxtpl 管线、叙述润色、误报附录 | 给定模板一键出报告，事实字段零手写 |
| M5 产品化（按需） | 本机 Web 控制台（自治模式切换、确认队列、证据浏览）、MCP 暴露、持续监测、增量复测 | — |

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
- **社区飞轮**：引擎与 skill 库分仓（`proofhound` + `proofhound-skills`），参照 nuclei-templates 模式接受社区贡献 verify skill——skill 生态是项目的长期护城河。
- **发布节奏**：M3 验证层跑通 + DVWA/XBEN 靶场 demo 后再公开发布；渠道 GitHub + 安全社区。
