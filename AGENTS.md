# AGENTS.md

> 面向 AI 编码 Agent 的项目指南。本文件基于仓库当前实际内容编写；项目已完成 M1（工具底座）、M2a（Skill 系统 + M1 遗留补强）、M2b（编排器核心）、M2c（模型路由与成本治理）、M3a（Finding 生命周期、证据包与去重）、M3b（验证执行层第一刀：证据门 + Verifier + verify-sqli 垂直切片）、M3d（发现自动化：katana 爬参 → sqli Hypothesis 自动产出）、M4（报告引擎：数据组装 + T1 叙述 + docxtpl 渲染 + 报告 CLI）与 M4.5（模板适配与叙述结构化：报告引擎驱动自定义企业模板）、M5a（Web API 与自主模式闸门：FastAPI 本机后端 + 三档自治模式动作闸门 + 确认队列）、M5b（本地 Web 控制台：纯静态零依赖 SPA + 证据包 Web 审阅 + 非回环绑定告警）、M6a（稳定性加固 + 控制台管理面）、M6b（CVSS 评分真实化：Verifier 产向量 + 代码确定性算分）。

## 项目概述

本项目是 **ProofHound**（暂定名，发布前需复查 GitHub/PyPI/Docker Hub/域名占用）——一个**自动化渗透测试 Agent 系统**。仓库包含设计文档与 M1 实现：

- `docs/design.md` —— 设计文档 v0.7（草案，状态：待评审），是整个仓库的权威输入，用途为"作为 Kimi Code 开发输入，指导从零实现"。
- `proofhound/` —— M1 工具底座（L0+L1）：Tool Manifest、安装器、Docker 沙箱、scope 校验、append-only 审计日志；M2a：L2 Skill 系统（registry + 导入安全闸）+ 两项 M1 遗留补强（文件目标 scope 解析、沙箱网络出口白名单）；M2b：L3 编排器核心（`proofhound/core/`：任务树/状态机、规划器、失败预算）+ 最小 LLM 客户端（`proofhound/llm/`）+ 确定性命令构造器（`tools/build.py`）+ 首个输出解析器（`tools/parsers/httpx_json.py`）+ Signal 模型（`findings/signal.py`）；M2c：模型路由三档 T0/T1/T2（`llm/router.py`）+ 用量计量与 Run 级 token 预算硬闸（`llm/usage.py`）+ 上下文治理（`core/context.py`：确定性压缩 + prompt 字符硬上限）+ live 演示脚本（`scripts/demo_live.py`）；M3a：Finding 数据模型与生命周期状态机（`findings/finding.py`，铁律硬编码）+ append-only FindingStore（findings.jsonl 快照追加）+ 去重指纹（`findings/dedup.py`）+ 证据包组装与离线 show（`findings/evidence.py` + `python -m proofhound.findings show`）+ 确定性 triage（`Orchestrator.run_triage_phase()`，规则表零 LLM 调用）；M3b：证据门（`verify/gate.py`，§5.4.2 矩阵代码化，fail-closed）+ 预置会话（`compliance/session.py`，Cookie/headers 挂 Scope，审计/state/日志只记 sha256 前 8 位）+ sqlmap 工具接入（pip 配方版本 pin + 强制 SHA256、PyPI 白名单源、`tools.d/<name>/lib` 隔离安装 + wrapper、manifest 新增 `image` 沙箱镜像声明、stdout 验证结论解析器配版本快照）+ Verifier Agent（`verify/verifier.py`，T2 档对抗校验，Pydantic 强校验 verdict，非法输出拒收）+ verify-sqli 垂直切片（`Orchestrator.run_verify_phase()` 确定性编排：带会话 baseline → sqlmap 确认 → 证据门 → Verifier 终审 → CONFIRMED/REJECTED），DVWA 实靶验收通过；M4：报告引擎（`proofhound/report/`：数据组装 data.py + T1 叙述 narrative.py + docxtpl 渲染 render.py + `python -m proofhound.report build` CLI + 默认模板 `templates/default_template.docx`），DVWA 产物出真实报告验收通过；M4.5：模板适配与叙述结构化（engagement extras 透传、severity_cn 中文档位、narrative_parts 三段叙述 + 单段派生、repro_text、cn_date 过滤器、evidence_index、`{{r }}` RichText 适配），自定义企业模板验收通过；M6b：CVSS 评分真实化（`verify/cvss.py` 纯 stdlib 实现 FIRST v3.1 官方 base 公式 + roundup，向量严格解析 fail-closed；Verifier verdict 扩展 `cvss_vector`/`cvss_rationale`——confirm 缺/非法向量即非法裁决、无降级路径，LLM 给的分数字段一律忽略；置态时代码算分覆盖 triage 种子 severity；报告层仅 Confirmed 透传 cvss 字段，默认模板加条件 CVSS 行）；其余分层（infra）仅有占位目录，属后续里程碑。
- `proofhound/api/` + `proofhound/autonomy.py` —— M5a：本机 Web API（FastAPI 应用工厂 `create_app(workspace_root)` + 后台执行器 `EngagementRunner`：一 engagement 一线程，状态机 created→scanning→triaging→verifying→confirming（可往返）→done/failed，全量写审计；API 层为编排器薄壳，阶段复用 run_scan/triage/verify_phase）+ 自主模式引擎（AutonomyMode 三档 supervised/semi_auto 默认/unattended；AutonomyGate 按动作风险等级 L0/L1/L2 裁定 auto/confirm/forbidden，未知等级 fail-closed；切换单向收紧自由、放宽须显式 operator 并记 autonomy_mode_changed；不可旁路声明：任何模式下 scope/预算/脱敏/审计永远生效）+ 动作确认队列（内存态 + confirmations.jsonl 追加持久化，重启可恢复，approve/reject 记 action_approved/action_rejected，超时默认拒绝）；M5b 起 `proofhound/api/static/` 内嵌纯静态 Web 控制台（FastAPI 挂载 `/` 与 `/static/*`，手写 HTML/CSS/原生 JS，零依赖零构建链、完全离线可用）；M6a 起附加管理面（`proofhound/api/management.py`：skill 上传/编辑/删除 + `scopes/` 文件 CRUD + workspace 级管理审计 `management.jsonl`，控制台技能/授权视图）。
- `skills/` —— 内置 skill 库，目前已有 `web-scan`（httpx SOP）与 `verify-sqli`（SQL 注入行为验证 SOP，risk_level L2）。

系统针对现有编排型 AI 渗透工具（以 PentAGI 为代表）的三大痛点设计：误报泛滥、速度慢、成本高。核心设计哲学是"**证据为王、验证驱动**"：一切候选发现默认为假，必须通过验证层状态机和证据门才能进入报告。

三大功能目标（F1~F3）：

1. **可导入 Skill**：采用 Agent Skills 开放规范（SKILL.md），支持本地目录、Git 仓库、内部 registry 三种导入来源。
2. **工具自管理**：本地预置工具优先；缺失工具按配方自动安装（白名单源 + 强制 SHA256 校验）；全程 Docker 沙箱执行。
3. **模板化报告**：用户提供 docx/html 模板自动出报告；事实性内容全部来自结构化数据，LLM 只做叙述润色。

## 仓库现状与开发阶段

- **M1（2026-08-06）、M2a、M2b、M2c、M3a、M3b（2026-08-07）、M3d、M6a、M6b（2026-08-08）已完成**：`pyproject.toml`、pytest 测试套件已就位；M2a 交付 L2 Skill 系统（`proofhound/skills/`：manifest 强校验、registry、导入安全闸）、scope 文件目标解析（`httpx -l targets.txt` 逐行校验，任一行越界即拒）、no_targets 默认拒绝、沙箱网络出口白名单（`proofhound/tools/egress.py`，默认 restricted）；M2b 交付 L3 编排器核心（任务树/DAG + 节点状态机、规划器——结构化 JSON 计划经 Pydantic schema + 语义双层校验、失败预算 + 规则表失败分类、最小 LLM 客户端，OpenAI 兼容、配置走 .env）并打通"web-scan → 计划 → 沙箱 httpx → Signal 落盘 → 全链路审计"最小链路；M2c 交付模型路由（三档 T0/T1/T2 独立配置、规划走 T1、T1==T2 同模型启动警告——红线 4）、用量计量（`llm_call` 审计；响应无 usage 按字符估算并标 estimated）与 Run 级 token 预算硬闸（调用前检查，超限停止规划循环、节点 blocked、记 `llm_budget_exceeded`，与 scope 同级不可绕过）、上下文治理（Signal 摘要按 kind 聚合压缩、计数不丢；prompt 字符硬上限，超则任务 failed 记 `context_overflow`，禁静默截断）；M3a 交付 Finding 生命周期状态机（Signal→Hypothesis→Reproduced→Confirmed + Rejected，铁律硬编码：version-cve 型与纯 status-code 证据永远禁止 Confirmed，迁移记 `finding_state` 审计）、去重指纹（sha256 规范化资产+漏洞类型+参数，同指纹合并记 `finding_deduplicated`）、证据包与"出处可调出"（`evidence/findings/<id>/`：证据原文 + sha256 manifest + finding.json，`python -m proofhound.findings show` 离线调出，纯文件查询）、确定性 triage（scan Signals 经规则表映射建/并 Finding 置 Hypothesis，落 findings.jsonl，零 LLM 调用）；M3b 交付验证执行层第一刀：证据门（`verify/gate.py`：sqli 要求 method ∈ {sqlmap-confirmed, boolean-diff, time-blind-diff} 且 evidence_kinds 含 behavioral，未知类型 fail-closed，与状态机铁律双层防守）、预置会话（`Scope.session`，构造器注入 `httpx -H`/`sqlmap --cookie`，LLM 只声明 `with_session` 不碰凭据；Cookie 在审计/state/日志中只记 sha256 前 8 位，专项测试断言全审计链无原文）、sqlmap 接入（`tools/manifests/sqlmap.yaml`：pip 配方 `sqlmap==1.10.8` + SHA256 + PyPI 白名单源，隔离装进 `tools.d/sqlmap/lib`；构造器强校验 level≤3/risk≤2/`--batch` 恒在；`SandboxRunner.run(image=...)` 按次覆盖沙箱镜像为 python:3.12-alpine）、Verifier Agent（`verify/verifier.py`：T2 档 kimi-k3，输入仅结构化摘要+证据包索引+diff 摘要——红线 3，输出 Pydantic 校验 confirm|reject，非法 verdict 拒收 fail-closed，记 `verifier_verdict`）、verify-sqli 垂直切片（`skills/verify-sqli/SKILL.md` L2 + `Orchestrator.run_verify_phase()`：Hypothesis→带会话 baseline→sqlmap 确认→证据入包（behavioral 标签/method/复现步骤）→REPRODUCED→Verifier 终审→CONFIRMED/REJECTED；Confirmed 三要件=行为证据∧证据门∧Verifier confirm）+ 种子入口（`scripts/seed_finding.py`）+ DVWA 实靶验收（`scripts/demo_verify_dvwa.py`：确定性 admin/password 登录拿 Cookie、security=low，正例 Confirmed、反例 version-cve 铁律拦截、show 离线调出全要素）；M3d 交付发现自动化切片（katana v1.7.0 binary 配方 GitHub release zip + 强制 sha256，装 `tools.d/katana/`，alpine:3.20 运行；构造器恒在 `-jsonl -silent -nc -fs rdn -cos "(?i)(logout|logoff|signout|signoff|phpids)"`、永不产 `-o`，depth/concurrency/rate_limit 硬上限；`tools/parsers/katana_jsonl.py` 对带查询串 GET 端点产 `param-endpoint` Signal + 分支 B 从 `response.body` 用 html.parser 合成 GET 表单查询 URL（无 value 字段填占位 1）——katana 默认不自动填充表单、`-aff` 副作用不可控不采用；triage 重构 `_triage_candidates`：web-probe 规则逐字段不变，param-endpoint 按 query 键精确匹配 `_SQLI_PARAM_HINTS`（约 20 个）展开 sqli 候选（severity=medium、evidence_kind=`crawl-endpoint`、param=键），dedup_key 补 param 分量，每 engagement 新建 sqli 上限 20 记 `triage_capped`，建/并前 check_scope 丢弃记 `triage_out_of_scope`；新 skill `skills/recon-crawl/`（L1，katana）；`OrchestratorPhases.scan_skills` 多 scan skill 逐 skill 过自主模式闸门 + 旧式单 skill phases `getattr` 回退零改动；DVWA 零种子全链路验收 `scripts/demo_discovery_dvwa.py`）；M4 交付报告引擎（`report/data.py`：findings.jsonl + 证据包 → ReportContext 四桶分桶（confirmed/conditional/hypothesis/rejected）+ 证据索引 + engagement 派生；`report/narrative.py`：T1 叙述生成，段落绑定 finding_id/固定章节键、无锚文字全量拒收，落 `Finding.narrative` + `narrative_sections.json` 并记 `narrative_generated`，BudgetExceededError 上抛；`report/render.py`：docxtpl + Jinja2 StrictUndefined + autoescape；`python -m proofhound.report build [--no-llm]`；`scripts/make_default_template.py` 生成默认模板；`scripts/demo_report.py` DVWA 产物验收通过）；M4.5 交付模板适配与叙述结构化（engagement extras 透传、severity_cn 中文档位、narrative_parts 三段叙述 + 单段 narrative 确定性派生（旧字符串格式兼容）、repro_text 编号复现文本、cn_date 过滤器、evidence_index 扁平证据索引、`{{r }}` RichText 渲染适配；`scripts/demo_report_enterprise.py` 自定义企业模板验收通过）；M5a（2026-08-07）交付本机 Web API 与自主模式闸门（`proofhound/autonomy.py`：AutonomyMode 三档 + AutonomyGate 闸门矩阵，supervised L1/L2 confirm、semi_auto L2 confirm、unattended 全 auto，未知等级 forbidden；切换单向收紧自由、放宽须显式 operator 记 `autonomy_mode_changed`；不可旁路声明写进 docstring 与测试；`proofhound/api/`：FastAPI `create_app(workspace_root)` + EngagementRunner 后台线程状态机 + 确认队列 confirmations.jsonl 持久化重启可恢复 + 报告/审计/证据端点，错误统一 403 scope_violation/402 budget_exceeded/409 invalid_state/404，cookie 永不进响应体、run 前目标重新过 check_scope、模板限 templates/ 内；`tests/test_autonomy.py` + `tests/test_api.py` 共 37 个新测试，全量 365 绿；`scripts/demo_api.py` DVWA 真实链路验收通过）；M5b（2026-08-08）交付本地 Web 控制台（`proofhound/api/static/` 纯静态零依赖 SPA，FastAPI 挂载 `/`：任务列表/创建（cookie password 框提交即清、三档模式中文说明）、任务详情（状态条 + 自治模式切换器放宽弹 operator 确认框、确认队列置顶警示 + 超时倒计时、Findings 看板含 rejected 灰显归因、证据包查看器全文行号 + 锚点高亮 + sha256、审计流着色 tail、报告区模板下拉 + narrative 开关 + 下载）、健康页（闸门矩阵 3×3 + 版本），轮询 2.5s 页面不可见暂停、零 Web 存储、全 textContent 渲染；后端附加式新增：证据文件全文只读端点（manifest 白名单 + 防穿越 + 行尾归一化对齐锚点 + 2MiB 截断）、`GET /api/templates`、`/api/health` 加 version/confirm_timeout、`__main__` 非回环绑定 stderr 醒目告警；`tests/test_console.py` 15 个新测试，全量 381 绿；`scripts/demo_console.py` 真实 uvicorn + DVWA 验收通过）；M3d（2026-08-08）交付发现自动化切片（katana 接入 + recon-crawl skill + triage param-endpoint 扩展 + runner 多 scan skill，细节见上条项目概述与 docs/design.md §5.4.1 M3d 注记；新测试 21 个全绿 + 旧 381 全绿共 402，其中 test_build.py 注册表断言一行沿用 M3b 先例更新；`scripts/demo_discovery_dvwa.py` DVWA 零种子全链路验收通过）；M6a（2026-08-08）交付稳定性加固 + 控制台管理面（`llm/repair.py`：T1 规划/T1 叙述/T2 Verifier 三处结构化输出统一一次修复重试——携带原始输出+错误描述追问，二次失败走原 plan_rejected/NarrativeError 零写入/VerifierError fail-closed 语义，预算硬闸覆盖重试，记 `llm_repair_attempt`；`api/management.py` + 管理端点：skill 上传/编辑/删除——zip ≤1MiB 防穿越单顶层目录、schema + required_tools ⊆ 构造器注册表校验、all-or-nothing 零写入、内置=resolve 逃出 workspace 的符号链接 skill（DELETE 409、PUT copy-on-edit 绝不顺链接写仓库）、registry 按请求重解析热重载；scope 约定目录 `scopes/` CRUD——文件名白名单 + CIDR/端口逐条校验 + session 键拒绝 + 目录外 404；workspace 级管理审计通道 `management.jsonl`；控制台技能/授权两视图（纯 textarea 零依赖）+ 创建任务 scope 改下拉多选（API 契约不变）；`seed_finding.py` 退役标记；新测试 55 个，全量 457 绿）；M6b 交付 CVSS 评分真实化（`verify/cvss.py`：纯 stdlib 实现 FIRST v3.1 官方 base 公式与 roundup、基准向量测试坐实，向量严格解析 fail-closed——缺/重/未知/temporal 指标、非法值、错版本一律拒绝、顺序宽容；Verifier verdict 扩展 `cvss_vector`/`cvss_rationale`——confirm 缺/非法向量 = 非法裁决 fail-closed 无降级，reject 不得携带，schema 无分数字段、LLM 给的数字一律忽略，对抗 SOP 增补"按证据定指标、不按漏洞类型套模板"；编排层置态时代码算分写入 `Finding.cvss_vector`/`cvss_score` 并覆盖 triage 种子 severity——**Confirmed 严重级不再是种子数据**（占位 `cvss` 标量退役，历史 Finding 不回填）；报告层仅 Confirmed 透传 cvss 字段（非 Confirmed 不展示分数、旧数据 None 容忍），默认模板详细发现章加条件 CVSS 行，`verifier_verdict` 审计携带向量）；尚无统一 engagement CLI（M1~M5a 交互为 python -m 模块入口 + HTTP API，M5b 起另有浏览器控制台）、成本仪表盘/模型自动降级（M2c 仅有审计事件）、M3 其余切片（baseline 完整档案、verify-xss/verify-lfi——M3c 预留、LLM triage、误报库）与 M5b 之后的模块（前端控制台、MCP 暴露、持续监测），也没有 CI、lint 配置。
- 一切实现工作都应以 `docs/design.md` 为准。修改设计决策时，同步更新该文档。
- 开发路线图（文档 §8）：

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| M0 流程验证（1~2 周） | 不写平台代码：把 recon/scan/verify/report 5 个 skill 装进 Kimi Code，手工编排跑通一个靶场 | 全流程 SOP 跑通，skill 划分定型 |
| M1 工具底座（2 周）——已完成（2026-08-06） | L0+L1：manifest、安装器、Docker 沙箱、scope 校验、审计日志；打通 httpx 一条工具链 | 离线镜像可用；越界命令被拒且有日志 |
| M2 编排器（2~3 周）——M2a、M2b、M2c 已完成（2026-08-07） | skill registry（M2a ✅）、任务 DAG + 规划器 + 失败预算 + 最小 LLM 客户端（M2b ✅）、模型路由 + 预算硬闸 + 上下文治理（M2c ✅；成本仪表盘未做，仅有 llm_call 审计事件）；M1 遗留补强（M2a ✅）：文件目标 scope 解析、沙箱网络出口白名单 | 单目标 recon+扫描全自动；上下文体积有上限；成本仪表盘可见 |
| M3 验证层（3 周）——M3a、M3b 已完成（2026-08-07） | M3a ✅：Finding 生命周期状态机（铁律硬编码）、证据包与离线 show、去重指纹、确定性 triage（零 LLM 调用）；M3b ✅：证据门（verify/gate.py）、预置会话（Cookie 脱敏）、sqlmap 接入（pip pin + SHA256）、Verifier Agent（T2）、verify-sqli 垂直切片（run_verify_phase），DVWA 实靶 Confirmed；待做：baseline 完整档案、verify-xss/verify-lfi（M3c 预留）、LLM triage、误报库 | XBEN/DVWA 上 Confirmed 发现 100% 带证据；误报率达标 |
| M3d 发现自动化切片——已完成（2026-08-08） | katana 接入（binary 配方 GitHub release zip + 强制 sha256 + tools.d 隔离，构造器恒在 `-fs rdn` + `-cos` 状态变更类（登出/IDS 开关）端点、永不产 `-o`）+ `recon-crawl` skill（L1）+ katana_jsonl 解析器（带查询串 GET 端点产 param-endpoint Signal + 分支 B 从 response.body 合成 GET 表单查询 URL，无 value 填占位 1）+ triage 扩展（`_triage_candidates`：`_SQLI_PARAM_HINTS` 启发式键名展开 sqli 候选、dedup 补 param 分量、每 engagement 上限 20 记 `triage_capped`、建/并前 check_scope 记 `triage_out_of_scope`）+ runner 多 scan skill（`OrchestratorPhases.scan_skills` 逐 skill 过闸 + 旧接口 getattr 回退）；verify-sqli 流水线零改动直接消费 | 新测试 21 个全绿 + 旧 381 全绿（共 402，含 test_build.py 一行注册表断言沿用 M3b 先例更新）；`scripts/demo_discovery_dvwa.py` DVWA 零种子全链路：katana 爬行 → sqli Hypothesis 自动产出（asset 含 /vulnerabilities/sqli/、param=id）→ L2 批准 sqli/id、拒绝其余 → sqlmap+Verifier→Confirmed |
| M4 报告引擎（1~2 周）——已完成（2026-08-07） | docxtpl 管线（render.py + 默认模板 ✅）、叙述润色（narrative.py T1 档，段落绑定 finding_id、无锚拒收 ✅）、误报附录（rejected 桶 + rejection_reason ✅）；PDF 管线未做 | 给定模板一键出报告，事实字段零手写 |
| M4.5 模板适配与叙述结构化——已完成（2026-08-07） | engagement extras 透传、severity_cn 中文档位、narrative_parts 三段叙述（单段 narrative 确定性派生、旧字符串格式兼容）、repro_text 复现文本、cn_date 过滤器、evidence_index 扁平证据索引、`{{r }}` RichText 渲染适配 | 自定义企业模板出真实报告（封面/时间/风险项/附录 A B/流程章读回自检通过），default_template 渲染回归不变 |
| M5a Web API 与自主模式闸门——已完成（2026-08-07） | FastAPI 本机后端（仅 API 无前端，`proofhound/api/` + `python -m proofhound.api`）+ 自主模式三档闸门（`proofhound/autonomy.py`：supervised/semi_auto/unattended × L0/L1/L2 矩阵代码化，fail-closed，切换审计 `autonomy_mode_changed`）+ 动作确认队列（confirmations.jsonl 持久化、重启可恢复、operator 审计 action_approved/action_rejected、超时默认拒绝）+ engagement 后台执行器（状态机全量审计，阶段复用编排器） | 新测试 37 个全绿 + 旧 328 全绿（共 365）；DVWA 真实链路：semi_auto 全流程零确认自动出报告 + L2 阻塞→API 批准→Confirmed |
| M5b 本地 Web 控制台——已完成（2026-08-08） | 纯静态零依赖 SPA（`proofhound/api/static/`，手写 HTML/CSS/原生 JS，无 npm/CDN/外部资源，完全离线可用）挂载于 `/`：任务列表/创建 + 任务详情（状态条/自治模式切换/确认队列审批 + 倒计时/Findings 看板/证据包查看器/审计流/报告区）+ 健康页三视图，轮询 2.5s 不可见暂停；后端附加式新增（旧契约零改动）：证据文件全文只读端点（manifest 白名单 + resolve 防穿越 + 行尾归一化对齐锚点 + 2MiB 截断头）、`GET /api/templates`、health 加 version/confirm_timeout、`__main__` 非回环绑定醒目告警 | 新测试 15 个全绿 + 旧 366 全绿（共 381）；`scripts/demo_console.py` 真实 uvicorn + DVWA：Part A semi_auto 全流程出报告 + Part B L2 阻塞→批准→Confirmed→证据逐文件 sha256/锚点核对 + 全程响应体无 cookie 原值 |
| M6a 稳定性加固 + 控制台管理面——已完成（2026-08-08） | ① LLM 结构化输出修复重试（`proofhound/llm/repair.py`：T1 规划/T1 叙述/T2 Verifier 三处统一接入，校验失败携带原始输出+错误描述追问一次，全程最多 1 次；重试 token 照常计量、预算硬闸覆盖重试；二次失败抛同类型异常走原失败语义（plan_rejected/NarrativeError 零写入/VerifierError fail-closed）不变；记 `llm_repair_attempt{tier,caller,error_type,result}`）；② Skill 管理面（`proofhound/api/management.py` + `GET/POST /api/skills`、`GET/PUT/DELETE /api/skills/{name}`：zip ≤1MiB、防穿越、单顶层目录、必含 SKILL.md、schema + required_tools ⊆ 构造器注册表、all-or-nothing 零写入；内置=resolve 逃出 workspace 的符号链接 skill，DELETE 409、PUT copy-on-edit 绝不顺链接写仓库；registry 按请求重解析热重载）；③ Scope 管理面（`workspace/scopes/` 约定目录，`GET/POST/PUT/DELETE /api/scopes`：文件名白名单 + CIDR/端口逐条校验 + session 键拒绝 + 目录外 404）；④ 管理审计通道 `management.jsonl`（skill_imported/skill_updated/skill_deleted/scope_created/scope_updated/scope_deleted 含 sha256，append-only）；⑤ 控制台技能/授权两视图（纯 textarea 零依赖）+ 创建表单 scope 下拉多选（API 契约不变）；⑥ `seed_finding.py` 退役标记 | 新测试 55 个全绿 + 旧 402 全绿（共 457）；`scripts/demo_management.py`（TestClient，无需 DVWA/Docker/LLM）：上传→列表→编辑（含非法保存被拒）→内置 409/copy-on-edit（仓库 sha 不变）→新建 scope→下拉数据源断言→创建 engagement→删除→management.jsonl 事件原文打印 |
| M6b CVSS 评分真实化——已完成（2026-08-08） | ① CVSS v3.1 计算器（`proofhound/verify/cvss.py`，纯 stdlib 零新依赖：官方 base 公式 + 官方 roundup，基准向量测试坐实；向量严格解析 fail-closed——缺/重/未知/temporal 指标、非法值、错版本一律拒绝，指标顺序宽容；分数→严重级按规范定性分级映射）；② Verifier 裁决扩展（`cvss_vector`/`cvss_rationale`：confirm 必须带合法向量、否则整个 verdict 非法 fail-closed 无"无分数确认"降级，reject 不得携带；schema 无分数字段、多余键忽略——LLM 只产向量不产数字；对抗 SOP 增补"按证据定指标、不按漏洞类型套模板"）；③ Finding 置态（confirm 分支代码算分写入 `cvss_vector`/`cvss_score` 并覆盖 triage 种子 severity——Confirmed 严重级不再是种子数据；占位 `cvss` 标量退役，历史不回填；`verifier_verdict` 审计携带向量）；④ 报告数据层（仅 Confirmed 透传 cvss 字段、非 Confirmed 恒 None、旧数据容忍）+ 默认模板条件 CVSS 行（`is not none` 判空，0.0 合法） | 新测试 13 个函数（参数化共 40 用例）全绿 + 旧 457 全绿（共 497；5 处旧罐头 confirm 回复按新契约补合法向量，沿用 M3b/M3d test_build.py 先例、断言零改动）；`scripts/demo_cvss_dvwa.py` DVWA 全链路实靶：Confirmed 携带合法向量 + 代码算分 + severity == 算分映射（覆盖种子值，不预设档位——按证据定指标）+ verifier_verdict 审计含向量 + 报告读回 CVSS 行 |
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
.venv/bin/python scripts/demo_live.py                 # 正常链路：T1 真实调用 + 沙箱 httpx 打本地靶标 + M3a triage 建 Finding
.venv/bin/python scripts/demo_live.py --max-tokens 0  # 演示预算硬闸：首次调用前即被闸（llm_budget_exceeded）
.venv/bin/python -m proofhound.findings show <finding_id> --dir evidence/demo_live/<时间戳>  # 离线调出完整证据包（纯文件查询，不碰网络/LLM）
```

M3b DVWA 实靶验证演示（真实 T2 终审，产物落 `evidence/demo_verify/`）：

```bash
.venv/bin/python scripts/demo_verify_dvwa.py          # 自动起 DVWA 容器 → 确定性登录拿 Cookie（security=low）
                                                      # → 种子正/反例 → run_verify_phase → Confirmed + 铁律反例
                                                      # → show 离线调出全要素 + 全产物 Cookie 脱敏自检
.venv/bin/python scripts/seed_finding.py --dir <evidence_dir> --asset <url> --vuln-type sqli [--param id]  # 手工播种 Hypothesis（已退役标记：M3d 起发现自动化，仅供旧演示复现 verify 路径）
```

`.env` 需 `PROOFHOUND_T2_*`（Verifier，kimi-k3）；DVWA 用 `vulnerables/web-dvwa` 镜像（不可达时脚本自动起容器，端口取 `--dvwa-url`，默认 8080）；sqlmap 经 pip 配方（版本 pin + SHA256）隔离装入 `tools.d/sqlmap/lib`，沙箱运行镜像 `python:3.12-alpine`。

M4 报告引擎演示（真实 T1 叙述，产物落 `evidence/demo_report/`）：

```bash
.venv/bin/python scripts/make_default_template.py                # 重新生成 templates/default_template.docx（全标签参考模板）
.venv/bin/python -m proofhound.report build --dir <evidence_dir> --out <docx> [--template <docx>]  # 叙述版（.env 需 PROOFHOUND_T1_*）
.venv/bin/python -m proofhound.report build --dir <evidence_dir> --out <docx> --no-llm             # 跳过叙述生成（槽位留占位）
.venv/bin/python scripts/demo_report.py [--dir evidence/demo_verify/<时间戳>]  # 端到端验收：复制 DVWA 产物 → 补齐 Rejected/Hypothesis 矩阵
                                                                             # → no-llm 对照 + T1 叙述版 → python-docx 读回自检
.venv/bin/python scripts/demo_report_enterprise.py [--dir evidence/demo_verify/<时间戳>]  # M4.5 验收：engagement.json 补 extras
                                                                             # → 自定义企业模板 T1 叙述版 + default_template 对照 → 读回自检
```

engagement 元信息：可选 `<evidence_dir>/engagement.json`（`{"target","scope","started_at","finished_at"}`，字段可缺省）；缺字段自动派生（target 取 findings 资产最高频 host，时间窗取 audit.jsonl 首/末条 ts）。M4.5 起允许任意额外键（company_name/system_name/report_date 等）原样透传进渲染上下文（extras 只进模板，不进叙述 prompt）。

M5a Web API 与自主模式演示（产物落 `evidence/demo_api/`）：

```bash
.venv/bin/python -m proofhound.api --workspace . [--port 8000] [--host 127.0.0.1]  # 本机 API（只绑 localhost 红线）
.venv/bin/python scripts/demo_api.py                 # DVWA 真实链路：Part A semi_auto 全流程零确认自动出报告
                                                     # + Part B L2 verify 阻塞→API 批准→sqlmap→Verifier→Confirmed
.venv/bin/python scripts/demo_api.py --skip-l2       # 仅 Part A（Part B 需 Docker + PROOFHOUND_T2_*）
```

API workspace 约定：目录内含 scope YAML、`templates/`、`skills/`、`tools.d/`；engagement 落 `<workspace>/engagements/<id>/`（api.json 元数据 + session.json 0600 + audit.jsonl + findings + confirmations.jsonl + report.docx）。确认队列等待超时 `--confirm-timeout`（默认 300s，超时默认拒绝记 action_rejected operator=system）。

M5b Web 控制台演示（产物落 `evidence/demo_console/`）：

```bash
.venv/bin/python -m proofhound.api --workspace . [--port 8000]   # 启动后浏览器开 http://127.0.0.1:8000/
.venv/bin/python scripts/demo_console.py                 # 真实 uvicorn 子进程 + DVWA：Step0 静态面 + Step1 非回环告警
                                                         # + Part A semi_auto 全流程出报告 + Part B L2 批准→Confirmed→证据审阅
                                                         # + Step C 全程响应体 cookie 防泄漏断言
.venv/bin/python scripts/demo_console.py --skip-l2       # 仅 Step0/1 + Part A（Part B 需 Docker + PROOFHOUND_T2_*）
.venv/bin/python scripts/demo_console.py --serve         # 自动检查后保持服务运行，供浏览器手动验收
```

M3d 发现自动化演示（零种子，产物落 `evidence/demo_discovery/`）：

```bash
.venv/bin/python scripts/demo_discovery_dvwa.py          # 全链路（需 T1+T2+Docker）：带 cookie 创建 semi_auto
                                                         # → katana 沙箱爬行 → triage 自动产出 sqli Hypothesis
                                                         # → L2 确认队列批准 sqli/id、拒绝其余 → sqlmap+Verifier
                                                         # → Confirmed + 证据包 katana 出处 + 脱敏自检
.venv/bin/python scripts/demo_discovery_dvwa.py --skip-l2  # 只验到 sqli Hypothesis 自动产出（仅需 T1）
```

katana 经 binary 配方（版本 pin + 强制 SHA256）装入 `tools.d/katana/`；爬参只产 Hypothesis，Confirmed 仍只能经 verify-sqli 行为验证 + 证据门 + Verifier。

M6a 管理面演示（TestClient，无需 DVWA/Docker/LLM，产物落 `evidence/demo_management/`）：

```bash
.venv/bin/python scripts/demo_management.py               # 上传 demo skill → 列表出现 → 编辑保存（含一次非法保存被拒）
                                                          # → 内置删除 409 / copy-on-edit（仓库文件 sha256 不变）
                                                          # → 新建 scope → 下拉数据源断言 → 用该 scope 创建 engagement
                                                          # → 删除 skill 与 scope → management.jsonl 全事件原文打印
```

M6b CVSS 评分实靶演示（复用 demo_discovery 骨架，需 T1+T2+Docker，产物落 `evidence/demo_cvss/`）：

```bash
.venv/bin/python scripts/demo_cvss_dvwa.py                  # discovery 全链路 → Confirmed 断言：cvss_vector 合法 +
                                                          # cvss_score == 代码算分 + severity == 算分映射（覆盖种子值，不预设档位）
                                                          # → verifier_verdict 审计含向量 → 报告读回 CVSS 行 + 脱敏自检
```

## 报告模板变量契约（M4/M4.5，§5.7）

docx 模板用 docxtpl（Jinja2 语法），渲染环境 **StrictUndefined**（引用契约外变量即报错）且替换值做 XML 转义（`autoescape=True`）。docxtpl 布局纪律：

- **表格/附录循环标签独占行**：`{%tr ... %}/{%p ... %}` 标签必须**独占表格行/段落**（整行/整段被替换为标签），行内 `{{ }}` 与 `{% if %}` 不受限；
- **`{{r }}` 必须配 RichText**：docxtpl 会把 `{{r }}` 的值插到 run 之外，**纯字符串整段丢失**（0.20.2 实测）——渲染器自动扫描模板 `{{r }}` 标签、按点路径末段键名把 context 的字符串值包装成 RichText（`\n` → 换行，`& < >` 内部转义），模板直接用 `{{r f.repro_text }}` 即可。

可用变量：

- `engagement.target` / `engagement.scope` / `engagement.started_at` / `engagement.finished_at`（可为 null）；**M4.5 extras**：engagement.json 任意额外键原样透传（如 `engagement.company_name` / `engagement.system_name` / `engagement.report_date`，缺键即 StrictUndefined 报错）
- `summary.confirmed` / `summary.conditional` / `summary.hypothesis` / `summary.rejected` / `summary.severity_counts`（dict，confirmed 按严重级计数）
- `confirmed_findings[]` / `conditional_findings[]`（Reproduced 未 Confirmed）/ `hypothesis_findings[]` / `rejected_findings[]`（误报附录数据源），每项：
  - `id, state, title, vuln_type, severity, severity_cn`（M4.5 中文档位：严重/高/中/低/提示，未知原样）`, asset, param, preconditions[], confidence, evidence_kinds[]`
  - `narrative`（叙述槽位，可为 null；模板用 `{{ f.narrative or '占位' }}`）、`narrative_parts`（M4.5 三段叙述 `{description, impact, remediation}`，可为 null；引用其子键须先确认叙述已生成）、`rejection_reason`（可为 null）
  - `repro_text`（M4.5 编号拼接复现文本，`\n` 连接，无步骤为空串；配 `{{r f.repro_text }}` 富文本换行）
  - `cvss_vector` / `cvss_score`（M6b：CVSS v3.1 向量 + 代码确定性算分；仅 Confirmed 桶有值，其余桶与旧 engagement 数据为 null；条件渲染须 `is not none` 判空——0.0 是合法值）
  - `verification.{method, evidence_refs[], baseline_diff, reproduction_steps[], verified_by, verified_at}`（可为 null，用 `{%p if f.verification %}` 守卫）
  - `verifier.{model, verdict, reason, cvss_vector, cvss_rationale}`（可为 null；后两者 M6b 起，reject 为 null）
  - `evidence_pack.{pack_dir, assembled, entries[]}`；`entries[]` = `{file, sha256, source_ref, line_anchor, missing}`（**注意是 entries 不是 items**：dict 的 `.items` 方法会遮蔽 Jinja 属性解析）
- `sections.overview` / `sections.remediation`（固定章节叙述，键恒在、值可为 null）
- `evidence_index[]`（M4.5 扁平证据索引：confirmed+conditional 全部条目，稳定排序），每项 `{finding_id, file, sha256, source_ref, line_anchor}`
- 过滤器 `cn_date`（M4.5：ISO 时间 → 「2026年8月7日」，空值 → 空串，非 ISO 原样返回），用法 `{{ engagement.started_at | cn_date }}`

参考实现即 `templates/default_template.docx`（尾部附同样契约说明页），由 `scripts/make_default_template.py` 生成、可入库重现。

## 项目纪律与环境

1. 里程碑纪律：一次只实现当前里程碑的内容，未经用户确认不提前实现后续里程碑的模块。
2. 环境注记：开发环境为 WSL（Linux），项目根 `~/proofhound`，Docker 为 WSL 内引擎，`/var/run/docker.sock` 原生可用；镜像拉取走 daemon 级代理（systemd drop-in 已配置），容器不继承任何代理。
3. 仓库卫生：.env、API 密钥、evidence/ 目录内容永不入库，.gitignore 必须包含 .env、evidence/ 和 engagements/（M5a API 运行目录，含 session.json 凭据）。

## 已知限制（M2a/M2c/M3a/M3b/M4/M4.5/M5a 遗留，后续里程碑处理）

1. **目标文件不挂进容器**：`httpx -l targets.txt` 的目标文件只在 scope 校验阶段于宿主侧读取；把目标文件（只读）挂载进容器属编排器职责，M2 后续切片处理。
2. **出口白名单仅覆盖 HTTP(S)**：restricted 模式下 HTTP(S) 流量经宿主机白名单正向代理强制出站；非 HTTP 原始 TCP 被 internal 网络整体阻断（fail-closed）；完整协议覆盖待 §5.10 mitmproxy 代理链。不读 proxy 环境变量的工具（如 httpx）须显式传代理参数（沙箱 `egress_proxy_url`）；工具级代理参数声明待 Tool Manifest 扩展。
3. **输出文件名误判**：形如 `out.json` 的参数会被裸域名正则误判为目标（fail-closed 方向，最多误拒，不会误放）； `-l` 消费的目标文件名已不受影响。
4. **构造器仅支持单目标**：`tools/build.py` 的 httpx 构造器只产 `-u <target>` 单目标 argv；`-l` 批量列表依赖"目标文件挂载进容器"（限制 1），M2 后续切片接入。
5. **预算并发精度**：token 预算为调用前检查（check-then-call），并行子任务间不互斥，最多超出一个在途调用的用量；不追求 token 级精确互斥。
6. **token 估算为启发式**：响应无 usage 字段时按 4 字符≈1 token 估算并标 `estimated`，以服务商 usage 为准。
7. **成本仪表盘与自动降级未做**：M2c 的成本可观测仅有 `llm_call` 审计事件；§5.3"超额自动降级模型或挂起请示"与 §5.6 成本仪表盘待后续里程碑。
8. **triage 规则表覆盖两类**（M3d 起）：web-probe→web-exposure（存活状态码 2xx/301/302/307/308/401/403）与 param-endpoint→sqli（query 键精确匹配 `_SQLI_PARAM_HINTS`）；更多映射规则与 LLM triage（T1 档）待 M3 后续切片。
9. **证据包整文件拷贝**：按 evidence_ref 把源文件整份拷入证据包（保留 #L 锚点语义），大文件场景的裁剪策略待定。
10. **Finding.asset 字符串化**：M3a 暂用字符串（Signal 原样）+ 独立 `param` 字段，§5.5 结构化 `asset{host,url,param}` 延后；Finding 存储为 findings.jsonl 快照追加（last-wins 回放），§5.5 SQLite 存储待后续。
11. **verify 阶段为确定性单遍编排**：`run_verify_phase` 无 planner、无 DAG 并行、无失败重试（失败记审计、Finding 停留原态 fail-closed）；接失败预算与并行化待 M3 后续切片。L2 skill 的逐次人工确认交互仍未做（registry 仅有 `requires_confirmation` 标记）。
12. **凭据脱敏只覆盖会话配置**：runner 对审计命令与证据落盘做 `Scope.session` 凭据的字节级替换（实靶验证 sqlmap 会回显 Cookie 头）；脱敏形态为完整 Cookie 头 + `k=v` 对 + 长度 ≥8 的裸值（短裸值豁免——实靶教训：`security=low` 的裸值 `low` 会把 "following" 替换坏）；工具自行打印的非会话类秘密（如响应体中的 token）不在其列。证据 #L 行号锚点按 `\n` 行号（read_text 规范化后），sqlmap 裸 `\r` 进度符不影响锚点一致性。
13. **pip+sha256 安装仅走 PyPI 元数据路径**：白名单宿主硬编码 `pypi.org`/`files.pythonhosted.org`；其他 pip 源（内网 mirror）待需要时扩展。
14. **baseline 为可达性对照（M3b 最小形态）**：带会话 2xx 即认证有效（不跟随跳转，302 登录页即判失效）；§5.4.3 完整 baseline 档案（随机路径/无效参数对照）待 baseline-check skill。
15. **Verifier 输入为摘要+索引**：Verifier 不读原始证据（红线 3），其判断依赖 verification 摘要质量；`downgrade` 裁定与多轮复核留待后续。sqlmap 构造器 level≤3/risk≤2 为硬上限。
16. **报告仅 docx**：§5.7 PDF 管线（Jinja2 → HTML → Paged.js/weasyprint）未做；模板只覆盖固定章节骨架，自定义模板须遵循契约（StrictUndefined 下契约外变量即报错）。
17. **结构化输出为单遍校验 + 一次修复重试**（M6a 起）：planner/narrative/verifier 三处经 `llm/repair.py` 统一助手——首轮非法携带错误描述追问一次，二次仍非法走原失败语义（narrative 全量拒收零落盘等不变），无多轮重试与部分落盘；残余随机性仍存（修复不保证成功，仅降低抖动）；Rejected 附录直接用结构化 `rejection_reason`（不经 LLM）。
18. **报告不含生成时刻 wall-clock**：为保证"同输入同输出"（内容级确定性），context 只含 engagement 时间窗；docx zip 字节级时间戳不保证一致（两次渲染 `word/document.xml` 一致、zip 容器字节未必）。engagement 元信息靠可选 `engagement.json`，缺省派生（资产高频 host + audit 首末条）。
19. **报告时间窗派生会被叙述延后**：时间窗取 audit.jsonl 首/末条，叙述生成的 `narrative_generated` 审计事件会使窗口末尾延后（晚于实际测试结束时刻）；后续切片改为 engagement.json 显式时间或叙述前定型。
20. **用户模板叙述槽位无守卫**：自定义企业模板直接引用 `f.narrative_parts.*` 与 `sections.overview`，`--no-llm`（叙述未生成）下触发 StrictUndefined——用户模板须叙述版构建；engagement extras 键缺失同理（StrictUndefined 即报错）。
21. **{{r }} 富文本依赖渲染器包装**：docxtpl 0.20.2 把 `{{r }}` 的值插到 run 之外、纯字符串会被丢弃（实测）；渲染器扫描模板 `{{r }}` 标签、按点路径末段键名把 context 字符串值包装成 RichText——契约内同名键会被一并包装（当前仅 `repro_text`，无碰撞）；数据层 context 仍为纯 JSON。
22. **cn_date 非 ISO 原样返回**：过滤器对非 ISO 输入不报错、原样透传（用户手填「2026年8月」类值可用）；转换只取年月日（丢弃时分秒，不做时区换算）。
23. **API 无认证**：M5a 只交付后端 API，无认证/授权层，只绑 localhost/内网（§5.9.3 红线）；多人访问须反向代理 + 登录认证，严禁无认证公网暴露。
24. **API 沙箱网络为演示取向**：`default_phases_factory` 用 host + open egress（与 demo 脚本一致）；restricted 出口白名单接入 API 运行栈留后续硬化切片。
25. **engagement 恢复为粗粒度**：进程中断后运行态 engagement 回退 created 整体重跑（scan/triage 幂等归并，verify 经确认队列复用既有批准记 `action_resumed`）；无阶段级断点续跑，确认等待中的线程不存活。
26. **verify 闸门覆盖面为单 skill**：EngagementRunner 只按 verify-sqli 的 vuln_type 集合圈定待确认 Finding；多 verify skill 选择/并行留 M3 后续切片。
27. **控制台轮询无 WebSocket**（M5b）：2.5s 轮询 + 页面不可见暂停，详情页每周期 4 个请求；本机单用户量级够用，SSE/WebSocket 与多用户协作留产品化阶段。
28. **token 用量列表逐行补拉**：`GET /api/engagements` 列表项不含 tokens_used（避免每次列表轮询全量扫各 engagement 审计），控制台列表行异步补拉详情端点；engagement 量大时再评估聚合字段。
29. **证据文件响应 2 MiB 截断**：控制台证据查看器单文件超 2 MiB 截断并带 `X-ProofHound-Truncated` 头（完整文件始终可从证据包目录离线查阅）；前端另有 20000 行渲染软上限。
30. **发现自动化仅 GET 查询参数端点**（M3d）：POST 表单、Submit 类按键不进本切片（POST 表单 verify 切片与 verify-xss/lfi 同属后续里程碑）；katana 默认不自动填充表单（`-aff` experimental 会真实提交含 logout/security 的 POST 表单，副作用不可控，v1.7.0 实测后不采用），GET 表单由解析器从 response.body 合成查询 URL、无 value 字段填占位 1（空值参数会让 sqlmap 失去 baseline 可比，DVWA 实靶实测）；启发式键名精确匹配**偏向漏报**（宁漏勿滥，每 engagement sqli 上限 20 条防确认洪泛）；`-fs rdn` 对 IP 型种子不收敛（v1.7.0 实测外域混进输出，由 triage check_scope + 沙箱强校验两层兜底，`-cs`/`-fs` 自定义表达式留后续硬化）；alpine:3.20 内 https CA 实测正常（manifest 无需 image 覆盖）；recon-crawl 面向带预置会话的授权目标——scope 无会话时构造器 fail-closed、爬行子任务 failed 记审计（会话感知规划留后续切片）；katana 爬行沿用沙箱默认 300s 超时，大站点可能不足（走失败预算，不写死长超时）；`-cos` 状态变更排除清单当前仅覆盖实测危害三类（logout/signout 系、phpids 开关），其他目标的状态变更 GET 链接（重置/开关类）按实测扩充。
