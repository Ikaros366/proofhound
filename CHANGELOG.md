# 更新日志

本文件记录 ProofHound 的所有显著变更。格式基于
[Keep a Changelog 1.1.0](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

M9a / M9b（内部消化，按维护者要求**不 bump 版本号**：`0.2.0` 保持不变）。

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

### 修复

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
