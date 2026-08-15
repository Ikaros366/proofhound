# 更新日志

本文件记录 ProofHound 的所有显著变更。格式基于
[Keep a Changelog 1.1.0](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

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
