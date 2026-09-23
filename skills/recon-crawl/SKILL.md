---
name: recon-crawl
# mutating: true —— 爬行会向目标发起大量真实请求（M9c③）
mutating: true
description: 基于 katana 的 Web 爬行与带参端点发现 SOP，产出 param-endpoint Signal
version: 1.0.0
required_tools: [katana]
risk_level: L1
inputs: [targets]
outputs: [signals]
---

# recon-crawl：katana 爬行与带参端点发现

围绕 katana 的爬行标准作业程序（SOP）：以种子 URL 为起点爬行站点，发现
**带查询串的 GET 端点**（param-endpoint），供 triage 展开注入假设。本
skill 是**发现类** skill：只产出 Signal（候选信号），**严禁产出
Confirmed**——Confirmed 必须经 verify-* skill 产出（职责隔离规则）。

## 前置检查

1. 已加载 scope 授权文件，且种子目标在授权范围内；越界即停止并向人工
   请示，不得自行剔除后继续。
2. katana 可用（本地预置或经工具管理器安装，版本与 manifest 匹配）。
3. 爬行范围由构造器恒在项 `-fs rdn` 限定种子根域（三层 scope 纵深第一
   层）；restricted 出口下 katana 必须显式传 `-proxy <egress_proxy_url>`
   （不读 proxy 环境变量；该地址是基础设施端点，scope 校验自动剔除）。

## 执行步骤

1. **第一个动作必须且只能是下面这个 run_tool**（对种子目标执行一次
   katana 爬行；沙箱内执行，确定性命令由构造器拼装，严禁手写命令、
   严禁加 `-o` 输出文件）。计划的每个 action 都必须带
   `expected_output` 与 `rationale` 字段（schema 强制）：

   ```json
   {"actions": [
     {"action": "run_tool", "skill": "recon-crawl", "tool": "katana",
      "params": {"target": "<state 中的 target>", "with_session": true},
      "expected_output": "param-endpoint Signals（带查询串 GET 端点）",
      "rationale": "爬行种子目标发现带参端点"}
   ]}
   ```

2. katana 执行成功后，**下一个动作直接 `finish`**（不得重复爬行、
   不得追加其他工具调用；重跑由 engagement 层决定）：

   ```json
   {"actions": [
     {"action": "finish", "skill": "recon-crawl",
      "expected_output": "爬行完成，带参端点 Signal 已落盘",
      "rationale": "一次爬行即完成本 SOP"}
   ]}
   ```

参数说明：

   - **本 skill 面向带预置会话的授权目标：`with_session` 固定为 true**
     （凭据由构造器从 scope 会话注入 `-H`，LLM 只声明、永不接触原文；
     scope 无会话时构造器 fail-closed 报错，按失败预算处理，不得改试
     false 绕过）；
   - `depth` 默认 2（1~5）、`concurrency` 默认 5（1~10）、`rate_limit`
     可选（≤150），目标出现限流迹象即降速；
   - 恒在项 `-jsonl -silent -nc -fs rdn` 与
     `-cos "(?i)(logout|logoff|signout|signoff|phpids)"`（排除状态变更类
     GET 链接：登出端点防自毁会话、phpids 开关防为目标开启 IDS）由构造器
     写死，不在 params 中声明；
   - 原始输出 100% 落盘 `evidence/`（红线 3），上下文只进解析后的
     结构化摘要 + 证据文件路径。

## 判定标准

- **param-endpoint**：katana JSONL 输出中 method 为 GET 且 URL 含非空
  query 的端点，逐条产 Signal（asset=完整 URL，evidence_ref=落盘
  JSONL 路径 + 行号）；POST、无 query、非端点记录不产 Signal。
- **form_page**（M8a）：响应体内含 POST 候选表单的页面，每页产一条
  Signal（asset=**页面 URL 本身**，不拼参数；字段名并集存
  `form_fields`）。合格规则：method 显式 post（大小写不敏感）且 ≥1 个
  有 name 的 input|select|textarea 字段；或 method 缺省 + 非空 action +
  有 name 的密码/文本字段。**同源防线**：action 解析后须与页面同
  scheme/host/port（空 action=页面自身），跨域表单一律不产——forms
  模式 sqlmap 实际 POST 的目标是 action，跨域会脱离 `-u` 的 scope
  校验覆盖面。
- 带参端点与表单页都只是**候选**（红线 2）：是否可注入由 triage 启发式
  与 verify-* 行为验证判定，本 skill 不做任何注入尝试。
- 每条 Signal 必须携带 evidence_ref；无证据不入库。

## 停下来请示人工（硬阻塞，不自动攻克）

- 出现验证码、MFA、WAF 人机校验；
- 目标返回持续 429 / 连接被重置（限流），降速后仍不缓解；
- 同一步骤连续失败 2 次（失败预算上限），失败信号须分类
  （凭证错误/验证码/限流/锁定/网络异常），禁止"一律重试"；
- 需要突破 scope 边界才能继续（如爬行发现跳转出授权域名）。
