---
name: verify-xss
# mutating: false —— 验证动作只读：浏览器只加载 payload 页面，
# 非破坏性 canary 探针，不提交状态变更（M9c③）
mutating: false
description: XSS 假设的行为验证 SOP——无头 Chromium canary 探针确认 payload 真实执行 + Verifier 终审，产出 Confirmed/Rejected
version: 1.0.0
required_tools: []
risk_level: L2
inputs: [hypotheses]
outputs: [findings]
---

# verify-xss：XSS 行为验证（浏览器 canary 确认）

围绕无头 Chromium（playwright）的 XSS**验证类** SOP（L2 利用验证）。本
skill 是 XSS 类 Confirmed 的唯一合法产出门径（职责隔离：发现类 skill
只能产出 Signal/Hypothesis）。执行由编排器 `run_verify_phase()` 确定性
驱动，唯一 LLM 调用是收尾的 Verifier 终审（T2 档，与发现端异模型）。

浏览器是**验证器**不是爬虫：本 skill 不做任何爬行/发现；驱动浏览器的一
切输入（候选 URL、payload 集）全部来自代码常量与 Finding 数据，LLM 不
参与任何浏览器参数与 payload 构造（红线 1）。

## 判定标准（铁律）

- **仅 canary 执行事件可确认**：payload 内嵌的唯一 token
  （`phxss_<12hex>`，每次尝试新生成）在页面上下文执行——置位
  `window[token]` 标记、或触发探针钩子捕获的 alert/confirm/prompt 调用。
- **"响应里反射了输入"永远不是证据**——反射不执行 = 不确认（这正是本
  项目要消灭的假阳性形态）。
- 全部 payload（≤6 条固定模板：script 标签 / img onerror / svg onload
  三类载体）干净执行完毕且无 canary → `REJECTED(actor=verify-xss)`。
- 任一次浏览器尝试出错（超时/异常）且未命中 canary → **blocked**
  （fail-closed：覆盖不全不做驳回，Finding 停留 Hypothesis 待人工）。

## 前置检查

1. 输入为 `hypothesis` 状态、`vuln_type=xss` 的 Finding（含 asset 与
   param）；其余漏洞类型不属于本 skill。
2. scope 已配置**预置会话**（session.cookies）；未配置即跳过并记审计，
   不得尝试无认证硬闯。
3. Chromium 可用（`playwright install chromium`）；不可用记
   `verify_blocked`，Finding 停留原态（fail-closed）。

## 执行步骤

1. **带会话 baseline**（httpx，不跟随跳转）：2xx 才算认证有效；被 302
   到登录页即停止，记 `verify_baseline_failed`。

2. **逐 payload 驱动浏览器**（`proofhound/verify/browser.py`，
   first-party 验证器；每次尝试一个干净 browser context）：

   - URL 由代码确定性构造：asset query 中 `param` 的值替换为当前
     payload（`{token}` 以 fresh token 替换）；param 不在 query 中即
     fail-closed；
   - **scope 防线（红线 5，双层）**：加载前 `check_scope`；页面加载后
     `page.route` 拦截全部子请求，**跨 origin 或越 scope 一律 abort**
     并记入请求链；
   - 会话注入：Cookie 经 `context.add_cookies` 按 origin 绑定，LLM 永不
     接触凭据原文；
   - 探针：`add_init_script` 先于页面脚本 hook alert/confirm/prompt；
     加载驻留后读取 `window[token]` 标记与事件数组；
   - 每次尝试记审计 `xss_probe_attempt`（按次计数，上限 = 模板条数）；
     超时默认 15s（可配）。

3. **证据落盘（红线 3）**：每次尝试落四份证据——canary 事件 JSON、
   执行后 DOM 快照、console 记录、请求/响应链（含状态码，**不记请求
   头**）——全部经字节级脱敏后写入 evidence 目录。

4. **证据入包**：canary 命中后追加 `behavioral` 证据标签，写
   `verification{method: browser-confirmed, evidence_refs, baseline_diff,
   reproduction_steps, verified_by, verified_at}` + **四段式**
   `claim`（参数 X 的输入在浏览器中被执行）/ `expected`（payload 中的
   canary token 在页面上下文执行）/ `actual`（实际捕获的事件摘要）；
   复现步骤中的 Cookie 一律写脱敏标记。

5. **状态迁移**：`REPRODUCED(actor=verify-xss)` → 证据门（§5.4.2，
   method ∈ {browser-confirmed} 且含行为类标签）→ Verifier 终审（T2，
   confirm 必携合法 CVSS 向量、代码算分）→ `CONFIRMED(actor=verifier)`
   或 `REJECTED(actor=verifier)`。

## 停下来请示人工（硬阻塞，不自动攻克）

- 会话失效（baseline 302 到登录页）：更新 scope 预置会话后重跑；
- 出现验证码、MFA、WAF 人机校验；
- 浏览器/Chromium 不可用，或导航持续超时（限流、WAF 拦截）；
- 需要突破 scope 边界才能继续（跨 origin 子请求已被 route abort 阻断）。

## 已知边界

- 仅覆盖 **reflected / GET 查询参数** 场景（katana 爬参候选）；
  stored/DOM 型与 POST 表单 XSS 属后续里程碑；
- --forms 式表单自解析、JS 驱动交互（点击/填表）不在本 skill 范围。
