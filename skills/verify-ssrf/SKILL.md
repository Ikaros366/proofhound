---
name: verify-ssrf
# mutating: false —— 验证动作只读：我们只向目标发只读探测（替换一个 query
# 参数取值），不提交任何表单、不改变目标状态。目标是否**代我们外发**一次
# 请求由目标自己决定，不由本 skill 写任何东西。（M16）
mutating: false
description: SSRF 假设的带外验证 SOP——宿主 listener 收到含本次 token 的回调请求即 Confirmed；未收到按"交付证明 + 对照探针"确定性判 Rejected 或 blocked
version: 1.0.0
required_tools: []
risk_level: L2
inputs: [hypotheses]
outputs: [findings]
---

# verify-ssrf：SSRF 带外回调验证

SSRF 的**验证类** SOP（L2 利用验证）。本 skill 是 `ssrf` 类 Confirmed 的
唯一合法产出门径（职责隔离：发现类 skill 只能产 Signal/Hypothesis）。执行
由编排器 `run_verify_phase()` 确定性驱动，唯一 LLM 调用是收尾的 Verifier
终审（T2 档，独立 agent + 输入边界）。

## 为什么必须"带外"确认

SSRF 没有可观测的响应差异：目标是否替我们发了请求，**答案不在目标给我们的
响应里**。响应里出现 callback URL 只是**反射**，不是 SSRF。故确认手段只能是
**带外二值事实**——我们自己起的回调 listener **收到了**那次请求。这与
verify-xss 用"canary 执行事件"、verify-idor 用"双会话属性违反"是同一种纪律：
**只有行为事实能确认，任何"看起来像"都不算。**

## 判定标准（铁律）

- **仅回调收到请求可确认**：回调 listener 收到一个路径中含**本次探针唯一
  token** 的请求 → Confirmed。token 为 128 位随机、只出现在我们注入的
  payload 里，比对走 `hmac.compare_digest`（常量时间）；路径不含 token 的
  请求一律记 `ssrf_callback_ignored`，**不计命中**。
- **目标响应内容永不作为证据**：反射、状态码、耗时、页面文案都不进判据。
- **干净未命中 → Rejected**，但必须先满足**交付证明**：回取同一探测 URL，
  正文里能找到我们的 token/nonce（证明目标当时收到的就是我们报告里的地址）。
  交付证明不成立 ⇒ **blocked**（无法证明 payload 被原样接收，不驳回）。
- **探针出错（网络/超时/非 2xx）→ blocked**（覆盖不全不驳回）。
- **随机地址对照探针**（`http://<random>.invalid:<port>/n/<nonce>`，不含我们
  的参数）命中时**不确认**——它只证明"该服务端会代访客发起请求、且能到达
  我们的 listener"，用于把"会发请求但不处理本参数"确定性判成 Rejected
  而非 blocked。

## 前置检查（任一不满足即 blocked，fail-closed）

1. 输入为 `hypothesis` 状态、`vuln_type=ssrf` 的 Finding；其余类型不属本 skill。
2. `param` 存在且候选来自 GET query 参数（`form_page` 表单候选不在本轮范围）。
3. scope 已配置**预置会话**；带会话 baseline 必须成立（与 verify-sqli 同一
   可达性对照），否则无法区分"参数未被处理"与"目标根本没响应"。
4. scope 已挂载（红线 5 的 scope 防线需要它）。
5. 回调 listener 可用，且回调 URL 的 host:port **等于** listener 实际绑定地址
   （自检：防配置漂移把回调指到别处）。

## 执行步骤

1. **scope 防线（红线 5）**：对 Finding asset 与**每个**探针 URL 过
   `check_scope`，越界记 `verify_scope_rejected` 并停。回调 URL 是我们的基础
   设施、不是目标，不进 scope；但受第 5 条自检约束。
2. **带会话 baseline**：复用既有可达性对照（httpx 带会话、不跟随跳转）。
3. **登记 token**（每探针一个），构造 payload：只替换 query 里 `param` 的值
   （`with_query_param`，其余 query/path 原样保留），`urlencode` 编码。
   变体集 ≤2 条（纯回调 URL；回调 URL + 同名参数二次拼接），**不做**协议/编码
   绕过变体（`gopher`/`dict`/`@`/十进制 IP 等）——那是绕过技巧，不是确认所需。
4. **对照探针**：随机地址（`.invalid` 主机 + nonce 路径）——一次无参数请求
   就不该发出的地址。
5. **逐变体探测**：按次记 `ssrf_probe_attempt{seq, variant, url, status, error}`；
   任一命中即停。**探针只读**：GET、不跟随重定向、不改目标状态。
6. **交付证明**：回取命中/未命中的探测 URL，检查正文含 token/nonce。
7. **确定性判定**（`proofhound/verify/ssrf.py::judge`，纯函数）：结论 + 全部
   依据落 `ssrf_<finding_id>_judgment.json`；回调记录落
   `ssrf_<finding_id>_callbacks.jsonl`（**只记 token/路径/来源 IP/UA/时间**，
   不记请求体，条数有上限）。
8. **证据入包**（仅 Confirmed 路径）：追加 `behavioral` 标签，写
   `verification{method: ssrf-callback-confirmed, evidence_refs: [baseline,
   回调记录, 判定 JSON], baseline_diff, reproduction_steps, verified_by,
   verified_at}` + **四段式** `claim`（参数 X 使服务端向外部地址发起请求）/
   `expected`（我们控制的地址应收到一次请求）/ `actual`（listener 收到的回调
   请求摘要与来源）。
9. **状态迁移**：`REPRODUCED(actor=verify-ssrf)` → 证据门（§5.4.2，method ∈
   {ssrf-callback-confirmed} 且含行为类标签）→ Verifier 终审（T2；只收确定性
   结论 + 行号锚点，**回调请求原文一行不进 prompt**）→ `CONFIRMED(actor=verifier)`
   或 `REJECTED(actor=verifier)`。

## 停下来请示人工（硬阻塞，不自动攻克）

- 目标无法回连宿主（远程靶/沙箱内目标）：回调收不到，判 blocked；需操作员
  设置 `PROOFHOUND_SSRF_CALLBACK_HOST` 并放行网络后重跑；
- 出现验证码、MFA、WAF 人机校验；
- 需要突破 scope 边界才能继续；
- 目标要求 POST/表单、header 注入等本轮未覆盖的 SSRF 形态（明示不支持，
  不做即兴发挥）。

## 已知边界

- 仅覆盖 **GET query 参数型 SSRF**；POST/表单、header 注入、无回调的盲 SSRF
  属后续里程碑；
- 回调需要目标能回连**宿主**：缺省只绑回环，只适用于本机/同主机目标；
- 同一超时窗口内的无关流量若恰携带本次 token 会被算作命中（token 128 位随机，
  概率可忽略）；
- 判定只回答"服务端是否代我们发了这次请求"，**不评价**该请求的影响面
  （读到了什么、是否可打内网）——那属 CVSS 与报告叙述。
