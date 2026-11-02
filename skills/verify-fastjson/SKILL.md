---
name: verify-fastjson
# mutating: false —— 验证动作只读：POST JSON 探针（基线 / 解析控制位 / gadget 变体 /
# 对照），确认只靠带外回调，不写目标状态、不做回显型利用、不落地文件。（M30）
mutating: false
description: 不安全反序列化（fastjson 系）假设的验证 SOP——观察点收到带本次唯一 token 的带外回调（DNS / TCP-LDAP / TCP-JDBC）才 Confirmed；观察通道不可用或覆盖不全判 blocked；解析控制位证明「没走反序列化」且无回调判 Rejected
version: 1.0.0
required_tools: []
risk_level: L2
inputs: [hypotheses]
outputs: [findings]
---

# verify-fastjson：不安全反序列化（fastjson 系）验证

`vuln_type = fastjson` 类 Confirmed 的**唯一合法产出门径**。执行由编排器
`run_verify_phase()` 确定性驱动；唯一的 LLM 调用是收尾的 **Verifier 终审**（T2）。

判定在 `verify/fastjson.py`（纯函数），发送与证据在 `fastjsonprobe.py`
——M26-a 以手工 CLI 形态交付，M30 接进编排主链路，判定实现只有一套。

## 本 skill 确认的是什么（**先划清边界**）

确认的是「**目标的 JSON 反序列化会把攻击者控制的数据当对象实例化**」：

- 观察点（DNSLog provider 或自建 TCP 监听）收到**带本次唯一 token** 的回调
  （通道：DNS / TCP-LDAP / TCP-JDBC）才算成立；
- 目标响应里的报错文本（`autoType is not support` 之类）、状态码、解析控制位的
  回显，一律**不是**证据——只能说明"请求被解析了"，不能说明"被实例化了"。

## 前置与纪律

- 只发 POST；每个 URL 发请求**前**必过 `check_scope`（红线 5）；
- gadget 片段由构造器生成，**禁止** `$ref` / `javaCodebase` / `javaFactory` /
  `JNDIReferenceFactory` 等危险片段（构造器硬校验）；
- 不做回显型利用、不做落地文件、不做反弹 shell；载荷只证明"能触发带外请求"；
- 观察通道是 **opt-in 基础设施**：`PROOFHOUND_DNSLOG_PROVIDER` /
  `PROOFHOUND_DNSLOG_DOMAIN` / `PROOFHOUND_DNSLOG_TOKEN` / `PROOFHOUND_DNSLOG_API`
  未配置时，若自建 TCP 监听也不可用，驱动抛 `FastjsonProbeError` ⇒ **blocked 并写明
  原因**，不会被静默跳过、更不会被当成"测过且安全"；
- 证据（`probe_<n>.json` / `request_<n>.json` / `response_<n>.txt` /
  `observations.json` / `judgment.json` / `summary.md`）落在
  `evidence/fastjson_<finding_id>/`，0600；token 只以 `sha256:<hex8>` 形态出现。

## 三态判定

- **confirmed**：带外回调带本次唯一 token 到达观察点；
- **rejected**：解析控制位证明"这段 JSON 根本没被当成对象处理"，且零回调；
- **blocked**：观察通道不可用 / 探针出错 / 覆盖不全。**不驳回**。

## 与证据门 / Verifier 的关系

确认后追加具名证据标签 `deserialize-gadget-callback`，
`verification.method = deserialize-callback-confirmed`；随后照常过证据门与 T2
Verifier 终审（铁律 2：状态码类证据永不确认）。
