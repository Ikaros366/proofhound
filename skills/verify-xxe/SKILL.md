---
name: verify-xxe
# mutating: false —— 验证动作只读：4 条 POST XML 探针（基线 / 外部实体读 canary /
# 阴性对照 / 回调），只读白名单文件（/etc/passwd、C:\Windows\win.ini），不做实体
# 膨胀、不做协议链、不写目标状态。（M30）
mutating: false
description: XML 外部实体注入假设的验证 SOP——外部实体指向的 canary 文件内容（或我们自己的 listener）被真实解析即 Confirmed；探针出错/覆盖不全判 blocked；两端签名与阴性对照都干净判 Rejected
version: 1.0.0
required_tools: []
risk_level: L2
inputs: [hypotheses]
outputs: [findings]
---

# verify-xxe：XML 外部实体注入验证

`vuln_type = xxe` 类 Confirmed 的**唯一合法产出门径**（职责隔离：发现类 skill 只能产
Signal/Hypothesis）。执行由编排器 `run_verify_phase()` 确定性驱动；唯一的 LLM 调用是
收尾的 **Verifier 终审**（T2，独立 agent + 输入边界）。

判定逻辑本身在 `verify/xxe.py`（纯函数，零 LLM），发送与证据落盘在 `xxeprobe.py`
——两者在 M25-a 就以**手工 CLI** 形态交付过；M30 把它们原样接进编排主链路，没有
第二套判定实现。

## 本 skill 确认的是什么（**先划清边界**）

确认的是「**目标的 XML 解析器会解析外部实体**」，两条通道任一成立即可：

1. **内容通道**：外部实体指向一个**白名单内**的本地文件，响应正文里出现该文件的
   已知签名（Linux `/etc/passwd` → `root:x:0:0`；Windows `win.ini` → `[fonts]`）；
2. **回调通道**：外部实体指向**我们自己的 listener**，且确实被访问（带本次唯一
   token）。

**不是**证据的：响应里出现我们发送的 XML 原文、`Content-Type` 是 xml、状态码、
报错文本。这些只能说明"请求被看见了"。

## 前置与纪律

- 只发 POST；每个 URL 发请求**前**必过 `check_scope`（红线 5，驱动内还有一层）；
- **canary 白名单只有两个文件**（Linux /etc/passwd、Windows win.ini）。自动通道
  只接受这两个目标，传其它路径直接抛 `XxeFileTargetError`——本 skill **不是**
  任意文件读取器；
- 不做实体膨胀（billion laughs / 递归实体）、不做远程 DTD、不做协议链、不做编码
  绕过、不做任何写操作；
- 证据（`probe_<n>.json` / `response_<n>.txt` / `judgment.json` / `summary.md`）
  落在 `evidence/xxe_<finding_id>/`，0600；响应正文只在证据文件里，**不进 prompt**。

## 三态判定

- **confirmed**：内容通道命中签名（且阴性对照未命中、基线未污染），或回调通道
  收到带本次 token 的访问；
- **rejected**：两端签名与阴性对照都干净，且请求确实被解析过（不是原样回显）；
- **blocked**：探针出错 / listener 起不来 / 覆盖不全。**不驳回**——"没测到"不等于
  "不存在"，Finding 停留 Reproduced 或 Hypothesis 交人工。

## 与证据门 / Verifier 的关系

确认后追加具名证据标签 `xml-entity-resolution`（**不是**笼统的 `behavioral`，让
"这条 Confirmed 靠外部实体解析"在证据层可分辨），`verification.method` 取
`xml-entity-file-confirmed` 或 `xml-entity-callback-confirmed`；随后照常过证据门
（铁律 2：状态码类证据永不确认）与 T2 Verifier 终审。
