---
name: verify-idor
description: IDOR/水平越权假设的属性验证 SOP——双会话（reference/victim 与主会话）对照判定属性违反 + Verifier 终审，产出 Confirmed/Rejected
version: 1.0.0
required_tools: []
risk_level: L2
inputs: [hypotheses]
outputs: [findings]
---

# verify-idor：IDOR/水平越权 属性验证（双会话对照）

围绕"Security Property"式验证的 IDOR**验证类** SOP（L2 利用验证）。属性
= **身份 A 不可访问身份 B 的私有对象**；验证 = 双会话对比——B
（reference/victim，对象属主）会话基准请求同 URL，A（主会话，低权限身
份）会话对比请求，确定性代码判定属性是否违反。本 skill 是 IDOR 类
Confirmed 的唯一合法产出门径（职责隔离：发现类 skill 只能产出
Signal/Hypothesis）。执行由编排器 `run_verify_phase()` 确定性驱动，唯
一 LLM 调用是收尾的 Verifier 终审（T2 档，与发现端异模型）。

IDOR/水平越权没有 payload 特征、没有 CVE——传统扫描器在此类几乎全灭；
但也天然适合属性化验证：判定逻辑（响应对比、相似度、阈值）全部是确定
性代码（红线 1），LLM 不参与任何请求构造与属性判定。

## 判定标准（铁律）

- **仅双会话属性违反可确认**：B 基准成立（2xx 且含实质数据——非空非
  错误页，写死 ≥ 32 字节）且 A 同 URL 请求 2xx 且与 B 基准正文相似度
  ≥ 0.9（difflib.SequenceMatcher）或 JSON 键集合重叠（Jaccard）≥ 0.8
  → 属性违反成立。阈值写死在 `proofhound/verify/idor.py`，不接受任何
  运行时调参。
- **单会话异常响应永远不是证据**——没有 B 基准对照的"可疑响应"不确
  认（这正是本项目要消灭的假阳性形态）。
- 判定不成立（A 被 403/404/重定向登录页/数据不相似）→
  `REJECTED(actor=verify-idor)`。
- 网络错误、B 基准不成立（属主自己也访问不到）等覆盖不全形态 →
  **blocked**（fail-closed：不驳回，Finding 停留 Hypothesis 待人工）。

## 前置检查

1. 输入为 `hypothesis` 状态、`vuln_type=idor` 的 Finding（含 asset 与
   param）；其余漏洞类型不属于本 skill。
2. scope 已配置**预置会话**（session.cookies，身份 A）；未配置即跳过
   并记审计，不得尝试无认证硬闯。
3. 已配置**第二身份会话**（`SessionConfig.reference`，reference/victim
   身份，字段与主会话同构）；缺第二会话即记 `verify_blocked`
   （fail-closed：双会话属性对比无从谈起）。

## 执行步骤

1. **scope 防线（红线 5）**：请求任何 URL 前对 Finding asset 过
   `check_scope`，越界记 `verify_scope_rejected` 停止。

2. **B 会话基准请求**（`proofhound/verify/idor.py` 的 stdlib fetch，
   GET、不跟随重定向）：记审计 `idor_probe_attempt{role:"reference"}`；
   响应体脱敏后落盘。网络错误 → blocked；非 2xx 或无实质数据 →
   blocked（基准不成立，覆盖不全不驳回）。

3. **A 会话对比请求**（主会话，同 URL 同方法）：记审计
   `idor_probe_attempt{role:"attacker"}`；响应体脱敏后落盘。网络错误
   → blocked。

4. **确定性属性判定**：`judge()` 产出结构化判定（双状态码、正文相似
   度数值、JSON 键重叠度、阈值快照、violation、逐条 reasons），判定
   JSON 全量落盘。

5. **证据入包**：违反成立则追加 `behavioral` 证据标签，写
   `verification{method: dual-session-confirmed, evidence_refs: [B 基准,
   A 对比, 判定 JSON], baseline_diff, reproduction_steps, verified_by,
   verified_at}` + **四段式** `claim`（身份 A 可访问身份 B 的私有对象）
   / `expected`（A 应被拒绝或返回不同数据）/ `actual`（双状态码与判定
   数值摘要）；复现步骤中两个会话的 Cookie 一律只写脱敏标记
   （`sha256:<hex8>`）——**脱敏是两个会话都要**（红线 5），
   `SessionConfig.secret_values()` 递归覆盖全部秘密值。

6. **状态迁移**：`REPRODUCED(actor=verify-idor)` → 证据门（§5.4.2，
   method ∈ {dual-session-confirmed} 且含行为类标签）→ Verifier 终审
   （T2，confirm 必携合法 CVSS 向量、代码算分）→
   `CONFIRMED(actor=verifier)` 或 `REJECTED(actor=verifier)`。

## 停下来请示人工（硬阻塞，不自动攻克）

- 任一会话失效（基准/对比被 302 到登录页）：更新对应会话后重跑；
- 出现验证码、MFA、WAF 人机校验；
- B 基准持续不成立（对象已删除/归属变化），需人工确认测试前提；
- 需要突破 scope 边界才能继续。

## 已知边界

- 仅覆盖**水平越权 / GET 对象**场景（同一 URL 换身份重放）：垂直越权
  （低权限访问管理功能）、多步业务流越权、写操作越权属后续里程碑；
- 需操作员提供两个身份的会话（主会话 + reference/victim）；对象的
  "私有性"（确属 B 所有）由 Verifier 终审与人工兜底；
- 判定基于响应相似度，对"同 URL 为不同身份渲染不同模板但数据同源"
  的变态形态可能漏报（宁漏勿滥）。
