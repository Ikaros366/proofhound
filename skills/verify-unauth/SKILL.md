---
name: verify-unauth
# mutating: false —— 验证动作只读：匿名与已认证各发一次**只读 GET**（不跟随重定向），
# 比对响应字节；不提交表单、不改目标状态。（M16-c）
mutating: false
description: 未授权暴露假设的验证 SOP——匿名客户端与已认证客户端请求同一 URL 得到等价响应即 Confirmed；匿名被拒则 Rejected，内容不同又不相似则 blocked
version: 1.0.0
required_tools: []
risk_level: L2
inputs: [hypotheses]
outputs: [findings]
---

# verify-unauth：未授权暴露（unauth-exposure）验证

`unauth-exposure` 类 Confirmed 的**唯一合法产出门径**（职责隔离：发现类 skill 只能
产 Signal/Hypothesis）。执行由编排器 `run_verify_phase()` 确定性驱动；LLM 只在两处出现
——独立的**敏感度判定器**（T1，产结论与锚点，**不产证据**）与收尾的 **Verifier 终审**
（T2，独立 agent + 输入边界）。

## 本 skill 确认的是什么（**先划清边界**）

「不需要登录就能拿到信息」这句话里混了两半：

- **可复现的一半**（**本 skill 确认的**）：「**同一 URL**，**匿名**客户端拿到的响应
  == **已认证**客户端拿到的响应」——判据落在**响应字节**上，是二值事实；
- **不可复现的一半**（**本 skill 不确认的**）：「这份内容**本来应该**要求登录」——
  那是敏感度的语义判断，没有二值观测量。它只影响报告的敏感度标注与叙述，
  **不构成 Confirmed 的证据**。

**这条边界是本 skill 的核心纪律**：`GATE_MATRIX["unauth-exposure"]` 的
`behavioral_kinds` 只认 `unauth-response-equivalence`（前置门产物），
**不认** AI 判定器的结论。故判定器判错**不可能造成误确认**——它最多影响报告分类。

## 判定标准（三态，铁律）

判定由 `proofhound/verify/unauth_control.py::judge_unauth` 做（纯确定性，零 LLM）：

- **`exposed`**：匿名 **2xx** 且（响应与已认证基准**逐字节相同** ‖ 相似度 ≥
  `PUBLIC_SIMILARITY_THRESHOLD`=0.9）→ **暴露成立**，唯一产证据的态；
- **`requires_auth`**：匿名 **非 2xx**（3xx/4xx/5xx）→ 资源**本就要求认证** →
  编排层 **Rejected**；
- **`blocked`**：匿名请求网络错误，或匿名 2xx 但内容与基准**既不逐字节相同、
  相似度也低于阈值** → **不驳回也不确认**（覆盖不全，fail-closed；宁可不判，也不猜）。

**为什么 `blocked` 不驳回**：内容"不同但不像"同样符合"匿名看到精简视图、
已认证看到完整视图"这一**合法且常见**的形态——把它当暴露证据是会误报的方向。
故本 skill **只做"字节级肯定"与"状态码否定"**，不做任何语义肯定。

## 与 verify-idor 的方向相反（**不可合并**）

`judge_control` 的 `public` 态在 **idor 语义下是"否定越权"（驳回）**，
而 `judge_unauth` 的 `exposed` 态在 **exposure 语义下是"肯定暴露"（确认）**。
**同一份响应，两个漏洞类型结论相反**。故两者独立成模块，且
`tests/test_unauth_control.py` 用同一份输入**显式钉住方向相反**，
防后人图省事合并逻辑（合并即静默改变其中一个类型的判定语义）。

## 前置检查（任一不满足即 blocked，fail-closed）

1. 输入为 `hypothesis` 状态、`vuln_type=unauth-exposure` 的 Finding；其余类型不属本 skill。
2. scope 已配置**预置会话**（已认证侧需要它；缺会话无法构造"已认证视图"）。
3. scope 已挂载（红线 5 的 scope 防线需要它）。
4. Finding asset 过 `check_scope`；越界记 `verify_scope_rejected` 并停。
5. 两侧 URL **完全一致**（含 query）——`judge_unauth` 内部亦做同 URL 自检。

## 执行步骤

1. **scope 防线（红线 5）**：对 Finding asset 过 `check_scope`。
2. **已认证基准请求**：带预置会话的只读 GET（不跟随重定向），记
   `unauth_probe_attempt{role: "authenticated"}`；请求失败 → `blocked`。
3. **匿名对照请求**：**完全不发凭据**（空 `SessionConfig`）请求**同一 URL**，
   记 `unauth_probe_attempt{role: "anonymous"}`。
4. **确定性判定**：`judge_unauth(baseline, anon)` → 三态 + 全部依据落
   `unauth_<finding_id>_control.json`（含两侧响应 sha256，供离线复核）。
5. **仅 `exposed` 态继续**；`requires_auth` → Rejected；`blocked` → 停 Hypothesis。
6. **敏感度判定（独立件，T1）**：把**脱敏 + 截断**后的响应正文交给
   `verify/unauth_judge.py`，得 `{sensitive, category, anchors, reason, confidence}`；
   实际送审文本落 `unauth_judge_<finding_id>_sent.txt`（"判定器看到了什么"可复核）。
   **判定器失败（非法输出/LLM 异常）→ blocked**（覆盖不全，不是"没暴露"）。
7. **证据入包**：追加 `unauth-response-equivalence` 标签，
   写 `verification{method: unauth-equivalence-confirmed, evidence_refs: [已认证基准,
   匿名响应, 判定 JSON], baseline_diff, reproduction_steps, verified_by, verified_at}`
   + **四段式** `claim`（该 URL 无需认证即可获得与已认证用户等价的内容）/
   `expected`（匿名请求应被拒或得到不同内容）/ `actual`（匿名响应的状态码、
   与基准的 sha256 相等性或相似度）。
8. **状态迁移**：`REPRODUCED(actor=verify-unauth)` → 证据门（§5.4.2，
   method ∈ {`unauth-equivalence-confirmed`} 且含 `unauth-response-equivalence`）
   → Verifier 终审（T2；只收枚举/数值/锚点，**响应体一行不进 prompt**）
   → `CONFIRMED(actor=verifier)` 或 `REJECTED(actor=verifier)`。

## 停下来请示人工（硬阻塞，不自动攻克）

- 目标需要认证才能访问候选 URL，但 scope 未配置预置会话 → blocked，需操作员补会话；
- 出现验证码、MFA、WAF 人机校验；
- 需要突破 scope 边界才能继续；
- 候选是 POST/JSON body 型接口（本轮只覆盖 GET）。

## 已知边界

- **只覆盖"匿名视图 ≡ 已认证视图"这一窄形态**；"匿名看到敏感内容、但已认证看到更多"
  这类真实暴露**仍不可 Confirmed**（停 Hypothesis + 报告层标注）。这是维护者裁定的
  覆盖取舍（见 `M16C_ADJUDICATION.md` / design.md §7.15）；
- **不做**关键词/正则敏感表：那既会漏又会误，且与"发现侧不靠关键词表"的既有立场冲突；
- 敏感度判定依赖模型，**其结论不稳定**（M15 实测语义判断形对照误报 3/4 次）——
  但因为它**不构成证据**，不稳定只影响报告分类，不影响确认的正确性；
- 相似度阈值 0.9 与 idor 共用同一常量；对"两视图渲染不同模板但数据同源"的形态可能
  判 `blocked`（宁漏勿滥方向）。
