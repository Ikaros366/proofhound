---
name: verify-sqli
# mutating: false —— 验证动作只读（sqlmap 固定 --batch，构造器硬禁
# risk>2 的 OR 型注入与任何写操作），不改变目标状态（M9c③）
mutating: false
description: SQL 注入假设的行为验证 SOP——带会话 baseline + sqlmap 确认 + Verifier 终审，产出 Confirmed/Rejected
version: 1.0.0
required_tools: [httpx, sqlmap]
risk_level: L2
inputs: [hypotheses]
outputs: [findings]
---

# verify-sqli：SQL 注入行为验证

围绕 sqlmap 的 SQL 注入**验证类** SOP（L2 利用验证）。本 skill 是
Confirmed 的唯一合法产出门径之一（职责隔离：发现类 skill 只能产出
Signal/Hypothesis）。执行由编排器 `run_verify_phase()` 确定性驱动，
唯一 LLM 调用是收尾的 Verifier 终审（T2 档，与发现端异模型）。

## 前置检查

1. 输入为 `hypothesis` 状态、`vuln_type=sqli` 的 Finding（含 asset 与
   param）；其余漏洞类型不属于本 skill。
2. scope 已配置**预置会话**（session.cookies，认证旁路 SOP 第①条）；
   未配置即跳过并记审计，不得尝试无认证硬闯。
3. sqlmap 可用（本地预置或经工具管理器按 manifest 安装，版本 pin +
   SHA256 校验），运行镜像为 manifest 声明的 python 镜像。

## 执行步骤

1. **带会话 baseline**（httpx，不跟随跳转）：

   ```bash
   httpx -u <asset> -H "Cookie: <session>" -status-code -title \
         -json -silent -no-color
   ```

   拿到 2xx 才算认证有效；被 302 到登录页（会话失效）即停止，记
   `verify_baseline_failed`，Finding 停留原态待人工更新会话。

2. **sqlmap 行为确认**（沙箱内执行，确定性命令，不经 LLM 拼装）：

   ```bash
   sqlmap -u <asset> --cookie <session> -p <param> \
          --level 1 --risk 1 --batch --flush-session --disable-coloring
   ```

   - `--batch` 禁交互、`--flush-session` 禁陈旧缓存，由构造器强制；
   - level ≤ 3、risk ≤ 2 为构造器硬上限，不得拔高；
   - **forms 变体（M8a）**：evidence_kinds 含 `crawl-form` 的候选（POST
     表单页，asset 为页面裸 URL）改用 `sqlmap --forms`——sqlmap 自解析
     页面内表单并测试其字段，**不指定 `-p`、构造器永不产 `--data`**
     （不手拼请求体）；构造器层 forms 与 param 互斥（fail-closed）；
   - 原始输出 100% 落盘 evidence/（红线 3），凭据在审计/state/日志中
     只记 sha256 前 8 位。

3. **证据入包**：sqlmap 确认后追加 `behavioral` 证据标签，写
   `verification{method: sqlmap-confirmed, evidence_refs, baseline_diff,
   reproduction_steps, verified_by, verified_at}`；复现步骤中的 Cookie
   一律写脱敏标记。

4. **状态迁移**：`REPRODUCED(actor=verify-sqli)` → 证据门（§5.4.2，
   method ∈ {sqlmap-confirmed, boolean-diff, time-blind-diff} 且含行为类
   标签）→ Verifier 终审 → `CONFIRMED(actor=verifier)` 或
   `REJECTED(actor=verifier)`。

## 判定标准

- **确认**：sqlmap 输出 "identified the following injection point(s)"，
  解析出 Parameter + Type/Title/Payload 技术清单。
- **驳回**：sqlmap 明确 "do not appear to be injectable"（或无任何注入
  点）→ `REJECTED(actor=verify-sqli)`，不进入 Verifier 环节。
- **证据门不过 / Verifier 失败或非法输出**：Finding 停留 Reproduced，
  记 `verify_gate_failed` / `verify_blocked`（fail-closed，不静默晋级）。

## 停下来请示人工（硬阻塞，不自动攻克）

- 会话失效（baseline 302 到登录页）：更新 scope 预置会话后重跑；
- 出现验证码、MFA、WAF 人机校验；
- 目标持续 429 / 连接重置（限流）；
- sqlmap 非 0 退出（网络异常、目标不可达等），记 `verify_tool_failed`；
- 需要突破 scope 边界才能继续。
