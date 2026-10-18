---
name: web-dirsearch
# mutating: true —— 字典爆路径会按词表向目标发起大量真实请求（M19-c）
mutating: true
description: 基于 dirsearch 的字典爆路径 SOP，产出 web-probe Signal（走既有 web-exposure 通道）
version: 1.0.0
required_tools: [dirsearch]
risk_level: L1
inputs: [targets]
outputs: [signals]
---

# web-dirsearch：dirsearch 字典爆路径

围绕 dirsearch 的目录/文件发现标准作业程序（SOP）：以授权目标为起点，按**内置
字典**枚举路径，发现**有响应的端点**并落成 `web-probe` Signal，供 triage 走既有
`web-exposure`（信息类观察，不可 Confirmed）与 `unauth-exposure`（有会话且命中
2xx 时可 Confirmed）两条通道。

本 skill 是**发现类** skill：只产出 Signal，**严禁产出 Confirmed**——Confirmed
必须经 verify-* skill 产出（职责隔离规则）。

## 前置检查

1. 已加载 scope 授权文件，且目标在授权范围内；越界即停止并向人工请示。
2. **scope 必须显式声明 `request_budget`**（`rate_rps` / `concurrency` /
   `max_requests` / 可选 `window_minutes`）。本 skill 只在声明了它时才挂进扫描
   阶段（opt-in）：字典爆破是「按词表主动发请求」的动作，**不声明请求量上限就
   默认开始爆破**不可接受。未声明时编排层记 `scan_skill_skipped` 并跳过，
   **不得**改用缺省预算绕过。
3. dirsearch 可用（`tools.d/` 离线预置或经工具管理器安装；依赖闭包非空，
   安装器按 manifest 的 `closure` 逐条 pin + sha256 装齐）。

## 执行步骤

1. **第一个动作必须且只能是下面这个 run_tool**（沙箱内执行，命令由构造器
   拼装，严禁手写命令）：

   ```json
   {"actions": [
     {"action": "run_tool", "skill": "web-dirsearch", "tool": "dirsearch",
      "params": {"target": "<state 中的 target>"},
      "expected_output": "web-probe Signals（有响应的路径）",
      "rationale": "按内置字典枚举授权目标路径"}
   ]}
   ```

2. 执行成功后**下一个动作直接 `finish`**（不得重复爆破、不得追加其他工具）：

   ```json
   {"actions": [
     {"action": "finish", "skill": "web-dirsearch",
      "expected_output": "字典爆路径完成，web-probe Signal 已落盘",
      "rationale": "一次枚举即完成本 SOP"}
   ]}
   ```

参数说明：

   - **速率 / 并发 / 请求总量 / 时间窗都不由你给**：它们来自
     `scope.request_budget`，由编排层在构造命令时注入。把
     `rate_rps`/`concurrency`/`max_requests`/`window_seconds` 写进 `params`
     会被构造器**直接拒装**（`ValueError`）——这是刻意的 fail-closed，
     防「以为授了限速、其实被覆盖」；
   - 可选参数：`extensions`（只允许字母数字、逗号分隔，缺省
     `php,asp,aspx,jsp,html,htm`）、`wordlist`（缺省容器内
     `/opt/tools/dicc.txt`，不得以 `-` 开头）、`with_session`（目标需认证时
     注入预置会话）；
   - **构造器永不产** `-r`/`--recursive`（递归成倍放大请求量）与
     `-F`/`--follow-redirects`（越界面随重定向扩大），不在 params 里尝试；
   - 报告由 wrapper `cat` 回 stdout 后 100% 落盘 `evidence/`（红线 3：沙箱
     rootfs 只读、`/tmp` 随容器销毁，不 cat 则证据蒸发）。

## 判定标准

- **web-probe**：dirsearch JSON 报告里每个有响应的条目逐条产 Signal
  （asset=完整 URL，evidence_ref=落盘 stdout 路径 + 行号）。坏条目
  （缺 URL / 非字典 / 状态码非整）计入 `skipped`，不静默丢弃。
- 状态码 ∈ `_EXPOSED_STATUSES`（含 401/403/3xx）才进 `web-exposure`；
  仅 2xx 且 scope 有可用预置会话时才追加 `unauth-exposure` 候选。
- 所有候选都只是**候选**（红线 2）：本 skill 不做任何注入/越权尝试。
- 每条 Signal 必须携带 evidence_ref；无证据不入库。

## 停下来请示人工（硬阻塞，不自动攻克）

- 出现验证码、MFA、WAF 人机校验；
- 目标返回持续 429 / 连接被重置（限流），降速后仍不缓解
  （注意：降速**只能**通过重新授权更低的 `request_budget` 实现，
  LLM 不得自行调参）；
- 同一步骤连续失败 2 次（失败预算上限），失败信号须分类；
- 需要突破 scope 边界才能继续（如报告里出现外域跳转）。
