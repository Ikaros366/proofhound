---
name: web-scan
description: 基于 httpx 的 Web 目标探活与指纹采集 SOP，产出结构化 Signal
version: 1.0.0
required_tools: [httpx]
risk_level: L1
inputs: [targets]
outputs: [signals]
---

# web-scan：httpx Web 探活与指纹采集

围绕 httpx 的 Web 扫描标准作业程序（SOP）。本 skill 是**发现类** skill：
只产出 Signal（候选信号），**严禁产出 Confirmed**——Confirmed 必须经
verify-* skill 产出（职责隔离规则）。

## 前置检查

1. 已加载 scope 授权文件，且全部输入目标在授权范围内；任一目标越界即
   停止并向人工请示，不得自行剔除后继续。
2. httpx 可用（本地预置或经工具管理器安装，版本与 manifest 匹配）。
3. 出口策略处于 restricted/none；restricted 下确认目标已含于出口白名单，
   且 httpx 不读 proxy 环境变量——必须显式传 `-proxy <egress_proxy_url>`
   （代理地址由沙箱 runner 的 `egress_proxy_url` 属性提供；该地址是
   基础设施端点，scope 校验自动剔除，不参与目标判定）。

## 执行步骤

1. 目标归一化：输入可为单目标（`-u`）或目标列表文件（`-l`）；列表文件
   先经 scope 校验逐行放行后方可使用。
2. 探活与基础指纹（沙箱内执行，确定性命令，不经 LLM 拼装）：

   ```bash
   httpx -u <target> -proxy <egress_proxy_url> -status-code -title \
         -tech-detect -follow-redirects \
         -json -silent -no-color -o evidence/<run_id>.httpx.jsonl
   ```

   - 批量场景改用 `-l <targets.txt>`，其余参数不变；
   - 速率保守：`-rate-limit 50` 起步，目标出现限流迹象即降速；
   - 原始输出 100% 落盘 `evidence/`（红线 3），上下文只进解析后的
     结构化摘要 + 证据文件路径。

3. 解析 httpx JSONL 输出，逐条产出 Signal：

   | 字段 | 来源 |
   |---|---|
   | asset | `url` / `host` |
   | status | `status_code` |
   | title | `title` |
   | tech | `tech` 列表 |
   | evidence_ref | 落盘 JSONL 路径 + 行号 |

## 判定标准

- **存活**：status_code 为 2xx/3xx/401/403 视为存活；5xx 记存活但标注异常。
- **Signal 触发例**：非常规端口开放 Web 服务、后台/管理路径标题
  （如 "Dashboard"、"phpMyAdmin"）、指纹识别到带已知 CVE 的组件版本
  （仅作 Signal，版本匹配型 CVE 永远不能直接晋级）。
- 每条 Signal 必须携带 evidence_ref；无证据不入库。

## 停下来请示人工（硬阻塞，不自动攻克）

- 出现验证码、MFA、WAF 人机校验；
- 目标返回持续 429 / 连接被重置（限流），降速后仍不缓解；
- 同一步骤连续失败 2 次（失败预算上限），失败信号须分类
  （凭证错误/验证码/限流/锁定/网络异常），禁止"一律重试"；
- 需要突破 scope 边界才能继续（如跳转出授权域名）。
