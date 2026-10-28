---
name: verify-error-disclosure
# mutating: false —— 验证动作只读：1 次正常 GET + ≤5 条**畸形**请求（非法字符/编码/
# 版本/方法/超长 URI），不带任何凭据、不写目标状态。（M23）
mutating: false
description: 服务器报错信息泄露假设的验证 SOP——同一 host 基线干净、畸形请求返回 4xx/5xx 且正文命中 ≥2 类技术披露标记即 Confirmed；通用错误页/零标记判 Rejected；只命中 1 类、基线被污染或探针发不出判 blocked
version: 1.0.0
required_tools: []
risk_level: L2
inputs: [hypotheses]
outputs: [findings]
---

# verify-error-disclosure：服务器报错信息泄露验证

`vuln_type = error-disclosure` 类 Confirmed 的**唯一合法产出门径**（职责隔离：发现类
skill 只能产 Signal/Hypothesis）。执行由编排器 `run_verify_phase()` 确定性驱动；唯一
的 LLM 调用是收尾的 **Verifier 终审**（T2，独立 agent + 输入边界）。

## 本 skill 确认的是什么（**先划清边界**）

**唯一认可确认手段 = 同一 host 上「正常 GET 干净」与「畸形请求的错误页命中 ≥2 类
技术披露标记」之间的差分**。两个条件必须同时成立：

1. **基线干净**：正常 `GET /` 的正文不含任何技术披露标记；
2. **畸形请求可归因**：同一 host 的畸形请求返回 4xx/5xx，且正文命中 **≥2 类**
   标记（Java 堆栈 / PHP 错误 / Python 异常 / .NET 异常 / Node 堆栈 /
   中间件版本 / 源码路径）。

同一个 host、只改请求形态，一个干净一个吐堆栈 ⇒ 可归因。判据全是确定性正则，
零 LLM。

**不作证据的东西**（一律不看）：

| 观测 | 为什么不是证据 |
|---|---|
| `Server: nginx/1.25` 这类**版本头** | 几乎所有站点都有；算进结论 = 100% 误报（维护者裁定：只记审计） |
| 通用错误页（`400 Bad Request` / WAF 的 "Request blocked"） | 零标记 ⇒ 真阴性，不是泄露 |
| 只命中 1 类（如正文只有一个 `Exception` 单词） | 文档、示例代码、通用错误页都能命中单词，不足以归因 |
| 状态码本身 | 4xx/5xx 只说明请求被拒，不说明回显了内部信息 |

> 与 sqlmap 的"报错型注入"刻意不同：**报错不是证据**。错误页里有没有"内部
> 细节"才是证据，且必须有两类以上。

## 探针（固定、无副作用、≤5 条）

| # | 畸形请求 | 常见触发 |
|---|---|---|
| 1 | 路径里插入 `…`（UTF-8 字节 `E2 80 A6`） | Tomcat：`Invalid character found in the request target` |
| 2 | 路径里插入非法百分号编码 `%zz` | 各中间件 400 + 堆栈 |
| 3 | 请求行用非法版本 `HTTP/9.9` | 505/400 |
| 4 | 方法 token 里嵌控制字符（`G\x01ET`） | 400 |
| 5 | 超长 URI（>8KB） | 414；有的栈会带路径 |

- **必须用裸 TCP socket 发送**：`urllib`/`httpx`/`requests` 会在**客户端**拒绝或
  规范化非法请求行，探针根本发不出去（这是本类型最容易翻车的一条）。
- **不发送任何凭据**：基线与探针都不带 Cookie —— 判据与身份无关，带凭据只会把
  "匿名可见的报错页"这个问题弄混。
- **命中即停**：一条 4xx/5xx 且 ≥2 类标记即已足够，不再发剩余探针。
- **不跟随重定向**：裸 socket 本来就不跟；3xx 原样暴露。

## 判定表（宁漏勿滥）

| 观测 | 结论 |
|---|---|
| 基线干净 ∧ 某条畸形探针 4xx/5xx ∧ 正文命中 ≥2 类标记 | **confirmed** → REPRODUCED → 证据门 → Verifier |
| 畸形探针全部有响应、零标记、至少一条 4xx/5xx | **rejected**（真阴性，actor=verify-error-disclosure） |
| 基线本身命中标记 / 只命中 1 类 / 某条探针连接重置或超时 / 畸形请求未被拒绝（全 2xx/3xx） / 标记出现在非错误响应里 | **blocked**（覆盖不全，绝不驳回） |

## 证据与审计

- 每次探针落 `error_disclosure_<finding>_<label>_response.txt`（状态行 + `Server` +
  `Content-Type` + 标记类别 + 正文前 256KB，经 `redact_bytes`）；判定依据落
  `error_disclosure_<finding>_judgment.json`。
- **不记录完整畸形请求的原始字节**（含控制字符）：只记转义摘要 + sha256。
- 按次审计 `error_disclosure_probe_attempt`（label/status/error/classes/body_bytes/
  request_sha256）、判定 `error_disclosure_judged`。
- 版本头单独记 `server_header_disclosed`（审计/报告分类线索），**不进**
  `evidence_kinds` 与 `verification`。

## 诚实边界（**本 skill 明确不做**）

1. **不做请求走私**（`Content-Length` 与 `Transfer-Encoding` 冲突）、不做 header
   洪泛、不做 `Host` 注入 —— 要么危险、要么是另一个类型；
2. **只探 host 级一次**（中间件错误页通常与路径无关），不按端点放大；
3. **只覆盖 HTTP 明文与 TLS（校验证书）**：自签名靶会 blocked（`error_kind=tls`），
   不提供"不校验证书"的开关；
4. **代理/WAF 会改变结论的归因**：畸形请求被网关直接拦掉时响应是网关页 ⇒ 通常落
   `rejected`；判定 JSON 的 `server_header` 与 blocked 原因会写明"响应来自哪一层"；
5. **截图只留基线页**：错误页是畸形请求的响应，浏览器无法"导航"到它；错误页正文
   进证据文件，不额外做 `set_content` 截图。
