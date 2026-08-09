# ProofHound

**证据驱动、验证优先的自动化渗透测试 Agent 系统。** 一切候选发现默认为假，必须通过行为验证、证据门与独立 Verifier 终审才能进入报告。

名称说明：本项目与 proofhound.org 的提示词管理平台没有任何关系，纯巧合撞名；PyPI 包名 proofhound 为本项目预留。

![控制台全流程演示](docs/demo.gif)

核心差异化：

- **证据门控反误报**：候选发现走 Signal→Hypothesis→Reproduced→Confirmed 状态机；版本匹配型 CVE、纯状态码型发现被铁律硬编码永久禁止 Confirmed；证据门（`verify/gate.py`）+ Verifier（独立模型对抗校验）双层防守。
- **出处可调出**：每条 Finding 配证据包（原文 + sha256 manifest + 行号锚点），`python -m proofhound.findings show <id>` 纯文件离线调出，不碰网络/LLM。
- **预算硬闸**：Run 级 token 预算调用前检查，超限即停并记审计，与 scope 授权同级不可绕过；LLM 三档路由（T0 廉价/T1 中档/T2 前沿），Verifier 与发现端必须不同模型。
- **授权先行**：无 scope 授权文件系统拒绝启动；每条拟执行命令先提取目标过 scope 校验，越界拒绝 + 记审计。
- **模板化报告**：docx 模板（docxtpl）一键出报告；事实字段全部来自结构化数据，LLM 只做叙述润色且段落必须锚定 Finding ID，另有确定性叙事事实守卫校验状态措辞与计数。

## ⚠️ 法律免责声明

**本工具仅用于获得书面授权的安全测试。** 未经授权对任何系统使用本工具（扫描、验证、利用）在绝大多数司法辖区属违法行为。使用者须自行确保拥有目标系统的有效书面授权，并对使用本工具产生的一切后果承担全部责任。作者不承担任何直接或间接责任。下载、安装或使用本工具即视为接受本声明。

## 架构五条红线

实现与本仓库一切贡献均受以下红线约束（详见 [docs/design.md](docs/design.md) §3）：

1. **LLM 只做推理**：确定性动作由调度器直接执行；LLM 规划输出结构化 JSON，不直接生成 shell 命令（命令由工具管理器按 manifest 模板拼装）。
2. **发现 ≠ 漏洞**：候选发现默认是假的，必须经行为验证晋级 Confirmed。
3. **上下文只进结构化摘要**：工具原始输出一律落盘 `evidence/`，LLM 上下文只有结构化数据 + 文件引用路径。
4. **模型按任务分级**：解析/润色用廉价模型，漏洞假设与 Verifier 用前沿模型；Verifier 与发现端必须用不同模型。
5. **授权前置**：scope 强制校验、预算帽、append-only 审计日志在任何自治模式下都不可绕过。

## Quickstart：十分钟复现（DVWA 全流程）

目标：全新机器从零 → DVWA 靶场 → 创建任务 → 批准 L2 → Confirmed → 出报告。

前提：Linux（WSL 亦可）+ 可用 Docker 守护进程 + Python 3.12 + 一组 OpenAI 兼容 LLM API key（T1、T2 两档且须为**不同模型**）。

```bash
# 1. 获取代码与依赖
git clone <仓库地址> proofhound && cd proofhound
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# 2. 配置 LLM：复制样例并填入 T1/T2 两档（T0 可选）
cp .env.example .env
vi .env            # 填 PROOFHOUND_T1_* 与 PROOFHOUND_T2_*

# 3. 起 DVWA 靶场容器（同名旧容器先清理：docker rm -f dvwa 2>/dev/null）
docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa

# 4. 写 scope 授权文件（无授权不启动；scope 目录本机私有、不入库）
mkdir -p scopes
printf 'networks: [127.0.0.0/8]\nports: [8080]\n' > scopes/dvwa.yaml

# 5. 起本机控制台（只绑 127.0.0.1；8000 被占用时换 --port 8001，浏览器地址相应替换）
.venv/bin/python -m proofhound.api --workspace . --port 8000
```

DVWA 首次使用需初始化数据库并登录拿会话 Cookie（admin/password，security=low）。以下纯标准库脚本输出可粘贴的 Cookie 串：

```bash
python3 - <<'EOF'
import http.cookiejar, re, urllib.parse, urllib.request
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
B = "http://127.0.0.1:8080"
tok = re.search(r"user_token['\"]\s+value=['\"]([0-9a-f]+)",
                op.open(B + "/setup.php").read().decode()).group(1)
op.open(B + "/setup.php",
        urllib.parse.urlencode({"create_db": "Create / Reset Database",
                                "user_token": tok}).encode())
tok = re.search(r"user_token['\"]\s+value=['\"]([0-9a-f]+)",
                op.open(B + "/login.php").read().decode()).group(1)
op.open(B + "/login.php",
        urllib.parse.urlencode({"username": "admin", "password": "password",
                                "Login": "Login", "user_token": tok}).encode())
print("; ".join(f"{c.name}={c.value}" for c in jar) + "; security=low")
EOF
```

然后浏览器打开 `http://127.0.0.1:8000/`：

1. **创建任务**：目标 `http://127.0.0.1:8080`，scope 勾选 `dvwa.yaml`，自治模式选 `semi_auto`，会话 Cookie 框粘贴上一步输出（提交后界面不再出现）。
2. 任务自动推进：katana 爬行发现带参端点 + httpx 探活 → 确定性 triage 自动产出 sqli Hypothesis。
3. **批准 L2**：verify-sqli（L2 利用验证）进入确认队列，控制台置顶警示，点「批准」放行 sqli/id。
4. sqlmap 沙箱行为确认 → 证据门 → Verifier（T2）终审 → Finding 变 **Confirmed**（CVSS 向量由 Verifier 产出、代码按官方公式确定性算分）。
5. **出报告**：报告区选模板 → 构建 → 下载 docx。误报附录（附录 B）与证据索引（附录 A）随报告自动生成。

命令行等效操作：

```bash
# 离线调出任意 Finding 的完整证据包（纯文件查询）
.venv/bin/python -m proofhound.findings show <finding_id> --dir engagements/<engagement_id>
# CLI 构建报告（--no-llm 跳过叙述生成）
.venv/bin/python -m proofhound.report build --dir engagements/<engagement_id> --out report.docx
```

## 工具指南

### 自带工具矩阵

| 工具 | 版本 | 用途 | 对应 Skill | 风险级 | 安装配方 |
|---|---|---|---|---|---|
| httpx | 1.10.0 | HTTP 探活与指纹识别 | web-scan | L1（主动扫描） | GitHub release zip + 强制 sha256 |
| katana | 1.7.0 | Web 爬行、带参端点发现 | recon-crawl | L1 | GitHub release zip + 强制 sha256 |
| sqlmap | 1.10.8 | SQL 注入行为验证 | verify-sqli | L2（利用验证） | PyPI 版本 pin + 强制 sha256，隔离装进 `tools.d/sqlmap/lib` |

### tools.d/ 预置教程（离线场景）

每个工具的安装配方按三级回退执行：**① `tools.d/` 本地预置 → ② 白名单源自动下载（强制 sha256）→ ③ 包管理器兜底**。涉敏/离线环境走第①级：

- 单二进制工具：把可执行文件放成 `tools.d/<name>/<name>`（如 `tools.d/httpx/httpx`），安装器自动检测收录。
- 自带字典/依赖文件的工具：整个发行目录放进 `tools.d/<name>/`，保证 `tools.d/<name>/<name>` 是可执行入口（可以是 wrapper 脚本，内部用相对路径引用自带文件）。以 dirsearch 为例：

```
tools.d/dirsearch/
├── dirsearch        # 可执行入口（wrapper，如 exec python3 lib/dirsearch.py "$@"）
└── lib/             # 发行件本体
    ├── dirsearch.py
    └── db/dicc.txt  # 自带字典随目录一起走
```

仓内先例：sqlmap 即 `tools.d/sqlmap/sqlmap`（wrapper）+ `tools.d/sqlmap/lib/`（pip 隔离安装本体）。`tools.d/installed.json` 记录各工具版本与来源快照。

### 自动下载的 sha256 核验纪律

所有自动下载走白名单源（GitHub release / PyPI）+ **强制 sha256 校验**：manifest 内版本 pin 死、哈希为发行件实测值，哈希不符即拒装。升级是显式动作——改 manifest 版本号并重新实测哈希，绝不每任务重复下载；沙箱运行镜像（alpine:3.20、python:3.12-alpine）首次使用拉取、其后本地复用。

### 接入新工具（开发者指南）

四个落点，以 katana 接入提交 `fcf9eb0`（M3d）为模板：

1. `proofhound/tools/manifests/<name>.yaml`：安装配方（版本 pin + sha256 + 白名单源 + parser 声明，Python 工具可声明 `image` 沙箱镜像覆盖）。
2. `proofhound/tools/build.py`：确定性命令构造器——LLM 只产结构化参数、不产 shell（红线 1）；危险参数（如 sqlmap level/risk）在构造器内硬上限。
3. `proofhound/tools/parsers/<name>_<fmt>.py`：输出解析器，配版本快照回归测试防格式漂移。
4. `skills/<skill-name>/SKILL.md`：Skill 声明（`risk_level` L0/L1/L2 + `required_tools`）；发现类 skill 只能产 Signal/Hypothesis，Confirmed 必须经 verify-* skill 产出。

## Skill 管理

控制台「技能」视图支持上传（zip ≤1MiB、单顶层目录、必含 SKILL.md）、在线编辑、删除；上传经 schema + required_tools ⊆ 构造器注册表校验，all-or-nothing 零写入；内置 skill 受保护（删除 409、编辑走 copy-on-edit 不改仓库文件）。

> ⚠️ **信任警告**：Skill 声明的 `required_tools` 会驱动沙箱内真实命令执行。**只导入可信来源的 Skill**；导入前审阅 SKILL.md 全文。

## 自主模式三档

| 动作风险级 | supervised | semi_auto（默认） | unattended |
|---|---|---|---|
| L0 被动 | 自动 | 自动 | 自动 |
| L1 主动扫描 | 需确认 | 自动 | 自动 |
| L2 利用验证 | 需确认 | 需确认 | 自动 |

未知风险级 fail-closed（一律禁止）。模式切换收紧自由、放宽须显式 operator 确认并记 `autonomy_mode_changed` 审计；确认请求超时默认拒绝。**任何模式下 scope 校验、预算硬闸、凭据脱敏、append-only 审计都不可旁路。**

## 报告模板

- 仓库自带 `templates/default_template.docx`（全标签参考模板，由 `scripts/make_default_template.py` 可重现生成）。
- 接入自己的模板：按 docxtpl（Jinja2）标签契约写 docx，放入 `templates/` 目录即可在控制台报告区下拉选用。契约要点：渲染环境 **StrictUndefined**（引用契约外变量即报错）；表格/段落循环标签 `{%tr %}/{%p %}` 必须独占行/段；多行文本用 `{{r }}` 富文本渲染；完整变量契约见 [AGENTS.md](AGENTS.md)「报告模板变量契约」一节。
- 私有企业模板属客户资产、不在本仓库范围内（本机保留 `templates/custom_enterprise_template.docx` 时被 .gitignore 排除，相关测试自动 skip）。企业模板实践示例：封面单位/系统名/报告日期三件套走 engagement extras（控制台创建表单直接填写，透传进渲染上下文、不进 LLM prompt）；风险项表格用 `{%tr for f in confirmed_findings %}` 循环；附录 A 证据索引对 `evidence_index` 循环。

## 安全模型

- **只绑回环**：API 默认监听 127.0.0.1；非回环绑定会在 stderr 打印醒目告警。
- **无认证边界声明**：API 无认证/授权层，定位单机自用。**多人使用必须前置反向代理（nginx + TLS）+ 登录认证；严禁无认证直接暴露公网。**
- **凭据脱敏体系**：预置会话 Cookie 只挂 Scope，审计/state/日志只记 sha256 前 8 位；控制台提交即清，响应体永不携带 cookie 原值。
- **沙箱隔离**：每 engagement 独立容器；工具目录只读挂载；网络出口限速 + 白名单（默认 restricted）；CPU/内存配额。
- **append-only 审计**：每条命令、每段输出、每次 LLM 调用、每次状态迁移全部落盘，兼作报告证据链。

## 路线图与已知限制

已完成：M1 工具底座（manifest/安装器/沙箱/scope/审计）→ M2 Skill 系统 + 编排器 + 模型路由预算 → M3 Finding 生命周期 + 证据门 + Verifier + verify-sqli 垂直切片 + katana 发现自动化 → M4 报告引擎 + 模板适配 → M5 Web API + 自主模式闸门 + 本地控制台 → M6 稳定性加固 + 管理面 + CVSS 真实化 + 叙事事实守卫。M7 开源准备即本仓库当前形态。待做：PDF 报告管线、verify-xss/verify-lfi、LLM triage、成本仪表盘、MCP 暴露、持续监测。

已知限制摘要（完整清单见 [AGENTS.md](AGENTS.md)「已知限制」）：行为验证仅 sqli 一条垂直切片；发现自动化仅覆盖 GET 查询参数端点；API 无认证；沙箱出口白名单仅覆盖 HTTP(S)；控制台为轮询无 WebSocket；报告仅 docx。

## 贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全漏洞报告请走 [SECURITY.md](SECURITY.md)。

## 许可证

[Apache-2.0](LICENSE)，Copyright 2026 Ikaros366。
