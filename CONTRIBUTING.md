# CONTRIBUTING.md

感谢贡献。本项目纪律不多但条条是红线，提交前请通读 [AGENTS.md](AGENTS.md) 与 [docs/design.md](docs/design.md)。

## 五条架构红线（不可妥协）

1. LLM 只做推理，不直接生成 shell 命令（确定性命令由工具管理器按 manifest 拼装）。
2. 发现 ≠ 漏洞：Confirmed 只能经 verify-* skill 行为验证 + 证据门 + Verifier 终审产出。
3. 上下文只进结构化摘要：工具原始输出一律落盘 `evidence/`。
4. 模型按任务分级：Verifier 与发现端必须用不同模型。
5. 授权前置：scope 校验、预算帽、append-only 审计在任何自治模式下不可绕过。

任何削弱上述机制的改动（如添加绕过 scope 的开关、审计可写覆盖）一律拒收。

## 提交要求

- **测试**：`.venv/bin/python -m pytest` 全绿方可提交；新功能必须配测试（无 Docker 环境用 `-m "not docker"` 跑纯单元）。
- **风格**：跟随周边既有代码风格；commit 信息与用户可见文档用中文，代码标识符用英文。
- **卫生**：`.env`、密钥、`evidence/`、`engagements/` 永不入库；不附带武器化 exploit 模块、不附带任何真实目标数据。
- **里程碑纪律**：一次只实现当前里程碑内容，设计决策变更须同步更新 docs/design.md。

## 新工具/新 Skill 接入

四落点：manifest 配方 + build.py 构造器 + 解析器（配版本快照测试）+ SKILL.md。参照 README「接入新工具」一节与 katana 接入提交。
