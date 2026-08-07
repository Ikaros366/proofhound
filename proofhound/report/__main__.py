"""``python -m proofhound.report``：报告构建 CLI（M4，§5.7）。

链路：build_context（数据组装，纯文件查询）→ 叙述生成（T1 档，可选
``--no-llm`` 跳过）→ 重 build_context（带入叙述）→ docxtpl 渲染出 docx。
叙述落 ``Finding.narrative`` + ``narrative_sections.json`` 并记审计
``narrative_generated``；渲染只读结构化 context。

用法：
    python -m proofhound.report build --dir <evidence_dir> --out <docx>
        [--template <docx>]   # 缺省 = 仓库 templates/default_template.docx
        [--no-llm]            # 跳过叙述生成（叙述槽位留占位）
        [--env-file .env]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from proofhound.compliance.audit import AuditLog
from proofhound.core.context import ContextOverflowError
from proofhound.findings.finding import FindingStore
from proofhound.llm.client import LLMError
from proofhound.llm.router import ModelRouter, Tier
from proofhound.llm.usage import BudgetExceededError, TokenBudget, UsageTracker
from proofhound.report.data import build_context
from proofhound.report.narrative import NarrativeError, NarrativeGenerator
from proofhound.report.render import RenderError, render_docx

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_TEMPLATE = REPO_ROOT / "templates" / "default_template.docx"


def _cmd_build(args: argparse.Namespace) -> int:
    evidence_dir = Path(args.dir)
    store = FindingStore(evidence_dir / "findings.jsonl")
    if not store.path.is_file():
        print(f"[错误] findings 存储不存在: {store.path}", file=sys.stderr)
        return 2
    template = Path(args.template) if args.template else DEFAULT_TEMPLATE
    if not template.is_file():
        print(f"[错误] 报告模板不存在: {template}", file=sys.stderr)
        return 2

    context = build_context(evidence_dir)
    if not args.no_llm:
        audit = AuditLog(evidence_dir / "audit.jsonl")
        try:
            budget = TokenBudget.from_env(args.env_file)
            tracker = UsageTracker()
            router = ModelRouter.from_env(
                args.env_file, audit=audit, tracker=tracker, budget=budget
            )
        except LLMError as exc:
            print(f"[配置错误] {exc}", file=sys.stderr)
            return 2
        if Tier.T1 not in router.configs:
            print(
                "[配置错误] 未配置 T1 档（叙述生成需要）：PROOFHOUND_T1_*"
                "（或用 --no-llm 跳过叙述生成）",
                file=sys.stderr,
            )
            return 2
        generator = NarrativeGenerator(router, audit)
        try:
            paragraphs = generator.generate(
                store.load_all(), store=store, evidence_dir=evidence_dir
            )
        except BudgetExceededError as exc:
            print(
                f"[预算硬闸] {exc}——可用 --no-llm 跳过叙述生成",
                file=sys.stderr,
            )
            return 1
        except (NarrativeError, ContextOverflowError, LLMError) as exc:
            print(
                f"[叙述生成失败] {exc}——可用 --no-llm 跳过叙述生成",
                file=sys.stderr,
            )
            return 1
        print(
            f"[*] 叙述生成完成：{len(paragraphs)} 段"
            f"（本阶段 {tracker.total_tokens()} tokens）"
        )
        context = build_context(evidence_dir)  # 重建：带入 narrative 与 sections

    try:
        out = render_docx(context.as_template_context(), template, Path(args.out))
    except RenderError as exc:
        print(f"[渲染失败] {exc}", file=sys.stderr)
        return 1
    summary = context.summary
    print(f"[*] 报告已生成: {out}")
    print(
        f"    confirmed={summary.confirmed} conditional={summary.conditional} "
        f"hypothesis={summary.hypothesis} rejected={summary.rejected}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m proofhound.report")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="组装数据 + 生成叙述 + 渲染 docx 报告")
    build.add_argument(
        "--dir", required=True, help="证据根目录（含 findings.jsonl 与 findings/）"
    )
    build.add_argument("--out", required=True, help="输出 docx 路径")
    build.add_argument(
        "--template",
        default=None,
        help=f"docx 模板路径（缺省 {DEFAULT_TEMPLATE}）",
    )
    build.add_argument(
        "--no-llm",
        action="store_true",
        help="跳过叙述生成（叙述槽位留占位文字）",
    )
    build.add_argument("--env-file", default=".env", help="LLM 配置文件路径")
    args = parser.parse_args(argv)
    if args.command == "build":
        return _cmd_build(args)
    return 2  # pragma: no cover - argparse required=True 已拦截


if __name__ == "__main__":
    sys.exit(main())
