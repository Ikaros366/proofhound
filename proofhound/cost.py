"""``python -m proofhound.cost``：单题成本归属 CLI（M11a，§5.6 成本可观测）。

口径（维护者裁决）：按「调用方 + 阶段」归属、**含修复重试**（修复重试单列）。
数据源 = engagement 的 ``audit.jsonl`` 中的 ``llm_call`` 事件（只读、纯文件、
零 LLM、零网络）。

用法：
    python -m proofhound.cost --dir <engagement_dir>
    python -m proofhound.cost --dir <engagement_dir> --json      # 机器可读
    python -m proofhound.cost --dir <engagement_dir> --finding F-2026-0009
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from proofhound.llm.cost import aggregate, load_calls, render_markdown


def _cmd_report(args: argparse.Namespace) -> int:
    audit_path = Path(args.dir) / "audit.jsonl"
    if not audit_path.is_file():
        print(f"[错误] 未找到审计文件: {audit_path}", file=sys.stderr)
        return 2

    calls = load_calls(audit_path)
    if args.finding:
        calls = [c for c in calls if c.finding_id == args.finding]
    report = aggregate(calls)

    if args.json:
        print(json.dumps(report.as_dict(), ensure_ascii=False, indent=2))
        return 0

    title = "单题成本归属"
    if args.finding:
        title += f"（仅 Finding {args.finding}）"
    print(render_markdown(report, title=title))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m proofhound.cost")
    parser.add_argument(
        "--dir",
        required=True,
        help="engagement 目录（含 audit.jsonl）",
    )
    parser.add_argument(
        "--finding",
        default=None,
        help="只看某个 Finding 的确认成本（其余调用点无 finding 归属，会被过滤掉）",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="输出 JSON（供脚本消费）而非 Markdown 摘要",
    )
    args = parser.parse_args(argv)
    return _cmd_report(args)


if __name__ == "__main__":
    sys.exit(main())
