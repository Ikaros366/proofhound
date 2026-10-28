"""CLI：``python -m proofhound.jsimport``——JS 接口发现 → 未授权确认（M24-a）。

```bash
python -m proofhound.jsimport \\
  --katana-jsonl evidence/<eng>/katana.stdout.log \\
  --scope scopes/lab.yaml --out evidence/jsimport/<ts> \\
  [--param-seed 1] [--fetch-missing] [--max-js 50] [--max-probes 100]
```

退出码（交接单 §6）：

- ``0``：至少 1 条 **confirmed**（匿名响应 ≡ 已认证响应）；
- ``1``：没有 confirmed（可能全 rejected / blocked / 清单）；
- ``2``：入口错误 / 无会话 / 会话失效 / scope 全拒 —— **结构性失败**，
  不是"测过且安全"。

CLI 本身不做任何判定：它只把参数翻成 :class:`~proofhound.jsimport.probe.ImportConfig`
并调用 :func:`~proofhound.jsimport.probe.run_jsimport`。
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from proofhound.compliance.scope import Scope
from proofhound.jsimport.crawl import DEFAULT_MAX_JS_BYTES, DEFAULT_MAX_JS_FILES
from proofhound.jsimport.probe import (
    DEFAULT_MAX_PROBES,
    DEFAULT_QPS,
    DEFAULT_TIMEOUT,
    ImportConfig,
    run_jsimport,
)

#: 缺省证据目录的父目录（与其余 demo/工具一致；``evidence/`` 不入库）
DEFAULT_OUT_PARENT = Path("evidence") / "jsimport"


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m proofhound.jsimport",
        description=(
            "从 katana JSONL 里的 JS 正文抽接口路径，"
            "对每个候选做「已认证 vs 匿名」确定性对比（结论来自 judge_unauth）"
        ),
    )
    parser.add_argument(
        "--katana-jsonl",
        required=True,
        nargs="+",
        metavar="PATH",
        help="katana -jsonl 输出（可多份；JS 正文取自 response.body）",
    )
    parser.add_argument(
        "--scope",
        required=True,
        help="scope 授权文件（YAML）；预置会话即「已认证视图」的来源",
    )
    parser.add_argument(
        "--out",
        default=None,
        help=f"证据输出目录（缺省 {DEFAULT_OUT_PARENT}/<UTC 时间戳>）",
    )
    parser.add_argument(
        "--param-seed",
        default="1",
        help="合成路径参数与 query 值时填的值（缺省 1）",
    )
    parser.add_argument(
        "--fetch-missing",
        action="store_true",
        help="JS 正文缺失时按 scope 校验后匿名补抓一次（缺省关）",
    )
    parser.add_argument(
        "--max-js",
        type=int,
        default=DEFAULT_MAX_JS_FILES,
        help=f"最多解析的 JS 文件数（缺省 {DEFAULT_MAX_JS_FILES}）",
    )
    parser.add_argument(
        "--max-js-bytes",
        type=int,
        default=DEFAULT_MAX_JS_BYTES,
        help=f"单个 JS 文件字节上限（缺省 {DEFAULT_MAX_JS_BYTES}）",
    )
    parser.add_argument(
        "--max-probes",
        type=int,
        default=DEFAULT_MAX_PROBES,
        help=f"最多探测的候选数（缺省 {DEFAULT_MAX_PROBES}）",
    )
    parser.add_argument(
        "--qps",
        type=float,
        default=DEFAULT_QPS,
        help=f"请求速率上限（缺省 {DEFAULT_QPS}，并发固定 1；0 = 不限速）",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"单请求超时秒数（缺省 {DEFAULT_TIMEOUT}）",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    paths = [Path(item) for item in args.katana_jsonl]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        print(f"[!] 找不到 katana JSONL: {', '.join(missing)}", file=sys.stderr)
        return 2
    scope_path = Path(args.scope)
    if not scope_path.is_file():
        print(f"[!] 找不到 scope 文件: {scope_path}", file=sys.stderr)
        return 2
    try:
        scope = Scope.from_file(scope_path)
    except Exception as exc:  # noqa: BLE001 - 入口错误统一报
        print(f"[!] scope 文件无法加载: {exc}", file=sys.stderr)
        return 2

    out_dir = Path(args.out) if args.out else DEFAULT_OUT_PARENT / _timestamp()
    config = ImportConfig(
        jsonl_paths=tuple(paths),
        scope=scope,
        out_dir=out_dir,
        param_seed=args.param_seed,
        fetch_missing=args.fetch_missing,
        max_js_files=max(1, args.max_js),
        max_js_bytes=max(1, args.max_js_bytes),
        max_probes=max(1, args.max_probes),
        qps=max(0.0, args.qps),
        timeout=max(0.1, args.timeout),
    )
    report = run_jsimport(config)
    for line in report.render_lines():
        print(line)
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
