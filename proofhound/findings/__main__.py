"""``python -m proofhound.findings``：Finding 证据包一键调出（M3a，§5.5）。

``show`` 子命令离线打印 Finding 全字段 + 证据包索引 + 证据内容与行号
锚点。全程纯文件查询：不碰网络、不调 LLM——"找出处"是文件查询，不是
模型回忆。

用法：
    python -m proofhound.findings show <finding_id> [--dir <evidence_dir>]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from proofhound.findings.finding import FindingStore


def _cmd_show(finding_id: str, evidence_dir: Path) -> int:
    store = FindingStore(evidence_dir / "findings.jsonl")
    if not store.path.is_file():
        print(f"[错误] findings 存储不存在: {store.path}", file=sys.stderr)
        return 2
    finding = store.get(finding_id)
    if finding is None:
        print(f"[错误] 未找到 Finding: {finding_id}", file=sys.stderr)
        return 1

    print(f"Finding {finding.id}")
    print(finding.model_dump_json(indent=2))

    pack_dir = evidence_dir / "findings" / finding.id
    manifest_path = pack_dir / "manifest.json"
    print(f"\n证据包: {pack_dir}")
    if not manifest_path.is_file():
        print("  （证据包未组装：无 manifest.json）")
        return 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = manifest.get("items", [])
    print(f"  manifest.json: {len(items)} 项")
    for item in items:
        if item.get("missing"):
            print(f"  - [缺失] source_ref={item['source_ref']}")
            continue
        print(f"  - {item['file']}")
        print(f"      sha256: {item['sha256']}")
        print(f"      source_ref: {item['source_ref']}")
        anchor = item.get("line_anchor")
        if anchor is not None:
            evidence_file = pack_dir / item["file"]
            lines = evidence_file.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            if 1 <= anchor <= len(lines):
                print(f"      L{anchor}> {lines[anchor - 1]}")
            else:
                print(f"      L{anchor}> （锚点超出文件行数 {len(lines)}）")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m proofhound.findings")
    sub = parser.add_subparsers(dest="command", required=True)
    show = sub.add_parser("show", help="离线调出 Finding 完整证据包")
    show.add_argument("finding_id")
    show.add_argument(
        "--dir",
        default="evidence",
        help="证据根目录（含 findings.jsonl 与 findings/），默认 ./evidence",
    )
    args = parser.parse_args(argv)
    if args.command == "show":
        return _cmd_show(args.finding_id, Path(args.dir))
    return 2  # pragma: no cover - argparse required=True 已拦截


if __name__ == "__main__":
    sys.exit(main())
