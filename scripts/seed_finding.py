#!/usr/bin/env python3
"""种子 Finding 工具（M3b）：手动创建测试用 Hypothesis。

**已退役标记（deprecated，M6a 注记）**：M3d 起发现已自动化（katana 爬参
→ triage 自动产出 sqli Hypothesis，`scripts/demo_discovery_dvwa.py` 零种子
全链路）。本脚本保留可用，但仅供旧演示复现 verify 路径
（`scripts/demo_verify_dvwa.py` 仍依赖它播种正/反例），新流程请勿再用它
作为发现入口。

LLM triage 未做（M3 后续切片），verify 阶段的输入 Hypothesis 由本工具
手工播种替代：建 SIGNAL → ``transition(HYPOTHESIS, actor="seed")`` →
findings.jsonl 快照追加 → 组装证据包，审计落 ``<evidence_dir>/audit.jsonl``。

用法：
    .venv/bin/python scripts/seed_finding.py --dir evidence/demo_verify/xxx \
        --asset "http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
        --vuln-type sqli --param id --title "DVWA sqli id 参数注入"
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行

from proofhound.compliance.audit import AuditLog
from proofhound.findings import (
    Finding,
    FindingState,
    FindingStore,
    assemble_evidence_pack,
    compute_dedup_key,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="播种测试用 Hypothesis Finding")
    parser.add_argument("--dir", required=True, help="证据根目录（含 findings.jsonl）")
    parser.add_argument("--asset", required=True, help="资产（URL 原样）")
    parser.add_argument("--vuln-type", required=True, help="漏洞类型（如 sqli）")
    parser.add_argument("--param", default=None, help="参数/路径分量（去重指纹用）")
    parser.add_argument("--title", default=None)
    parser.add_argument("--severity", default="medium")
    parser.add_argument(
        "--evidence-kinds",
        default="status-code",
        help="逗号分隔的证据种类标签（默认 status-code，模拟 scan 来源）",
    )
    parser.add_argument(
        "--source-ref",
        action="append",
        default=[],
        help="可选来源证据引用（路径#L行号），可多次",
    )
    args = parser.parse_args(argv)

    evidence_dir = Path(args.dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(evidence_dir / "audit.jsonl")
    store = FindingStore(evidence_dir / "findings.jsonl")

    kinds = [k.strip() for k in args.evidence_kinds.split(",") if k.strip()]
    finding = Finding(
        id=store.next_id(),
        state=FindingState.SIGNAL,
        title=args.title,
        vuln_type=args.vuln_type,
        severity=args.severity,
        asset=args.asset,
        param=args.param,
        confidence="low",
        evidence_kinds=kinds,
        dedup_key=compute_dedup_key(args.asset, args.vuln_type, args.param),
        source_signal_refs=list(args.source_ref),
        created_at=_utc_now(),
        updated_at=_utc_now(),
        audit=audit,
    )
    finding.transition(
        FindingState.HYPOTHESIS,
        actor="seed",
        reason="手工播种测试用 Hypothesis（LLM triage 未做，M3b 替代入口）",
    )
    store.append(finding)
    pack_dir = assemble_evidence_pack(finding, evidence_base=evidence_dir)

    print(f"[+] 种子 Finding 已落盘: {finding.id}")
    print(f"    state={finding.state.value} vuln_type={finding.vuln_type} "
          f"asset={finding.asset} param={finding.param}")
    print(f"    dedup_key={finding.dedup_key[:24]}... evidence_kinds={kinds}")
    print(f"    证据包: {pack_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
