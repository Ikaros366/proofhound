#!/usr/bin/env python3
"""M4 报告引擎验收 demo（不进 pytest）：用 DVWA demo 产物出真实报告。

链路：复制一份 demo_verify 产物（不改 M3b 原始产物）→ 补齐验收矩阵
（version-cve Hypothesis→Rejected；缺 web-exposure 则播种一条 Hypothesis；
写 engagement.json）→ 先出 --no-llm 对照报告（此时无叙述，占位文字在）
→ 再出真实 T1 叙述版报告 → python-docx 读回自检（汇总表分桶/证据索引
sha256/误报附录/叙述可回溯 finding_id）。

用法：
    .venv/bin/python scripts/demo_report.py [--dir evidence/demo_verify/<ts>]
                                            [--dvwa-url http://127.0.0.1:8080]
.env 需要：PROOFHOUND_T1_*（叙述生成；缺则叙述版构建报错退出 2）。
产物落 evidence/demo_report/<时间戳>/（gitignored）。
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 允许直接以脚本方式运行
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用 seed_finding / 模板常量

from docx import Document

from proofhound.compliance.audit import AuditLog
from proofhound.findings import FindingState, FindingStore, assemble_evidence_pack
from proofhound.report.__main__ import main as report_main

import seed_finding
from make_default_template import PLACEHOLDER

CHECKS: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    CHECKS.append((name, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")


def _texts(doc: Document) -> tuple[list[str], list[str]]:
    paras = [p.text for p in doc.paragraphs if p.text.strip()]
    cells = [c.text for t in doc.tables for r in t.rows for c in r.cells]
    return paras, cells


def prepare_matrix(evidence_dir: Path, dvwa_url: str) -> None:
    """在副本上补齐验收矩阵：Rejected version-cve + Hypothesis web-exposure。"""
    audit = AuditLog(evidence_dir / "audit.jsonl")
    store = FindingStore(evidence_dir / "findings.jsonl")

    version_cve = next(
        (f for f in store.load_all() if f.vuln_type == "version-cve"), None
    )
    if version_cve is not None and version_cve.state is FindingState.HYPOTHESIS:
        version_cve.audit = audit
        version_cve.transition(
            FindingState.REJECTED,
            actor="demo_report",
            reason="版本匹配型 CVE：仅版本指纹比对，无行为验证手段，"
            "按 §5.4.1 铁律永远禁止直接 Confirmed，判误报排除",
        )
        store.append(version_cve)
        assemble_evidence_pack(version_cve, evidence_base=evidence_dir)
        print(f"[*] {version_cve.id} version-cve → Rejected（误报附录数据源）")

    if not any(f.vuln_type == "web-exposure" for f in store.load_all()):
        seed_finding.main([
            "--dir", str(evidence_dir), "--asset", f"{dvwa_url}/",
            "--vuln-type", "web-exposure", "--severity", "info",
            "--title", "DVWA 站点存活（web 暴露面）",
        ])

    (evidence_dir / "engagement.json").write_text(
        json.dumps(
            {
                "target": dvwa_url,
                "scope": "127.0.0.0/8（仅 loopback，DVWA 本地靶场）",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"[*] engagement.json 已写入（target={dvwa_url}）")


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofHound M4 报告引擎验收")
    parser.add_argument(
        "--dir",
        default=None,
        help="demo_verify 产物目录（缺省取 evidence/demo_verify/ 最新）",
    )
    parser.add_argument("--dvwa-url", default="http://127.0.0.1:8080")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"))
    args = parser.parse_args()

    if args.dir:
        src = Path(args.dir)
    else:
        candidates = sorted(
            p for p in (REPO_ROOT / "evidence" / "demo_verify").iterdir()
            if p.is_dir()
        )
        if not candidates:
            print("[错误] evidence/demo_verify/ 无产物，先跑 demo_verify_dvwa.py",
                  file=sys.stderr)
            return 2
        src = candidates[-1]
    if not (src / "findings.jsonl").is_file():
        print(f"[错误] 产物目录无 findings.jsonl: {src}", file=sys.stderr)
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = REPO_ROOT / "evidence" / "demo_report" / stamp
    evidence_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, evidence_dir, dirs_exist_ok=True)
    print(f"[*] 验收副本: {evidence_dir}（源 {src}，原始产物未改动）")

    prepare_matrix(evidence_dir, args.dvwa_url)

    # 1. --no-llm 对照（此时无叙述落盘，占位文字应在）
    nollm_out = evidence_dir / "report_nollm.docx"
    print("\n[*] 构建 --no-llm 对照报告 ...")
    rc = report_main([
        "build", "--dir", str(evidence_dir), "--out", str(nollm_out),
        "--no-llm", "--env-file", args.env_file,
    ])
    if rc != 0:
        return rc

    # 2. 真实 T1 叙述版
    llm_out = evidence_dir / "report.docx"
    print("\n[*] 构建叙述版报告（T1 真实调用）...")
    rc = report_main([
        "build", "--dir", str(evidence_dir), "--out", str(llm_out),
        "--env-file", args.env_file,
    ])
    if rc != 0:
        return rc

    # 3. 读回自检
    print("\n[*] 报告读回自检 ...")
    store = FindingStore(evidence_dir / "findings.jsonl")
    confirmed = [
        f for f in store.load_all() if f.state is FindingState.CONFIRMED
    ]

    llm_paras, llm_cells = _texts(Document(str(llm_out)))
    summary_table = next(
        t for t in Document(str(llm_out)).tables
        if t.rows[0].cells[0].text == "ID"
        and t.rows[0].cells[1].text == "严重级"
    )
    check(
        f"汇总表分桶正确（表头 + {len(confirmed)} 条 confirmed 行）",
        len(summary_table.rows) == len(confirmed) + 1,
    )

    pack_manifest = json.loads(
        (evidence_dir / "findings" / confirmed[0].id / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    sha256s = [item["sha256"] for item in pack_manifest["items"] if item.get("sha256")]
    check(
        "详细发现含证据包索引（文件名 + sha256）",
        all(any(s in cell for cell in llm_cells) for s in sha256s),
    )

    rejected = next(f for f in store.load_all() if f.vuln_type == "version-cve")
    check(
        "误报附录含 version-cve 及拒绝原因",
        any("version-cve" in cell for cell in llm_cells)
        and any(rejected.rejection_reason[:20] in cell for cell in llm_cells),
    )

    narratives_ok = all(f.narrative for f in confirmed)
    narratives_in_doc = all(
        any(f.narrative in p for p in llm_paras) for f in confirmed
    )
    check(
        "叙述段每段可回溯 finding_id（非空且出现在报告对应段）",
        narratives_ok and narratives_in_doc,
    )

    nollm_paras, _ = _texts(Document(str(nollm_out)))
    check(
        "--no-llm 对照：占位文字在、叙述不在",
        any(PLACEHOLDER in p for p in nollm_paras)
        and not any(
            f.narrative and f.narrative in p
            for f in confirmed
            for p in nollm_paras
        ),
    )

    failed = [name for name, ok in CHECKS if not ok]
    print(f"\n[*] 产物: {llm_out} / {nollm_out}")
    if failed:
        print(f"[失败] {len(failed)} 项未过: {failed}")
        return 1
    print("[*] 全部自检通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
