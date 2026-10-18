"""证据包组装（M3a，§5.5"出处可调出"）。

把 Finding 引用的证据（``路径#L<行号>`` 形式的 evidence_ref）收集到
``<evidence_base>/findings/<finding_id>/`` 目录：

- 证据原文整文件拷入（保留 #L 行号锚点语义），文件名
  ``<stem>-<sha256前8位><suffix>``（确定性、防撞名）；同一源文件多锚点
  只拷一次、锚点各自记录；
- ``manifest.json``：含 sha256 的证据文件清单（file/sha256/source_ref/
  line_anchor）；源文件缺失记 ``missing: true``（显式可见，不崩溃）；
- ``finding.json``：Finding 全量快照；``verification.reproduction_steps``
  非空时写 ``reproduction_steps.md``。

全程只读源证据、只写 evidence 目录；不碰网络、不调 LLM——"找出处"是
文件查询，不是模型回忆。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

from proofhound.findings.finding import Finding


def split_evidence_ref(ref: str) -> tuple[str, int | None]:
    """拆分 ``路径#L<行号>`` 形式的 evidence_ref；无锚点时行号为 None。"""
    path, sep, anchor = ref.rpartition("#L")
    if sep and path and anchor.isdigit():
        return path, int(anchor)
    return ref, None


def _collect_refs(finding: Finding) -> list[str]:
    """收集 Finding 的全部证据引用（source_signal_refs 优先，去重保序）。"""
    refs = list(finding.source_signal_refs)
    if finding.verification is not None:
        refs.extend(finding.verification.evidence_refs)
    seen: set[str] = set()
    unique: list[str] = []
    for ref in refs:
        if ref not in seen:
            seen.add(ref)
            unique.append(ref)
    return unique


def _materialize(src: Path, dest: Path) -> None:
    """把一个源证据文件"放进"证据包：**优先硬链接**，不可用才整文件拷贝。

    M19-b：原实现无条件 ``shutil.copyfile`` ⇒ 同一个源文件会被**每条** Finding
    各拷一份。`web-exposure` 是全池唯一**没有** triage 上限的类型，候选量又与
    探测路径数同阶：实测 300 条候选取同一份 106,800 B 的 dirsearch 报告时，
    证据目录膨胀到 **32,342,076 B（302.8×）**；按 dirsearch 的
    ``max_requests=5000`` 上限，最坏情况是数百 MB 量级。

    硬链接**不改变任何可观测语义**：包内文件照旧可单独 ``open``/``cat``，
    ``manifest.json`` 里的 sha256 与 ``finding.json`` 一字不变，只是同源证据在
    磁盘上只占一份。**可搬迁性**：跨文件系统时 ``os.link`` 抛 OSError 自动回落
    为拷贝；把证据包整体 ``cp -r`` / ``tar`` 出去后各自是独立文件，语义不变。
    """
    if dest.exists():
        dest.unlink()
    try:
        os.link(src, dest)
    except OSError:
        shutil.copyfile(src, dest)


def assemble_evidence_pack(finding: Finding, *, evidence_base: str | Path) -> Path:
    """组装/刷新证据包，返回包目录路径。"""
    pack_dir = Path(evidence_base) / "findings" / finding.id
    pack_dir.mkdir(parents=True, exist_ok=True)

    items: list[dict] = []
    copied: dict[str, dict] = {}  # 源路径 → 已拷贝项（多锚点复用）
    for ref in _collect_refs(finding):
        src_str, anchor = split_evidence_ref(ref)
        src = Path(src_str)
        if src_str in copied:
            item = dict(copied[src_str])
            item["source_ref"] = ref
            item["line_anchor"] = anchor
            items.append(item)
            continue
        if not src.is_file():
            items.append(
                {
                    "file": None,
                    "sha256": None,
                    "source_ref": ref,
                    "line_anchor": anchor,
                    "missing": True,
                }
            )
            copied[src_str] = items[-1]
            continue
        digest = hashlib.sha256(src.read_bytes()).hexdigest()
        pack_name = f"{src.stem}-{digest[:8]}{src.suffix}"
        _materialize(src, pack_dir / pack_name)
        items.append(
            {
                "file": pack_name,
                "sha256": digest,
                "source_ref": ref,
                "line_anchor": anchor,
            }
        )
        copied[src_str] = items[-1]

    manifest = {"finding_id": finding.id, "items": items}
    (pack_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (pack_dir / "finding.json").write_text(
        finding.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    steps = finding.verification.reproduction_steps if finding.verification else []
    if steps:
        (pack_dir / "reproduction_steps.md").write_text(
            "\n".join(f"{i}. {step}" for i, step in enumerate(steps, start=1)) + "\n",
            encoding="utf-8",
        )
    return pack_dir
