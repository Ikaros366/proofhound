"""证据包组装与 show 离线调出测试（M3a，§5.5"出处可调出"）。

覆盖验收点：
- 证据包组装：整文件拷贝、manifest 含 sha256 清单与行号锚点、
  reproduction_steps.md、源文件缺失显式标记；
- show：打印 Finding 全字段 + 证据索引 + 带行号锚点的证据原文；
  全程离线（socket 被封死仍通过），不碰网络不调 LLM。
"""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from proofhound.findings.__main__ import main as findings_main
from proofhound.findings.evidence import assemble_evidence_pack, split_evidence_ref
from proofhound.findings.finding import Finding, FindingStore, Verification

HTTPX_LINES = [
    '{"url":"http://127.0.0.1:9/a","status_code":404}',
    '{"url":"http://127.0.0.1:9/b","status_code":200,"title":"B"}',
    '{"url":"http://127.0.0.1:9/c","status_code":403}',
]


@pytest.fixture
def evidence_dir(tmp_path):
    """带一份假 httpx 原始输出（3 行）的证据目录。"""
    directory = tmp_path / "evidence"
    directory.mkdir()
    (directory / "run1.stdout.log").write_text(
        "\n".join(HTTPX_LINES) + "\n", encoding="utf-8"
    )
    return directory


def _make_finding(evidence_dir: Path, **overrides) -> Finding:
    log = evidence_dir / "run1.stdout.log"
    defaults = dict(
        id="F-2026-0001",
        state="hypothesis",
        vuln_type="web-exposure",
        asset="http://127.0.0.1:9/b",
        dedup_key="sha256:deadbeef",
        evidence_kinds=["status-code"],
        source_signal_refs=[f"{log}#L2"],
        verification=Verification(
            method="manual-check",
            evidence_refs=[f"{log}#L3"],
            reproduction_steps=["打开 /b", "对照 /c"],
        ),
        created_at="2026-08-07T00:00:00.000+00:00",
        updated_at="2026-08-07T00:00:00.000+00:00",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---- split_evidence_ref ----


def test_split_evidence_ref():
    assert split_evidence_ref("/a/b.log#L12") == ("/a/b.log", 12)
    assert split_evidence_ref("/a/b.log") == ("/a/b.log", None)
    assert split_evidence_ref("/a/b.log#Lx") == ("/a/b.log#Lx", None)


# ---- 证据包组装 ----


def test_assemble_pack_copies_evidence_with_sha256_manifest(evidence_dir):
    finding = _make_finding(evidence_dir)
    pack_dir = assemble_evidence_pack(finding, evidence_base=evidence_dir)

    assert pack_dir == evidence_dir / "findings" / finding.id
    manifest = json.loads((pack_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["finding_id"] == finding.id
    assert len(manifest["items"]) == 2  # 同源文件两个锚点

    src = evidence_dir / "run1.stdout.log"
    expected_sha = hashlib.sha256(src.read_bytes()).hexdigest()
    item = manifest["items"][0]
    assert item["sha256"] == expected_sha
    assert item["line_anchor"] == 2
    assert item["source_ref"].endswith("#L2")
    assert manifest["items"][1]["line_anchor"] == 3
    # 同一源文件只拷一次
    assert item["file"] == manifest["items"][1]["file"]
    # 拷贝内容逐字节一致
    assert (pack_dir / item["file"]).read_bytes() == src.read_bytes()
    # finding.json 快照与复现步骤
    snapshot = json.loads((pack_dir / "finding.json").read_text(encoding="utf-8"))
    assert snapshot["id"] == finding.id
    assert "audit" not in snapshot
    steps = (pack_dir / "reproduction_steps.md").read_text(encoding="utf-8")
    assert "1. 打开 /b" in steps and "2. 对照 /c" in steps


def test_assemble_pack_marks_missing_source(evidence_dir):
    finding = _make_finding(
        evidence_dir,
        source_signal_refs=[str(evidence_dir / "ghost.log#L1")],
        verification=None,
    )
    pack_dir = assemble_evidence_pack(finding, evidence_base=evidence_dir)
    manifest = json.loads((pack_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["items"][0]["missing"] is True
    assert manifest["items"][0]["file"] is None
    assert not (pack_dir / "reproduction_steps.md").exists()


# ---- show 离线调出 ----


def _prepare_store(evidence_dir: Path) -> Finding:
    finding = _make_finding(evidence_dir)
    FindingStore(evidence_dir / "findings.jsonl").append(finding)
    assemble_evidence_pack(finding, evidence_base=evidence_dir)
    return finding


def test_show_offline_with_line_anchors(evidence_dir, monkeypatch, capsys):
    """socket 全面封死：show 仍完整输出，证明全程离线。"""
    finding = _prepare_store(evidence_dir)

    def _no_network(*args, **kwargs):
        raise AssertionError("show 不得触碰网络")

    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)

    rc = findings_main(["show", finding.id, "--dir", str(evidence_dir)])
    assert rc == 0
    out = capsys.readouterr().out
    # Finding 全字段
    assert f"Finding {finding.id}" in out
    assert '"vuln_type": "web-exposure"' in out
    assert '"state": "hypothesis"' in out
    # 证据索引：sha256 清单 + 源引用
    expected_sha = hashlib.sha256(
        (evidence_dir / "run1.stdout.log").read_bytes()
    ).hexdigest()
    assert expected_sha in out
    assert "run1.stdout.log#L2" in out
    # 行号锚点原文
    assert f"L2> {HTTPX_LINES[1]}" in out
    assert f"L3> {HTTPX_LINES[2]}" in out


def test_show_subprocess_entrypoint(evidence_dir):
    """python -m proofhound.findings show 入口装配验证。"""
    finding = _prepare_store(evidence_dir)
    result = subprocess.run(
        [sys.executable, "-m", "proofhound.findings", "show", finding.id,
         "--dir", str(evidence_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert finding.id in result.stdout
    assert "L2>" in result.stdout


def test_show_unknown_id_and_missing_store(evidence_dir, capsys):
    _prepare_store(evidence_dir)
    assert findings_main(["show", "F-2099-0001", "--dir", str(evidence_dir)]) == 1
    assert findings_main(["show", "F-2026-0001", "--dir", str(evidence_dir / "x")]) == 2
