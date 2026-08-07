"""模板渲染测试（M4，§5.7）：docxtpl + StrictUndefined + 默认模板读回。

覆盖：最小模板渲染、模板缺失/变量未定义的清晰报错、默认模板全量渲染
（章节齐全/汇总表行数/详细发现证据索引/误报附录/叙述占位）、渲染确定性
（同输入 → word/document.xml 内容一致）。python-docx 读回验证，零网络。
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest
from docx import Document

from proofhound.report.data import build_context
from proofhound.report.render import RenderError, render_docx

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # 复用模板生成脚本

import make_default_template  # noqa: E402


@pytest.fixture
def minimal_template(tmp_path):
    """最小合法模板：一个变量 + 一个表格循环。"""
    doc = Document()
    doc.add_paragraph("目标：{{ engagement.target }}")
    table = doc.add_table(rows=3, cols=2)
    table.cell(0, 0).text = "ID"
    table.cell(0, 1).text = "类型"
    table.cell(1, 0).text = "{%tr for f in confirmed_findings %}"
    table.cell(2, 0).text = "{{ f.id }}"
    table.cell(2, 1).text = "{{ f.vuln_type }}"
    row = table.add_row()
    row.cells[0].text = "{%tr endfor %}"
    path = tmp_path / "minimal.docx"
    doc.save(str(path))
    return path


@pytest.fixture
def default_template(tmp_path):
    """默认模板：由生成脚本现产（保证测试与脚本不漂移）。"""
    path = tmp_path / "default_template.docx"
    make_default_template.main(["--out", str(path)])
    return path


def _paragraph_texts(doc: Document) -> list[str]:
    return [p.text for p in doc.paragraphs if p.text.strip()]


def _table_texts(doc: Document) -> list[str]:
    return [c.text for t in doc.tables for r in t.rows for c in r.cells]


# ---- 最小模板 ----


def test_minimal_template_renders(report_evidence_dir, minimal_template, tmp_path):
    context = build_context(report_evidence_dir).as_template_context()
    out = render_docx(context, minimal_template, tmp_path / "out.docx")
    doc = Document(str(out))
    assert any("目标：127.0.0.1:9" in p for p in _paragraph_texts(doc))
    # 汇总循环：表头 + 2 条 confirmed
    assert len(doc.tables[0].rows) == 3
    assert [c.text for c in doc.tables[0].rows[1].cells] == ["F-2026-0005", "rce"]
    assert [c.text for c in doc.tables[0].rows[2].cells] == ["F-2026-0001", "sqli"]


def test_missing_template_raises(report_evidence_dir, tmp_path):
    context = build_context(report_evidence_dir).as_template_context()
    with pytest.raises(RenderError, match="模板不存在"):
        render_docx(context, tmp_path / "nope.docx", tmp_path / "out.docx")


def test_undefined_variable_raises(report_evidence_dir, minimal_template, tmp_path):
    """StrictUndefined：引用契约外变量即清晰报错，不静默空渲染。"""
    context = build_context(report_evidence_dir).as_template_context()
    del context["engagement"]  # 模板引用 engagement.target → 未定义
    with pytest.raises(RenderError, match="变量未定义"):
        render_docx(context, minimal_template, tmp_path / "out.docx")


# ---- 默认模板全量渲染 ----


def test_default_template_structure(
    report_evidence_dir, default_template, tmp_path
):
    context = build_context(report_evidence_dir).as_template_context()
    out = render_docx(context, default_template, tmp_path / "report.docx")
    doc = Document(str(out))
    paras = _paragraph_texts(doc)
    tables = _table_texts(doc)

    # 章节骨架齐全（§5.7 固定章节）
    for heading in (
        "1. 测试概述",
        "2. 授权范围",
        "3. 方法论",
        "4. 发现汇总",
        "5. 详细发现",
        "6. 需特定条件的发现",
        "7. 疑似未验证（附录 A）",
        "8. 已排除误报及原因（附录 B）",
        "9. 修复建议",
    ):
        assert any(heading in p for p in paras), f"缺章节: {heading}"

    # 汇总表：表头 + 2 条 confirmed（按 severity 排序：critical 在前）
    summary_table = next(
        t for t in doc.tables if t.rows[0].cells[0].text == "ID"
        and t.rows[0].cells[1].text == "严重级"
    )
    assert len(summary_table.rows) == 3
    assert summary_table.rows[1].cells[0].text == "F-2026-0005"
    assert summary_table.rows[2].cells[0].text == "F-2026-0001"

    # 详细发现：证据索引（文件名 + sha256）与复现步骤
    confirmed = next(
        f for f in context["confirmed_findings"] if f["id"] == "F-2026-0001"
    )
    entry = confirmed["evidence_pack"]["entries"][0]
    assert any(entry["sha256"] in cell for cell in tables)
    assert any(entry["file"] in cell for cell in tables)
    assert any("1. 步骤一" in p for p in paras)
    assert any("2. 步骤二" in p for p in paras)
    assert any("sqlmap-confirmed" in cell for cell in tables)

    # 误报附录：version-cve + 拒绝原因
    assert any("version-cve" in cell for cell in tables)
    assert any("铁律禁止直接 Confirmed" in cell for cell in tables)

    # 疑似未验证附录：web-exposure
    assert any("web-exposure" in cell for cell in tables)

    # 叙述槽位为空 → 占位文字（--no-llm 对照语义）
    assert any(make_default_template.PLACEHOLDER in p for p in paras)


def test_default_template_renders_narrative(
    report_evidence_dir, default_template, tmp_path
):
    """叙述落盘后渲染出叙述文字而非占位。"""
    import json

    from proofhound.findings.finding import FindingStore

    store = FindingStore(report_evidence_dir / "findings.jsonl")
    finding = store.get("F-2026-0001")
    finding.narrative = "该注入可致后台数据库内容泄漏。"
    store.append(finding)
    (report_evidence_dir / "narrative_sections.json").write_text(
        json.dumps(
            {"overview": "概述段落。", "remediation": "修复建议段落。"},
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    context = build_context(report_evidence_dir).as_template_context()
    out = render_docx(context, default_template, tmp_path / "report.docx")
    paras = _paragraph_texts(Document(str(out)))
    assert any("该注入可致后台数据库内容泄漏。" in p for p in paras)
    assert any("概述段落。" == p for p in paras)
    assert any("修复建议段落。" == p for p in paras)


def test_render_deterministic(report_evidence_dir, default_template, tmp_path):
    """同输入同输出：两次渲染的 word/document.xml 内容字节一致。"""
    context = build_context(report_evidence_dir).as_template_context()
    out1 = render_docx(context, default_template, tmp_path / "r1.docx")
    out2 = render_docx(context, default_template, tmp_path / "r2.docx")

    def _document_xml(path: Path) -> bytes:
        with zipfile.ZipFile(path) as zf:
            return zf.read("word/document.xml")

    assert _document_xml(out1) == _document_xml(out2)


def test_render_escapes_xml_special_chars(report_evidence_dir, minimal_template, tmp_path):
    """替换值中的 & < > 必须原样保留（XML 转义，防 recover 解析静默吞字）。"""
    from proofhound.findings.finding import FindingStore

    store = FindingStore(report_evidence_dir / "findings.jsonl")
    finding = store.get("F-2026-0001")
    finding.asset = "http://127.0.0.1:9/app?id=1&Submit=Submit<b>"
    store.append(finding)
    context = build_context(report_evidence_dir).as_template_context()
    out = render_docx(context, minimal_template, tmp_path / "out.docx")
    cells = _table_texts(Document(str(out)))
    assert "sqli" in cells
    # 详细验证：默认模板下资产单元格原样呈现 & 与 <>
    default_tpl = tmp_path / "default.docx"
    make_default_template.main(["--out", str(default_tpl)])
    out2 = render_docx(context, default_tpl, tmp_path / "out2.docx")
    cells2 = _table_texts(Document(str(out2)))
    assert any(
        "http://127.0.0.1:9/app?id=1&Submit=Submit<b>" == cell for cell in cells2
    )
