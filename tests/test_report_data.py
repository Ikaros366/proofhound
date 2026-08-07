"""报告数据组装测试（M4，§5.7 数据与表现分离）。

覆盖：四态分桶、severity 排序、证据包索引（file/sha256/锚点）、
engagement.json 优先与派生两条路径、无 manifest 显式标记、
narrative/rejection_reason 透传、sections 读取。全程纯文件查询。
"""

from __future__ import annotations

import hashlib
import json

from proofhound.report.data import build_context


def test_bucketing_and_counts(report_evidence_dir):
    context = build_context(report_evidence_dir)
    assert [f.id for f in context.confirmed_findings] == [
        "F-2026-0005",  # critical 排在 high 前（severity 权重优先于 id）
        "F-2026-0001",
    ]
    assert [f.id for f in context.conditional_findings] == ["F-2026-0002"]
    assert [f.id for f in context.hypothesis_findings] == ["F-2026-0003"]
    assert [f.id for f in context.rejected_findings] == ["F-2026-0004"]
    summary = context.summary
    assert (summary.confirmed, summary.conditional) == (2, 1)
    assert (summary.hypothesis, summary.rejected) == (1, 1)
    assert summary.severity_counts == {"critical": 1, "high": 1}  # 按权重排序


def test_evidence_pack_index(report_evidence_dir):
    context = build_context(report_evidence_dir)
    confirmed = next(f for f in context.confirmed_findings if f.id == "F-2026-0001")
    pack = confirmed.evidence_pack
    assert pack.assembled is True
    assert pack.pack_dir.endswith("findings/F-2026-0001")
    assert len(pack.entries) == 1
    entry = pack.entries[0]
    source = report_evidence_dir / "run1.stdout.log"
    assert entry.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert entry.file.startswith("run1.stdout-") and entry.file.endswith(".log")
    assert entry.source_ref == f"{source}#L2"
    assert entry.line_anchor == 2
    assert entry.missing is False

    # 未组装证据包的 finding：显式 assembled=False，不崩溃
    conditional = context.conditional_findings[0]
    assert conditional.evidence_pack.assembled is False
    assert conditional.evidence_pack.entries == []


def test_structured_fields_passthrough(report_evidence_dir):
    context = build_context(report_evidence_dir)
    confirmed = next(f for f in context.confirmed_findings if f.id == "F-2026-0001")
    assert confirmed.verification["method"] == "sqlmap-confirmed"
    assert confirmed.verification["reproduction_steps"] == ["步骤一", "步骤二"]
    assert confirmed.evidence_kinds == ["status-code", "behavioral"]
    rejected = context.rejected_findings[0]
    assert rejected.rejection_reason.startswith("版本匹配型 CVE")
    assert rejected.vuln_type == "version-cve"


def test_engagement_derived_from_audit_and_assets(report_evidence_dir):
    """无 engagement.json：target 取资产最高频 host，时间窗取 audit 首/末条。"""
    context = build_context(report_evidence_dir)
    assert context.engagement.target == "127.0.0.1:9"
    events = (report_evidence_dir / "audit.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    first_ts = json.loads(events[0])["ts"]
    last_ts = json.loads(events[-1])["ts"]
    assert context.engagement.started_at == first_ts
    assert context.engagement.finished_at == last_ts
    assert context.engagement.scope is None


def test_engagement_json_overrides_derivation(report_evidence_dir):
    (report_evidence_dir / "engagement.json").write_text(
        json.dumps(
            {"target": "engaged.example", "scope": "127.0.0.0/8"},
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    context = build_context(report_evidence_dir)
    assert context.engagement.target == "engaged.example"
    assert context.engagement.scope == "127.0.0.0/8"
    # 未给的字段仍走派生
    assert context.engagement.started_at is not None


def test_engagement_time_window_falls_back_to_findings(tmp_path):
    """无 audit 且无 engagement.json：时间窗退化为 findings 时间戳 min/max。"""
    (tmp_path / "findings.jsonl").write_text("", encoding="utf-8")
    context = build_context(tmp_path)
    assert context.engagement.started_at is None
    assert context.engagement.finished_at is None
    assert context.summary.confirmed == 0


def test_sections_loaded_and_tolerates_bad_json(report_evidence_dir):
    # 契约键恒在（StrictUndefined 下可判空），未生成为 None
    assert build_context(report_evidence_dir).sections == {
        "overview": None,
        "remediation": None,
    }
    (report_evidence_dir / "narrative_sections.json").write_text(
        json.dumps({"overview": "概述", "remediation": "建议"}, ensure_ascii=False),
        encoding="utf-8",
    )
    context = build_context(report_evidence_dir)
    assert context.sections == {"overview": "概述", "remediation": "建议"}
    (report_evidence_dir / "narrative_sections.json").write_text(
        "{bad json", encoding="utf-8"
    )
    assert build_context(report_evidence_dir).sections == {
        "overview": None,
        "remediation": None,
    }


def test_template_context_is_plain_json(report_evidence_dir):
    """渲染输入为纯 JSON 类型 dict（数据与表现分离：渲染器只读它）。"""
    context = build_context(report_evidence_dir).as_template_context()
    # 可 JSON 序列化即纯结构化
    json.dumps(context)
    assert set(context) >= {
        "engagement", "summary", "confirmed_findings",
        "conditional_findings", "hypothesis_findings", "rejected_findings",
        "sections",
    }


# ---- M4.5：extras 透传 / severity_cn / repro_text / evidence_index ----


def test_engagement_extras_passthrough(report_evidence_dir):
    """M4.5：engagement.json 任意额外键原样透传进渲染上下文（只进模板）。"""
    (report_evidence_dir / "engagement.json").write_text(
        json.dumps(
            {
                "target": "http://127.0.0.1:9",
                "company_name": "某某单位",
                "system_name": "自定义企业演示系统",
                "report_date": "2026年8月",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    engagement = build_context(report_evidence_dir).as_template_context()["engagement"]
    assert engagement["company_name"] == "某某单位"
    assert engagement["system_name"] == "自定义企业演示系统"
    assert engagement["report_date"] == "2026年8月"
    assert engagement["target"] == "http://127.0.0.1:9"  # 已知字段不变


def test_engagement_no_file_no_extras(report_evidence_dir):
    """无 engagement.json：只有四个契约字段，无 extras。"""
    engagement = build_context(report_evidence_dir).as_template_context()["engagement"]
    assert set(engagement) == {"target", "scope", "started_at", "finished_at"}


def test_engagement_known_field_validation_unchanged(report_evidence_dir):
    """已知字段校验不变：坏类型仍 ValidationError（extras 不放松已知字段）。"""
    import pydantic
    import pytest

    (report_evidence_dir / "engagement.json").write_text(
        json.dumps({"target": 123, "company_name": "某单位"}), encoding="utf-8"
    )
    with pytest.raises(pydantic.ValidationError):
        build_context(report_evidence_dir)


def test_severity_cn_mapping(report_evidence_dir):
    """M4.5：中文档位映射 critical→严重/high→高/medium→中/low→低/info→提示。"""
    context = build_context(report_evidence_dir)
    by_id = {
        f.id: f
        for bucket in (
            context.confirmed_findings,
            context.conditional_findings,
            context.hypothesis_findings,
            context.rejected_findings,
        )
        for f in bucket
    }
    assert by_id["F-2026-0005"].severity_cn == "严重"  # critical
    assert by_id["F-2026-0001"].severity_cn == "高"  # high
    assert by_id["F-2026-0002"].severity_cn == "中"  # medium
    assert by_id["F-2026-0004"].severity_cn == "低"  # low
    assert by_id["F-2026-0003"].severity_cn == "提示"  # info


def test_severity_cn_unknown_passthrough(report_evidence_dir):
    """未知级别原样返回。"""
    from proofhound.findings.finding import Finding, FindingStore

    store = FindingStore(report_evidence_dir / "findings.jsonl")
    store.append(
        Finding(
            id="F-2026-0009",
            state="hypothesis",
            vuln_type="custom",
            severity="weird",
            asset="http://127.0.0.1:9/x",
            dedup_key="sha256:weird",
            created_at="2026-08-07T00:00:00.000+00:00",
            updated_at="2026-08-07T00:00:00.000+00:00",
        )
    )
    context = build_context(report_evidence_dir)
    weird = next(f for f in context.hypothesis_findings if f.id == "F-2026-0009")
    assert weird.severity_cn == "weird"


def test_repro_text(report_evidence_dir):
    """M4.5：编号拼接复现文本（\\n 连接）；无 verification 为空串。"""
    context = build_context(report_evidence_dir)
    confirmed = next(f for f in context.confirmed_findings if f.id == "F-2026-0001")
    assert confirmed.repro_text == "1. 步骤一\n2. 步骤二"
    no_verification = next(
        f for f in context.confirmed_findings if f.id == "F-2026-0005"
    )
    assert no_verification.repro_text == ""


def test_evidence_index_assembly(report_evidence_dir):
    """M4.5 扁平证据索引：confirmed+conditional 全部条目，稳定桶序。"""
    context = build_context(report_evidence_dir)
    # fixture 中仅 F-2026-0001 组装了证据包（1 条目）；conditional 未组装不贡献
    assert len(context.evidence_index) == 1
    item = context.evidence_index[0]
    assert item.finding_id == "F-2026-0001"
    source = report_evidence_dir / "run1.stdout.log"
    assert item.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert item.source_ref == f"{source}#L2"
    assert item.line_anchor == 2
    assert item.file is not None and item.file.startswith("run1.stdout-")
    # 渲染上下文可见（纯 JSON 结构化）
    dumped = context.as_template_context()["evidence_index"]
    assert dumped[0]["finding_id"] == "F-2026-0001"
    assert dumped[0]["sha256"] == item.sha256
