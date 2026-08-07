"""append-only 审计日志测试（§5.8）。"""

import json

from proofhound.compliance.audit import AuditLog


def test_record_appends_jsonl(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("command_executed", command=["httpx", "-u", "http://a"], exit_code=0)
    log.record("command_rejected", command=["httpx", "-u", "http://b"])

    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event"] == "command_executed"
    assert first["exit_code"] == 0
    assert "ts" in first
    second = json.loads(lines[1])
    assert second["event"] == "command_rejected"


def test_reopen_does_not_truncate(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record("e1")
    log = AuditLog(path)  # 重新打开同一文件
    log.record("e2")
    assert [e["event"] for e in log.read_all()] == ["e1", "e2"]


def test_creates_parent_dirs(tmp_path):
    log = AuditLog(tmp_path / "nested" / "dir" / "audit.jsonl")
    log.record("init")
    assert log.path.exists()


def test_read_all_empty(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.read_all() == []
