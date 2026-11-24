from universe.audit import AuditLog
from universe.models import Command, Result, RiskLevel
from universe.secrets import REDACTED


def test_audit_redacts_and_persists(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    cmd = Command(
        source="ara",
        target="android.phone",
        action="type",
        params={"text": "segreto-in-chiaro", "hint": "nome"},
    )
    result = Result.success(cmd, RiskLevel.MEDIUM, result="ok", dry_run=True)
    entry = log.record(cmd, result, RiskLevel.MEDIUM, sensitive_params=["text"])
    assert entry["params"]["text"] == REDACTED
    assert entry["params"]["hint"] == "nome"
    raw = path.read_text(encoding="utf-8")
    assert "segreto-in-chiaro" not in raw
    assert "type" in raw
    assert log.entries()[0]["id"] == cmd.id


def test_audit_redacts_tokens_even_without_extra_keys(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    cmd = Command(
        source="bot",
        target="rest.generic",
        action="create_item",
        params={"token": "abc123", "name": "ok"},
    )
    result = Result.success(cmd, RiskLevel.MEDIUM, dry_run=True)
    entry = log.record(cmd, result, RiskLevel.MEDIUM)
    assert entry["params"]["token"] == REDACTED
    assert entry["params"]["name"] == "ok"
    assert "abc123" not in (tmp_path / "audit.jsonl").read_text()
