"""Tests for structured audit logging and redaction."""

import json

from src.security.audit import AuditLogger, hash_text, redact


def test_redact_nested_sensitive_keys():
    redacted = redact(
        {
            "api_key": "sk-live",
            "nested": {"password": "hunter2", "safe": "value"},
            "items": [{"token": "abc"}],
        }
    )
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["nested"]["password"] == "[REDACTED]"
    assert redacted["nested"]["safe"] == "value"
    assert redacted["items"][0]["token"] == "[REDACTED]"


def test_hash_text_is_deterministic():
    assert hash_text("alert") == hash_text("alert")
    assert hash_text("alert") != hash_text("alert2")


def test_audit_logger_writes_jsonl_and_redacts(tmp_path):
    path = tmp_path / "audit" / "runs.jsonl"
    logger = AuditLogger(path)
    logger.log({"event": "agent_run_start", "api_key": "sk-live", "alert_id": "abc"})

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["api_key"] == "[REDACTED]"
    assert event["alert_id"] == "abc"
    assert "timestamp" in event
