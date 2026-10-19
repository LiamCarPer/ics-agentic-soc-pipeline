"""Tests for hardened agent tools: context, path confinement, rule generation."""

import pytest

from scripts.agent import (
    _attack_signature,
    _sid,
    analyze_anomaly,
    generate_suricata_rule,
    write_nist_incident_report,
)
from src.security.context import clear_run_context, register_run_context
from src.security.guards import validate_rule
from src.security.schemas import AlertPayload


def base_alert() -> dict:
    return {
        "alert_id": "e8358fb5-101a-43ba-93cd-8f9b95e30ac6",
        "timestamp": "2026-06-13T10:58:14+00:00",
        "plc_id": "plc_intake",
        "plc_ip": "172.21.0.10",
        "anomaly_score": -0.0011,
        "window_summary": {
            "tank_level_mean": 70.78,
            "tank_level_max": 80.4,
            "has_write_fc": 1,
            "source_ips": ["172.24.0.10", "172.22.0.10"],
            "function_codes": [3, 6],
        },
        "raw_data": [],
    }


def validated(alert: dict | None = None) -> dict:
    return AlertPayload.model_validate(alert or base_alert()).model_dump(mode="json")


@pytest.fixture
def context(tmp_path):
    alert = validated()
    ctx = register_run_context(
        alert,
        "--- ASSET INFO ---\nplc-intake\n--- IEC 62443 CONTROLS ---\nSR 1.4",
        rag_ids=("asset_inventory_001", "iec62443_controls_001"),
        output_dir=tmp_path,
    )
    yield ctx
    clear_run_context(alert["alert_id"])


def test_report_tool_writes_inside_output_dir(context, tmp_path):
    path = write_nist_incident_report.func(
        context.alert_id, "Unauthorized write causing cavitation risk."
    )
    output = tmp_path / f"incident_{context.alert_id}.md"
    assert path == str(output)
    assert output.is_file()
    text = output.read_text(encoding="utf-8")
    assert "plc_intake" in text
    assert "172.21.0.10" in text
    assert "SR 1.4" in text


def test_report_tool_rejects_traversal_alert_id(tmp_path):
    with pytest.raises(ValueError):
        write_nist_incident_report.func("a/../../pwn-a-b-c-d", "attempted traversal")
    assert not (tmp_path.parent.parent / "pwn-a-b-c-d.md").exists()


def test_report_tool_requires_registered_context():
    with pytest.raises(ValueError, match="no active run context"):
        write_nist_incident_report.func(
            "11111111-1111-4111-8111-111111111111", "summary"
        )


def test_rule_tool_writes_alert_only_rule(context, tmp_path):
    result = generate_suricata_rule.func(context.alert_id)
    output = tmp_path / f"block_{context.alert_id}.rules"
    assert output.is_file()
    rule = output.read_text(encoding="utf-8")
    assert "alert modbus 172.24.0.10 any -> 172.21.0.10 502" in rule
    assert 'content:"|00 06|"' in rule
    assert "flow:established,to_server" in rule
    assert f"sid:{_sid(context.alert_id)}" in rule
    assert "drop" not in rule.lower()
    assert validate_rule(rule) == "PASSED"
    assert str(output) in result


def test_rule_tool_handles_fc16(tmp_path):
    payload = base_alert()
    payload["window_summary"]["function_codes"] = [3, 16]
    alert = validated(payload)
    register_run_context(alert, "context", output_dir=tmp_path)
    try:
        generate_suricata_rule.func(alert["alert_id"])
        rule = (tmp_path / f"block_{alert['alert_id']}.rules").read_text()
        assert 'content:"|00 10|"' in rule
        assert "attempted-admin" in rule
    finally:
        clear_run_context(alert["alert_id"])


def test_rule_tool_handles_fc131(tmp_path):
    payload = base_alert()
    payload["window_summary"]["function_codes"] = [3, 131]
    payload["window_summary"]["has_write_fc"] = 0
    alert = validated(payload)
    register_run_context(alert, "context", output_dir=tmp_path)
    try:
        generate_suricata_rule.func(alert["alert_id"])
        rule = (tmp_path / f"block_{alert['alert_id']}.rules").read_text()
        assert 'content:"|00 83|"' in rule
        assert "attempted-recon" in rule
    finally:
        clear_run_context(alert["alert_id"])


def test_rule_tool_requires_context():
    with pytest.raises(ValueError, match="no active run context"):
        generate_suricata_rule.func("11111111-1111-4111-8111-111111111111")


def test_attack_signature_uses_untrusted_source():
    source, destination, function_code, has_write = _attack_signature(validated())
    assert source == "172.24.0.10"
    assert destination == "172.21.0.10"
    assert function_code == 6
    assert has_write is True


def test_analyze_tool_rejects_invalid_ip():
    with pytest.raises(ValueError):
        analyze_anomaly.func(
            anomaly_score=-0.05,
            tank_level_mean=50.0,
            tank_level_max=60.0,
            has_write_fc=False,
            function_codes=[3],
            source_ips=["not-an-ip"],
            plc_ip="172.21.0.10",
        )


def test_analyze_tool_rejects_invalid_function_code():
    with pytest.raises(ValueError):
        analyze_anomaly.func(
            anomaly_score=-0.05,
            tank_level_mean=50.0,
            tank_level_max=60.0,
            has_write_fc=False,
            function_codes=[99],
            source_ips=["172.22.0.10"],
            plc_ip="172.21.0.10",
        )
