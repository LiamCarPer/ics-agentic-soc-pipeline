"""Tests for scripts/webhook_receiver.py — FastAPI endpoints."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from scripts.webhook_receiver import app, _received_alerts

client = TestClient(app)

SAMPLE_ALERT = {
    "alert_id": "e8358fb5-101a-43ba-93cd-8f9b95e30ac6",
    "timestamp": "2026-06-13T10:58:14+00:00",
    "plc_id": "plc_intake",
    "plc_ip": "172.21.0.10",
    "anomaly_score": -0.0011,
    "window_start": "2026-06-13T10:57:49+00:00",
    "window_end": "2026-06-13T10:58:14+00:00",
    "window_summary": {
        "tank_level_mean": 70.78,
        "tank_level_max": 80.4,
        "has_write_fc": 1,
        "source_ips": ["172.24.0.10", "172.22.0.10"],
        "function_codes": [3, 6],
    },
    "raw_data": [],
}


@patch("scripts.webhook_receiver.run_agent")
def test_webhook_success(mock_run_agent):
    mock_run_agent.return_value = {
        "summary": "Analysis complete.",
        "incident_path": "/app/outputs/incident_e8358fb5.md",
        "rule_path": "/app/outputs/block_e8358fb5.rules",
    }
    resp = client.post("/alert", json=SAMPLE_ALERT)
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "received"
    assert data["alert_id"] == SAMPLE_ALERT["alert_id"]
    assert data["agent_summary"] == "Analysis complete."
    assert data["incident_path"] is not None
    assert data["rule_path"] is not None

    mock_run_agent.assert_called_once()
    call_arg = mock_run_agent.call_args[0][0]
    assert call_arg["alert_id"] == SAMPLE_ALERT["alert_id"]


@patch("scripts.webhook_receiver.run_agent")
def test_webhook_agent_error(mock_run_agent):
    mock_run_agent.side_effect = RuntimeError("LLM API timeout")
    resp = client.post("/alert", json=SAMPLE_ALERT)
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "received"
    assert "agent_error" in data
    assert "LLM API timeout" in data["agent_error"]


@pytest.mark.parametrize(
    "payload,expected_status",
    [
        ({}, 422),
        ({"alert_id": "not-a-uuid"}, 422),
        ({"alert_id": "e8358fb5-101a-43ba-93cd-8f9b95e30ac6"}, 422),
    ],
)
def test_webhook_invalid_payload(payload, expected_status):
    resp = client.post("/alert", json=payload)
    assert resp.status_code == expected_status


def test_list_alerts():
    _received_alerts.clear()
    resp = client.get("/alerts")
    assert resp.status_code == 200
    assert resp.json() == []
