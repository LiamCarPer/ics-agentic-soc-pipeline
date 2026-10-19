"""Tests for scripts/webhook_receiver.py — validation, auth, rate limit, async."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from scripts import webhook_receiver
from scripts.webhook_receiver import _agent_results, _received_alerts, app
from src.security.rate_limit import SlidingWindowRateLimiter

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

AGENT_RESULT = {
    "summary": "Analysis complete.",
    "incident_path": "/app/outputs/incident_e8358fb5.md",
    "rule_path": "/app/outputs/block_e8358fb5.rules",
    "run_id": "run-1",
    "audit_log": "/app/outputs/audit/agent_runs.jsonl",
}


@pytest.fixture(autouse=True)
def reset_state():
    _received_alerts.clear()
    _agent_results.clear()
    webhook_receiver._rate_limiter.reset()
    yield
    webhook_receiver._rate_limiter.reset()


@patch("scripts.webhook_receiver.run_agent")
def test_webhook_success(mock_run_agent):
    mock_run_agent.return_value = AGENT_RESULT
    resp = client.post("/alert", json=SAMPLE_ALERT)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
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
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "failed"
    assert "agent_error" in data
    assert "LLM API timeout" in data["agent_error"]


@pytest.mark.parametrize(
    "payload,expected_status",
    [
        ({}, 422),
        ({"alert_id": "not-a-uuid"}, 422),
        ({"alert_id": "e8358fb5-101a-43ba-93cd-8f9b95e30ac6"}, 422),
        ({**SAMPLE_ALERT, "alert_id": "a/../../pwn-a-b-c-d"}, 422),
        ({**SAMPLE_ALERT, "unexpected": "field"}, 422),
    ],
)
def test_webhook_invalid_payload(payload, expected_status):
    resp = client.post("/alert", json=payload)
    assert resp.status_code == expected_status


def test_list_alerts():
    resp = client.get("/alerts")
    assert resp.status_code == 200
    assert resp.json() == []


@patch("scripts.webhook_receiver.run_agent")
def test_async_endpoint_queues_and_records(mock_run_agent):
    mock_run_agent.return_value = AGENT_RESULT
    resp = client.post("/alert/async", json=SAMPLE_ALERT)
    assert resp.status_code == 202
    assert resp.json()["status"] == "queued"

    # TestClient runs background tasks before returning the response.
    result = client.get(f"/alerts/{SAMPLE_ALERT['alert_id']}")
    assert result.status_code == 200
    assert result.json()["status"] == "completed"


@patch("scripts.webhook_receiver.run_agent")
def test_api_key_required_when_configured(mock_run_agent, monkeypatch):
    mock_run_agent.return_value = AGENT_RESULT
    monkeypatch.setenv("WEBHOOK_API_KEY", "test-key")

    unauthorized = client.post("/alert", json=SAMPLE_ALERT)
    assert unauthorized.status_code == 401

    authorized = client.post(
        "/alert", json=SAMPLE_ALERT, headers={"X-API-Key": "test-key"}
    )
    assert authorized.status_code == 200


@patch("scripts.webhook_receiver.run_agent")
def test_rate_limit_returns_429(mock_run_agent, monkeypatch):
    mock_run_agent.return_value = AGENT_RESULT
    monkeypatch.setattr(
        webhook_receiver, "_rate_limiter", SlidingWindowRateLimiter(1, 60)
    )

    first = client.post("/alert", json=SAMPLE_ALERT)
    assert first.status_code == 200
    second = client.post("/alert", json=SAMPLE_ALERT)
    assert second.status_code == 429
    assert "Retry-After" in second.headers


def test_health_is_unauthenticated():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
