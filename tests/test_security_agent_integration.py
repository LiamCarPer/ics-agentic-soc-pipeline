"""Integration test for run_agent with a fake LLM.

This exercises the real context registry, tool implementations, path
confinement, audit logging and output discovery without an API key or network.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import agent as agent_module
from scripts.agent import run_agent
from src.security.context import get_run_context

ALERT = {
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


class FakeAgent:
    """Calls the real tools in the same order the LLM should."""

    def __init__(self, alert: dict):
        self.alert = alert

    def invoke(self, messages, config):
        summary = self.alert["window_summary"]
        analysis = agent_module.analyze_anomaly.func(
            anomaly_score=self.alert["anomaly_score"],
            tank_level_mean=summary["tank_level_mean"],
            tank_level_max=summary["tank_level_max"],
            has_write_fc=bool(summary["has_write_fc"]),
            function_codes=summary["function_codes"],
            source_ips=summary["source_ips"],
            plc_ip=self.alert["plc_ip"],
        )
        report = agent_module.write_nist_incident_report.func(
            self.alert["alert_id"], analysis
        )
        rule = agent_module.generate_suricata_rule.func(self.alert["alert_id"])
        return {
            "messages": [
                SimpleNamespace(
                    type="ai",
                    content="",
                    tool_calls=[{"name": "analyze_anomaly", "args": {"score": -0.1}}],
                ),
                SimpleNamespace(type="tool", content=report),
                SimpleNamespace(
                    type="ai",
                    content="",
                    tool_calls=[{"name": "generate_suricata_rule", "args": {}}],
                ),
                SimpleNamespace(type="tool", content=rule),
                SimpleNamespace(type="ai", content="Analysis complete.", tool_calls=[]),
            ]
        }


def test_run_agent_with_fake_llm(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_module, "OUTPUTS_DIR", tmp_path)
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit" / "runs.jsonl"))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    monkeypatch.setattr(
        agent_module,
        "retrieve_context_details",
        lambda alert: (
            "--- ASSET INFO ---\nplc-intake\n--- CONTROLS ---\nSR 1.4",
            ["doc-1"],
        ),
    )
    monkeypatch.setattr(agent_module, "ChatOpenAI", lambda **kwargs: object())

    def fake_create_agent(model, tools, system_prompt):
        return FakeAgent(ALERT)

    monkeypatch.setattr(agent_module, "create_agent", fake_create_agent)

    result = run_agent(ALERT)

    assert result["summary"] == "Analysis complete."
    assert Path(result["incident_path"]).is_file()
    assert Path(result["rule_path"]).is_file()
    assert Path(result["incident_path"]).parent == tmp_path

    audit_lines = Path(result["audit_log"]).read_text(encoding="utf-8").splitlines()
    assert len(audit_lines) == 2
    assert '"event": "agent_run_start"' in audit_lines[0]
    assert '"event": "agent_run_end"' in audit_lines[1]

    # The run context must not leak after the run.
    assert get_run_context(ALERT["alert_id"]) is None


def test_run_agent_rejects_invalid_alert_before_llm():
    bad = dict(ALERT)
    bad["alert_id"] = "a/../../pwn-a-b-c-d"
    with pytest.raises(ValueError, match="invalid alert"):
        run_agent(bad)
