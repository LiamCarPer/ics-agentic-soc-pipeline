"""
webhook_receiver.py — Event bridge for anomaly alerts.

Receives alerts from the detection service, stores them in memory,
and immediately triggers the OT SOC Agent (LLM pipeline) for enrichment
and report generation.

Endpoints:
    POST /alert   — receive one alert, trigger agent, return results
    GET  /alerts  — return all received alerts (for verification)

Run:
    python scripts/webhook_receiver.py
"""

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Ensure project root is on sys.path for `from src.*` imports
_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator
import uvicorn

from scripts.agent import run_agent

load_dotenv()

app = FastAPI(title="Alert Webhook Receiver", version="0.2.0")

# ---------------------------------------------------------------------------
# In-memory alert store (stand-in for a real queue like SQS or RabbitMQ)
# ---------------------------------------------------------------------------
_received_alerts: List[dict] = []


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class WindowSummary(BaseModel):
    tank_level_mean: float
    tank_level_max: float
    has_write_fc: int
    source_ips: List[str]
    function_codes: List[int]


class AlertPayload(BaseModel):
    alert_id: str = Field(..., description="Unique UUID for this alert")
    timestamp: str = Field(..., description="ISO 8601 timestamp of the last row in the window")
    plc_id: str = Field(..., description="PLC identifier")
    anomaly_score: float = Field(..., description="decision_function value (more negative = more anomalous)")
    window_summary: WindowSummary
    raw_data: List[dict]

    plc_ip: Optional[str] = Field(None, description="IP address of the PLC")
    window_start: Optional[str] = Field(None, description="ISO 8601 timestamp of the first row")
    window_end: Optional[str] = Field(None, description="ISO 8601 timestamp of the last row")

    @field_validator("alert_id")
    @classmethod
    def alert_id_must_be_uuid(cls, v: str) -> str:
        parts = v.split("-")
        if len(parts) != 5 or not all(p.strip() != "" for p in parts):
            raise ValueError(f"alert_id must be a UUID string, got {v!r}")
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/alert", status_code=202)
def handle_alert(alert: AlertPayload):
    now = datetime.now(timezone.utc).isoformat()
    alert_dict = alert.model_dump()

    print(
        f"[{now}] PUBLISH alert_id={alert.alert_id} "
        f"to queue:alerts | plc={alert.plc_id} "
        f"score={alert.anomaly_score:.3f}"
    )
    _received_alerts.append(alert_dict)

    # TODO: production → fire-and-forget with asyncio.create_task / background worker
    try:
        agent_result = run_agent(alert_dict)
        print(
            f"[{now}] AGENT DONE alert_id={alert.alert_id} "
            f"incident={agent_result.get('incident_path', 'N/A')} "
            f"rule={agent_result.get('rule_path', 'N/A')}"
        )
        return {
            "status": "received",
            "alert_id": alert.alert_id,
            "agent_summary": agent_result.get("summary", ""),
            "incident_path": agent_result.get("incident_path"),
            "rule_path": agent_result.get("rule_path"),
        }
    except Exception as exc:
        print(f"[{now}] AGENT FAILED alert_id={alert.alert_id}: {exc}", file=sys.stderr)
        return {
            "status": "received",
            "alert_id": alert.alert_id,
            "agent_error": str(exc),
        }


@app.get("/alerts")
def list_alerts():
    return _received_alerts


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
