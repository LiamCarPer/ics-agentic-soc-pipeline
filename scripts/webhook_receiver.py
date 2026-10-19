"""
webhook_receiver.py — Event bridge for anomaly alerts.

Receives alerts from the detection service, validates them, stores them in
memory, and triggers the OT SOC Agent (LLM pipeline) for enrichment and report
generation.

Endpoints:
    POST /alert          — validate + run the agent synchronously (200)
    POST /alert/async    — validate + queue the agent (202)
    GET  /alerts         — return all received alerts (debug)
    GET  /alerts/{id}    — return the result/status for one alert
    GET  /health         — liveness (unauthenticated)

Security:
    - Optional X-API-Key auth (WEBHOOK_API_KEY).
    - Per-client sliding-window rate limit (WEBHOOK_RATE_LIMIT/WINDOW).
    - Request body cap (WEBHOOK_MAX_BODY_BYTES).
    - Strict Pydantic validation of every alert field.
    - The sync endpoint returns 200; 202 is used only for the async endpoint.
    - The in-memory store is a lab stand-in for a queue (see docs/AI_SECURITY.md).

Run:
    python scripts/webhook_receiver.py
"""

import hmac
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

# Ensure project root is on sys.path for `from src.*` imports
_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
import uvicorn

from scripts.agent import run_agent
from src.security.rate_limit import SlidingWindowRateLimiter
from src.security.schemas import AlertPayload

load_dotenv()

app = FastAPI(title="Alert Webhook Receiver", version="0.3.0")

# ---------------------------------------------------------------------------
# In-memory alert store (stand-in for a real queue like SQS or RabbitMQ)
# ---------------------------------------------------------------------------
_received_alerts: List[dict] = []
_agent_results: dict[str, dict] = {}

_MAX_BODY_BYTES = int(os.getenv("WEBHOOK_MAX_BODY_BYTES", "1048576"))
_rate_limiter = SlidingWindowRateLimiter(
    limit=int(os.getenv("WEBHOOK_RATE_LIMIT", "30")),
    window_seconds=float(os.getenv("WEBHOOK_RATE_WINDOW", "60")),
)


# ---------------------------------------------------------------------------
# Security dependencies
# ---------------------------------------------------------------------------


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    expected = os.getenv("WEBHOOK_API_KEY")
    if expected and not hmac.compare_digest(x_api_key or "", expected):
        raise HTTPException(
            status_code=401,
            detail="invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


def enforce_rate_limit(request: Request):
    client_key = request.client.host if request.client else "unknown"
    allowed, retry_after = _rate_limiter.check(client_key)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="rate limit exceeded",
            headers={"Retry-After": str(max(1, int(retry_after)))},
        )


@app.middleware("http")
async def limit_request_body(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > _MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413, content={"detail": "request body too large"}
                )
        except ValueError:
            return JSONResponse(
                status_code=400, content={"detail": "invalid Content-Length"}
            )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Agent execution
# ---------------------------------------------------------------------------


def _run_and_record(alert_dict: dict) -> dict:
    alert_id = alert_dict["alert_id"]
    try:
        result = run_agent(alert_dict)
        record = {
            "status": "completed",
            "alert_id": alert_id,
            "agent_summary": result.get("summary", ""),
            "incident_path": result.get("incident_path"),
            "rule_path": result.get("rule_path"),
            "run_id": result.get("run_id"),
            "audit_log": result.get("audit_log"),
        }
    except Exception as exc:  # noqa: BLE001 - surface failures to the caller
        record = {
            "status": "failed",
            "alert_id": alert_id,
            "agent_error": str(exc),
        }
    _agent_results[alert_id] = record
    return record


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post(
    "/alert",
    dependencies=[Depends(require_api_key), Depends(enforce_rate_limit)],
)
def handle_alert(alert: AlertPayload):
    now = datetime.now(timezone.utc).isoformat()
    alert_dict = alert.model_dump(mode="json")

    print(
        f"[{now}] PUBLISH alert_id={alert.alert_id} "
        f"to queue:alerts | plc={alert.plc_id} "
        f"score={alert.anomaly_score:.3f}"
    )
    _received_alerts.append(alert_dict)
    return _run_and_record(alert_dict)


@app.post(
    "/alert/async",
    status_code=202,
    dependencies=[Depends(require_api_key), Depends(enforce_rate_limit)],
)
def handle_alert_async(alert: AlertPayload, background_tasks: BackgroundTasks):
    now = datetime.now(timezone.utc).isoformat()
    alert_dict = alert.model_dump(mode="json")
    alert_id = alert_dict["alert_id"]

    print(f"[{now}] QUEUE alert_id={alert_id} for background processing")
    _received_alerts.append(alert_dict)
    _agent_results[alert_id] = {"status": "queued", "alert_id": alert_id}
    background_tasks.add_task(_run_and_record, alert_dict)
    return {"status": "queued", "alert_id": alert_id}


@app.get("/alerts", dependencies=[Depends(require_api_key)])
def list_alerts():
    return _received_alerts


@app.get("/alerts/{alert_id}", dependencies=[Depends(require_api_key)])
def get_alert_result(alert_id: str):
    result = _agent_results.get(alert_id)
    if result is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.environ.get("WEBHOOK_HOST", "127.0.0.1"),
        port=int(os.environ.get("WEBHOOK_PORT", "8000")),
    )
