# ICS Agentic SOC Pipeline

**ML anomaly detection → RAG enrichment → LLM agent (NIST reports + Suricata rules).**

An end-to-end agentic AI pipeline that acts as a Level 1 SOC Analyst for OT/ICS environments. Built for the [OT-Security-Lab](https://github.com/LiamCarPer/ot-security-lab) water treatment simulation.

[![CI](https://github.com/LiamCarPer/ics-agentic-soc-pipeline/actions/workflows/test.yml/badge.svg)](https://github.com/LiamCarPer/ics-agentic-soc-pipeline/actions/workflows/test.yml)

---

## Architecture

```
Telemetry CSV → detect_anomalies.py → alerts.jsonl
                                            ↓
                                     POST /alert → webhook_receiver.py
                                            ↓
                                     src/rag.py (ChromaDB enrichment)
                                            ↓
                                     agent.py (LangChain + GPT-4o-mini)
                                            ↓
                              outputs/incident_*.md  +  block_*.rules
```

(Full ASCII diagram in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).)

---

## Quick Start

### Prerequisites

- Python 3.11+
- An OpenAI API key (or [OpenRouter](https://openrouter.ai) key)

### Setup

```bash
git clone https://github.com/LiamCarPer/ics-agentic-soc-pipeline.git
cd ics-agentic-soc-pipeline
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Environment

```bash
# .env
OPENAI_API_KEY=sk-...
# Optional: for OpenRouter or Ollama
OPENAI_BASE_URL=https://openrouter.ai/api/v1
```

### Ingest Knowledge

```bash
python scripts/ingest_rag.py --reset
```

### Start the Webhook Receiver

```bash
uvicorn scripts.webhook_receiver:app --host 0.0.0.0 --port 8000
```

### Send an Alert

```bash
curl -X POST http://localhost:8000/alert \
  -H "Content-Type: application/json" \
  -d @sample_alert.json
```

The receiver logs `PUBLISH alert_id=...`, triggers the agent, and returns the incident report summary and Suricata rule path in the response.

### Outputs

| File | Contents |
|------|----------|
| `outputs/incident_*.md` | NIST SP 800-61 incident report with affected assets, observed activity, impact assessment, and RAG citations |
| `outputs/block_*.rules` | Suricata rule targeting the specific Modbus pattern (FC 6 writes, FC 131 scans, etc.) |

---

## Components

### 1. Detection Service

Train and run the anomaly detection model:

```bash
# Generate telemetry
python scripts/generate_telemetry.py

# Detect anomalies
python scripts/detect_anomalies.py \
  --input data/test/telemetry.csv \
  --output data/alerts.jsonl \
  --model models/isolation_forest.joblib \
  --scaler models/scaler.joblib \
  --threshold -0.03
```

### 2. RAG Ingestion

Ingest OT knowledge into ChromaDB (asset inventory, IEC 62443 controls, past incidents):

```bash
python scripts/ingest_rag.py --reset
```

### 3. Webhook Receiver

FastAPI server that receives alerts and triggers the agent:

```bash
uvicorn scripts.webhook_receiver:app --host 0.0.0.0 --port 8000
```

### 4. Agent

Run the agent standalone on a single alert:

```bash
python scripts/agent.py --alert sample_alert.json
```

---

## Tests

All tests are deterministic — no API key, no live ChromaDB, no network required.

```bash
python -m pytest tests/ -v
```

The test suite covers:

| Test file | Tests | What it proves |
|-----------|-------|----------------|
| `tests/test_rag.py` | 9 | Anomaly classification (6 branches), query building (2), ChromaDB mocked retrieval (2) |
| `tests/test_agent.py` | 16 | SID generation (3), rule validation (4), anomaly analysis logic (9) |

---

## Documentation

| Doc | Description |
|-----|-------------|
| [`docs/PRD.md`](docs/PRD.md) | Full product requirements document — problem statement, vision, roadmap, success metrics |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System architecture diagram and data flow |
| [`docs/ANOMALY_DEFINITIONS.md`](docs/ANOMALY_DEFINITIONS.md) | Plain-language anomaly specifications with MITRE ATT&CK for ICS mappings |
| [`docs/FEATURE_ENGINEERING.md`](docs/FEATURE_ENGINEERING.md) | Feature design — windowing, scaling, Iteration 2 results, physics rationale |
| [`docs/AGENT_DESIGN.md`](docs/AGENT_DESIGN.md) | Agent framework choice, tool design, prompt strategy, LLM selection |

---

## CI/CD

This repository uses GitHub Actions for continuous integration. On every push or pull request to `main`, the CI workflow:

1. Sets up Python 3.11
2. Installs dependencies from `requirements.txt`
3. Runs all 25 tests

No live services, no API keys, no GPU required in CI.
