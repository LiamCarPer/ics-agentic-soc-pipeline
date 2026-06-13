# ICS Agentic SOC Pipeline

End-to-end pipeline: ML anomaly detection → RAG enrichment → LLM agent (NIST reports + Suricata rules).

## Pipeline Overview

```
Telemetry CSV → detect_anomalies.py → alerts.jsonl
                                           ↓
                                     src/rag.py (ChromaDB enrichment)
                                           ↓
                                     agent.py (LLM agent)
                                           ↓
                              outputs/incident_*.md  +  block_*.rules
```

## 1. Detection Service

Run the anomaly detection pipeline from the command line:

```bash
python scripts/detect_anomalies.py \
  --input data/test/telemetry.csv \
  --output data/alerts.jsonl \
  --model models/isolation_forest.joblib \
  --scaler models/scaler.joblib
```

Optional arguments:
- `--window-size N` — sliding window size in rows (default: 6)
- `--stride N` — step between windows (default: 1)
- `--threshold FLOAT` — manual decision function cutoff; scores below this are flagged. If omitted, uses the model's default `predict()`.

## 2. RAG Ingestion

Ingest OT knowledge into ChromaDB (asset inventory, IEC 62443 controls, past incidents):

```bash
python scripts/ingest_rag.py --reset
```

## 3. Agent (OT SOC Analyst)

Requires a `.env` file with your OpenAI (or OpenRouter) API key:

```bash
# .env
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://openrouter.ai/api/v1  # optional, for OpenRouter
```

Run the agent on a single alert:

```bash
# From a JSON file
python scripts/agent.py --alert outputs/test_write.json

# Or pipe from stdin
cat data/alerts.jsonl | head -1 | python scripts/agent.py
```

The agent:
1. Retrieves RAG context (asset info, IEC 62443 controls, past incidents)
2. Calls `analyze_anomaly` — deterministic classification of the alert
3. Calls `write_nist_incident_report` — saves `outputs/incident_{alert_id}.md`
4. Calls `generate_suricata_rule` — saves `outputs/block_{alert_id}.rules`
5. Prints a summary with file paths

### Outputs

| File | Contents |
|------|----------|
| `outputs/incident_*.md` | NIST SP 800-61 incident report with affected assets, observed activity, impact, recommended actions, and RAG citations |
| `outputs/block_*.rules` | Suricata rule targeting the specific Modbus pattern (FC 6 writes, FC 131 scans, etc.) |

