# System Architecture — Agentic OT SOC Analyst

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         OT-Security-Lab (Docker)                        │
│                                                                         │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐                │
│  │ plc_intake   │   │ plc_treatment│   │plc_distrib.  │   L1 Control   │
│  │ 172.21.0.10  │   │ 172.21.0.11  │   │ 172.21.0.12  │                │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘                │
│         └──────────────────┼──────────────────┘                        │
│                            ▼                                           │
│  ┌──────────────────────────────────────────────────┐                 │
│  │          Telemetry Collector (new)                │                 │
│  │  Polls PLC registers every N seconds via Modbus   │                 │
│  └──────────────────────┬───────────────────────────┘                 │
│                         ▼                                            │
│  ┌──────────────────────────────────────────────────┐                 │
│  │       ML Anomaly Detection (FastAPI + IForest)    │  Phase 1        │
│  └──────────────────────┬───────────────────────────┘                 │
│                         ▼                                            │
│  ┌──────────────────────────────────────────────────┐                 │
│  │            SQS Producer (Phase 2)                 │                 │
│  └──────────────────────┬───────────────────────────┘                 │
│                         │                                              │
├─────────────────────────┼─────────────────────────────────────────────┤
│                         ▼ AWS SQS                                     │
├─────────────────────────┼─────────────────────────────────────────────┤
│                         ▼                                            │
│  ┌──────────────────────────────────────────────────┐                 │
│  │       RAG Enricher (ChromaDB + sentence-transform)│ Phase 3        │
│  │  ┌──────────┐ ┌───────────┐ ┌───────────────┐   │                 │
│  │  │ Inventory │ │IEC 62443 │ │Past Incidents │   │                 │
│  │  └──────────┘ └───────────┘ └───────────────┘   │                 │
│  └──────────────────────┬───────────────────────────┘                 │
│                         ▼                                            │
│  ┌──────────────────────────────────────────────────┐                 │
│  │    LLM Agent (LangChain + GPT-4o-mini)           │  Phase 4        │
│  │  ┌──────────┐ ┌───────────┐ ┌───────────────┐   │                 │
│  │  │ Analyze  │ │ NIST Rpt  │ │ Suricata Rule │   │                 │
│  │  └──────────┘ └───────────┘ └───────────────┘   │                 │
│  └──────────────────────┬───────────────────────────┘                 │
│                         ▼                                            │
│  ┌──────────────────────────────────────────────────┐                 │
│  │  Output: Alert JSON + Report + .rules file        │                 │
│  │  Written to detection/logs/ and SIEM feed         │                 │
│  └──────────────────────────────────────────────────┘                 │
│                                                                         │
│  ┌──────────────┐   ┌────────────┐   ┌──────────────┐                │
│  │  Grafana     │◄──│  Loki      │◄──│  Promtail    │                │
│  │  Dashboard   │   │  Storage   │   │  Tail logs   │                │
│  └──────────────┘   └────────────┘   └──────────────┘                │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. Telemetry Collector polls all 3 PLCs via Modbus TCP (FC 3) every N seconds
2. Register snapshots sent to ML Inference API (FastAPI + Isolation Forest)
3. If anomaly score > threshold → alert JSON pushed to AWS SQS
4. SQS consumer triggers RAG enrichment against ChromaDB (asset inventory, IEC 62443, past incidents)
5. Enriched alert sent to LLM Agent (LangChain + GPT-4o-mini)
6. Agent writes analysis, NIST incident report, and Suricata `.rules` file
7. Outputs logged to Loki via Promtail → visible in Grafana SOC dashboard
8. `.rules` file staged for review before deployment
