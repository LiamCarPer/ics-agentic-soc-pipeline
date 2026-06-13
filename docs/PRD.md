# Product Requirements Document: The Agentic OT SOC Analyst

**Author:** Liam Carvajal Perez
**Status:** Draft v1.0
**Date:** 2026-06-13
**Repository:** [ics-agentic-soc-pipeline](https://github.com/LiamCarPer/ics-agentic-soc-pipeline)

---

## 1. Executive Summary

I am building an agentic AI system that acts as a Level 1 SOC Analyst for my [OT-Security-Lab](https://github.com/LiamCarPer/ot-security-lab). Instead of just training a model, this system will ingest real-time telemetry from my lab's water treatment simulation — three OpenPLC instances (Intake, Treatment, Distribution), a Scada-LTS HMI, and an InfluxDB historian — detect anomalies using unsupervised machine learning, enrich those alerts with contextual knowledge (asset inventory, IEC 62443 guidelines, past incidents) via a RAG pipeline, and then use an LLM agent to draft NIST-aligned incident reports and generate Suricata/Snort rules.

This project proves I can do more than call API wrappers. It demonstrates vertical-specific ML engineering, event-driven automation, RAG pipeline development, and agentic AI systems — end to end, deployed against a real OT network.

---

## 2. Problem Statement

### The Gap

OT security teams face a staffing crisis. There are far more industrial control systems to monitor than qualified analysts to monitor them. Level 1 SOC analysts spend most of their time on triage — checking if a Modbus anomaly is a real attack or a sensor glitch, looking up asset ownership, cross-referencing playbooks, and writing reports. This is repetitive, pattern-based work that AI can handle.

### Why Rules Aren't Enough

My OT-Security-Lab already has four rule-based detection scripts:

| Rule | Logic | Limitation |
|------|-------|------------|
| `cross_zone_traffic.py` | IP allow-list | Misses attacks from compromised legitimate hosts |
| `modbus_anomaly.py` | Unauthorized write detection | Cannot detect register manipulation within allowed sessions |
| `ot_brute_force.py` | Sliding window (5 exceptions / 60s) | Brittle threshold — easy to evade |
| `process_safety_violation.py` | Stateful register shadowing | Only catches known safety patterns |

These rules are static. They cannot adapt to novel attack patterns, subtle physics deviations, or multi-step campaigns. An ML-based approach complements them by detecting statistical anomalies that no fixed rule could express.

---

## 3. My OT-Security-Lab Foundation

This system is built on top of my existing OT-Security-Lab — a Docker-based water treatment facility simulation with full IEC 62443 zone-conduit architecture.

### Lab Network Topology

| Docker Network | Subnet | Purdue Level | Devices |
|----------------|--------|--------------|---------|
| `control_network` | 172.21.0.0/24 | L1 — Control | `plc_intake` (172.21.0.10), `plc_treatment` (172.21.0.11), `plc_distribution` (172.21.0.12) |
| `supervisory_network` | 172.22.0.0/24 | L2 — Supervisory | `ot_hmi` (172.22.0.10) — Scada-LTS |
| `ops_network` | 172.23.0.0/24 | L3 — Operations | `ot_historian` (172.23.0.10) — InfluxDB |
| `it_network` | 172.24.0.0/24 | L4/L5 — Enterprise | `ot_attacker` (172.24.0.10), SIEM stack |

The gateway (`ot_gateway`) enforces conduit-based iptables rules between zones. Traffic is monitored via Promtail + Loki + Grafana, with a live SOC overview dashboard already in place.

### Existing Data Assets

- **Asset Inventory**: 9 assets with IPs, models, firmware, and Purdue level assignments
- **IEC 62443 Gap Analysis**: 12 security requirements mapped to implemented controls
- **Incident Response Playbooks**: Documented IR playbook for PLC tampering scenarios
- **Alert Logs**: JSON Lines alert feed covering 4 alert types with MITRE ATT&CK for ICS mapping
- **Attack Simulation Scripts**: Three attack scenarios that trigger the detection rules

---

## 4. Product Vision

I am building an AI system that:

1. **Learns normal behavior** from my lab's process telemetry (register values, tank levels, flow rates, pressure) using unsupervised ML
2. **Detects anomalies** the static rules would miss — subtle drift, novel manipulation patterns, physics violations
3. **Enriches every alert** with contextual intelligence — what asset is affected, what IEC 62443 requirement applies, what past incidents look similar
4. **Acts autonomously** — drafts NIST incident reports and generates deployable Suricata/Snort rules
5. **Integrates into the existing pipeline** — pushes alerts to AWS SQS, feeds the Grafana dashboard, deploys new firewall rules

The system will not replace the SOC analyst. It will elevate them from triage to strategic response.

---

## 5. Core Features

### Phase 1: ML Anomaly Detection Engine (The Trigger)

**What I build:** An unsupervised ML model trained on time-series Modbus register telemetry from my lab's three PLCs.

**Training data source:** I will collect register snapshots from `plc_intake`, `plc_treatment`, and `plc_distribution` over normal operation cycles. Features include:
- Register values (holding registers 0–100 per PLC)
- Rate of change between consecutive reads
- Deviation from rolling baseline means
- Valve states vs. tank level coherence (cross-register invariants)

**Model choice:** Isolation Forest — lightweight, interpretable, well-suited for high-dimensional time-series anomaly detection. I will also experiment with an Autoencoder (Keras/TensorFlow) for comparison and document the trade-offs.

**Detection outputs:**
- Anomaly score (0–1) with threshold
- Which registers/features contributed most to the score
- Timestamp, PLC IP, Modbus function code context

**Integration:** The model will be wrapped in a FastAPI endpoint that the lab's alert pipeline can call on each new telemetry window.

### Phase 2: Event-Driven Alert Pipeline (The Integration)

**What I build:** When the ML model detects an anomaly above threshold, the system formats the alert as structured JSON and pushes it to an AWS SQS queue. A separate consumer reads from the queue and writes to the Loki alert stream, which surfaces immediately in the Grafana SOC dashboard.

**Alert schema (extending the existing lab format):**

```json
{
  "timestamp": "2026-06-13T14:30:00.123456",
  "alert_type": "ML_ANOMALY_DETECTED",
  "source_ip": "172.21.0.10",
  "anomaly_score": 0.87,
  "top_features": ["reg_5_tank_level", "reg_0_inlet_valve"],
  "ml_model": "isolation_forest_v1",
  "mitre_id": "T0836",
  "description": "Tank level deviation of 23% detected on plc_intake under normal HMI command",
  "raw_telemetry": { ... }
}
```

**Why SQS:** Decouples ML inference from downstream consumers. The lab's Promtail can tail the SQS consumer's log output, or the consumer can write directly to a log file that Promtail targets. This design lets me swap components without rewiring the pipeline.

**Optional webhook:** I will also expose a webhook endpoint so downstream systems (e.g., TheHive, Shuffle) can subscribe to alerts directly.

### Phase 3: RAG Context Retrieval (The Knowledge)

**What I build:** When an alert fires, a Python script ingests the alert and performs a RAG lookup against a local vector database (ChromaDB) containing three corpora:

| Corpus | Source | Purpose |
|--------|--------|---------|
| **Asset Inventory** | `asset-inventory/assets.csv` | Knows `172.21.0.10` = `plc_intake` (OpenPLC v4, L1 Control Zone, Critical Intake Control) |
| **IEC 62443 Guidelines** | `iec62443/compliance-summary.md` + `gap-analysis.csv` | Which SR requirements apply to the affected asset and zone |
| **Past Incidents** | `detection/logs/alerts.json`, `incident-response/` | Similar past alerts and their resolution playbooks |

**Vector store setup:**
- Embedding model: `all-MiniLM-L6-v2` (sentence-transformers) — small, fast, runs locally
- Chunking: Documents split at section/paragraph level with metadata tags for asset IP, zone, and document source
- Query: Alert `source_ip` + `alert_type` + anomaly features → retrieve top-3 relevant chunks

**RAG output:** A context JSON object appended to the alert:

```json
{
  "asset_context": {
    "hostname": "plc_intake",
    "device_type": "PLC",
    "zone": "Control",
    "purdue_level": "L1",
    "manufacturer": "Autonomy Logic",
    "firmware": "4.0.7"
  },
  "iec62443_requirements": [
    "SR_3.1 — Zone boundary protection",
    "SR_5.2 — Integrity monitoring"
  ],
  "similar_incidents": [
    {
      "timestamp": "2026-05-20T20:19:49",
      "alert_type": "UNAUTHORIZED_MODBUS_WRITE",
      "resolution": "Blocked attacker IP at gateway",
      "playbook": "ir-playbook-unauthorised-plc-change.md"
    }
  ]
}
```

### Phase 4: Agentic AI Decision Engine (The Action)

**What I build:** The enriched alert feeds into an LLM agent built with LangChain. The agent has access to three tools:

1. **Analyze Tool:** Takes the anomaly + RAG context and produces a structured analysis — what happened, why it's suspicious, what the impact could be
2. **Report Tool:** Drafts a standardized NIST Incident Report (based on NIST SP 800-61 Rev 2) with fields for detection time, affected assets, attack vector, impact assessment, and recommended actions
3. **Rules Tool:** Generates a Suricata or Snort rule to block the specific malicious Modbus payload and outputs it as a ready-to-deploy `.rules` file

**Agent orchestration:**
- The LLM receives: alert + RAG context + system prompt with OT security expertise
- It decides which tools to call and in what order
- All reasoning is logged for audit and improvement
- The final output is a JSON package containing: analysis, incident report draft, and a `.rules` file

**Model:** I will use GPT-4o-mini or Claude 3.5 Haiku for the agent — cost-effective with strong reasoning. The system prompt will encode OT-specific knowledge (Purdue model, Modbus function codes, IEC 62443 principles).

---

## 6. System Architecture

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
2. Register snapshots sent to ML Inference API
3. If anomaly score > threshold → alert JSON pushed to SQS
4. SQS consumer triggers RAG enrichment against ChromaDB
5. Enriched alert sent to LLM Agent
6. Agent writes analysis, NIST report, and `.rules` file
7. Outputs logged to Loki via Promtail → visible in Grafana SOC dashboard
8. `.rules` file staged for deployment to gateway or IDS

---

## 7. Tech Stack Decisions

| Component | Technology | Rationale |
|-----------|------------|-----------|
| ML Model | `scikit-learn` (Isolation Forest), `tensorflow` (Autoencoder) | Well-documented, proven for time-series anomaly detection; no GPU required |
| ML API | `FastAPI` + `uvicorn` | Lightweight async Python server; fits container-based deployment |
| Message Queue | `boto3` → AWS SQS | Industry standard; decouples components; shows cloud integration |
| Vector DB | `ChromaDB` | Local, no external infra, simple API, good for small-to-medium corpuses |
| Embeddings | `sentence-transformers/all-MiniLM-L6-v2` | 384-dim, runs on CPU, fast inference |
| Agent Framework | `LangChain` | Most mature tool-calling ecosystem; strong OT/ICS prompt community |
| LLM | GPT-4o-mini (via `litellm` or direct API) | Cost-effective (~$0.15/M input), strong reasoning, easy API |
| Testing | `pytest` + `pytest-mock` | Standard; CI pipeline validates RAG retrieval quality |
| CI/CD | GitHub Actions | Automatic `pytest` run on PR/push to main |
| Infrastructure | Docker Compose | Extends existing lab deployment; no new infra required |

---

## 8. Integration Points

### With the Existing Lab

| Integration | Detail |
|-------------|--------|
| **Network** | Telemetry collector talks Modbus TCP (port 502) on `control_network` (172.21.0.0/24) |
| **Alert stream** | Phase 2 consumer writes JSON logs to `detection/logs/ml_alerts.json` — Promtail already targets this directory |
| **Grafana dashboard** | New Loki label `{job="ml_alerts"}` added to the existing Industrial Threat Stream panel |
| **Asset inventory** | RAG pipeline ingests `asset-inventory/assets.csv` directly from the repo |
| **IEC 62443 docs** | RAG pipeline ingests `iec62443/compliance-summary.md` and `gap-analysis.csv` |
| **Incident playbooks** | RAG pipeline ingests `incident-response/` and `governance/incident_response/` |
| **Gateway firewall** | Generated `.rules` files staged to `detection/rules/` for review before deployment |

### External Integrations

| Integration | Purpose |
|-------------|---------|
| **AWS SQS** | Decouple ML inference from enrichment/action pipeline |
| **GitHub Actions** | Run `pytest` on RAG retrieval functions on every push |
| **Suricata/Snort** | Generated rules are format-compatible out of the box |

---

## 9. Phased Delivery Roadmap

### Phase 1: ML Anomaly Detection Engine (Weeks 1–2)

**Deliverables:**
- [ ] Telemetry collector script (Modbus TCP polling, register extraction)
- [ ] Data collection pipeline — capture 24h+ of normal operation for each PLC
- [ ] Isolation Forest model trained and saved as `.pkl`
- [ ] Autoencoder model (optional, for comparison) trained and saved as `.h5`
- [ ] FastAPI inference endpoint with `/predict` route
- [ ] Model evaluation notebook (precision, recall, F1 on known attacks)
- [ ] Unit tests for telemetry parsing and anomaly scoring

**Validation:** Model detects at least 80% of the known attacks from `simulate_process_violation.py` and `simulate_attack.py` with <10% false positive rate on normal data.

### Phase 2: Event-Driven Alert Pipeline (Week 3)

**Deliverables:**
- [ ] SQS queue creation (Terraform or AWS CLI script)
- [ ] SQS producer module integrated into inference API
- [ ] SQS consumer script (poll queue, format alert, write to log)
- [ ] Webhook endpoint as alternative to SQS
- [ ] Promtail config update to tail `ml_alerts.json`
- [ ] Grafana dashboard panel for ML anomaly stream
- [ ] Integration test: end-to-end from PLC poll → SQS → Grafana

**Validation:** Alert appears in Grafana within 5 seconds of anomaly detection.

### Phase 3: RAG Context Retrieval (Week 4)

**Deliverables:**
- [ ] ChromaDB instance (Docker container in the lab stack)
- [ ] Embedding pipeline — chunk asset inventory, IEC 62443 docs, past incidents
- [ ] Vector store seeded with all three corpora
- [ ] RAG query function (alert → top-3 context chunks)
- [ ] Context JSON schema and output format
- [ ] `pytest` tests for retrieval quality (precision@k, recall@k)
- [ ] GitHub Actions workflow to run RAG tests on push

**Validation:** For a known alert `UNAUTHORIZED_MODBUS_WRITE` from `172.24.0.10`, the RAG pipeline correctly retrieves the `plc_intake` asset record and the relevant IEC 62443 boundary protection requirement in ≥80% of test runs.

### Phase 4: Agentic AI Decision Engine (Weeks 5–6)

**Deliverables:**
- [ ] LangChain agent with Analyze, Report, and Rules tools
- [ ] System prompt engineering for OT SOC analyst persona
- [ ] NIST SP 800-61 incident report template
- [ ] Suricata/Snort rule generator (valid Modbus payload patterns)
- [ ] End-to-end orchestration script (alert in → agent → outputs)
- [ ] Audit logging (every reasoning step and tool call)
- [ ] Full integration test triggering all lab attack scenarios

**Validation:**
- Agent generates a coherent NIST report for every attack scenario
- Generated Suricata rules are syntactically valid (tested with `suricata -T`)
- Agent completes within 30 seconds of receiving enriched alert

---

## 10. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Anomaly detection rate (Recall) | ≥85% of scripted attacks | Compare ML alerts vs. known ground truth from attack simulations |
| False positive rate (FPR) | ≤10% | Run against 24h of normal operation, count false alarms |
| Alert-to-Grafana latency | ≤5 seconds | Timestamp difference between ML inference and Loki ingestion |
| RAG retrieval precision@3 | ≥80% | Manual review of top-3 retrieved chunks for 50 test queries |
| Agent task completion time | ≤30 seconds per alert | Wall-clock from enriched alert input to all outputs written |
| NIST report quality | Pass manual review | Checklist-based review by a SOC analyst (or self-review against NIST SP 800-61) |
| Rule syntactic validity | 100% | Generated `.rules` files pass `suricata -T` syntax check |

---

## 11. Non-Functional Requirements

### Performance

- ML inference must complete in <500ms per telemetry window (FastAPI on CPU)
- RAG query must complete in <1 second (ChromaDB local, small corpus)
- Agent orchestration must complete in <30 seconds (dominated by LLM API latency)

### Security

- All API endpoints bound to Docker internal networks only (no public exposure in lab)
- AWS credentials for SQS stored as environment variables, never committed
- LLM API keys managed via environment variables or Docker secrets
- Generated Suricata rules are reviewed before deployment (not auto-deployed in Phase 4)

### Reliability

- SQS provides at-least-once delivery guarantee
- Failed RAG queries fall back to "no context available" — agent still fires with a warning
- LLM API failures retry 3× with exponential backoff, then log and alert

### Maintainability

- Each component runs in its own Docker container
- Configuration via environment variables and YAML files
- All modules have `pytest` coverage (target: ≥70%)
- CI pipeline (GitHub Actions) runs lint + test on every push

### Auditability

- Every agent reasoning step and tool call logged to structured JSON
- All alerts, RAG queries, and agent outputs written to Loki
- Model versions tracked via `model_version` field in alert output

---

## 12. Appendix

### A. OT-Security-Lab Asset Inventory (Relevant Excerpt)

| Asset ID | Hostname | IP Address | Zone | Purdue Level | Device Type |
|----------|----------|------------|------|-------------|-------------|
| ASSET-01 | plc-intake | 172.21.0.10 | Control | L1 | PLC (OpenPLC v4) |
| ASSET-02 | plc-treatment | 172.21.0.11 | Control | L1 | PLC (OpenPLC v4) |
| ASSET-03 | plc-distribution | 172.21.0.12 | Control | L1 | PLC (OpenPLC v4) |
| ASSET-04 | ot-hmi | 172.22.0.10 | Supervisory | L2 | SCADA (Scada-LTS) |
| ASSET-07 | ot-historian | 172.23.0.10 | Operations | L3 | Historian (InfluxDB) |

### B. IEC 62443 Requirements Relevant to This System

| SR ID | Requirement | Relevance |
|-------|-------------|-----------|
| SR 3.1 | Zone boundary protection | Agent-generated rules enforce zone conduits |
| SR 5.2 | Integrity monitoring | ML model detects integrity violations in register values |
| SR 6.1 | Audit log generation | All agent actions and alerts logged to Loki |
| SR 7.3 | Incident response | Agent drafts NIST incident reports automatically |

### C. Alert Schema Reference

The system extends the existing lab alert schema (JSON Lines). New fields from the ML pipeline:

| Field | Type | Phase | Description |
|-------|------|-------|-------------|
| `anomaly_score` | float (0–1) | 1 | ML model confidence score |
| `top_features` | string[] | 1 | Register/feature names contributing most to anomaly |
| `ml_model` | string | 1 | Model identifier and version |
| `rag_context` | object | 3 | Asset context, IEC 62443 refs, similar incidents |
| `agent_analysis` | string | 4 | LLM's natural language analysis |
| `nist_report` | object | 4 | Structured NIST SP 800-61 incident report |
| `suricata_rule` | string | 4 | Generated Suricata rule content |

### D. References

- NIST SP 800-61 Rev 2: Computer Security Incident Handling Guide
- NIST SP 800-82 Rev 2: Guide to Industrial Control Systems Security
- IEC 62443-3-2: Security for Industrial Automation and Control Systems — Zone and Conduit Model
- IEC 62443-3-3: System Security Requirements and Security Levels
- MITRE ATT&CK for ICS: https://attack.mitre.org/techniques/ics/
- OT-Security-Lab: https://github.com/LiamCarPer/ot-security-lab
