# Agent Design — LLM-Powered OT SOC Analyst

## Framework Choice: LangChain

LangChain was chosen over Pydantic AI for two reasons:

- **Ecosystem maturity.** LangChain has the largest tool-calling and agent orchestration community. Its `create_agent` runtime handles tool invocation, state management and iteration limits out of the box.
- **Portfolio relevance.** LangChain is the most-requested agent framework on Upwork and in industrial AI engineering roles. Demonstrating LangChain proficiency on a real OT pipeline carries more weight than a smaller framework.

The agent uses the following stack:

| Component | Package | Role |
|-----------|---------|------|
| Agent runtime | `langchain.agents.create_agent` | Tool-calling loop with an iteration limit |
| LLM | `langchain_openai.ChatOpenAI` | GPT-4o-mini (configurable) for reasoning and content generation |
| Tools | `langchain_core.tools.tool` decorator | Three Python functions wrapped as LangChain tools |
| Schema | `pydantic.BaseModel` | Strict alert schema; tool inputs are validated in Python |

## LLM Selection: GPT-4o-mini (Swappable)

**Default:** OpenAI `gpt-4o-mini` via `OPENAI_API_KEY` environment variable. Cost-effective (~$0.15/M input tokens), strong reasoning, fast.

**Architecture is LLM-agnostic.** The `ChatOpenAI` class accepts `base_url` via the `OPENAI_BASE_URL` environment variable. To swap to a local Ollama model:

```bash
export OPENAI_BASE_URL=http://localhost:11434/v1
export OPENAI_API_KEY=ollama  # required but unused
```

Change the model name via `LLM_MODEL` (or the `model=` argument in `scripts/agent.py`) to `llama3.2` or `mistral`. No other code changes are needed. Set `LLM_LOCAL_ONLY=1` to reject non-local endpoints.

## System Prompt Strategy

The system prompt encodes five directives:

1. **Persona:** "You are a Level 1 SOC Analyst specializing in OT/ICS security at a water treatment facility." Establishes domain authority and safety-critical mindset.

2. **Tool order:** "You must call tools in this exact sequence: (1) `analyze_anomaly`, (2) `write_nist_incident_report`, (3) `generate_suricata_rule`." Enforces deterministic pipeline while keeping reasoning within the LLM.

3. **Citation requirement:** "When writing the report, explicitly cite the IEC 62443 controls and past incidents from the RAG context by name (e.g., SR 5.1 — Network Segmentation)." Ensures the RAG pipeline's value is visible in every output.

4. **Suricata rule spec:** "The rule must use `alert modbus` protocol keyword and stay alert-only." The tool derives the actual source/destination IPs and the specific Modbus function code from the validated alert; the model does not supply them.

5. **Output format:** "After all tools complete, print a one-paragraph summary of what was done and the file paths created."

## Tool Design

### `analyze_anomaly`

| Aspect | Detail |
|--------|--------|
| **Inputs** | `anomaly_score`, `tank_level_mean`, `tank_level_max`, `has_write_fc`, `function_codes`, `source_ips`, `plc_ip` |
| **Logic** | Deterministic classifier based on alert fields. Checks for Modbus write (FC 6/16), exception responses (FC 131), tank overfill (>85%), cavitation risk (<15% tank), and combines these patterns into a structured natural-language assessment. |
| **Why deterministic** | Avoids circular LLM calls (tool calling LLM calling LLM). The classification mirrors `src/rag._classify_anomaly` but adds impact assessment and recommended next steps. |

### `write_nist_incident_report`

| Aspect | Detail |
|--------|--------|
| **Inputs** | `alert_id`, `analysis_summary` |
| **Context** | The tool fetches the validated alert and RAG context from the per-run context registry by `alert_id`; the model cannot supply or override citations. |
| **Output** | Writes `outputs/incident_{alert_id}.md` with a markdown report following simplified NIST SP 800-61 Rev 2 structure: Incident Summary, Affected Assets, Observed Activity, Potential Impact, Recommended Actions, References. |
| **Why a tool** | Enforces consistent report format. The LLM provides the narrative; the tool handles context, file I/O and template composition. |

### `generate_suricata_rule`

| Aspect | Detail |
|--------|--------|
| **Inputs** | `alert_id` |
| **Output** | Writes `outputs/block_{alert_id}.rules` with an alert-only Suricata rule targeting the specific Modbus pattern. Source, destination and function code are derived from the validated alert. SID = `1_000_000 + sha256(alert_id)[:8] % 9_000_000`. |
| **Validation** | `src/security/guards.validate_rule` enforces `alert modbus`, balanced parentheses, `msg:`, `sid:` in the local range, `classtype:`, `rev:`, and rejects `drop`/`reject`/`pass`/`bypass`. This is structural validation, not `suricata -T`. |
| **Why a tool** | Centralizes SID generation, alert-only policy, file naming and validation. The LLM does not supply network identifiers or paths. |

## SID Generation Scheme

```
base = 1_000_000
sid = base + (sha256(alert_id)[:8] as int) % 9_000_000
```

This gives a deterministic SID in the local range (1,000,000–9,999,999) for every alert. A production deployment needs a managed SID registry to prevent collisions across rule sources.

## Agent Workflow

```
Load alert JSON
    ↓
validate with AlertPayload (strict schema)
    ↓
retrieve_context_details(alert)  ← src/rag.py (returns text + chunk IDs)
    ↓
register_run_context(alert, context)  ← tools read this by alert_id
    ↓
Format user message: untrusted alert data + untrusted RAG context
    ↓
System prompt (OT L1 persona + injection warning) + user message
    ↓
create_agent(model, tools=[analyze, report, rule])
    ↓
Agent loop:
  1. LLM calls analyze_anomaly(...)
  2. LLM receives analysis text
  3. LLM calls write_nist_incident_report(alert_id, summary)
  4. LLM receives file path
  5. LLM calls generate_suricata_rule(alert_id)
  6. LLM receives file path
  7. LLM produces final summary
    ↓
Write audit record, return summary + paths
```

## Validation Strategy

| Check | Method |
|-------|--------|
| Alert input | Strict Pydantic schema: UUID, IP, function-code allowlist, bounds, no extra fields |
| Suricata rule syntax | Structural validation in `src/security/guards.py` (no `suricata -T` in CI) |
| Rule action | Alert-only; `drop`/`reject`/`pass`/`bypass` rejected |
| NIST report completeness | Format template ensures all sections present |
| Agent follows tool order | System prompt instructs; `recursion_limit=50` prevents runaway |
| Output paths | UUID-derived filenames, resolved-path confinement under `outputs/` |
| RAG citation quality | Context is fetched by the tool from the run registry; manual review still required |
| Audit | JSONL with prompt hash, RAG chunk IDs, tool calls/args hashes, output hashes, latency |
| Prompt injection | Untrusted-data delimiters + capability restriction; red-team suite |

## Security hardening (2026-10)

The original design let the model choose `rag_context`, source/destination IPs and
function codes. Under a prompt-injection threat model that is an
over-privileged tool. The hardened design:

- validates the alert before any LLM call;
- strips `raw_data` from the prompt and delimits all untrusted content;
- registers the validated alert and retrieved context in a per-run registry;
- tools accept only `alert_id` (plus the analysis narrative), then fetch the
  context and derive network identifiers themselves;
- confines writes to UUID-named files under `outputs/`;
- verifies model/RAG artifacts by SHA-256 before use;
- logs hashes and tool calls, not prompts or secrets.

The deterministic red-team suite and the evasion/poisoning evaluations are in
`security/`; the threat model is in `docs/AI_SECURITY.md`.
