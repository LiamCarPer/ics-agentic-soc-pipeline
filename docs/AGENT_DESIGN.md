# Agent Design — LLM-Powered OT SOC Analyst

## Framework Choice: LangChain + LangGraph

LangChain was chosen over Pydantic AI for two reasons:

- **Ecosystem maturity.** LangChain has the largest tool-calling and agent orchestration community. The `langgraph` sub-package provides `create_react_agent`, a production-ready ReAct agent that handles tool invocation, state management, and early stopping out of the box.
- **Portfolio relevance.** LangChain is the most-requested agent framework on Upwork and in industrial AI engineering roles. Demonstrating LangChain proficiency on a real OT pipeline carries more weight than a smaller framework.

The agent uses the following stack:

| Component | Package | Role |
|-----------|---------|------|
| Agent runtime | `langgraph.prebuilt.create_react_agent` | ReAct loop with tool calling, max iterations, early stopping |
| LLM | `langchain_openai.ChatOpenAI` | GPT-4o-mini for reasoning and content generation |
| Tools | `langchain_core.tools.tool` decorator | Three Python functions wrapped as LangChain tools |
| Schema | `pydantic.BaseModel` | Tool input schemas auto-generated from function signatures |

## LLM Selection: GPT-4o-mini (Swappable)

**Default:** OpenAI `gpt-4o-mini` via `OPENAI_API_KEY` environment variable. Cost-effective (~$0.15/M input tokens), strong reasoning, fast.

**Architecture is LLM-agnostic.** The `ChatOpenAI` class accepts `base_url` via the `OPENAI_BASE_URL` environment variable. To swap to a local Ollama model:

```bash
export OPENAI_BASE_URL=http://localhost:11434/v1
export OPENAI_API_KEY=ollama  # required but unused
```

Change the model name in `scripts/agent.py` from `gpt-4o-mini` to `llama3.2` or `mistral`. No other code changes needed.

## System Prompt Strategy

The system prompt encodes five directives:

1. **Persona:** "You are a Level 1 SOC Analyst specializing in OT/ICS security at a water treatment facility." Establishes domain authority and safety-critical mindset.

2. **Tool order:** "You must call tools in this exact sequence: (1) `analyze_anomaly`, (2) `write_nist_incident_report`, (3) `generate_suricata_rule`." Enforces deterministic pipeline while keeping reasoning within the LLM.

3. **Citation requirement:** "When writing the report, explicitly cite the IEC 62443 controls and past incidents from the RAG context by name (e.g., SR 5.1 — Network Segmentation)." Ensures the RAG pipeline's value is visible in every output.

4. **Suricata rule spec:** "The rule must use `alert modbus` protocol keyword, specify correct source/destination IPs, include a `sid:` unique to this alert (use `1000000 + hash(alert_id) % 9000000`), and target the specific Modbus function code observed." No generic rules.

5. **Output format:** "After all tools complete, print a one-paragraph summary of what was done and the file paths created."

## Tool Design

### `analyze_anomaly`

| Aspect | Detail |
|--------|--------|
| **Inputs** | `anomaly_score`, `tank_level_mean`, `tank_level_max`, `has_write_fc`, `function_codes`, `source_ips`, `plc_ip` |
| **Logic** | Deterministic classifier based on alert fields. Checks for Modbus write (FC 6/16), exception responses (FC 131), tank overfill (>90%), cavitation risk (<15% tank), and combines these patterns into a structured natural-language assessment. |
| **Why deterministic** | Avoids circular LLM calls (tool calling LLM calling LLM). The classification mirrors `src/rag._classify_anomaly` but adds impact assessment and recommended next steps. |

### `write_nist_incident_report`

| Aspect | Detail |
|--------|--------|
| **Inputs** | `alert_id`, `plc_ip`, `anomaly_score`, `analysis_summary`, `rag_context`, `function_codes`, `source_ips`, `tank_level_mean`, `tank_level_max` |
| **Output** | Writes `outputs/incident_{alert_id}.md` with a markdown report following simplified NIST SP 800-61 Rev 2 structure: Incident Summary, Affected Assets, Observed Activity, Potential Impact, Recommended Actions, References. |
| **Why a tool** | Enforces consistent report format. The LLM provides the reasoning and citations; the tool handles file I/O and template composition. |

### `generate_suricata_rule`

| Aspect | Detail |
|--------|--------|
| **Inputs** | `source_ip`, `destination_ip`, `function_code`, `has_write_fc`, `alert_id` |
| **Output** | Writes `outputs/block_{alert_id}.rules` with a syntactically valid Suricata rule targeting the specific Modbus pattern. SID = `1_000_000 + hash(alert_id) % 9_000_000`. |
| **Validation** | Since Suricata is not installed in this environment, the tool performs structural validation: ensures the rule matches `alert ... ( ... )` pattern, contains `sid:`, `classtype:`, `msg:`, and protocol keyword `modbus`. Returns success/failure. |
| **Why a tool** | Centralizes SID generation, file naming convention, and validation logic. The LLM does not need to remember SID ranges or file paths. |

## SID Generation Scheme

```
base = 1_000_000
sid = base + (hash(alert_id) % 9_000_000)
```

This guarantees a unique SID for every alert (because `alert_id` is UUID4) while keeping SIDs in a predictable range (1,000,000–9,999,999).

## Agent Workflow

```
Load alert JSON
    ↓
retrieve_context(alert)  ← src/rag.py
    ↓
Format user message: alert JSON + RAG context
    ↓
System prompt (OT L1 persona) + User message
    ↓
create_react_agent(model, tools=[analyze, report, rule])
    ↓
Agent loop:
  1. LLM decides: call analyze_anomaly(...)
  2. LLM receives analysis text
  3. LLM decides: call write_nist_incident_report(...)
  4. LLM receives file path
  5. LLM decides: call generate_suricata_rule(...)
  6. LLM receives file path
  7. LLM produces final summary
    ↓
Print summary and file paths
```

## Validation Strategy

| Check | Method |
|-------|--------|
| Suricata rule syntax | Structural regex validation (no `suricata -T` available) |
| NIST report completeness | Format template ensures all sections present |
| Agent follows tool order | System prompt instructs; max iterations=10 prevents runaway |
| RAG citation quality | Manual review of outputs for IEC 62443 and past incident references |
