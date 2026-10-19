# AI security — threat model and controls

This document describes how the agentic SOC prototype is secured, what was
verified, and what remains risky. It follows the structure of a threat model,
not a compliance checklist. The system is a **lab prototype**; "hardened" here
means the trust boundaries are enforced and tested, not that the system is
certified or safe for production.

Framework references: OWASP Top 10 for LLM Applications (2025), MITRE ATLAS,
NIST AI Risk Management Framework (AI RMF 1.0) and the Generative AI Profile
(NIST AI 600-1). IEC 62443 and NIST SP 800-61/800-82 provide the OT context.

## 1. System and data flow

```
untrusted alert JSON
        │
        ▼
[webhook] strict schema ── API key ── rate limit ── body cap
        │
        ├── POST /alert        (synchronous, 200)
        └── POST /alert/async  (background task, 202)
        │
        ▼
[run context] validated alert + retrieved RAG context (keyed by alert_id)
        │
        ├── RAG: ChromaDB ← documents verified by SHA-256 manifest
        │
        ▼
[prompt] system prompt + <untrusted_alert_data> + <untrusted_rag_context>
        │
        ▼
[LLM provider] allowlisted host; local-only mode available
        │
        ▼
[tools] analyze (deterministic) → report (context lookup) → rule (context lookup)
        │
        ▼
[path-confined outputs] incident_<uuid>.md, block_<uuid>.rules
        │
        ▼
[audit] JSONL with hashes, tool calls, outputs, latency
        │
        ▼
human review → staged rule (never auto-deployed)
```

## 2. Assets

| Asset | Why it matters |
| :--- | :--- |
| OT process availability/safety | A bad rule or a missed manipulation can damage equipment or spill water |
| Alert and telemetry confidentiality | Process data and source identities are sensitive |
| LLM provider credentials | Cost and account compromise |
| Model and knowledge-base integrity | Poisoned inputs change triage conclusions |
| Generated report/rule integrity | An analyst may act on a fabricated report or rule |
| Audit trail | Forensics and accountability |

## 3. Trust boundaries

1. **Network → webhook**: fully untrusted input (alert fields, sizes, identifiers).
2. **Knowledge base → prompt**: documents are trusted-but-verified; a modified
   document is a supply-chain attack.
3. **Prompt → LLM**: the model is not trusted to follow instructions or to keep
   data/instructions separate. Assume prompt injection can succeed.
4. **LLM → tools**: tool arguments are untrusted; tools re-derive values from the
   validated run context and confine side effects.
5. **Tools → filesystem**: filenames and paths are attacker-influenced in the
   original design; now UUID-derived and confined.
6. **Model artifact → process**: unpickling is code execution; artifacts are
   hash-verified before load.
7. **Local system → LLM provider**: alert data leaves the network; provider
   allowlist and local-only mode are the controls.

## 4. Threat register

| ID | Threat | OWASP LLM | MITRE ATLAS | Impact | Controls | Evidence | Residual risk |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| T1 | Direct/indirect prompt injection via telemetry or RAG | LLM01 | AML.T0051 | Agent follows attacker instructions, writes malicious content | Schema validation; untrusted-data delimiters; context lookup by alert_id; tools re-derive values; alert-only rule guard | `RT-002`, `RT-011`; `tests/test_security_sanitize.py` | The LLM can still be influenced within its allowed capabilities; no model-level injection classifier |
| T2 | Insecure output handling / path traversal | LLM05 | — | Arbitrary file write outside `outputs/` | Strict UUIDs; `safe_output_path`; UUID-derived filenames | `RT-001`, `RT-006`, `RT-007`; `tests/test_security_paths.py` | None known for the file-write path |
| T3 | Excessive agency (tools with broad side effects) | LLM06 | — | Agent deploys a rule or changes a PLC | Tools only write files; rules are alert-only; human review; no network/PLC tools; dry-run staging | `RT-008`; `tests/test_security_tools.py` | A malicious report can still mislead a human reviewer |
| T4 | Model/dependency supply chain | LLM03 | AML.T0010 | Arbitrary code execution via pickle, compromised dependency, poisoned embedding model | SHA-256 model/RAG manifests verified before load; pinned AI-BOM; pip-audit; review of dependency updates | `tests/test_security_artifacts.py`; `scripts/verify_artifacts.py`; `security/ai-bom.json` | Embedding model revision is not pinned; joblib remains a trusted format |
| T5 | Data/model poisoning (RAG and training) | LLM04, LLM08 | AML.T0020 | Retrieval returns attacker text; detector learns dangerous states as normal | RAG manifest verification and instruction-pattern warnings; training-data provenance documented; poisoning eval | `RT-012`; `security/evals/poisoning_results.md` | Training data is synthetic and not access-controlled; poisoning reduces recall sharply |
| T6 | Sensitive information disclosure to the LLM/logs | LLM02 | AML.T0024 | Process data or credentials leave the network / land in logs | `raw_data` dropped before prompting; audit logs hashes/metadata and redacts sensitive keys; provider allowlist; local-only mode | `tests/test_security_audit.py`; `tests/test_security_egress.py` | Window summary and source IPs still go to the provider |
| T7 | Unbounded consumption / cost abuse | LLM10 | — | Bill spike or resource exhaustion | API key; per-client rate limit; body-size cap; raw-data cap; prompt-size cap; recursion limit | `RT-005`, `RT-013`; `tests/test_security_rate_limit.py` | No distributed limiter or per-key budget |
| T8 | Evasion of the ML detector | — | AML.T0015 | Attack is not flagged | Per-class evaluation; evasion experiment; physics/rule backstops recommended | `security/evals/evasion_results.md` | Overfill is not detected; slow scans evade; nine features are dead |
| T9 | Overreliance / misinformation | LLM09 | — | Analyst trusts a wrong report | Deterministic report template; retrieval grounding; explicit limitations; human review; no auto-deploy | `docs/MODEL_CARD.md`; `tests/test_security_tools.py` | The narrative paragraph is LLM-generated and may be wrong |
| T10 | System prompt leakage | LLM07 | — | Prompt reveals internals | Prompt contains no secrets or credentials; egress policy | Review of `SYSTEM_PROMPT` | The prompt itself is not confidential |
| T11 | Missing audit/forensics | — | — | No reconstruction of agent actions | JSONL audit log: prompt hash, RAG IDs, tool calls/args hashes, outputs, latency | `tests/test_security_audit.py` | Log is local and not tamper-evident |
| T12 | Webhook spoofing / unauthorized alerts | — | — | Fake alerts trigger work or data insertion | Optional API key (constant-time compare); rate limit; strict schema; body cap | `tests/test_webhook.py` | Auth is optional by default and there is no TLS/mTLS |

## 5. ML security findings (verified)

These are the results that matter for "securing AI/ML", not just the LLM wrapper.

1. **Nine of 15 features are dead.** Tree inspection of the committed model
   shows 0/100 trees split on any valve, function-code or source-IP feature.
   Those columns are constant in the normal training set, so the Isolation
   Forest never learned them. The model is effectively a tank-level detector.
   Consequence: `has_write_fc`/`is_known_good_ip` do **not** make writes or scans
   trivially detectable, contrary to `docs/FEATURE_ENGINEERING.md`.
2. **Overfill is invisible.** 0/4 test windows; 0 dangerous windows across every
   ramp rate, including the final 95% plateau. The contamination-derived
   decision boundary never reaches the overfill range, so those windows score
   normal.
3. **Low-rate scans evade.** With one FC 131 exception per window, detection is
   1–2 out of 55–595 windows, and the source IP does not change the score
   because `is_known_good_ip` is dead. The 5/5 scanning result in the main
   evaluation is a tank-pattern coincidence.
4. **Poisoning works.** Adding 5% anomaly-shaped windows to the normal training
   set drops recall to 0.215 (scanning 32%, cavitation 62%, physics 5%); at 10%
   recall is 0.130 (scanning 6%, cavitation 42%). At 20% recall is 0.135 and
   scanning 0%.
5. **The original `alert_id` path traversal was real.** `a/../../pwn-a-b-c-d`
   passed the old validator and resolved outside `outputs/`. It is now rejected
   by the schema and by path confinement.

## 6. Controls and where they are tested

| Control | Implementation | Verification |
| :--- | :--- | :--- |
| Strict schema | `src/security/schemas.py` | `tests/test_security_schemas.py` |
| Path confinement | `src/security/paths.py` | `tests/test_security_paths.py` |
| Prompt delimiters | `src/security/sanitize.py` | `tests/test_security_sanitize.py`; `RT-011` |
| Tool context | `src/security/context.py`, `scripts/agent.py` | `tests/test_security_tools.py` |
| Rule guard | `src/security/guards.py` | `tests/test_security_guards.py`; `RT-008`–`RT-010` |
| Artifact integrity | `src/security/artifacts.py`, manifests | `tests/test_security_artifacts.py` |
| Audit logging | `src/security/audit.py` | `tests/test_security_audit.py`; `RT-014` |
| Provider allowlist | `src/security/egress.py` | `tests/test_security_egress.py` |
| Rate limiting | `src/security/rate_limit.py` | `tests/test_security_rate_limit.py`; `RT-013` |
| Red-team suite | `scripts/redteam_agent.py` | `tests/test_security_redteam.py` |
| ML robustness | `security/evals/` | `evasion_results.md`, `poisoning_results.md` |

Run the verification yourself:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH= ./venv/bin/python -m pytest tests/ -q
./venv/bin/python scripts/verify_artifacts.py
./venv/bin/python scripts/redteam_agent.py
./venv/bin/python security/evals/evasion_experiment.py
./venv/bin/python security/evals/poisoning_experiment.py
```

## 7. Framework mapping

| Framework | How it is used here |
| :--- | :--- |
| OWASP LLM Top 10 (2025) | Threat IDs in the register: LLM01–LLM10 |
| MITRE ATLAS | Prompt injection (AML.T0051), supply chain (AML.T0010), evasion (AML.T0015), poisoning (AML.T0020), model exfiltration (AML.T0024) |
| NIST AI RMF | GOVERN: SECURITY.md/ownership; MAP: this threat model and asset inventory; MEASURE: red-team tests and ML evals; MANAGE: controls, residual-risk register, incident playbook |
| NIST AI 600-1 | Prompt injection, data privacy, information integrity, value chain risks |
| IEC 62443 | Zone/conduit context and the OT safety constraints on response |
| NIST SP 800-61/800-82 | Incident report structure and ICS security framing |

## 8. Residual risk register (accepted for the prototype)

| Risk | Why it remains | Next step |
| :--- | :--- | :--- |
| In-memory queue/results | Lab demo; no broker | SQS/RabbitMQ + worker + DLQ |
| Optional API key, no TLS | Local demo convenience | Enforce key in shared envs; mTLS at ingress |
| No distributed rate limit | Single process | Gateway/API-manager quota |
| Rules not run through `suricata -T` in CI | Optional tooling | Containerized syntax check + staging gate |
| Embedding model revision unpinned | Docker build downloads it | Pin a Hugging Face revision and verify the cache |
| LLM provider trust | External API | Local-only mode for sensitive sites; DPA review |
| Report narrative may be wrong | LLM-generated text | Citation checker and analyst review |
| Audit log not tamper-evident | Local JSONL | Ship to append-only/SIEM storage |
| Synthetic ML metrics | No field data | Collect labelled production telemetry |

## 9. Incident response for AI-specific events

| Event | First actions |
| :--- | :--- |
| Suspected prompt injection | Preserve the alert JSON and audit log; identify the tool calls; rotate any exposed key; disable `/alert` until patched |
| Poisoned RAG document | Fail ingestion, restore the last verified manifest, diff the document, re-ingest, review recent reports that cited it |
| Model artifact tampering | Do not load; restore from a trusted source; verify hashes; investigate access to `models/` |
| Unexpected rule generation | Check the rule guard and audit output; remove staged rules; review `outputs/block_*.rules` |
| Cost/abuse spike | Rotate the webhook/API key; tighten rate limits; review provider usage |
| Data leakage suspicion | Disable external LLM access (`LLM_LOCAL_ONLY=1`), review prompts/audit metadata, notify according to policy |

## 10. Out of scope

- Formal certification (ISO/IEC 42001, NIST AI RMF conformance, IEC 62443 SL).
- Membership inference, model extraction and model inversion: the model is
  small, the training data is synthetic, and no sensitive personal data is used.
- Adversarial robustness of the embedding model itself.
- A production identity/authorization system for the webhook.
- Supply-chain signing (Sigstore/in-toto) and a signed SBOM.
