# Security policy

## Scope

This repository is a **lab prototype**, not a production SOC product. It
demonstrates an ML → RAG → LLM agent pipeline for OT alert triage. The security
work in this repo is deliberately scoped: it hardens the trust boundaries that
the prototype actually has, and documents the residual risks rather than
claiming the system is "secure".

The detailed threat model, framework mapping and risk register are in
[`docs/AI_SECURITY.md`](docs/AI_SECURITY.md). The model card is in
[`docs/MODEL_CARD.md`](docs/MODEL_CARD.md).

## Reporting a vulnerability

Please do not open a public issue for a security bug. Email
`carvajalperezliam7@gmail.com` with:

- the affected file/component and commit,
- a reproduction (request, alert JSON, rule, or document),
- the impact you believe it has,
- whether you want credit.

This is a personal project; expect a best-effort response, not a formal SLA.

## Supported versions

Only the `main` branch is maintained. There are no backports or long-term
support branches.

## Security posture (implemented)

| Control | Where |
| :--- | :--- |
| Strict alert schema (UUID, IP, function-code allowlist, bounds, no extra fields) | `src/security/schemas.py` |
| Output path confinement + UUID-derived filenames | `src/security/paths.py`, `scripts/agent.py` |
| Untrusted-data prompt delimiters and control-character stripping | `src/security/sanitize.py` |
| Tools use validated run context, not LLM-supplied RAG/IP/FC values | `src/security/context.py`, `scripts/agent.py` |
| Alert-only Modbus rule guard; SID range check | `src/security/guards.py` |
| Model and RAG artifact SHA-256 manifests, verified before load/ingest | `src/security/artifacts.py`, `models/manifest.json`, `data/rag_documents/manifest.json` |
| Structured audit log with secret redaction | `src/security/audit.py` |
| Webhook API key, rate limit, body cap, strict schema, 200/202 semantics | `scripts/webhook_receiver.py` |
| LLM provider allowlist and local-only mode | `src/security/egress.py` |
| Deterministic red-team suite (14 cases) | `scripts/redteam_agent.py`, `security/redteam/` |
| ML evasion and poisoning measurements | `security/evals/` |
| CI security gates (artifact verification, red team, bandit, detect-secrets, pip-audit) | `.github/workflows/security.yml` |

## Secrets

- `.env` is gitignored; `.env.example` contains placeholders only.
- Never commit API keys, webhook keys, or Hugging Face tokens.
- The webhook API key is optional by default for local demos; set
  `WEBHOOK_API_KEY` in any shared environment.
- The agent audit log records hashes and metadata, not prompts or secrets.

## Dependencies and artifacts

- `requirements.txt` declares runtime dependencies; `requirements-dev.txt` adds
  security tooling.
- Model and embedding artifacts are supply-chain inputs. The committed model is
  hash-pinned and verified before `joblib.load`; tampering fails closed.
- The embedding model is downloaded at Docker build time. A production
  deployment should pin a Hugging Face revision and verify the local cache.

## Known limitations (accepted for the prototype)

- In-memory alert/result store and an in-process background task, not a durable
  queue.
- No TLS or mTLS; API-key auth is optional unless configured.
- Generated rules are structurally validated and may be checked with
  `suricata -T`, but that is not a required CI gate.
- Prompt injection is mitigated by capability restriction and delimiting, not
  solved. Assume the LLM can be compromised.
- The ML model is trained on synthetic data; its metrics are not field
  performance. See `security/evals/` for evasion and poisoning results.
- No formal certification (ISO 42001, NIST AI RMF conformance) is claimed.
