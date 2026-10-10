# Architecture

## Implemented data flow

```text
UTF-8 JSONL
  -> streaming parser and normalized Pydantic SecurityEvent
  -> deterministic Phase 3 rule engine
  -> evidence-linked Alert objects
  -> validated safe YAML correlation policy
  -> deterministic alert relationships with explicit explanations
  -> transactional SQLite alerts / incidents / relationships / audit
  -> incident CLI, chronological timeline, lifecycle operations
```

## Module boundaries

- schemas.py: normalized event contract and UTC/IP validation.
- ingestion/jsonl.py: streaming JSONL parsing with line-numbered issues.
- db.py: schema versions 1–3 and transactional event persistence.
- detection/rules.py and detection/engine.py: existing declarative detection and stable evidence-linked alert IDs.
- correlation.py: strict Pydantic correlation policy, safe YAML loading, entity extraction, time-window matching, and human-readable relationship explanations.
- incidents.py: incident persistence, assignment, notes, optimistic version checks, lifecycle transitions, audit history, and timeline assembly.
- incident_cli.py: end-to-end correlate and local investigation commands.
- cli.py: existing CLI plus incident command integration.

## Correlation semantics

Correlation is separate from detection. Supported strategies are shared host, shared username, shared source IP, exact username+source-IP pair, and overlapping evidence event IDs. The policy order controls which explanation is selected when more than one strategy matches. Intervals are linked when their non-overlap gap is less than or equal to the configured window; severity and time proximity alone never form a relationship. Missing entities never match.

Transitive connected components are allowed only when allow_transitive is true. The engine records accepted edges and their shared values. Existing incident records are not automatically merged. An alert is assigned to at most one incident; when it matches multiple existing investigations, strategy priority and stable identifiers choose one candidate. See CORRELATION_POLICY.md.

## Incident lifecycle and provenance

Incident workflow state (open, in_progress, resolved, closed) is not a maliciousness verdict. Resolution requires an analyst-supplied classification and summary. Reopening clears the current resolution fields but preserves the earlier conclusion in audit history. Updates use optimistic version checks and lifecycle changes, assignments, and notes write audit records in transactions.

The timeline distinguishes source event time from application audit time and tags provenance. If an event record is unavailable, it shows the event ID only rather than inventing telemetry.

## Database evolution

Schema v1 held metadata; v2 added normalized events; v3 adds alert payloads, incidents, unique alert-to-incident assignments, correlation explanations, analyst notes, and audit history. Migration DDL and version changes share a transaction. Foreign keys are enabled on incident-store connections. Newer unsupported schema versions are rejected. See DATABASE_SCHEMA.md.

## Design constraints and limitations

- Local-first; no cloud service, remote database, paid API, or key is required.
- YAML is safe-loaded and schema-validated; no arbitrary code, regex, or shell expressions execute.
- The CLI is a local single-user tool and does not provide authentication or concurrent web access.
- Events and alert payloads are stored locally; the event parser retains accepted input events in memory for evaluation.
- Correlation strategies are deliberately simple exact matches. Shared NAT addresses, service accounts, and reused host identifiers can create explainable false links; analysts must review evidence.
- Alert generation is stateless; incident persistence and assignment are stateful and idempotent for stable alert IDs.
- Phase 5 dashboard and Phase 6 labeled evaluation are not started.
