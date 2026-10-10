# Architecture

## Implemented Phase 1–2 data flow

```text
UTF-8 JSONL file
    |
    v
Streaming line reader -> line-numbered parse/validation issues
    |
    v
Pydantic normalized SecurityEvent (UTC timestamps, validated IPs, provenance)
    |
    v
Transactional SQLite inserts (event_id primary key, versioned schema)
```

Phase 2 implements the normalized event contract, JSONL reader, local SQLite migration/event table, and CLI. Deterministic detection rules, alert correlation, incident cases, and the dashboard are not implemented.

## Design constraints

- Local-first runtime; SQLite comes from the Python standard library.
- Pydantic is the only runtime dependency and is used for typed boundary validation.
- No cloud database, hosted queue, paid API, or API key is required.
- Treat event data as untrusted. Unknown top-level fields are rejected.
- Timestamps must include a timezone and are normalized to UTC.
- Event IDs are unique in SQLite. Existing IDs are skipped; no overwrites occur.
- Strict ingestion rejects the batch on its first malformed record before persistence. Non-strict ingestion reports line-numbered errors, continues parsing, and persists all valid unique records in one transaction.
- Synthetic scenario labels are retained only as evaluation metadata and must never drive a detection decision.
- JSONL is read line by line. The current implementation retains validated events for a batch transaction, so memory is proportional to valid events in one input file. A configurable maximum file/line size and database-batched streaming are hardening follow-ups.
- All tests are deterministic and do not contact external systems.

## Database evolution

The Phase 1 schema version is 1. Phase 2 migrates it in-place to schema version 2, adding the `events` table and indexes. See [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md).

## Phase evolution

1. Repository foundation: package, CLI, SQLite bootstrap, docs, tests, CI — complete.
2. Event normalization and JSONL ingestion with SQLite persistence — implementation under verification.
3. Safe deterministic detection rules and evidence-linked alerts.
4. Correlation of related alerts into incidents.
5. Local investigation dashboard.
6. Labeled synthetic evaluation and reproducible metrics.
7. Hardening and optional presentation hosting.
