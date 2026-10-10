# Project Status

Last updated: 2026-10-10

## Current milestone

**Phase 2 — Event Ingestion and Normalization**

Implementation is committed to `main`; Phase 2 remains under verification until the latest CI run on the final documented commit succeeds. Do not begin Phase 3 until then.

## Phase checklist

- [x] Pydantic normalized event schema for authentication, process, and network records.
- [x] UTC timestamp normalization and rejection of timezone-naive timestamps.
- [x] IPv4/IPv6 validation and canonicalization.
- [x] Optional process metadata, source provenance, and evaluation-only scenario metadata.
- [x] Streaming line-by-line JSONL parser with line-numbered issues and a 1 MiB per-line limit.
- [x] Strict mode aborts on the first invalid record; non-strict mode continues and reports issues.
- [x] Duplicate IDs within one file are rejected and separately counted.
- [x] Schema-version-2 SQLite migration from the Phase 1 schema.
- [x] Parameterized, explicitly transactional SQLite inserts and unique event IDs.
- [x] CLI `ingest --input PATH --db PATH [--strict]`.
- [x] Synthetic JSONL fixture and schema/database/CLI tests.
- [x] Event schema, database schema, architecture, and README usage documented.
- [ ] Verify pytest, Ruff lint/format, and mypy in GitHub Actions for Python 3.11, 3.12, and 3.13 on the final documented commit.
- [ ] Audit final tree, test totals, and latest remote workflow result.

## Implemented behavior

- Required fields: event ID, timezone-aware timestamp, event type, host ID, action, and source ID.
- Authentication requires username; process requires process metadata; network requires at least one valid IP.
- Scenario ID/label metadata is preserved only for evaluation; it is not detection evidence.
- Non-strict mode skips blank lines, reports malformed JSON/schema, oversized records, and duplicate input IDs, and continues parsing.
- Strict mode aborts at the first malformed or duplicate record before initializing or writing the database.
- Event IDs are the unique storage key. Existing IDs are skipped and counted, never overwritten.
- Schema version 1 migrates in-place to version 2; future versions are rejected. Migration failure rolls back schema changes and version metadata.
- Unexpected event insert failures abort and roll back all event inserts in the batch.

## Verification record

Pending final GitHub Actions result on the documented commit. Earlier CI runs may reflect intermediate file-level commits and do not count as final acceptance evidence.

## Limitations

- The reader reads source lines incrementally and rejects lines larger than 1 MiB, but retains validated events in memory before the single transaction. Memory still scales with accepted event count.
- The 1 MiB per-line limit bounds each individual input record, not the total file size or total number of accepted events. Future work may add bounded batch commits with explicitly different atomicity semantics.
- No organizational logs, detection rules, correlation, dashboard, or active response were used or implemented in Phase 2.
- No paid infrastructure or external APIs were introduced.

## Cost and infrastructure

Core processing is local. SQLite comes from Python's standard library; Pydantic is the only new runtime dependency. No cloud resource, trial, payment method, paid API, or external database was used.
