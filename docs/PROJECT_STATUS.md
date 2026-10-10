# Project Status

Last updated: 2026-10-10

## Current milestone

**Phase 2 — Event Ingestion and Normalization: COMPLETE**

Phase 2 is implemented and verified by GitHub Actions on Python 3.11, 3.12, and 3.13. Phase 3 has not been started.

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
- [x] GitHub Actions matrix passed pytest, Ruff lint, Ruff format, and mypy on Python 3.11, 3.12, and 3.13.
- [x] Remote repository tree and current branch state re-audited.
- [ ] Phase 3 — deterministic detection rules and evidence-linked alerts.

## Implemented behavior

- Required fields: event ID, timezone-aware timestamp, event type, host ID, action, and source ID.
- Authentication requires username; process requires process metadata; network requires at least one valid IP.
- Scenario ID/label metadata is preserved only for evaluation; it is not detection evidence.
- Non-strict mode skips blank lines, reports malformed JSON/schema, oversized records, and duplicate input IDs, and continues parsing.
- Strict mode aborts at the first malformed or duplicate record before initializing or writing the database.
- Event IDs are the unique storage key. Existing IDs are skipped and counted, never overwritten.
- Schema version 1 migrates in-place to version 2; future versions are rejected. Migration failure rolls back schema changes and version metadata.
- Unexpected event insert failures abort and roll back all event inserts in the batch.
- `soc-sentinel ingest --input data/samples/authentication.jsonl --db data/soc-sentinel.sqlite3` is the documented local synthetic-data path.

## Verification record

- **Final implementation commit:** `c736686eff8e7d7110b6bb186d04db7c2d44ab32`.
- **GitHub Actions:** [run #70](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38048926052) completed successfully on that commit.
- **Matrix:** Python 3.11, 3.12, and 3.13 each passed package installation, pytest (33 tests collected; all passed), `ruff check .`, `ruff format --check .`, and `mypy src tests`.
- **Local test execution:** GitHub Actions ran the suite against the remote checkout. This environment could not clone GitHub directly, so no claim is made that the whole suite was separately executed in a local container.
- **Branch:** `main` only. No branches were created or deleted; no force-push or history rewrite occurred.
- **Cost:** no paid service, trial, API key, external database, or cloud resource was used.

## Limitations

- The reader reads source lines incrementally and rejects lines larger than 1 MiB, but retains validated events in memory before the single transaction. Memory still scales with accepted event count.
- The 1 MiB per-line limit bounds each individual input record, not the total file size or total number of accepted events. Future work may add bounded batch commits with explicitly different atomicity semantics.
- No organizational logs, detection rules, alert correlation, dashboard, or active response were used or implemented in Phase 2.
- No paid infrastructure or external APIs were introduced.

## Cost and infrastructure

Core processing is local. SQLite comes from Python's standard library; Pydantic is the only new runtime dependency. No cloud resource, trial, payment method, paid API, or external database was used.

## Next step

**Phase 3 — Deterministic Detection Engine.** Define a safe, data-only detection-rule schema with allow-listed operators, deterministic event matching, alert models tied to source event IDs, and positive/negative synthetic tests. Do not use scenario labels as evidence and do not execute rule content dynamically.
