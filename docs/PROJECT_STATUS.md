# Project Status

Last updated: 2026-10-10

## Current milestone

**Phase 2 — Event Ingestion and Normalization**

Implementation is committed to `main`; verify automated CI before marking this phase complete. Do not begin Phase 3 until the acceptance criteria are verified.

## Phase checklist

- [x] Pydantic normalized event schema for authentication, process, and network records.
- [x] UTC timestamp normalization and explicit rejection of timezone-naive timestamps.
- [x] IPv4/IPv6 validation and canonicalization.
- [x] Optional process metadata, source provenance, and evaluation-only scenario metadata.
- [x] Streaming line-by-line JSONL parsing with line-numbered errors.
- [x] Strict mode aborts on first input error; non-strict mode continues and reports issues.
- [x] Duplicate IDs within a file rejected and reported.
- [x] Versioned SQLite migration from schema 1 to schema 2.
- [x] Parameterized, transactional SQLite inserts and unique event IDs.
- [x] CLI `ingest --input PATH --db PATH [--strict]`.
- [x] Synthetic event fixture and schema/database/CLI tests added.
- [x] Event schema, database schema, architecture, and README usage documented.
- [ ] Verify tests, Ruff lint/format, and mypy in GitHub Actions for Python 3.11, 3.12, and 3.13.
- [ ] Audit final committed tree, CLI output, and latest remote workflow result.

## Implemented behavior

- Required fields: event ID, timezone-aware timestamp, event type, host ID, action, and source ID.
- Authentication events require a username; process events require process metadata; network events require at least one IP.
- Evaluation scenario metadata is preserved but documented as non-evidence.
- Non-strict ingest skips blank lines, reports malformed JSON/schema/input duplicates, and continues through the file.
- Strict ingest rejects on the first invalid record before opening/initializing the destination database.
- Event IDs are the unique storage key. Repeated ingestion does not overwrite existing events.
- Schema version 1 migrates in-place to version 2; a future version is rejected.
- Unexpected insert errors abort and roll back the entire insertion batch.

## Verification record

Pending: record final commit SHA and actual workflow result after the current tree has completed CI.

## Limitations

- The JSONL reader iterates file lines rather than reading the full source text into memory, but valid events are retained in the parsed batch before transactional persistence. Memory therefore scales with accepted events.
- No configurable hard maximum for file size, line size, attributes size, or nested JSON complexity is implemented yet.
- No real organizational logs, detections, alerting, or active response were used or implemented.
- No paid infrastructure or API dependencies were introduced.

## Cost and infrastructure

Core processing is local. SQLite comes from Python's standard library. Pydantic is the only new runtime dependency. No cloud resource, trial, payment method, paid API, or external database was used.
