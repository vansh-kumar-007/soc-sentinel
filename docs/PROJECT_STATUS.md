# Project Status

Last updated: 2026-10-10

## Current milestone

**Phase 4 — Alert Correlation and Incident Investigation: implementation underway; acceptance verification pending.**

The existing repository and Phase 3 baseline were audited before implementation. Starting main commit was `f9c1042ed6912eb9c92441d49729bdf0c18781f8`; Phase 3 CI run #117 passed on that commit. Incident work is being added to the same repository and main branch.

## Phase checklist

### Phase 1 — Foundation
- [x] Python package, CLI, SQLite bootstrap, docs, tests, and CI matrix.

### Phase 2 — Event ingestion and normalization
- [x] Pydantic event contract and UTC/IP validation.
- [x] Streaming JSONL parsing with line-numbered issues and strict/non-strict modes.
- [x] SQLite schema v2 migration and transactional event persistence.
- [x] Ingestion CLI and synthetic fixtures.
- [x] GitHub Actions quality matrix passed on Python 3.11–3.13.

### Phase 3 — Deterministic detection engineering
- [x] Typed, data-only YAML rules with safe loading and strict validation.
- [x] Deterministic match, threshold, and sequence strategies.
- [x] Evidence-linked alerts with stable IDs, grouping context, severity, and rationale.
- [x] Three synthetic detection rules, CLI, tests, and documentation.
- [x] GitHub Actions passed tests, Ruff lint/format, and mypy on Python 3.11–3.13.

### Phase 4 — Alert correlation and incident investigation
- [x] Initial audit of latest main, schema version 2, current alert model, stable alert IDs, and baseline CI.
- [x] Add strict data-only YAML correlation policy and explainable exact-entity/evidence relationships.
- [x] Add incident records, lifecycle states, assignment, notes, resolution, audit history, and timeline operations.
- [x] Add SQLite schema v3 with incident/alert relationship constraints and migration.
- [x] Add correlation and incident CLI commands.
- [x] Add synthetic tests for policy validation, entity/time-window matching, transitive relationships, migration, lifecycle, and replay.
- [ ] Verify complete pytest suite, Ruff lint/format, and mypy.
- [ ] Verify GitHub Actions on Python 3.11, 3.12, and 3.13 on the final head.
- [ ] Audit final diff, documentation, branch state, and final commit.

## Phase 4 implementation notes (not yet final acceptance)

- Correlation is separate from detection; severity and timestamp proximity alone do not link alerts.
- Supported strategies: shared host, shared username, shared source IP, explicit username+source-IP pair, and overlapping evidence event IDs.
- Correlation policy is in `correlation.yaml`; its format is documented in `docs/CORRELATION_POLICY.md`.
- Schema v3 adds persisted alert payloads, incidents, unique alert assignment, correlation explanations, notes, and audit history.
- Lifecycle and timeline semantics are documented in `docs/INCIDENT_WORKFLOW.md`.
- No hosted database, paid service, API key, or external API is required.
- The end-to-end command stores events first and alert/incident state in a separate transaction. Event ingestion may remain committed if the later incident transaction fails; incident state itself is atomic.
- This CLI is local single-user software and is not an authenticated multi-user service.

## Verification record

- Phase 2: [GitHub Actions run #72](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38049101494).
- Phase 3 baseline: [GitHub Actions run #117](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38050260040).
- Phase 4: pending final green run. Intermediate failures are not acceptance evidence.

## Next milestone

Phase 5 is the local SOC investigation dashboard. It must not begin until Phase 4's final code and CI verification are complete.
