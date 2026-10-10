# Project Status

Last updated: 2026-10-10

## Current milestone

**Phase 4 — Alert Correlation and Incident Investigation: implemented.** Acceptance verification passed on GitHub Actions run [#181](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38052536164) on Python 3.11, 3.12, and 3.13: 83 tests per version, Ruff lint, Ruff formatting, and mypy.

Repository: https://github.com/vansh-kumar-007/soc-sentinel  
Integration branch: main  
Starting Phase 4 commit: f9c1042ed6912eb9c92441d49729bdf0c18781f8

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
- [x] Audit latest main, schema v2, alert representation, evidence references, stable alert IDs, and baseline CI.
- [x] Strict data-only YAML policy and deterministic exact-entity/evidence relationships.
- [x] Configurable minimum shared-entity threshold and time window.
- [x] Transitive correlation is disabled by the model default and can be explicitly enabled in policy; repository policy documents its opt-in.
- [x] Correlation explanations preserve the primary strategy, corroborating shared values, and time gap.
- [x] SQLite schema v3 migration preserves events and adds alerts, incidents, unique alert assignment, explanations, notes, and audit history.
- [x] Transactional incident updates, status transition validation, optimistic version checks, assignment, notes, resolution, reopening, and audit history.
- [x] Timeline labels security-event versus application-audit timestamps and source provenance.
- [x] Local CLI for correlate, list/show, lifecycle updates, analyst assignment, notes, timeline, and audit history.
- [x] Synthetic positive/negative correlation, transitive/non-transitive, replay idempotency, lifecycle, migration rollback, unsupported schema version, and CLI tests.
- [x] GitHub Actions passed 83 tests per Python version, Ruff lint, Ruff format, and mypy.

## Phase 4 limitations

- Exact identifiers are not identity resolution; NAT, service accounts, reused host IDs, and incomplete telemetry can still produce false links or missed links.
- Existing incidents are not merged automatically. A new alert matching several active incidents is assigned to one deterministic candidate.
- The end-to-end command commits event ingestion first, then commits alert and incident state in a separate transaction. An incident transaction failure can leave successfully ingested events behind; incident/alert/link/explanation/audit changes are atomic with each other.
- The CLI is a local single-user tool, not an authenticated multi-user service.
- Timeline records only evidence references when source event details are unavailable; it does not fabricate telemetry.
- Phase 5 dashboard and labeled detection evaluation have not started.

## Verification record

- Phase 2: [GitHub Actions run #72](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38049101494).
- Phase 3 baseline: [GitHub Actions run #117](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38050260040).
- Phase 4 implementation and quality checks: [GitHub Actions run #181](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38052536164).

The final documentation changes are being validated by the same CI workflow on the current main head.

## Next milestone

**Phase 5 — SOC investigation dashboard.** It must not begin until the current Phase 4 final head passes CI.
