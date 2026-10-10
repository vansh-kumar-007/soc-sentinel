# Project Status

Last updated: 2026-10-10

## Current milestone

**Phase 3 — Deterministic Detection Engineering Engine: implementation in progress.**

Phase 2 is complete and verified. Phase 3 source code, initial YAML rules, tests, and documentation have been committed to `main`. Phase 3 remains pending until the current head passes the full GitHub Actions matrix and the final remote tree is audited.

## Phase checklist

### Phase 1 — Foundation
- [x] Python package, CLI, SQLite bootstrap, docs, tests, and CI matrix.

### Phase 2 — Event ingestion and normalization
- [x] Pydantic event contract and UTC/IP validation.
- [x] Streaming JSONL parsing with line-numbered issues and strict/non-strict modes.
- [x] SQLite schema version 2 migration and transactional event persistence.
- [x] Ingestion CLI and synthetic fixtures.
- [x] GitHub Actions passed pytest, Ruff lint/format, and mypy on Python 3.11, 3.12, and 3.13.

### Phase 3 — Deterministic detection engineering
- [x] Typed, data-only YAML rule schema with safe loading and strict unknown-field rejection.
- [x] Allow-listed normalized fields/operators and field-type compatibility checks.
- [x] Deterministic match, threshold, and two-stage sequence strategies.
- [x] Evidence-linked alerts with stable IDs, grouping context, severity, rationale, and optional ATT&CK references.
- [x] DET-001 authentication failure burst rule.
- [x] DET-002 failed-login then success sequence rule.
- [x] DET-003 encoded PowerShell command-line indicator rule.
- [x] Rule validation and detection CLI commands, including JSON output.
- [x] Positive/negative synthetic tests for rules, thresholds, ordering, windows, grouping, process lookalikes, duplicate events, and scenario-label independence.
- [x] Rule format, detection catalog, architecture, and README usage documentation.
- [ ] Final GitHub Actions matrix passes pytest, Ruff lint/format, and mypy on Python 3.11, 3.12, and 3.13.
- [ ] Audit the final current-head commit, branch state, and verification links.

## Rule behavior

- `validate-rules --rules rules/` safely loads and validates every shipped YAML rule.
- `detect --input FILE --rules rules/` evaluates the normalized JSONL records without a database or network service.
- Conditions are ANDed and use explicit allow-listed operators; arbitrary Python, shell commands, regex, and scenario fields are not supported.
- Missing optional fields do not match, including inequality and negative-membership operators.
- DET-001 requires five failed logins for the same username/source IP within 600 seconds.
- DET-002 requires at least three failed logins followed strictly later by success for the same username/source IP within 600 seconds.
- DET-003 flags PowerShell-family process names whose command line contains the encoded-command switch. It is a heuristic indicator, not a malware verdict.
- Alert IDs are deterministic from rule ID, grouping context, and ordered evidence event IDs. The engine is stateless and does not persist alert lifecycle state.
- Scenario labels are never consulted by the detection engine.

## Verification record

- **Phase 2 acceptance:** [GitHub Actions run #72](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38049101494) passed on Phase 2 commit `a2026b4cc76c6f3bc6a160dd0b65944c3b5c0a33`.
- **Phase 3 CI:** pending final run for the current `main` head. Intermediate CI run #82 failed one process-rule negative test because the indicator was too broad (`-enc` also matched `-Encoding`). The rule was narrowed to `-EncodedCommand`; do not treat the intermediate failure as final acceptance evidence.
- **Local test execution:** no claim of a separate local full-suite run; verification will be based on GitHub Actions against the remote checkout.
- **Branch:** `main` only; no force-push or history rewrite.
- **Cost:** no paid service, external database, or external API was introduced.

## Limitations

- Rule conditions are AND-only; there is no arbitrary OR, regular expression, dynamic code, or shell execution.
- DET-001 groups by username and source IP, so records without either value are skipped for that rule.
- DET-002 requires username and source IP to match exactly; it does not incorporate MFA, device identity, geolocation, or session risk. A success after failures does not prove compromise.
- DET-003 relies on process name and command-line telemetry. Parent process, user context, and hash are not required by the initial rule; command-line data may be absent or truncated.
- Alert generation is stateless. Identical complete inputs produce stable alert IDs, but there is no persisted alert lifecycle or incident correlation yet.
- The JSONL parser retains validated events in memory before evaluation. Very large-file streaming detection is future hardening work.

## Cost and infrastructure

Local-first runtime. SQLite is from Python's standard library; Pydantic and PyYAML are runtime dependencies. No cloud resource, trial, payment method, paid API, or remote database is required.

## Next step

After Phase 3 passes final CI and repository audit, Phase 4 should correlate evidence-linked alerts into incident cases with deterministic entity/time-window rules and an explicit incident lifecycle. Do not start Phase 4 before Phase 3 verification is complete.
