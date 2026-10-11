# Project Status

Last updated: 2026-10-11

## Current milestone

**Phase 7 — Detection precision and benchmark trustworthiness: Complete and Verified.** The exact feature head `17616e8a256b1f972be0b77df4cc05f845f78317` passed [manual CI run #263](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38158271822): 122 tests per Python 3.11–3.13 job, Ruff lint/format and mypy passed across the matrix, and Python 3.11 passed rule validation and production evaluation. It was merged to `main` as `1f261add4edefa0d56e490d984eb42a78c1d1afc`; [post-merge CI run #264](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38158602062) independently passed all three jobs and regenerated reports. Phase 6 remains complete and verified as the historical baseline (run [#252](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38152063404)).

Phase 5 remains implemented and verified; see the previous verification record below. The implementation passed [GitHub Actions run #199](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38054736275) on Python 3.11, 3.12, and 3.13: 96 tests per version, Ruff lint, Ruff formatting, and mypy.

Repository: https://github.com/vansh-kumar-007/soc-sentinel  
Integration branch: main  
Final verification: [manual workflow-dispatch run #267](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38161278282) passed on exact current `main` SHA `8696cd059ba4a1459eaacc3f6c8338d7cd413f8d`: 122 tests passed on Python 3.11, 3.12, and 3.13; Ruff lint, formatting, and mypy passed across the matrix. Python 3.11 rule validation and production benchmark evaluation passed, producing artifact [detection-evaluation-8696cd059ba4a1459eaacc3f6c8338d7cd413f8d](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38161278282/artifacts/11709893555). Measured aggregate metrics: TP 10, FP 1, FN 0, supplemental TN 47, precision 0.909091, recall 1.000000, F1 0.952381. PRs [#1](https://github.com/vansh-kumar-007/soc-sentinel/pull/1) and [#2](https://github.com/vansh-kumar-007/soc-sentinel/pull/2) are merged.
Starting Phase 4 commit: f9c1042ed6912eb9c92441d49729bdf0c18781f8

## Phase checklist

### Phase 7 — Detection precision and benchmark trustworthiness (complete and verified)

- [x] Add a safe, declarative case-insensitive token-boundary operator for command-line switch detection.
- [x] Change DET-003 to require a standalone encoded-command switch.
- [x] Add positive, negative, casing, quoting, and lookalike regression tests.
- [x] Reproduce before/after benchmark results from the production evaluation CLI and inspect the JSON report artifact.
- [x] Verify positive/negative switch cases and per-rule/aggregate metrics on the exact PR head in [manual CI run #263](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38158271822).
- [x] Verify integrated `main` with all three Python jobs, rule validation, evaluation CLI, and report artifact in [post-merge CI run #264](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38158602062).
- [x] Confirm benchmark labels, event records, and expected detection evidence are unchanged; only explanatory scenario metadata was updated.
- [x] Confirm JSON/Markdown metric agreement and deterministic report generation through evaluator regression tests.
- [x] Confirm dashboard evaluation remains covered by automated Streamlit AppTest; no manual browser verification is claimed.

The DET-003 change removes the measured `-EncodedCommandlet` false positive without changing its negative ground-truth label; the production CLI measured aggregate precision 0.909091 and F1 0.952381 with no false negatives. DET-001 remains unchanged: five failed logins alone cannot establish whether activity is malicious. Phase 7 was merged via [PR #1](https://github.com/vansh-kumar-007/soc-sentinel/pull/1) and the integrated `main` head passed [run #264](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38158602062).


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
- Phase 5 dashboard is implemented; see dashboard docs. Phase 6 evaluation is implemented; see evaluation docs.

## Verification record

- Phase 5 implementation: [GitHub Actions run #199](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38054736275), 96 tests per Python version; lint, formatting, and type checking passed.

- Phase 2: [GitHub Actions run #72](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38049101494).
- Phase 3 baseline: [GitHub Actions run #117](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38050260040).
- Phase 4 implementation and final documentation: [GitHub Actions run #187](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38052619830).

The final documentation set passed the same CI workflow; this status-only update records that verification.

### Phase 5 — SOC investigation dashboard

- [x] Optional Streamlit extra; CLI does not import Streamlit.
- [x] Framework-independent dashboard services for database-backed summary, filters, alert list, incident detail, and source-event lookup.
- [x] Read-only/query-only SQLite access for dashboard reads; existing Phase 4 service methods for writes.
- [x] Operations overview, incident explorer, alert/evidence view, timeline, correlation explanations, notes, audit, assignment, lifecycle and resolution controls.
- [x] Synthetic lab runs only bundled fixtures, shipped rule profiles, and checked-in correlation policy.
- [x] Reproducible eight-event demo fixture with authentication correlation, encoded PowerShell indicator, and benign lookalike.
- [x] Demo seed/reset command protects the default working database and requires a demo-named target for reset.
- [x] Dashboard service tests, CLI-independence test, module import smoke test, and Streamlit AppTest startup smoke test added.
- [x] Documentation includes local setup, safety notes, troubleshooting, screenshot checklist, and no-deploy policy.
- [x] GitHub Actions run #199 passed 96 tests per Python version, Ruff lint, Ruff formatting, and mypy.

## Phase 5 limitations

- Local single-user interface only; no authentication or authorization layer.
- Dashboard currently uses a single local SQLite file and does not ingest live telemetry.
- Incident filtering is in-memory over the current local dataset; alert explorer is capped at 1,000 records.
- Streamlit interaction uses a selector to open a case rather than a third-party table-selection component.
- No real screenshots have been captured or committed.
- No public deployment or external infrastructure changes were performed.

## Phase 6 — Reproducible detection evaluation

- [x] Audited the Phase 5 final commit, branch state, CI run #200, evaluation plan, event schema, rule loader, detection engine, CLI, dashboard, tests, and docs.
- [x] Added an independently labeled versioned benchmark at `data/evaluation/benchmark.json` with 19 scenarios, 75 unique event records, and 10 expected detection instances.
- [x] Added strict dataset/event validation, ground-truth isolation checks, unique ID and reference validation, replay semantics, stable fingerprints, and deterministic matching around the existing production detection engine.
- [x] Added aggregate/per-rule TP, FP, FN, supplemental TN, precision, recall, F1, scenario outcomes, and false-positive/false-negative details.
- [x] Added JSON and Markdown report generation and the `soc-sentinel evaluate` CLI with optional mismatch exit status.
- [x] Added a dashboard evaluation page that consumes the evaluator's canonical report object rather than implementing separate metrics.
- [x] Added evaluator validation, matching, metric, determinism, report, and CLI tests.
- [x] Updated README, architecture, and evaluation methodology.
- [x] Complete test suite, Ruff lint, Ruff formatting, and mypy on Python 3.11, 3.12, and 3.13 (120 tests each; also verified on implementation-baseline run #252).
- [x] `validate-rules` CLI smoke test and real evaluation CLI/report/artifact steps passed on Python 3.11 in runs #251 and #252.
- [x] Repository hygiene audit: only `main` exists; generated reports/DBs/secrets are not tracked in the repository tree.

Verification history:
- [GitHub Actions run #243](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38056708280) executed pytest on Python 3.11, 3.12, and 3.13 and found the F1-rounding regression: 117 passed, 1 failed per version. Other gates were skipped.
- [Run #244](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38147274126) failed before creating jobs because the new workflow conditions used invalid double-quoted string literals; the conditions are now single-quoted.
- [Run #245](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38147435240) surfaced a missing colon in a test definition. Follow-up source inspection found a second missing colon; both are corrected on main.
- [Run #247](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38147814980) passed pytest (120 tests) and Ruff lint on all three Python versions, then failed Ruff formatting on three files. This commit applies the formatter changes reported by that run. Type checking and report generation did not run because the format gate stopped the jobs.
- [Run #248](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38148111026) passed pytest (120 tests), Ruff lint, and Ruff format on Python 3.11–3.13. Mypy then found one `no-any-return` diagnostic at `tests/test_evaluation.py:27`; `read_benchmark()` returned `json.loads()` directly. This correction validates that the root is an object and returns an explicitly shaped dictionary.

- [Run #249](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38148239361) passed 120 tests, Ruff lint, Ruff formatting, and mypy on all three Python versions. Python 3.11 ran the evaluation CLI and uploaded generated JSON/Markdown reports.
- [Run #250](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38148398688) passed the full matrix on code/test SHA `f072a7074282b55c4efb27f23f4fdf437d886a14`: 120 passed per Python version; Ruff lint, Ruff formatting, and mypy passed on each. Its Python 3.11 job also validated all 3 shipped rules, ran the evaluator (TP 10, FP 2, FN 0, supplemental TN 46; precision 0.833333, recall 1.0, F1 0.909091), and uploaded report artifact `detection-evaluation-f072a7074282b55c4efb27f23f4fdf437d886a14`.
- [Run #251](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38148691555) passed on exact-head SHA `8457cca814a7047b4aebcc6cd69e6db9050fa9b3`: all three jobs completed successfully with 120 tests each, Ruff lint/format and mypy passed on every Python version, and Python 3.11 passed rule validation plus actual evaluation/report artifact steps. The artifact contains `evaluation.json` and `evaluation.md`.
- [Run #252](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38152063404) then passed on exact-head SHA `e4fbbc9783a5224c5215e6616e915891cccf1116`: all three matrix jobs succeeded with 120 tests each, Ruff lint/format and mypy passed, rule validation and report generation completed, and artifact `detection-evaluation-e4fbbc9783a5224c5215e6616e915891cccf1116` contains the measured JSON and Markdown reports.

Verification hygiene: a passing Actions run is evidence only for its exact commit SHA. The final delivery report identifies both the delivered SHA and its corresponding successful run.
- [x] Publish measured benchmark outcomes, per-rule metrics, and each known false-positive evidence set.

### Phase 6 findings to review

The measured false positives are DET-001 on evidence `mistype-1`–`mistype-5` and DET-003 on `substring-lookalike`. Neither ground-truth label was changed after observing detector output. A token-boundary improvement to DET-003 remains a separately reviewed future rule change.

## Next milestone

**Phase 8 has not started.** Phase 7 is complete and verified; no Phase 8 implementation work has been initiated.
