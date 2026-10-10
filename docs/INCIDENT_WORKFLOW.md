# Incident investigation workflow

## Local-first end-to-end flow

1. Parse normalized JSONL and validate each event.
2. Run the unchanged Phase 3 detection rules to produce deterministic, evidence-linked alerts.
3. Persist accepted events, alert payloads, incident links, explanations, and audit records in local SQLite.
4. Use incident commands to investigate evidence, assign an analyst, add notes, change status, resolve, reopen, and inspect the timeline.

Alert generation remains stateless. Correlation and incident lifecycle are stateful. Re-running the same complete input is idempotent for event IDs, alert IDs, and incident-alert links; newly available alerts can extend existing investigations.

## Status and conclusions

- `open` → `in_progress` or `resolved`.
- `in_progress` → `open` or `resolved`.
- `resolved` → `open` (reopen) or `closed`.
- `closed` is terminal in the current CLI.

Resolving requires a classification (`true_positive`, `benign_positive`, `false_positive`, or `inconclusive`) and a non-empty analyst summary. A detection or correlation never sets a true-positive conclusion. Reopening clears current resolution fields but keeps the earlier classification and summary in the audit record.

Every status/assignment/note operation appends audit history transactionally. Status and assignment updates require the version shown by `show-incident`; stale versions fail with a reload-and-retry error. Notes optionally accept `--version` for the same concurrency guard. This is a local single-user tool, not an authenticated multi-user service.

## Timeline provenance

Timeline entries label timestamps as `security_event` (source telemetry event time or alert observed time) or `application_audit` (correlation, analyst notes, assignments, and lifecycle actions). Each entry identifies provenance such as `source_telemetry`, `detection_rule`, `correlation_engine`, or `analyst_input`. If an underlying event is no longer available in the local event table, the timeline shows only its event ID and marks the source unavailable; it does not invent event details.
