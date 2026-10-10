# Normalized Event Schema (Phase 2)

The public model is `soc_sentinel.schemas.SecurityEvent`; it is validated with Pydantic 2. Input is JSON objects, one per non-blank line.

## Required fields

| Field | Type / constraint | Meaning |
|---|---|---|
| `event_id` | string, 1–128 characters matching letters, digits, underscore, dot, colon, hyphen | Stable identity; unique in SQLite |
| `timestamp` | ISO-8601 datetime with timezone | Event time; normalized to UTC |
| `event_type` | `authentication`, `process`, `network` | Event family |
| `host_id` | non-empty string, max 255 | Host/device identifier |
| `action` | `login`, `logout`, `execute`, `connect`, `disconnect`, `other` | Reported action |
| `source_id` | non-empty string, max 512 | Source/file/system label supplied by the caller |

`outcome` defaults to `unknown`; valid values are `success`, `failure`, `unknown`.

## Optional fields

- `username`: non-empty string up to 255 characters.
- `source_ip`, `destination_ip`: valid IPv4 or IPv6 addresses, normalized to canonical string representation.
- `process`: object with optional `name`, `executable`, `pid`, `parent_pid`, `command_line`, and SHA-256 hash.
- `scenario`: optional `scenario_id` and `label` for synthetic test/evaluation bookkeeping.
- `attributes`: bounded by the input file and memory budget at this stage; arbitrary JSON object for extra source-specific properties.

The model forbids undeclared top-level fields to catch schema mistakes early.

## Event-specific requirements

- Authentication: requires `username`; actions are `login`, `logout`, or `other`.
- Process: requires `process`; actions are `execute` or `other`.
- Network: requires at least one IP address; actions are `connect`, `disconnect`, or `other`.

These requirements prevent irrelevant fields from being made mandatory for every event family.

## Timestamp handling

Naive timestamps are rejected because their timezone cannot be safely inferred. Explicit offsets and UTC timestamps are converted to UTC. Stored timestamps use ISO-8601 UTC with a trailing `Z`.

## Evaluation labels and detection safety

`scenario.scenario_id` and `scenario.label` are metadata intended for test/evaluation bookkeeping. They are not detection evidence. Future detection code must evaluate event telemetry fields and source evidence, never scenario labels.

## Error policy

The JSONL reader skips blank lines and counts non-blank records. In non-strict mode, malformed JSON, invalid schema, and duplicate IDs within the input are rejected with line-numbered issues while parsing continues. In strict mode the first such issue aborts parsing; the CLI does not write any events from that input.

When ingesting non-strictly, valid events are inserted transactionally. Event IDs already present in SQLite are skipped using the database primary key and reported separately as database duplicates. A failed transaction writes none of that insertion batch.
