# Architecture

## Implemented data flow

```text
UTF-8 JSONL input
    |
    v
Streaming JSONL reader -> line-numbered parse/validation issues
    |
    v
Pydantic normalized SecurityEvent (UTC timestamps, validated IPs, provenance)
    |
    +------------------------------+
    |                              |
    v                              v
Transactional SQLite ingest     Safe YAML rule loader
                                   |
                                   v
                          Pydantic DetectionRule
                          (allow-listed fields/operators)
                                   |
                                   v
                         Deterministic rule engine
                         (match / threshold / sequence)
                                   |
                                   v
                          Evidence-linked Alert objects
                                   |
                                   v
                         CLI text or JSON output
```

## Module boundaries

- `schemas.py`: normalized security-event contract.
- `ingestion/jsonl.py`: line-by-line JSONL parsing and event validation.
- `db.py`: versioned SQLite initialization and transactional event persistence.
- `detection/rules.py`: strict Pydantic rule schema, allow-lists, safe YAML loading.
- `detection/engine.py`: pure deterministic matching, grouping, threshold/sequence evaluation, and alert construction.
- `cli.py`: existing `check-db` and `ingest` commands plus `validate-rules` and `detect`.

## Detection engine contract

Rules are data-only YAML. Safe loading and Pydantic validation reject unknown keys, fields, operators, invalid thresholds, unsupported field/event-type combinations, and invalid windows. The engine does not evaluate Python expressions, execute shell commands, read arbitrary event attributes, or use scenario metadata.

Conditions are ANDed. Supported operators are `eq`, `ne`, `in`, `not_in`, `contains`, `icontains`, `starts_with`, `ends_with`, `gt`, `gte`, `lt`, and `lte`. Numeric comparisons are limited to process PID fields; timestamp comparisons are equality/inequality only. Missing optional fields never match.

The engine sorts events by timestamp and event ID, de-duplicates repeated event IDs (first occurrence wins), sorts rules by stable rule ID, and sorts final alerts deterministically. Alert IDs are derived from rule ID, grouping context, and ordered evidence event IDs. The engine is stateless; persistent alert lifecycle/deduplication is not yet implemented.

## Design constraints

- Local-first runtime; SQLite comes from Python's standard library.
- Pydantic is used for typed boundary validation; PyYAML is used only for safe YAML parsing.
- No cloud database, hosted queue, paid API, or API key is required.
- Event IDs are unique in SQLite. Existing IDs are skipped; no overwrites occur.
- Strict ingestion rejects its input before persistence; non-strict ingestion reports line-numbered issues and continues.
- Scenario labels are evaluation metadata and must never drive detection decisions.
- JSONL is read line by line, but valid events are retained for a single ingestion transaction. Memory scales with accepted events.
- All tests are deterministic and do not contact external systems.

## Database evolution

The Phase 1 schema version is 1. Phase 2 migrates it in-place to schema version 2, adding the `events` table and indexes. See [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md).

## Phase evolution

1. Repository foundation: package, CLI, SQLite bootstrap, docs, tests, CI — complete.
2. Event normalization and JSONL ingestion with SQLite persistence — complete.
3. Safe deterministic rules and evidence-linked alerts — implemented and CI verified; see [DETECTION_CATALOG.md](DETECTION_CATALOG.md).
4. Correlation of related alerts into incidents.
5. Local investigation dashboard.
6. Labeled synthetic evaluation and reproducible metrics.
7. Hardening and optional presentation hosting.
