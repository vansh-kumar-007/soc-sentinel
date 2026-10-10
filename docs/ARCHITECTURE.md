# Architecture

## Phase 1 boundary

Phase 1 establishes packaging, CLI behavior, a local SQLite bootstrap, tests, documentation, and CI. It does not implement event ingestion, detection rules, correlation, incidents, or a dashboard.

## Intended data flow

```text
JSONL / authorized local logs
        |
        v
Parser + schema validation
        |
        v
Normalized events (UTC timestamps, stable fields, provenance)
        |
        v
Deterministic YAML rule evaluation
        |
        v
Evidence-linked alerts
        |
        v
Time/entity correlation -> incidents
        |
        v
Local SQLite persistence -> investigation UI
        |
        v
Labeled scenario evaluation (precision, recall, F1, latency)
```

This is the planned architecture; stages after repository foundation are not implemented.

## Design constraints

- Local-first runtime. SQLite from the Python standard library is the initial persistence layer.
- No cloud database, hosted queue, paid API, or API key is required for core functionality.
- Validate inputs at boundaries; event data and rule files are untrusted.
- Rule operators must be allow-listed and data-only. Never evaluate arbitrary Python, shell, or expressions from rule files.
- Store timestamps consistently in UTC and retain provenance so alerts can be audited.
- Use synthetic and labeled evaluation data; publish metrics only when computed reproducibly.
- Keep UI concerns separate from ingestion, detections, and storage.

## Phase evolution

1. Repository foundation: package, CLI, SQLite bootstrap, docs, tests, CI.
2. Ingestion: bounded JSONL parser, normalized-event validation, timestamps and provenance.
3. Detection engine: safe YAML schema and deterministic rules with evidence-linked results.
4. Correlation: group related alerts by entities and bounded time windows.
5. Dashboard: local event/alert/incident exploration.
6. Evaluation: labeled synthetic fixtures and reproducible metrics.
7. Hardening/release: abuse cases, dependency review, reproducibility and optional hosting assessment.
