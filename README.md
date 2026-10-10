# SOC Sentinel

**A local-first detection engineering and incident investigation lab.**

SOC Sentinel is a defensive security project for validating security-event records and eventually applying deterministic detections, investigating evidence-backed alerts, and evaluating detection quality using reproducible synthetic scenarios.

## Principles

- **₹0 by design:** local core, no cloud account, paid service, remote database, AI API, or API key.
- **Defensive-only:** start with synthetic fixtures; use only data from systems you own or are authorized to investigate.
- **Evidence first:** preserve event source provenance; detection labels are metadata, not evidence.
- **Reproducible:** behavior is testable and future detection quality is measured against labeled scenarios.
- **Small milestones:** each phase has explicit acceptance criteria and a project status record.

## Current status

Phase 3 — Deterministic Detection Engineering Engine (implemented; CI verified). See [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md).

## Requirements

- Python 3.11–3.13
- SQLite (included in Python)
- Pydantic 2 for runtime schema validation
- Development tools: pytest, Ruff, mypy

## Quick start

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
mypy src tests
```

## CLI

Show the version and initialize or migrate a local database:

```bash
soc-sentinel --version
soc-sentinel check-db data/soc-sentinel.sqlite3
```

Ingest the bundled synthetic fixture:

```bash
soc-sentinel ingest --input data/samples/authentication.jsonl --db data/soc-sentinel.sqlite3
```

Non-strict mode (default) continues after invalid JSON/schema records and duplicate IDs within the input. It prints counts and each rejected line number, then persists all valid input records. Event IDs already stored in SQLite are skipped and counted as database duplicates. A database insert error rolls back the whole insert transaction.

Strict mode aborts at the first malformed or schema-invalid record before touching the database:

```bash
soc-sentinel ingest --input data/samples/authentication.jsonl --db data/soc-sentinel.sqlite3 --strict
```

Exit codes: `0` ingestion completed (non-strict mode may report rejected lines); `1` input I/O or database failure; `2` strict validation failure.

See [docs/EVENT_SCHEMA.md](docs/EVENT_SCHEMA.md) for the normalized record contract and [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) for SQLite migrations and storage.

## Detection engineering CLI

Validate the shipped declarative YAML rules:

```bash
soc-sentinel validate-rules --rules rules/
```

Run the deterministic detection engine against synthetic or authorized JSONL telemetry:

```bash
soc-sentinel detect --input data/samples/authentication.jsonl --rules rules/
```

Emit machine-readable alert output:

```bash
soc-sentinel detect --input data/samples/authentication.jsonl --rules rules/ --json
```

Use `--strict` to abort if any nonblank input record fails JSON/schema validation. Default non-strict mode evaluates valid records and reports rejected rows. Exit codes for these commands: `0` operation completed; `1` input I/O failure; `2` rule validation failure; `3` strict detection input validation failure.

The rule format is documented in [docs/RULE_FORMAT.md](docs/RULE_FORMAT.md), and the shipped rules, evidence, false positives, and limitations are described in [docs/DETECTION_CATALOG.md](docs/DETECTION_CATALOG.md). A detection is an investigative lead, not proof of malicious activity. The engine never uses scenario labels as evidence.

## Planned next

Alert correlation, incident investigation UI, and comprehensive labeled detection evaluation remain future phases. Do not treat scenario metadata in input files as detection evidence.

## Security and privacy

Do not commit credentials, private logs, personal data, or local database files. Use synthetic or authorized logs only. Review [SECURITY.md](SECURITY.md).
