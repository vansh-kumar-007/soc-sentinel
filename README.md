# SOC Sentinel

**A local-first detection engineering and incident investigation lab.**

SOC Sentinel is a defensive security project for ingesting structured security events, applying deterministic detection rules, investigating evidence-backed alerts, and evaluating detection quality against reproducible synthetic scenarios.

The first milestone focuses on a reliable Python foundation. Event ingestion, detection, correlation, and the dashboard will be added incrementally.

## Principles

- **₹0 by design:** core functionality runs locally without a cloud account, paid service, external database, AI API, or API key.
- **Defensive-only:** use synthetic fixtures and logs from systems you own or are explicitly authorized to examine.
- **Evidence first:** detections must be explainable and refer to source events.
- **Reproducible:** behavior is covered by tests and future detection quality is evaluated against labeled scenarios.
- **Small, reviewable changes:** each milestone has acceptance criteria and an updated status.

## Current status

Phase 1 — Repository Foundation. See [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md).

## Technology choices

- Python 3.11–3.13
- Standard-library SQLite for local persistence
- pytest for tests
- Ruff for linting and formatting
- mypy for static type checking
- GitHub Actions for CI

The Phase 1 package has no runtime dependencies. Development tools are optional extras.

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

Try the CLI:

```bash
soc-sentinel --version
soc-sentinel check-db ./data/soc-sentinel.sqlite3
```

The database command creates a local SQLite database and a small metadata table. Keep real logs and database files out of Git. The version command does not create files or require a database.

## Project layout

- `src/soc_sentinel/`: CLI and local database foundation
- `tests/`: behavioral unit tests
- `docs/`: architecture, threat model, decisions, detection and evaluation plans
- `.github/workflows/`: automated checks
- `data/`: local runtime data, ignored by Git

## Planned capabilities (not implemented yet)

1. JSONL event ingestion and validation.
2. Deterministic, schema-validated YAML detection rules.
3. Evidence-linked alerts and entity/time-window correlation.
4. Incident investigation workflow and dashboard.
5. Labeled synthetic evaluation scenarios and reproducible metrics.
6. Hardening and optional presentation hosting after the core is stable.

These are roadmap items, not claims about the current implementation.

## Security and privacy

Do not commit credentials, private logs, personal data, or generated database files. Review [SECURITY.md](SECURITY.md). Never test against systems you do not own or have permission to assess.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

No software license has been selected yet. See [docs/LICENSING.md](docs/LICENSING.md). Public visibility alone does not grant general permission to reuse this code.
