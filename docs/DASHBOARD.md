# SOC Sentinel dashboard

## Install

```bash
python -m pip install -e ".[dev,dashboard]"
pytest
ruff check .
ruff format --check .
mypy src tests
```

The dashboard dependency is optional. A CLI-only installation remains `python -m pip install -e .`.

## Seed and launch

```bash
soc-sentinel demo-seed --db data/soc-sentinel-demo.sqlite3
SOC_SENTINEL_DB=data/soc-sentinel-demo.sqlite3 streamlit run src/soc_sentinel/dashboard.py --server.address 127.0.0.1
```

PowerShell:

```powershell
soc-sentinel demo-seed --db data/soc-sentinel-demo.sqlite3
$env:SOC_SENTINEL_DB = "data/soc-sentinel-demo.sqlite3"
streamlit run src/soc_sentinel/dashboard.py --server.address 127.0.0.1
```

The application binds to loopback by default in the checked-in Streamlit config, and Streamlit usage statistics are disabled. The environment variable changes the local database file; it does not expose arbitrary fixture paths.

## Detection evaluation

The **Detection evaluation** navigation item runs the same framework-independent evaluator used by the CLI against `data/evaluation/benchmark.json` and the checked-in `rules/` directory. It displays aggregate precision, recall, F1, TP/FP/FN/TN counts, per-rule metrics, scenario outcomes, and false-positive/false-negative details. It is available even before a demo SQLite database has been created and does not read or mutate incident state.

The dashboard does not calculate its own metrics. For the full matching definition, fingerprints, and deterministic JSON/Markdown report generation, see [docs/EVALUATION.md](EVALUATION.md). To write local report files, run:

```bash
soc-sentinel evaluate --dataset data/evaluation/benchmark.json --rules rules/ --output reports/evaluation/
```

## Workflow

- **Operations overview:** actual SQLite counts for incidents, statuses, alerts by severity, creation activity, and entities found in incident records.
- **Incident explorer:** search/filter by text, status, severity, observed date, analyst, host, and username; deterministic sorting and pagination.
- **Alerts & evidence:** persisted alert IDs, rule IDs, rationale, grouping context, ATT&CK references, evidence IDs, and source fields when the source event still exists.
- **Timeline:** chronological entries with security-event versus application-audit timestamps and provenance.
- **Correlation:** the persisted relationship strategy, shared values, gap, and explanation.
- **Notes and audit:** timestamped analyst notes and backend audit entries.
- **Manage:** version-checked status/assignment changes, resolution classification and summary, reopening, and explicit confirmation before terminal closure.
- **Synthetic lab:** allow-listed repository fixtures and rule profiles run through the same parser, detection engine, correlation policy, and persistence services as the CLI.

## Database behavior and troubleshooting

- Missing database: run `soc-sentinel demo-seed --db data/soc-sentinel-demo.sqlite3`.
- Wrong/corrupt schema: verify the target is a schema-v3 SOC Sentinel SQLite file; the read-only dashboard does not migrate it.
- Stale update: reload the incident workspace and retry against the current version.
- Streamlit missing: install `python -m pip install -e ".[dashboard]"`.
- Port already in use: select another local port using `--server.port 8502`, while retaining `--server.address 127.0.0.1`.
- Demo reset: use `--reset` only with a separate demo-named database. The default working database is protected.

## Security and future hosting

No credentials, secrets, network APIs, or remote services are required. Do not use real organizational logs in the committed fixtures. Do not expose this unauthenticated dashboard publicly. Any future remote deployment must first add authentication/authorization, secure session and transport configuration, and a tested persistence plan. Free-tier storage can be ephemeral; no hosting was configured in this phase.

## Portfolio screenshot checklist

Capture genuine local screenshots of: overview metrics; filtered incident queue; alert/evidence detail; timeline provenance; correlation explanation; lifecycle/resolution form; and synthetic pipeline results. Only commit screenshots actually captured from the running application.
