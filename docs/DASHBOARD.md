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
SOC_SENTINEL_MODE=local-analyst SOC_SENTINEL_DB=data/soc-sentinel-demo.sqlite3 streamlit run src/soc_sentinel/dashboard.py --server.address 127.0.0.1
```

PowerShell:

```powershell
soc-sentinel demo-seed --db data/soc-sentinel-demo.sqlite3
$env:SOC_SENTINEL_MODE = "local-analyst"
$env:SOC_SENTINEL_DB = "data/soc-sentinel-demo.sqlite3"
streamlit run src/soc_sentinel/dashboard.py --server.address 127.0.0.1
```

The application binds to loopback by default in the checked-in Streamlit config, and Streamlit usage statistics are disabled. The environment variable changes the local database file; it does not expose arbitrary fixture paths.

## Detection evaluation

The **Detection evaluation** navigation item runs the same framework-independent evaluator used by the CLI against `data/evaluation/benchmark.json` and the checked-in `rules/` directory. It displays aggregate precision, recall, F1, TP/FP/FN/TN counts, per-rule metrics, scenario outcomes, and false-positive/false-negative details. It is available even before a demo SQLite database has been created and does not read or mutate incident state.

Automated verification uses Streamlit `AppTest` to navigate to the evaluation page and assert the measured metrics and false-positive/false-negative detail sections. No separate manual browser session or screenshot verification was performed for Phase 6.

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


## Phase 8 operating modes and refresh

The dashboard has two operating modes, enforced in the Python service layer:

- **Local analyst:** run the package dashboard directly; lifecycle transitions, assignments, notes, the allow-listed synthetic pipeline, and the existing SQLite workflow remain available.
- **Public demo:** deploy the repository-root `streamlit_app.py` entry point. It forces public-demo mode, uses a disposable `/tmp` SQLite database, seeds only the checked-in synthetic SOC walkthrough when the file is absent, and rejects dashboard-service writes. Existing database files are never reset or overwritten during initialization. The public lab can run the allow-listed detection/correlation workflow in a separate temporary SQLite database; it displays the generated alerts and correlated incidents, then discards the preview database without changing public or analyst records.

The public entry point ignores any analyst database path and never reads the local working database. Its SQLite file is process-scoped under the temporary directory, contains only the bundled synthetic fixture, and is disposable on restart. Invalid mode values stop the dashboard safely. The operations overview derives alert severity/rule counts and recent activity from SQLite. The alert explorer filters by text, severity, rule, host, username, observation dates, and incident association while preserving evidence links. The evaluation page recalculates the current report and compares aggregate and per-rule metrics with the verified Phase 6 artifact. Refresh current data using the sidebar button; each render queries current application state. This is not external telemetry ingestion. The last-render timestamp is a UI refresh indicator, not a telemetry timestamp.

### Public hosting

The repository is prepared for Streamlit Community Cloud using the root `streamlit_app.py` entry point. To publish, select this repository and branch in the [Streamlit Community Cloud deployment page](https://share.streamlit.io/). The hosting account action is still required; no public URL is claimed until a deployment is opened and verified. Streamlit Community Cloud apps can hibernate after 12 hours without traffic, and the temporary synthetic database is disposable; there is no persistent-storage or continuous-uptime guarantee. See the [Community Cloud app management documentation](https://docs.streamlit.io/deploy/streamlit-community-cloud/manage-your-app). Do not use the public instance for real logs or analyst casework.

Phase 6 baseline provenance is recorded in [CI run #252](https://github.com/vansh-kumar-007/soc-sentinel/actions/runs/38152063404), which uploaded the original `detection-evaluation-e4fbbc9783a5224c5215e6616e915891cccf1116` report artifact. Current metrics are recalculated by `evaluate_dataset` from the canonical benchmark and current rules, not from dashboard constants.
