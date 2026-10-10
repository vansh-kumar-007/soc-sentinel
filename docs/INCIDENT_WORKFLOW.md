# SOC dashboard and synthetic investigation workflow

## Local dashboard

The optional Streamlit dashboard consumes `dashboard_services.py`, which wraps Phase 4 incident interfaces and exposes read-only SQLite queries for metrics, filters, alerts, and source-event details. Status, assignment, notes, resolution, and reopening use the Phase 4 application methods and retain optimistic version checks and audit entries.

The dashboard's `SOC_SENTINEL_DB` environment variable selects the database. It does not create a database silently. Read views require an existing schema-v3 database and open it in SQLite read-only/query-only mode. The synthetic workflow writes only when the analyst submits the form.

## Synthetic workflow

The lab only accepts fixture keys mapped in code to `data/samples/soc-demo.jsonl` or `data/samples/authentication.jsonl`, three shipped detection profiles, and the repository's `correlation.yaml`. It does not accept arbitrary paths or execute process command lines.

The walkthrough has eight fictional events. It is designed to produce three alerts: DET-001 and DET-002 from related authentication telemetry, plus DET-003 for an encoded PowerShell command-line indicator. The benign `-Encoding` lookalike must not trigger DET-003. The two authentication alerts should correlate; the process alert remains a separate incident. These expected outputs are covered by tests.

## Demo database reset

`soc-sentinel demo-seed --db data/soc-sentinel-demo.sqlite3` is repeatable and skips existing event IDs. To reset, `--reset` is required and the destination filename must contain `demo`. The exact `data/soc-sentinel.sqlite3` working database is protected. Do not use a real investigation database as a demo target.

## Provenance and interpretation

Source event fields are read from the event table; alert rationale and ATT&CK references come from persisted detection output; correlation explanation is persisted by the correlation engine; notes and lifecycle decisions are analyst/application records. Missing event rows are shown as missing while their alert evidence IDs remain visible. A rule match or correlation is not proof of compromise.

## Local security

Bind Streamlit to `127.0.0.1`. Do not expose the unauthenticated write-capable dashboard on a public interface. No external calls or telemetry export occur during normal local use.
