"""Dashboard service tests use only temporary SQLite databases and synthetic fixtures."""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from soc_sentinel.dashboard_services import (
    DashboardServiceError,
    add_investigation_note,
    assign_incident_to_analyst,
    change_incident_status,
    ensure_public_demo_database,
    get_dashboard_summary,
    get_incident_details,
    list_dashboard_alerts,
    list_dashboard_incidents,
    reopen_incident,
    resolve_incident,
    run_public_synthetic_preview,
    run_synthetic_investigation,
)
from soc_sentinel.db import initialize_database
from soc_sentinel.demo import seed_demo_database
from soc_sentinel.incidents import IncidentError
from soc_sentinel.operating_mode import OperatingModeError


def seeded(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    path = tmp_path / "soc-sentinel-demo.sqlite3"
    result = run_synthetic_investigation(path)
    return path, result


def test_empty_database_summary_is_real_and_empty(tmp_path: Path) -> None:
    path = initialize_database(tmp_path / "empty.sqlite3")
    summary = get_dashboard_summary(path)
    assert summary["total_incidents"] == 0
    assert summary["total_alerts"] == 0
    assert summary["activity"] == []
    assert all(row["count"] == 0 for row in summary["alerts_by_severity"])


def test_missing_database_is_not_created_by_read_services(tmp_path: Path) -> None:
    path = tmp_path / "missing.sqlite3"
    with pytest.raises(DashboardServiceError, match="database not found"):
        get_dashboard_summary(path)
    assert not path.exists()


def test_demo_pipeline_is_reproducible_and_idempotent(tmp_path: Path) -> None:
    path, first = seeded(tmp_path)
    second = run_synthetic_investigation(path)
    assert first["records_read"] == 8
    assert first["events_inserted"] == 8
    assert first["records_rejected"] == 0
    assert first["alerts_generated"] == 3
    assert second["events_inserted"] == 0
    assert second["event_duplicates"] == 8
    assert [item["alert_id"] for item in first["alerts"]] == [
        item["alert_id"] for item in second["alerts"]
    ]
    assert len(first["incidents"]) == 2
    assert [item["incident_id"] for item in first["incidents"]] == [
        item["incident_id"] for item in second["incidents"]
    ]
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 3
        assert connection.execute("SELECT COUNT(*) FROM incident_alerts").fetchone()[0] == 3


def test_summary_and_incident_filters_use_persisted_data(tmp_path: Path) -> None:
    path, _ = seeded(tmp_path)
    summary = get_dashboard_summary(path)
    assert summary["total_incidents"] == 2
    assert summary["open_incidents"] == 2
    assert summary["total_alerts"] == 3
    assert sum(row["count"] for row in summary["alerts_by_severity"]) == 3
    assert sum(row["count"] for row in summary["alerts_by_rule"]) == 3
    auth = list_dashboard_incidents(path, host="ws-fin-07")
    assert auth["total"] == 1
    assert auth["items"][0]["entities"]["username"] == ["jordan.chen"]
    user = list_dashboard_incidents(path, username="jordan")
    assert user["total"] == 1
    searched = list_dashboard_incidents(path, query="INC-", page_size=1)
    assert searched["total"] == 2
    assert searched["pages"] == 2
    assert len(searched["items"]) == 1
    page_two = list_dashboard_incidents(path, query="INC-", page_size=1, page=2)
    assert page_two["items"][0]["incident_id"] != searched["items"][0]["incident_id"]
    high = list_dashboard_incidents(path, severities={"high"})
    assert high["total"] == 1
    with pytest.raises(DashboardServiceError, match="Unsupported incident sort"):
        list_dashboard_incidents(path, sort_by="raw_sql")


def test_alert_and_evidence_detail_includes_correlation_provenance(tmp_path: Path) -> None:
    path, _ = seeded(tmp_path)
    alerts = list_dashboard_alerts(path)
    assert len(alerts) == 3
    auth_incident = list_dashboard_incidents(path, host="ws-fin-07")["items"][0]
    detail = get_incident_details(path, auth_incident["incident_id"])
    assert len(detail["alerts"]) == 2
    assert detail["correlation_explanations"]
    assert all(item["explanation"] for item in detail["correlation_explanations"])
    assert detail["evidence_events"]
    assert all(
        item["provenance"] == "source_telemetry" for item in detail["evidence_events"].values()
    )
    timeline = detail["timeline"]
    assert timeline == sorted(
        timeline,
        key=lambda item: (
            item["timestamp"],
            item["kind"],
            str(item.get("event_id", item.get("audit_id", item.get("alert_id", "")))),
        ),
    )
    assert {item["timestamp_type"] for item in timeline} >= {"security_event", "application_audit"}


def test_alert_filters_preserve_evidence_and_incident_links(tmp_path: Path) -> None:
    path, _ = seeded(tmp_path)
    all_alerts = list_dashboard_alerts(path, limit=1000)
    assert all_alerts
    chosen = all_alerts[0]
    filtered = list_dashboard_alerts(
        path,
        rule_ids={chosen["rule_id"]},
        incident_association="linked",
    )
    assert filtered
    assert all(item["rule_id"] == chosen["rule_id"] for item in filtered)
    assert all(item["incident_id"] for item in filtered)
    for item in filtered:
        details = get_incident_details(path, item["incident_id"])
        assert set(item["evidence_event_ids"]).issubset(
            set(details["evidence_events"]) | set(details["missing_event_ids"])
        )
    with pytest.raises(DashboardServiceError, match="Incident association"):
        list_dashboard_alerts(path, incident_association="anything")


def test_missing_source_event_is_reported_not_fabricated(tmp_path: Path) -> None:
    path, _ = seeded(tmp_path)
    incident = list_dashboard_incidents(path, host="ws-fin-07")["items"][0]
    details = get_incident_details(path, incident["incident_id"])
    event_id = details["alerts"][0]["evidence_event_ids"][0]
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM events WHERE event_id=?", (event_id,))
    refreshed = get_incident_details(path, incident["incident_id"])
    assert event_id in refreshed["missing_event_ids"]
    timeline_item = next(item for item in refreshed["timeline"] if item.get("event_id") == event_id)
    assert timeline_item["source_available"] is False


def test_lifecycle_assignment_notes_resolution_reopen_and_stale_conflict(tmp_path: Path) -> None:
    path, _ = seeded(tmp_path)
    incident = list_dashboard_incidents(path, host="ws-fin-07")["items"][0]
    incident_id, version = incident["incident_id"], incident["version"]
    assigned = assign_incident_to_analyst(path, incident_id, "analyst-demo", version)
    assert assigned.assigned_analyst == "analyst-demo"
    with pytest.raises(IncidentError, match="stale incident version"):
        assign_incident_to_analyst(path, incident_id, "stale-writer", version)
    note = add_investigation_note(
        path,
        incident_id,
        "Reviewed synthetic authentication evidence.",
        expected_version=assigned.version,
    )
    assert note["note"].startswith("Reviewed")
    current = list_dashboard_incidents(path, host="ws-fin-07")["items"][0]
    resolved = resolve_incident(
        path, incident_id, "inconclusive", "Need more telemetry.", current["version"]
    )
    assert resolved.status.value == "resolved"
    reopened = reopen_incident(path, incident_id, resolved.version)
    assert reopened.status.value == "open"
    assert reopened.resolution_classification is None
    with pytest.raises(IncidentError, match="resolution requires"):
        resolve_incident(path, incident_id, "inconclusive", "  ", reopened.version)
    audit = get_incident_details(path, incident_id)["timeline"]
    assert any(item["kind"] == "assignment_changed" for item in audit)
    assert any(item["kind"] == "note" and item.get("note") for item in audit)
    assert any(item["kind"] == "status_changed" for item in audit)


def test_invalid_lifecycle_transition_is_visible(tmp_path: Path) -> None:
    path, _ = seeded(tmp_path)
    incident = list_dashboard_incidents(path, host="ws-fin-07")["items"][0]
    with pytest.raises(IncidentError, match="invalid status transition"):
        change_incident_status(path, incident["incident_id"], "closed", incident["version"])


def test_demo_reset_requires_demo_named_target_and_preserves_other_db(tmp_path: Path) -> None:
    protected_like = tmp_path / "working.sqlite3"
    protected_like.write_text("keep me", encoding="utf-8")
    with pytest.raises(ValueError, match="filename must contain 'demo'"):
        seed_demo_database(protected_like, reset=True)
    assert protected_like.read_text(encoding="utf-8") == "keep me"
    demo_path = tmp_path / "soc-sentinel-demo.sqlite3"
    first = seed_demo_database(demo_path)
    assert first["reset_performed"] is False
    reset = seed_demo_database(demo_path, reset=True)
    assert reset["reset_performed"] is True
    assert reset["alerts_generated"] == 3
    with sqlite3.connect(demo_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 3


def test_demo_seed_cli_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from soc_sentinel.cli import main

    path = tmp_path / "cli-demo.sqlite3"
    assert main(["demo-seed", "--db", str(path), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["events_inserted"] == 8
    assert output["alerts_generated"] == 3
    assert path.is_file()


def test_cli_import_does_not_import_streamlit() -> None:
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import soc_sentinel.cli; assert 'streamlit' not in sys.modules",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_dashboard_module_imports_without_starting_ui() -> None:
    pytest.importorskip("streamlit")
    module = importlib.import_module("soc_sentinel.dashboard")
    assert callable(module.main)


def test_dashboard_app_starts_without_creating_a_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    missing_database = tmp_path / "not-created.sqlite3"
    monkeypatch.setenv("SOC_SENTINEL_DB", str(missing_database))
    monkeypatch.setenv("SOC_SENTINEL_MODE", "public-demo")
    app_path = Path(__file__).parents[1] / "src" / "soc_sentinel" / "dashboard.py"
    app = AppTest.from_file(str(app_path), default_timeout=15).run()
    assert not app.exception
    assert not missing_database.exists()


def test_dashboard_evaluation_page_uses_canonical_evaluator_without_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    original_mode = os.environ.get("SOC_SENTINEL_MODE")
    monkeypatch.setenv("SOC_SENTINEL_DB", str(tmp_path / "missing.sqlite3"))
    monkeypatch.setenv("SOC_SENTINEL_MODE", "public-demo")
    app_path = Path(__file__).parents[1] / "src" / "soc_sentinel" / "dashboard.py"
    try:
        app = AppTest.from_file(str(app_path), default_timeout=20).run()
    finally:
        if original_mode is None:
            os.environ.pop("SOC_SENTINEL_MODE", None)
        else:
            os.environ["SOC_SENTINEL_MODE"] = original_mode
    app.radio[0].set_value("Detection evaluation").run()
    assert not app.exception
    assert any("Detection evaluation" in item.value for item in app.title)
    assert any("PUBLIC · READ ONLY" in item.value for item in app.markdown)
    assert any("Synthetic benchmark only" in item.value for item in app.warning)
    metrics = {item.label: item.value for item in app.metric}
    assert metrics["Precision"] == "0.909"
    assert metrics["Recall"] == "1.000"
    assert metrics["F1 score"] == "0.952"
    assert metrics["False positives"] == "1"
    assert metrics["False negatives"] == "0"
    assert any("Unexpected alerts / false positives" in item.label for item in app.expander)
    assert any(
        "Missed expected detections / false negatives" in item.label for item in app.expander
    )


def test_public_demo_mode_rejects_all_dashboard_service_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, seeded_result = seeded(tmp_path)
    incident_id = seeded_result["incidents"][0]["incident_id"]
    with sqlite3.connect(path) as connection:
        before = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("events", "alerts", "incidents", "incident_notes", "incident_audit")
        }
        incident_before = connection.execute(
            "SELECT status, assigned_analyst, version FROM incidents WHERE incident_id=?",
            (incident_id,),
        ).fetchone()
    monkeypatch.setenv("SOC_SENTINEL_MODE", "public-demo")
    attempted: list[Callable[[], object]] = [
        lambda: change_incident_status(path, incident_id, "in_progress", 1),
        lambda: assign_incident_to_analyst(path, incident_id, "attacker", 1),
        lambda: add_investigation_note(path, incident_id, "unauthorized note", expected_version=1),
        lambda: resolve_incident(path, incident_id, "inconclusive", "unauthorized", 1),
        lambda: reopen_incident(path, incident_id, 1),
        lambda: run_synthetic_investigation(path),
        lambda: seed_demo_database(path, reset=True),
    ]
    for action in attempted:
        with pytest.raises(OperatingModeError, match="read-only"):
            action()
    with sqlite3.connect(path) as connection:
        after = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("events", "alerts", "incidents", "incident_notes", "incident_audit")
        }
        incident_after = connection.execute(
            "SELECT status, assigned_analyst, version FROM incidents WHERE incident_id=?",
            (incident_id,),
        ).fetchone()
    assert after == before
    assert incident_after == incident_before


def test_public_demo_initialization_is_synthetic_and_never_resets_existing_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "soc-sentinel-public-demo.sqlite3"
    monkeypatch.setenv("SOC_SENTINEL_MODE", "public-demo")
    first = ensure_public_demo_database(path)
    assert first["initialized"] is True
    summary = get_dashboard_summary(path)
    assert summary["total_incidents"] == 2
    assert summary["total_alerts"] == 3
    with sqlite3.connect(path) as connection:
        before = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("events", "alerts", "incidents", "incident_notes", "incident_audit")
        }
    second = ensure_public_demo_database(path)
    assert second["initialized"] is False
    with sqlite3.connect(path) as connection:
        after = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("events", "alerts", "incidents", "incident_notes", "incident_audit")
        }
    assert after == before


def test_public_synthetic_preview_does_not_change_public_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "soc-sentinel-public-demo.sqlite3"
    monkeypatch.setenv("SOC_SENTINEL_MODE", "public-demo")
    ensure_public_demo_database(path)

    def snapshot() -> dict[str, list[tuple[object, ...]]]:
        with sqlite3.connect(path) as connection:
            tables = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            ]
            return {
                table: sorted(connection.execute(f'SELECT * FROM "{table}"').fetchall(), key=repr)
                for table in tables
            }

    before = snapshot()
    result = run_public_synthetic_preview(fixture_key="soc_demo", rule_profile="all")
    after = snapshot()

    assert result["fixture"] == "soc-demo.jsonl"
    assert result["alerts_generated"] > 0
    assert result["incidents"]
    assert result["database"] == "ephemeral-public-preview (discarded after execution)"
    assert before == after


def test_invalid_operating_mode_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, seeded_result = seeded(tmp_path)
    monkeypatch.setenv("SOC_SENTINEL_MODE", "public-ish")
    with pytest.raises(OperatingModeError, match="SOC_SENTINEL_MODE"):
        change_incident_status(path, seeded_result["incidents"][0]["incident_id"], "in_progress", 1)
