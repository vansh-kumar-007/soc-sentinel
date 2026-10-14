"""App-level regression tests for dashboard navigation and safe public rendering."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from soc_sentinel.dashboard_services import (
    get_dashboard_summary,
    list_dashboard_alerts,
    list_dashboard_incidents,
    run_synthetic_investigation,
)
from soc_sentinel.db import initialize_database
from soc_sentinel.operating_mode import PUBLIC_DEMO


def _render_app(monkeypatch: pytest.MonkeyPatch, database_path: Path) -> Any:
    """Run the real Streamlit script against an isolated test database."""
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SOC_SENTINEL_DB", str(database_path))
    monkeypatch.setenv("SOC_SENTINEL_MODE", "local-analyst")
    app_path = Path(__file__).parents[1] / "src" / "soc_sentinel" / "dashboard.py"
    return AppTest.from_file(str(app_path), default_timeout=25).run()


def _keyed(elements: Any, key: str) -> Any:
    """Find an AppTest widget by its explicit Streamlit key."""
    return next(element for element in elements if element.key == key)


def _database_snapshot(database_path: Path) -> tuple[tuple[object, ...], ...]:
    with sqlite3.connect(database_path) as connection:
        return tuple(
            connection.execute(
                "SELECT incident_id, status, assigned_analyst, version FROM incidents "
                "ORDER BY incident_id"
            ).fetchall()
        )


def test_overview_navigation_opens_the_intended_incident_without_widget_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOC_SENTINEL_MODE", "local-analyst")
    database_path = tmp_path / "soc-sentinel-demo.sqlite3"
    seeded = run_synthetic_investigation(database_path)
    app = _render_app(monkeypatch, database_path)
    assert not app.exception

    chooser = _keyed(app.selectbox, "overview_incident_choice")
    selected_label = chooser.value
    selected = next(
        incident
        for incident in get_dashboard_summary(database_path)["recent_incidents"]
        if f"{incident['reference']} · {incident['title']}" == selected_label
    )

    _keyed(app.button, "overview_investigate_incident").click().run()

    assert not app.exception
    assert app.session_state["navigation"] == "Incident explorer"
    assert app.session_state["selected_incident"] == selected["incident_id"]
    assert app.session_state["opened_incident"] == selected["incident_id"]
    assert any(item.value == selected["title"] for item in app.subheader)
    assert len(seeded["incidents"]) == 2


def test_alert_navigation_opens_the_associated_incident_without_widget_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOC_SENTINEL_MODE", "local-analyst")
    database_path = tmp_path / "soc-sentinel-demo.sqlite3"
    run_synthetic_investigation(database_path)
    app = _render_app(monkeypatch, database_path)
    app.radio[0].set_value("Alerts & evidence").run()
    assert not app.exception

    selected_alert_id = _keyed(app.selectbox, "alerts_inspect_alert").value
    alert = next(
        item
        for item in list_dashboard_alerts(database_path, limit=1000)
        if item["alert_id"] == selected_alert_id
    )
    assert alert["incident_id"]

    _keyed(app.button, "open_associated_incident").click().run()

    assert not app.exception
    assert app.session_state["navigation"] == "Incident explorer"
    assert app.session_state["selected_incident"] == alert["incident_id"]
    assert app.session_state["opened_incident"] == alert["incident_id"]
    incident = next(
        item
        for item in list_dashboard_incidents(database_path)["items"]
        if item["incident_id"] == alert["incident_id"]
    )
    assert any(item.value == incident["title"] for item in app.subheader)


@pytest.mark.parametrize("incident_index", [0, 1])
def test_open_investigation_workspace_shows_each_incident_and_preserves_its_data(
    incident_index: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOC_SENTINEL_MODE", "local-analyst")
    database_path = tmp_path / "soc-sentinel-demo.sqlite3"
    seeded = run_synthetic_investigation(database_path)
    target_id = seeded["incidents"][incident_index]["incident_id"]
    before = _database_snapshot(database_path)
    app = _render_app(monkeypatch, database_path)
    app.radio[0].set_value("Incident explorer").run()
    assert not app.exception

    incidents = list_dashboard_incidents(database_path)["items"]
    target = next(item for item in incidents if item["incident_id"] == target_id)
    target_label = f"{target['reference']} · {target['title']}"
    _keyed(app.selectbox, "explorer_incident_choice").set_value(target_label).run()
    _keyed(app.button, "open_investigation_workspace").click().run()

    assert not app.exception
    assert app.session_state["selected_incident"] == target_id
    assert app.session_state["opened_incident"] == target_id
    assert any(target["title"] == item.value for item in app.subheader)
    assert any("Opened " + target_label in item.value for item in app.success)
    assert {item.label for item in app.tabs} >= {
        "Overview",
        "Alerts & evidence",
        "Timeline",
        "Correlation",
        "Notes",
        "Audit",
        "Manage",
    }
    _keyed(app.button, "refresh_current_data").click().run()
    assert not app.exception
    assert app.session_state["selected_incident"] == target_id
    assert app.session_state["opened_incident"] == target_id
    assert _database_snapshot(database_path) == before


def test_overview_activity_chart_uses_persisted_dates_and_empty_state_is_honest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOC_SENTINEL_MODE", "local-analyst")
    populated_path = tmp_path / "populated.sqlite3"
    run_synthetic_investigation(populated_path)
    populated_summary = get_dashboard_summary(populated_path)
    assert populated_summary["activity"]
    assert sum(item["incidents"] for item in populated_summary["activity"]) == 2
    populated_app = _render_app(monkeypatch, populated_path)
    assert not populated_app.exception
    assert not any("No activity recorded" in item.value for item in populated_app.markdown)

    empty_path = initialize_database(tmp_path / "empty.sqlite3")
    empty_summary = get_dashboard_summary(empty_path)
    assert empty_summary["activity"] == []
    empty_app = _render_app(monkeypatch, empty_path)
    assert not empty_app.exception
    assert any("No activity recorded" in item.value for item in empty_app.markdown)



def test_incident_explorer_rejects_inverted_date_range_without_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOC_SENTINEL_MODE", "local-analyst")
    database_path = tmp_path / "soc-sentinel-demo.sqlite3"
    run_synthetic_investigation(database_path)
    app = _render_app(monkeypatch, database_path)
    app.radio[0].set_value("Incident explorer").run()
    app.date_input[0].set_value(date(2026, 10, 12)).run()
    app.date_input[1].set_value(date(2026, 10, 11)).run()
    assert not app.exception
    assert any("must be on or before" in item.value for item in app.warning)

def test_public_initialization_error_does_not_disclose_traceback_or_source_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setenv("SOC_SENTINEL_MODE", PUBLIC_DEMO)
    configured_database = tmp_path / f"soc-sentinel-public-demo-{os.getpid()}.sqlite3"
    configured_database.write_text("not a SQLite database", encoding="utf-8")
    monkeypatch.setenv("SOC_SENTINEL_DB", str(tmp_path / "not-used.sqlite3"))
    app_path = Path(__file__).parents[1] / "src" / "soc_sentinel" / "dashboard.py"

    app = AppTest.from_file(str(app_path), default_timeout=25).run()

    assert not app.exception
    messages = [item.value for item in app.error] + [item.value for item in app.caption]
    visible_text = "\n".join(messages)
    assert "could not be initialized safely" in visible_text
    assert "Traceback" not in visible_text
    assert "sqlite3" not in visible_text
    assert str(tmp_path) not in visible_text
