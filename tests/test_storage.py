"""SQLite event persistence and migration tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from soc_sentinel.db import initialize_database, insert_events
from soc_sentinel.schemas import SecurityEvent
from tests.test_schemas import authentication_event


def test_phase_one_schema_migrates_to_v2_idempotently(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_metadata (key, value) VALUES ('schema_version', '1')"
        )

    initialize_database(database_path)
    initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        indexes = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
    assert version == ("2",)
    assert {"schema_metadata", "events"} <= tables
    assert {"idx_events_timestamp", "idx_events_type_timestamp", "idx_events_host"} <= indexes


def test_insert_skips_duplicates_and_preserves_scenario_metadata(tmp_path: Path) -> None:
    database_path = tmp_path / "events.sqlite3"
    event = SecurityEvent.model_validate(authentication_event())

    _, inserted_first, duplicates_first = insert_events(database_path, [event])
    _, inserted_second, duplicates_second = insert_events(database_path, [event])

    assert (inserted_first, duplicates_first) == (1, 0)
    assert (inserted_second, duplicates_second) == (0, 1)
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT timestamp_utc, source_id, scenario_json FROM events WHERE event_id = ?",
            (event.event_id,),
        ).fetchone()
    assert row[0] == "2026-10-10T06:30:00Z"
    assert row[1] == "unit-test-fixture"
    assert '"label":"benign"' in row[2]


def test_database_batch_rolls_back_on_unexpected_failure(tmp_path: Path) -> None:
    database_path = tmp_path / "events.sqlite3"
    event = SecurityEvent.model_validate(authentication_event())
    initialize_database(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TRIGGER abort_for_test BEFORE INSERT ON events "
            "WHEN NEW.event_id = 'trigger-failure' "
            "BEGIN SELECT RAISE(ABORT, 'test failure'); END"
        )

    failing_event = SecurityEvent.model_validate(
        authentication_event(event_id="trigger-failure", source_id="test")
    )
    with pytest.raises(sqlite3.IntegrityError, match="test failure"):
        insert_events(database_path, [event, failing_event])

    with sqlite3.connect(database_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 0


def test_future_schema_version_is_rejected(tmp_path: Path) -> None:
    database_path = tmp_path / "future.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_metadata (key, value) VALUES ('schema_version', '99')"
        )
    with pytest.raises(RuntimeError, match="newer than supported"):
        initialize_database(database_path)


def test_failed_migration_rolls_back_schema_and_version(tmp_path: Path) -> None:
    database_path = tmp_path / "broken-migration.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_metadata (key, value) VALUES ('schema_version', '1')"
        )
        connection.execute("CREATE TABLE events (event_id TEXT PRIMARY KEY)")

    with pytest.raises(sqlite3.OperationalError):
        initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
        indexes = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_events_timestamp'"
        ).fetchall()
    assert version == ("1",)
    assert indexes == []
