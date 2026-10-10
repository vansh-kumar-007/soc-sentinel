"""Tests for local SQLite initialization."""

from __future__ import annotations

import sqlite3

from soc_sentinel.db import initialize_database


def test_database_has_schema_version_metadata(tmp_path) -> None:
    database_path = tmp_path / "soc.sqlite3"

    returned_path = initialize_database(database_path)

    assert returned_path == database_path.resolve()
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
    assert row == ("1",)


def test_database_initialization_is_idempotent(tmp_path) -> None:
    database_path = tmp_path / "soc.sqlite3"

    initialize_database(database_path)
    initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        rows = connection.execute("SELECT key, value FROM schema_metadata ORDER BY key").fetchall()
    assert rows == [("schema_version", "1")]
