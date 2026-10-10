"""Small, idempotent SQLite bootstrap for the local-first application."""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA_VERSION = 1


def initialize_database(database_path: str | Path) -> Path:
    """Create the database and metadata table, returning its resolved path.

    Parent directories are created when needed. The operation is idempotent.
    SQLite is part of the Python standard library, so no external service is needed.
    """
    path = Path(database_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO schema_metadata (key, value)
            VALUES ('schema_version', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (str(_SCHEMA_VERSION),),
        )

    return path
