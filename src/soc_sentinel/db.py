"""SQLite storage, schema migrations, and transactional event persistence."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC
from pathlib import Path
from typing import Any

from soc_sentinel.schemas import SecurityEvent

_SCHEMA_VERSION = 2


def initialize_database(database_path: str | Path) -> Path:
    """Initialize or migrate a local database to the current schema.

    Phase 1 databases at schema version 1 are migrated forward in-place. The migration
    to the current schema runs in one transaction. A newer database version is rejected.
    """
    path = Path(database_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_metadata "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        rows = connection.execute("SELECT value FROM schema_metadata WHERE key = 'schema_version'").fetchall()
        if len(rows) > 1:
            raise RuntimeError("database contains duplicate schema_version metadata")
        version = int(rows[0][0]) if rows else 0
        if version > _SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema version {version} is newer than supported {_SCHEMA_VERSION}"
            )
        if version < 1:
            connection.execute(
                "INSERT INTO schema_metadata (key, value) VALUES ('schema_version', '1') "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            )
            version = 1
        if version < 2:
            _migrate_to_v2(connection)
            connection.execute(
                "UPDATE schema_metadata SET value = '2' WHERE key = 'schema_version'"
            )
    return path


def _migrate_to_v2(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK(event_type IN ('authentication', 'process', 'network')),
            host_id TEXT NOT NULL,
            username TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            action TEXT NOT NULL,
            outcome TEXT NOT NULL,
            process_json TEXT,
            source_id TEXT NOT NULL,
            scenario_json TEXT,
            attributes_json TEXT NOT NULL,
            ingested_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_utc)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON events(event_type, timestamp_utc)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_username ON events(username)")


def insert_events(
    database_path: str | Path, events: Iterable[SecurityEvent]
) -> tuple[Path, int, int]:
    """Atomically insert events, skipping IDs already stored in SQLite.

    Returns (resolved database path, inserted count, duplicate count). Any unexpected
    database error rolls back the entire event insertion transaction.
    """
    path = initialize_database(database_path)
    inserted = 0
    duplicates = 0
    with sqlite3.connect(path) as connection:
        for event in events:
            payload = event.model_dump(mode="python")
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO events (
                    event_id, timestamp_utc, event_type, host_id, username,
                    source_ip, destination_ip, action, outcome, process_json,
                    source_id, scenario_json, attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["event_id"],
                    payload["timestamp"].astimezone(UTC).isoformat().replace("+00:00", "Z"),
                    payload["event_type"].value,
                    payload["host_id"],
                    payload["username"],
                    payload["source_ip"],
                    payload["destination_ip"],
                    payload["action"].value,
                    payload["outcome"].value,
                    _json_or_none(payload["process"]),
                    payload["source_id"],
                    _json_or_none(payload["scenario"]),
                    json.dumps(payload["attributes"], separators=(",", ":"), sort_keys=True),
                ),
            )
            if cursor.rowcount == 1:
                inserted += 1
            else:
                duplicates += 1
    return path, inserted, duplicates


def _json_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return json.dumps(value.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
