"""SQLite storage, schema migrations, and transactional event persistence."""
from __future__ import annotations
import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC
from pathlib import Path
from typing import Any
from soc_sentinel.schemas import SecurityEvent

_SCHEMA_VERSION = 3

def initialize_database(database_path: str | Path) -> Path:
    """Initialize or transactionally migrate a local database to the current schema."""
    path = Path(database_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        connection.execute("BEGIN")
        connection.execute("CREATE TABLE IF NOT EXISTS schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        row = connection.execute("SELECT value FROM schema_metadata WHERE key = 'schema_version'").fetchone()
        version = int(row[0]) if row else 0
        if version > _SCHEMA_VERSION:
            raise RuntimeError(f"database schema version {version} is newer than supported {_SCHEMA_VERSION}")
        if version < 1:
            connection.execute("INSERT INTO schema_metadata (key, value) VALUES ('schema_version', '1') ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            version = 1
        if version < 2:
            _migrate_to_v2(connection)
            connection.execute("UPDATE schema_metadata SET value = '2' WHERE key = 'schema_version'")
            version = 2
        if version < 3:
            _migrate_to_v3(connection)
            connection.execute("UPDATE schema_metadata SET value = '3' WHERE key = 'schema_version'")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return path

def _migrate_to_v2(connection: sqlite3.Connection) -> None:
    connection.execute("""CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY, timestamp_utc TEXT NOT NULL,
        event_type TEXT NOT NULL CHECK(event_type IN ('authentication', 'process', 'network')),
        host_id TEXT NOT NULL, username TEXT, source_ip TEXT, destination_ip TEXT,
        action TEXT NOT NULL, outcome TEXT NOT NULL, process_json TEXT, source_id TEXT NOT NULL,
        scenario_json TEXT, attributes_json TEXT NOT NULL,
        ingested_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))""")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_utc)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON events(event_type, timestamp_utc)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_username ON events(username)")

def _migrate_to_v3(connection: sqlite3.Connection) -> None:
    """Create incident tables within the same transaction as the schema version update."""
    connection.execute("""CREATE TABLE alerts (
        alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL,
        severity TEXT NOT NULL CHECK(severity IN ('informational','low','medium','high','critical')),
        first_observed TEXT NOT NULL, last_observed TEXT NOT NULL, payload_json TEXT NOT NULL)""")
    connection.execute("CREATE INDEX idx_alerts_first_observed ON alerts(first_observed)")
    connection.execute("""CREATE TABLE incidents (
        incident_id TEXT PRIMARY KEY, reference TEXT NOT NULL UNIQUE, title TEXT NOT NULL, summary TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('open','in_progress','resolved','closed')),
        severity TEXT NOT NULL CHECK(severity IN ('informational','low','medium','high','critical')),
        first_observed TEXT NOT NULL, last_observed TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        alert_ids_json TEXT NOT NULL, entities_json TEXT NOT NULL, event_count INTEGER NOT NULL CHECK(event_count >= 0),
        alert_count INTEGER NOT NULL CHECK(alert_count >= 1), assigned_analyst TEXT,
        resolution_classification TEXT CHECK(resolution_classification IN
          ('true_positive','benign_positive','false_positive','inconclusive') OR resolution_classification IS NULL),
        resolution_summary TEXT, version INTEGER NOT NULL CHECK(version >= 1))""")
    connection.execute("CREATE INDEX idx_incidents_status_observed ON incidents(status, first_observed)")
    connection.execute("CREATE INDEX idx_incidents_severity ON incidents(severity)")
    connection.execute("""CREATE TABLE incident_alerts (
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE RESTRICT,
        alert_id TEXT NOT NULL UNIQUE REFERENCES alerts(alert_id) ON DELETE RESTRICT,
        linked_at TEXT NOT NULL, PRIMARY KEY (incident_id, alert_id))""")
    connection.execute("CREATE INDEX idx_incident_alerts_incident ON incident_alerts(incident_id)")
    connection.execute("""CREATE TABLE correlation_explanations (
        explanation_id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE RESTRICT,
        alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE RESTRICT,
        related_alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE RESTRICT,
        strategy TEXT NOT NULL, shared_values_json TEXT NOT NULL,
        time_gap_seconds REAL NOT NULL CHECK(time_gap_seconds >= 0), explanation TEXT NOT NULL,
        created_at TEXT NOT NULL, UNIQUE (incident_id, alert_id, related_alert_id, strategy))""")
    connection.execute("""CREATE TABLE incident_audit (
        audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE RESTRICT,
        action TEXT NOT NULL, actor TEXT NOT NULL, details_json TEXT NOT NULL, occurred_at TEXT NOT NULL)""")
    connection.execute("CREATE INDEX idx_incident_audit_timeline ON incident_audit(incident_id, occurred_at, audit_id)")
    connection.execute("""CREATE TABLE incident_notes (
        note_id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE RESTRICT,
        actor TEXT NOT NULL, note TEXT NOT NULL CHECK(length(trim(note)) > 0), created_at TEXT NOT NULL)""")
    connection.execute("CREATE INDEX idx_incident_notes_timeline ON incident_notes(incident_id, created_at, note_id)")

def insert_events(database_path: str | Path, events: Iterable[SecurityEvent]) -> tuple[Path, int, int]:
    """Atomically insert events, skipping IDs already stored in SQLite."""
    path = initialize_database(database_path)
    inserted = 0
    duplicates = 0
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        connection.execute("BEGIN")
        for event in events:
            cursor = connection.execute("""INSERT OR IGNORE INTO events (
                event_id, timestamp_utc, event_type, host_id, username, source_ip, destination_ip,
                action, outcome, process_json, source_id, scenario_json, attributes_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event.event_id, event.timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                 event.event_type.value, event.host_id, event.username, event.source_ip, event.destination_ip,
                 event.action.value, event.outcome.value, _json_or_none(event.process), event.source_id,
                 _json_or_none(event.scenario), json.dumps(event.attributes, separators=(",", ":"), sort_keys=True)))
            if cursor.rowcount == 1: inserted += 1
            else: duplicates += 1
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return path, inserted, duplicates

def _json_or_none(value: Any) -> str | None:
    if value is None: return None
    if hasattr(value, "model_dump"):
        return json.dumps(value.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
