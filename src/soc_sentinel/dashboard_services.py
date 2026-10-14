"""Framework-independent services used by the local SOC dashboard."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

from soc_sentinel.correlation import load_correlation_policy
from soc_sentinel.db import insert_events
from soc_sentinel.detection.engine import evaluate_events
from soc_sentinel.detection.rules import Severity, load_rules
from soc_sentinel.incidents import (
    Incident,
    IncidentError,
    IncidentStatus,
    ResolutionClassification,
    add_note,
    assign_analyst,
    correlate_and_persist,
    get_incident,
    list_incidents,
    show_incident,
    update_status,
)
from soc_sentinel.ingestion.jsonl import parse_jsonl_file
from soc_sentinel.operating_mode import (
    PUBLIC_DEMO,
    operating_mode,
    require_analyst_mode,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = {"soc_demo": "soc-demo.jsonl", "authentication": "authentication.jsonl"}
RULE_PROFILES: dict[str, tuple[str, ...] | None] = {
    "all": None,
    "authentication": ("DET-001", "DET-002"),
    "process": ("DET-003",),
}


class DashboardServiceError(RuntimeError):
    """Actionable dashboard data/workflow error."""


def _database_file(database_path: str | Path) -> Path:
    path = Path(database_path).expanduser().resolve()
    if not path.is_file():
        raise DashboardServiceError(
            f"SQLite database not found: {path}. Run soc-sentinel demo-seed or "
            "initialize an existing database with soc-sentinel check-db."
        )
    return path


def _read_connection(database_path: str | Path) -> sqlite3.Connection:
    path = _database_file(database_path)
    try:
        connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return connection
    except sqlite3.Error as exc:
        raise DashboardServiceError(f"Cannot open SQLite database read-only: {exc}") from exc


def _validate_date_range(
    observed_from: date | None, observed_to: date | None, *, field: str
) -> None:
    """Reject inverted date bounds before filtering persisted records."""
    if observed_from is not None and observed_to is not None and observed_from > observed_to:
        raise DashboardServiceError(f"{field} start date must be on or before its end date.")


def _as_dict(incident: Incident) -> dict[str, Any]:
    return incident.model_dump(mode="json")


def get_dashboard_summary(database_path: str | Path) -> dict[str, Any]:
    """Return metrics calculated from persisted rows, never demo constants."""
    connection = _read_connection(database_path)
    try:
        statuses = {
            row["status"]: row["count"]
            for row in connection.execute(
                "SELECT status, COUNT(*) AS count FROM incidents GROUP BY status"
            )
        }
        severities = {
            row["severity"]: row["count"]
            for row in connection.execute(
                "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
            )
        }
        rule_counts = {
            row["rule_id"]: row["count"]
            for row in connection.execute(
                "SELECT rule_id, COUNT(*) AS count FROM alerts GROUP BY rule_id"
            )
        }
        activity = [
            {"date": row["day"], "incidents": row["count"]}
            for row in reversed(
                connection.execute(
                    """SELECT substr(created_at,1,10) AS day, COUNT(*) AS count FROM incidents
                GROUP BY substr(created_at,1,10) ORDER BY day DESC LIMIT 30"""
                ).fetchall()
            )
        ]
    except sqlite3.Error as exc:
        raise DashboardServiceError(
            f"Database is unavailable or is not a SOC Sentinel schema-v3 database: {exc}"
        ) from exc
    finally:
        connection.close()
    incidents = list_incidents(database_path, read_only=True)
    hosts: Counter[str] = Counter()
    users: Counter[str] = Counter()
    for incident in incidents:
        hosts.update(incident.entities.get("host_id", []))
        users.update(incident.entities.get("username", []))
    recent = sorted(incidents, key=lambda item: (item.updated_at, item.incident_id), reverse=True)[
        :8
    ]
    severity_rows = [
        {"severity": key, "count": severities.get(key, 0)}
        for key in ("critical", "high", "medium", "low", "informational")
    ]
    return {
        "total_incidents": len(incidents),
        "open_incidents": statuses.get("open", 0),
        "in_progress_incidents": statuses.get("in_progress", 0),
        "resolved_incidents": statuses.get("resolved", 0),
        "closed_incidents": statuses.get("closed", 0),
        "total_alerts": sum(severities.values()),
        "alerts_by_severity": severity_rows,
        "alerts_by_rule": [
            {"rule_id": rule_id, "count": count} for rule_id, count in sorted(rule_counts.items())
        ],
        "recent_incidents": [_as_dict(item) for item in recent],
        "activity": activity,
        "top_hosts": [{"entity": key, "incidents": value} for key, value in hosts.most_common(8)],
        "top_users": [{"entity": key, "incidents": value} for key, value in users.most_common(8)],
        "definitions": {
            "total_incidents": "Persisted incident records, including closed cases.",
            "open_incidents": "Incidents whose current lifecycle status is open.",
            "in_progress_incidents": "Incidents currently being investigated.",
            "resolved_incidents": "Incidents with an analyst-recorded resolution classification.",
            "closed_incidents": "Resolved incidents moved to the terminal closed state.",
            "total_alerts": "Unique persisted alert records, independent of incident count.",
            "activity": "Incidents grouped by application creation date in UTC.",
            "alerts_by_rule": "Persisted alert counts grouped by the rule ID in each alert payload.",
            "top_hosts": "Number of incident records that list each host entity.",
            "top_users": "Number of incident records that list each username entity.",
        },
    }


def list_dashboard_incidents(
    database_path: str | Path,
    *,
    query: str = "",
    statuses: set[str] | None = None,
    severities: set[str] | None = None,
    assigned_analyst: str = "",
    host: str = "",
    username: str = "",
    observed_from: date | None = None,
    observed_to: date | None = None,
    sort_by: str = "last_observed",
    descending: bool = True,
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    """Search/filter incidents and return a deterministic page."""
    sort_fields = {
        "reference",
        "status",
        "severity",
        "first_observed",
        "last_observed",
        "updated_at",
        "alert_count",
        "event_count",
    }
    if sort_by not in sort_fields:
        raise DashboardServiceError(f"Unsupported incident sort field: {sort_by}")
    _validate_date_range(observed_from, observed_to, field="Observed")
    invalid_statuses = (statuses or set()) - {item.value for item in IncidentStatus}
    if invalid_statuses:
        raise DashboardServiceError("Unsupported incident status filter.")
    invalid_severities = (severities or set()) - {item.value for item in Severity}
    if invalid_severities:
        raise DashboardServiceError("Unsupported incident severity filter.")
    if page < 1 or page_size < 1 or page_size > 200:
        raise DashboardServiceError(
            "Page must be positive and page_size must be between 1 and 200."
        )
    incidents = list_incidents(database_path, read_only=True)
    q, analyst_q, host_q, user_q = (
        query.strip().casefold(),
        assigned_analyst.strip().casefold(),
        host.strip().casefold(),
        username.strip().casefold(),
    )
    filtered: list[Incident] = []
    for item in incidents:
        text = " ".join((item.incident_id, item.reference, item.title, item.summary)).casefold()
        if q and q not in text:
            continue
        if statuses and item.status.value not in statuses:
            continue
        if severities and item.severity.value not in severities:
            continue
        if analyst_q and analyst_q not in (item.assigned_analyst or "").casefold():
            continue
        if host_q and not any(
            host_q in value.casefold() for value in item.entities.get("host_id", [])
        ):
            continue
        if user_q and not any(
            user_q in value.casefold() for value in item.entities.get("username", [])
        ):
            continue
        if observed_from and item.first_observed.date() < observed_from:
            continue
        if observed_to and item.last_observed.date() > observed_to:
            continue
        filtered.append(item)
    filtered.sort(key=lambda item: (getattr(item, sort_by), item.incident_id), reverse=descending)
    total = len(filtered)
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, pages)
    start = (page - 1) * page_size
    return {
        "items": [_as_dict(item) for item in filtered[start : start + page_size]],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


def get_incident_details(database_path: str | Path, incident_id: str) -> dict[str, Any]:
    """Return persisted incident, alerts, explanations, timeline and available event fields."""
    details = show_incident(database_path, incident_id, read_only=True)
    ids = sorted({eid for alert in details["alerts"] for eid in alert["evidence_event_ids"]})
    events: dict[str, dict[str, Any]] = {}
    connection = _read_connection(database_path)
    try:
        for offset in range(0, len(ids), 400):
            batch = ids[offset : offset + 400]
            if not batch:
                continue
            marks = ",".join("?" for _ in batch)
            rows = connection.execute(
                f"""SELECT event_id,timestamp_utc,event_type,host_id,username,source_ip,
                destination_ip,action,outcome,process_json,source_id,attributes_json
                FROM events WHERE event_id IN ({marks})""",
                batch,
            ).fetchall()
            for row in rows:
                events[row["event_id"]] = {
                    "event_id": row["event_id"],
                    "timestamp": row["timestamp_utc"],
                    "event_type": row["event_type"],
                    "host_id": row["host_id"],
                    "username": row["username"],
                    "source_ip": row["source_ip"],
                    "destination_ip": row["destination_ip"],
                    "action": row["action"],
                    "outcome": row["outcome"],
                    "process": json.loads(row["process_json"]) if row["process_json"] else None,
                    "source_id": row["source_id"],
                    "attributes": json.loads(row["attributes_json"]),
                    "source_available": True,
                    "provenance": "source_telemetry",
                }
    except sqlite3.Error as exc:
        raise DashboardServiceError(f"Cannot retrieve source evidence: {exc}") from exc
    finally:
        connection.close()
    details["evidence_events"] = events
    details["missing_event_ids"] = [event_id for event_id in ids if event_id not in events]
    return details


def list_dashboard_alerts(
    database_path: str | Path,
    *,
    query: str = "",
    severities: set[str] | None = None,
    rule_ids: set[str] | None = None,
    host: str = "",
    username: str = "",
    incident_association: str = "all",
    observed_from: date | None = None,
    observed_to: date | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Filter persisted alert payloads without breaking incident/evidence relationships."""
    _validate_date_range(observed_from, observed_to, field="Observed")
    valid_severities = {"informational", "low", "medium", "high", "critical"}
    if severities and severities - valid_severities:
        raise DashboardServiceError("Unsupported alert severity filter.")
    if limit < 1:
        raise DashboardServiceError("Alert limit must be positive.")
    connection = _read_connection(database_path)
    try:
        rows = connection.execute(
            """SELECT a.payload_json,ia.incident_id,i.reference AS incident_reference
            FROM alerts a LEFT JOIN incident_alerts ia USING(alert_id)
            LEFT JOIN incidents i USING(incident_id)
            ORDER BY a.first_observed DESC,a.alert_id DESC LIMIT ?""",
            (min(max(limit, 1), 1000),),
        ).fetchall()
    except sqlite3.Error as exc:
        raise DashboardServiceError(f"Cannot list persisted alerts: {exc}") from exc
    finally:
        connection.close()
    if incident_association not in {"all", "linked", "unassigned"}:
        raise DashboardServiceError("Incident association must be all, linked, or unassigned.")
    needle = query.strip().casefold()
    host_query = host.strip().casefold()
    username_query = username.strip().casefold()
    result: list[dict[str, Any]] = []
    for row in rows:
        alert = json.loads(row["payload_json"])
        if severities and alert["severity"] not in severities:
            continue
        if rule_ids and alert["rule_id"] not in rule_ids:
            continue
        linked = row["incident_id"] is not None
        if incident_association == "linked" and not linked:
            continue
        if incident_association == "unassigned" and linked:
            continue
        first_day = str(alert["first_observed"])[:10]
        last_day = str(alert["last_observed"])[:10]
        if observed_from and last_day < observed_from.isoformat():
            continue
        if observed_to and first_day > observed_to.isoformat():
            continue
        entity_text = json.dumps(alert["grouping_context"], sort_keys=True).casefold()
        if host_query and host_query not in entity_text:
            continue
        if username_query and username_query not in entity_text:
            continue
        alert["incident_id"] = row["incident_id"]
        alert["incident_reference"] = row["incident_reference"]
        searchable = " ".join(
            (
                alert["alert_id"],
                alert["rule_id"],
                alert["rule_title"],
                alert["rationale"],
                alert["first_observed"],
                alert["last_observed"],
                entity_text,
            )
        ).casefold()
        if not needle or needle in searchable:
            result.append(alert)
    return result


def change_incident_status(
    database_path: str | Path,
    incident_id: str,
    status: str,
    expected_version: int,
    *,
    actor: str = "analyst",
) -> Incident:
    require_analyst_mode()
    try:
        target = IncidentStatus(status)
    except ValueError as exc:
        raise IncidentError(f"invalid incident status: {status}") from exc
    return update_status(database_path, incident_id, target, expected_version, actor=actor)


def assign_incident_to_analyst(
    database_path: str | Path,
    incident_id: str,
    analyst: str | None,
    expected_version: int,
    *,
    actor: str = "analyst",
) -> Incident:
    require_analyst_mode()
    return assign_analyst(database_path, incident_id, analyst, expected_version, actor=actor)


def add_investigation_note(
    database_path: str | Path,
    incident_id: str,
    note: str,
    *,
    expected_version: int,
    actor: str = "analyst",
) -> dict[str, Any]:
    require_analyst_mode()
    return add_note(
        database_path, incident_id, note, actor=actor, expected_version=expected_version
    )


def resolve_incident(
    database_path: str | Path,
    incident_id: str,
    classification: str,
    summary: str,
    expected_version: int,
    *,
    actor: str = "analyst",
) -> Incident:
    require_analyst_mode()
    try:
        resolution = ResolutionClassification(classification)
    except ValueError as exc:
        raise IncidentError(f"invalid resolution classification: {classification}") from exc
    return update_status(
        database_path,
        incident_id,
        IncidentStatus.RESOLVED,
        expected_version,
        actor=actor,
        classification=resolution,
        summary=summary,
    )


def reopen_incident(
    database_path: str | Path,
    incident_id: str,
    expected_version: int,
    *,
    actor: str = "analyst",
) -> Incident:
    require_analyst_mode()
    current = get_incident(database_path, incident_id, read_only=True)
    if current.status != IncidentStatus.RESOLVED:
        raise IncidentError("only a resolved incident can be reopened")
    return update_status(
        database_path, incident_id, IncidentStatus.OPEN, expected_version, actor=actor
    )


def _run_synthetic_investigation(
    database_path: str | Path,
    *,
    fixture_key: str = "soc_demo",
    rule_profile: str = "all",
    actor: str = "synthetic-demo",
) -> dict[str, Any]:
    """Run only bundled fixtures, rule files, and the checked-in correlation policy."""
    if fixture_key not in FIXTURES:
        raise DashboardServiceError("Choose a bundled synthetic fixture.")
    if rule_profile not in RULE_PROFILES:
        raise DashboardServiceError("Choose a supported shipped detection profile.")
    fixture = PROJECT_ROOT / "data" / "samples" / FIXTURES[fixture_key]
    rules = load_rules(PROJECT_ROOT / "rules")
    allowed = RULE_PROFILES[rule_profile]
    if allowed is not None:
        rules = [rule for rule in rules if rule.rule_id in allowed]
    policy = load_correlation_policy(PROJECT_ROOT / "correlation.yaml")
    batch = parse_jsonl_file(fixture, strict=False)
    path, inserted, duplicates = insert_events(database_path, batch.events)
    alerts = evaluate_events(batch.events, rules)
    incidents = correlate_and_persist(path, alerts, batch.events, policy, actor=actor)
    return {
        "database": str(path),
        "fixture": fixture.name,
        "rule_profile": rule_profile,
        "records_read": batch.records_read,
        "events_inserted": inserted,
        "event_duplicates": duplicates,
        "records_rejected": batch.records_rejected,
        "alerts_generated": len(alerts),
        "alerts": [alert.model_dump(mode="json") for alert in alerts],
        "incidents": [_as_dict(item) for item in incidents],
        "issues": [
            {"line_number": item.line_number, "message": item.message} for item in batch.issues
        ],
    }


def run_synthetic_investigation(
    database_path: str | Path,
    *,
    fixture_key: str = "soc_demo",
    rule_profile: str = "all",
    actor: str = "synthetic-demo",
) -> dict[str, Any]:
    """Run the bundled pipeline only in local analyst mode."""
    require_analyst_mode()
    return _run_synthetic_investigation(
        database_path, fixture_key=fixture_key, rule_profile=rule_profile, actor=actor
    )


def ensure_public_demo_database(database_path: str | Path) -> dict[str, Any]:
    """Create a synthetic-only public demo database once; never reset or overwrite it."""
    mode = operating_mode()
    if mode != PUBLIC_DEMO:
        raise DashboardServiceError("Public demo initialization requires public-demo mode.")
    path = Path(database_path).expanduser().resolve()
    if path.exists():
        try:
            connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=3)
            try:
                row = connection.execute(
                    "SELECT value FROM schema_metadata WHERE key='schema_version'"
                ).fetchone()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise DashboardServiceError(
                "The public demo database is unavailable; it was not reset."
            ) from exc
        if row is None or row[0] != "3":
            raise DashboardServiceError(
                "The existing public demo database has an unsupported schema; it was not reset."
            )
        return {"initialized": False, "database": str(path)}
    result = _run_synthetic_investigation(
        path, fixture_key="soc_demo", rule_profile="all", actor="public-demo-bootstrap"
    )
    return {"initialized": True, "database": str(path), "result": result}


def run_public_synthetic_preview(
    *,
    fixture_key: str = "soc_demo",
    rule_profile: str = "all",
) -> dict[str, Any]:
    """Run an allow-listed synthetic pipeline in an isolated temporary database."""
    if operating_mode() != PUBLIC_DEMO:
        raise DashboardServiceError("Synthetic preview is available only in public-demo mode.")
    with tempfile.TemporaryDirectory(prefix="soc-sentinel-public-preview-") as temporary_directory:
        result = _run_synthetic_investigation(
            Path(temporary_directory) / "preview.sqlite3",
            fixture_key=fixture_key,
            rule_profile=rule_profile,
            actor="public-demo-preview",
        )
        # Never expose the temporary path; the database is deleted before this returns.
        result["database"] = "ephemeral-public-preview (discarded after execution)"
        return result
