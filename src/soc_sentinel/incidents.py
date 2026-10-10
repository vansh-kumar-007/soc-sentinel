"""Persistent local incident workflow, correlation, lifecycle, and timeline."""

from __future__ import annotations
import hashlib
import json
import sqlite3
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator
from soc_sentinel.correlation import CorrelationPolicy, alert_entities, correlate_pair
from soc_sentinel.db import initialize_database
from soc_sentinel.detection.engine import Alert
from soc_sentinel.detection.rules import Severity
from soc_sentinel.schemas import SecurityEvent


class IncidentStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class ResolutionClassification(StrEnum):
    TRUE_POSITIVE = "true_positive"
    BENIGN_POSITIVE = "benign_positive"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"


class IncidentError(ValueError):
    """Invalid incident operation, transition, or stale update."""


class Incident(BaseModel):
    """Typed incident snapshot; status is workflow state, not a threat verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    incident_id: str
    reference: str
    title: str
    summary: str
    status: IncidentStatus = IncidentStatus.OPEN
    severity: Severity
    first_observed: datetime
    last_observed: datetime
    created_at: datetime
    updated_at: datetime
    alert_ids: list[str]
    entities: dict[str, list[str]]
    event_count: int = Field(ge=0)
    alert_count: int = Field(ge=1)
    assigned_analyst: str | None = None
    resolution_classification: ResolutionClassification | None = None
    resolution_summary: str | None = None
    version: int = Field(ge=1)

    @field_validator("first_observed", "last_observed", "created_at", "updated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("incident timestamps must include a timezone")
        return value.astimezone(UTC)


def _now() -> datetime:
    return datetime.now(UTC)


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _connect(path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(initialize_database(path), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _load_incident(row: sqlite3.Row) -> Incident:
    return Incident.model_validate(
        {
            "incident_id": row["incident_id"],
            "reference": row["reference"],
            "title": row["title"],
            "summary": row["summary"],
            "status": row["status"],
            "severity": row["severity"],
            "first_observed": row["first_observed"],
            "last_observed": row["last_observed"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "alert_ids": json.loads(row["alert_ids_json"]),
            "entities": json.loads(row["entities_json"]),
            "event_count": row["event_count"],
            "alert_count": row["alert_count"],
            "assigned_analyst": row["assigned_analyst"],
            "resolution_classification": row["resolution_classification"],
            "resolution_summary": row["resolution_summary"],
            "version": row["version"],
        }
    )


def _audit(
    connection: sqlite3.Connection,
    incident_id: str,
    action: str,
    actor: str,
    details: dict[str, Any],
    occurred_at: str,
) -> None:
    connection.execute(
        "INSERT INTO incident_audit (incident_id, action, actor, details_json, occurred_at) VALUES (?, ?, ?, ?, ?)",
        (incident_id, action, actor, json.dumps(details, sort_keys=True), occurred_at),
    )


def _severity(alerts: Iterable[Alert]) -> Severity:
    order = {
        Severity.INFORMATIONAL: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return max((alert.severity for alert in alerts), key=lambda item: order[item])


def _incident_identity(alert_ids: list[str]) -> tuple[str, str]:
    digest = hashlib.sha256("\n".join(sorted(alert_ids)).encode()).hexdigest()[:16]
    return f"inc_{digest}", f"INC-{digest[:8].upper()}"


def _build_incident(
    alert_ids: list[str],
    alerts: Mapping[str, Alert],
    entities_by_alert: Mapping[str, dict[str, set[str]]],
    now: datetime,
) -> Incident:
    linked = sorted(
        (alerts[item] for item in alert_ids), key=lambda a: (a.first_observed, a.alert_id)
    )
    incident_id, reference = _incident_identity([item.alert_id for item in linked])
    all_entities: dict[str, set[str]] = {}
    for alert in linked:
        for key, values in entities_by_alert.get(alert.alert_id, {}).items():
            all_entities.setdefault(key, set()).update(values)
    entities = {key: sorted(values) for key, values in sorted(all_entities.items()) if values}
    rules = sorted({item.rule_id for item in linked})
    title = (
        linked[0].rule_title
        if len(linked) == 1
        else f"Correlated security activity ({len(linked)} alerts)"
    )
    summary = f"{len(linked)} evidence-linked alert(s) from rule(s) {', '.join(rules)}. Correlation is an investigation lead, not proof of malicious intent."
    return Incident(
        incident_id=incident_id,
        reference=reference,
        title=title,
        summary=summary,
        severity=_severity(linked),
        first_observed=min(a.first_observed for a in linked),
        last_observed=max(a.last_observed for a in linked),
        created_at=now,
        updated_at=now,
        alert_ids=[a.alert_id for a in linked],
        entities=entities,
        event_count=len({event for item in linked for event in item.evidence_event_ids}),
        alert_count=len(linked),
        version=1,
    )


def correlate_and_persist(
    database_path: str | Path,
    alerts: list[Alert],
    events: list[SecurityEvent],
    policy: CorrelationPolicy,
    *,
    actor: str = "system",
) -> list[Incident]:
    """Persist alerts and create/extend incidents atomically and idempotently."""
    path = initialize_database(database_path)
    incoming = {alert.alert_id: alert for alert in alerts}
    now = _stamp(_now())
    connection = _connect(path)
    touched: set[str] = set()
    try:
        connection.execute("BEGIN IMMEDIATE")
        for alert in sorted(incoming.values(), key=lambda item: item.alert_id):
            connection.execute(
                """INSERT OR IGNORE INTO alerts
                (alert_id, rule_id, severity, first_observed, last_observed, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    alert.alert_id,
                    alert.rule_id,
                    alert.severity.value,
                    _stamp(alert.first_observed),
                    _stamp(alert.last_observed),
                    json.dumps(alert.model_dump(mode="json"), sort_keys=True),
                ),
            )
        rows = connection.execute(
            "SELECT alert_id, payload_json FROM alerts ORDER BY alert_id"
        ).fetchall()
        all_alerts = {
            row["alert_id"]: Alert.model_validate_json(row["payload_json"]) for row in rows
        }
        all_alerts.update(incoming)
        evidence_ids = sorted(
            {eid for alert in all_alerts.values() for eid in alert.evidence_event_ids}
        )
        stored_events: dict[str, SecurityEvent] = {event.event_id: event for event in events}
        for start in range(0, len(evidence_ids), 500):
            batch = evidence_ids[start : start + 500]
            if not batch:
                continue
            rows = connection.execute(
                f"SELECT * FROM events WHERE event_id IN ({','.join('?' for _ in batch)})", batch
            ).fetchall()
            for row in rows:
                stored_events.setdefault(
                    row["event_id"],
                    SecurityEvent.model_validate(
                        {
                            "event_id": row["event_id"],
                            "timestamp": row["timestamp_utc"],
                            "event_type": row["event_type"],
                            "host_id": row["host_id"],
                            "username": row["username"],
                            "source_ip": row["source_ip"],
                            "destination_ip": row["destination_ip"],
                            "action": row["action"],
                            "outcome": row["outcome"],
                            "process": json.loads(row["process_json"])
                            if row["process_json"]
                            else None,
                            "source_id": row["source_id"],
                            "scenario": json.loads(row["scenario_json"])
                            if row["scenario_json"]
                            else None,
                            "attributes": json.loads(row["attributes_json"]),
                        }
                    ),
                )
        entities = {key: alert_entities(alert, stored_events) for key, alert in all_alerts.items()}
        rows = connection.execute(
            "SELECT ia.alert_id, ia.incident_id, i.status FROM incident_alerts ia JOIN incidents i USING(incident_id)"
        ).fetchall()
        assignment = {row["alert_id"]: row["incident_id"] for row in rows}
        statuses = {row["incident_id"]: row["status"] for row in rows}
        active_ids = {incident_id for incident_id, status in statuses.items() if status != "closed"}
        # Existing incidents are never merged; a new alert chooses one deterministic best match.
        for alert in sorted(
            incoming.values(), key=lambda item: (item.first_observed, item.alert_id)
        ):
            if alert.alert_id in assignment:
                continue
            candidates: list[tuple[int, str, str, Any]] = []
            for related_id in sorted(all_alerts):
                incident_id = assignment.get(related_id)
                if not incident_id or incident_id not in active_ids or related_id == alert.alert_id:
                    continue
                decision = correlate_pair(
                    alert,
                    all_alerts[related_id],
                    entities[alert.alert_id],
                    entities[related_id],
                    policy,
                )
                if decision:
                    candidates.append(
                        (
                            policy.strategies.index(decision.strategy),
                            incident_id,
                            related_id,
                            decision,
                        )
                    )
            if candidates:
                _, incident_id, _, decision = sorted(
                    candidates, key=lambda item: (item[0], item[1], item[2])
                )[0]
                connection.execute(
                    "INSERT INTO incident_alerts (incident_id, alert_id, linked_at) VALUES (?, ?, ?)",
                    (incident_id, alert.alert_id, now),
                )
                connection.execute(
                    """INSERT OR IGNORE INTO correlation_explanations
                    (incident_id, alert_id, related_alert_id, strategy, shared_values_json, time_gap_seconds, explanation, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        incident_id,
                        alert.alert_id,
                        decision.related_alert_id,
                        decision.strategy,
                        json.dumps(decision.shared_values, sort_keys=True),
                        decision.time_gap_seconds,
                        decision.explanation,
                        now,
                    ),
                )
                if statuses.get(incident_id) == "resolved":
                    connection.execute(
                        "UPDATE incidents SET status='open', resolution_classification=NULL, resolution_summary=NULL WHERE incident_id=?",
                        (incident_id,),
                    )
                    _audit(
                        connection,
                        incident_id,
                        "reopened_by_new_evidence",
                        actor,
                        {
                            "new_alert_id": alert.alert_id,
                            "previous_resolution_classification": "retained in earlier audit record",
                            "reason": decision.explanation,
                        },
                        now,
                    )
                    statuses[incident_id] = "open"
                _audit(
                    connection,
                    incident_id,
                    "alert_correlated",
                    actor,
                    {
                        "alert_id": alert.alert_id,
                        "related_alert_id": decision.related_alert_id,
                        "strategy": decision.strategy,
                        "shared_values": decision.shared_values,
                        "explanation": decision.explanation,
                    },
                    now,
                )
                assignment[alert.alert_id] = incident_id
                touched.add(incident_id)
            else:
                group = {alert.alert_id}
                edges: list[tuple[str, str, Any]] = []
                frontier = [alert.alert_id]
                while frontier:
                    source_id = frontier.pop(0)
                    if not policy.allow_transitive and source_id != alert.alert_id:
                        continue
                    for candidate in sorted(
                        incoming.values(), key=lambda item: (item.first_observed, item.alert_id)
                    ):
                        cid = candidate.alert_id
                        if cid in group or cid in assignment:
                            continue
                        decision = correlate_pair(
                            all_alerts[source_id],
                            candidate,
                            entities[source_id],
                            entities[cid],
                            policy,
                        )
                        if decision:
                            group.add(cid)
                            frontier.append(cid)
                            edges.append((cid, source_id, decision))
                incident = _build_incident(sorted(group), all_alerts, entities, _parse_stamp(now))
                connection.execute(
                    """INSERT OR IGNORE INTO incidents
                    (incident_id, reference, title, summary, status, severity, first_observed, last_observed,
                     created_at, updated_at, alert_ids_json, entities_json, event_count, alert_count,
                     assigned_analyst, resolution_classification, resolution_summary, version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)""",
                    (
                        incident.incident_id,
                        incident.reference,
                        incident.title,
                        incident.summary,
                        incident.status.value,
                        incident.severity.value,
                        _stamp(incident.first_observed),
                        _stamp(incident.last_observed),
                        now,
                        now,
                        json.dumps(incident.alert_ids),
                        json.dumps(incident.entities, sort_keys=True),
                        incident.event_count,
                        incident.alert_count,
                        incident.version,
                    ),
                )
                for linked_id in sorted(group):
                    connection.execute(
                        "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, linked_at) VALUES (?, ?, ?)",
                        (incident.incident_id, linked_id, now),
                    )
                    assignment[linked_id] = incident.incident_id
                for linked_id, related_id, decision in edges:
                    connection.execute(
                        """INSERT OR IGNORE INTO correlation_explanations
                        (incident_id, alert_id, related_alert_id, strategy, shared_values_json, time_gap_seconds, explanation, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            incident.incident_id,
                            linked_id,
                            related_id,
                            decision.strategy,
                            json.dumps(decision.shared_values, sort_keys=True),
                            decision.time_gap_seconds,
                            decision.explanation,
                            now,
                        ),
                    )
                _audit(
                    connection,
                    incident.incident_id,
                    "incident_created",
                    actor,
                    {
                        "alert_ids": sorted(group),
                        "policy_id": policy.policy_id,
                        "transitive": policy.allow_transitive,
                        "correlation_edges": len(edges),
                    },
                    now,
                )
                active_ids.add(incident.incident_id)
                statuses[incident.incident_id] = "open"
                touched.add(incident.incident_id)
        for incident_id in sorted(touched):
            rows = connection.execute(
                """SELECT a.payload_json FROM incident_alerts ia JOIN alerts a USING(alert_id)
                WHERE ia.incident_id=? ORDER BY a.alert_id""",
                (incident_id,),
            ).fetchall()
            linked = [Alert.model_validate_json(row["payload_json"]) for row in rows]
            entity_map = {item.alert_id: entities.get(item.alert_id, {}) for item in linked}
            updated = _build_incident(
                [item.alert_id for item in linked], all_alerts, entity_map, _parse_stamp(now)
            )
            current = connection.execute(
                "SELECT version FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
            connection.execute(
                """UPDATE incidents SET title=?, summary=?, severity=?, first_observed=?, last_observed=?,
                updated_at=?, alert_ids_json=?, entities_json=?, event_count=?, alert_count=?, version=?
                WHERE incident_id=?""",
                (
                    updated.title,
                    updated.summary,
                    updated.severity.value,
                    _stamp(updated.first_observed),
                    _stamp(updated.last_observed),
                    now,
                    json.dumps(updated.alert_ids),
                    json.dumps(updated.entities, sort_keys=True),
                    updated.event_count,
                    updated.alert_count,
                    current["version"] + 1,
                    incident_id,
                ),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return list_incidents(path)


def list_incidents(database_path: str | Path, *, status: str | None = None) -> list[Incident]:
    connection = _connect(database_path)
    try:
        if status is None:
            rows = connection.execute(
                "SELECT * FROM incidents ORDER BY first_observed, incident_id"
            ).fetchall()
        else:
            try:
                valid = IncidentStatus(status).value
            except ValueError as exc:
                raise IncidentError(f"invalid incident status: {status}") from exc
            rows = connection.execute(
                "SELECT * FROM incidents WHERE status=? ORDER BY first_observed, incident_id",
                (valid,),
            ).fetchall()
        return [_load_incident(row) for row in rows]
    finally:
        connection.close()


def get_incident(database_path: str | Path, incident_id: str) -> Incident:
    connection = _connect(database_path)
    try:
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id=? OR reference=?", (incident_id, incident_id)
        ).fetchone()
        if row is None:
            raise IncidentError(f"incident not found: {incident_id}")
        return _load_incident(row)
    finally:
        connection.close()


def _change(
    database_path: str | Path,
    incident_id: str,
    expected_version: int,
    actor: str,
    action: str,
    updates: dict[str, Any],
) -> Incident:
    connection = _connect(database_path)
    now = _stamp(_now())
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id=? OR reference=?", (incident_id, incident_id)
        ).fetchone()
        if row is None:
            raise IncidentError(f"incident not found: {incident_id}")
        current = _load_incident(row)
        if current.version != expected_version:
            raise IncidentError(
                f"stale incident version: expected {expected_version}, current version is {current.version}; reload before retrying"
            )
        values = current.model_dump(mode="json")
        values.update(updates)
        values["updated_at"] = now
        values["version"] = current.version + 1
        updated = Incident.model_validate(values)
        allowed = {
            "open": {"open", "in_progress", "resolved"},
            "in_progress": {"in_progress", "open", "resolved"},
            "resolved": {"resolved", "open", "closed"},
            "closed": {"closed"},
        }
        if updated.status.value not in allowed[current.status.value]:
            raise IncidentError(
                f"invalid status transition: {current.status.value} -> {updated.status.value}"
            )
        if updated.status == IncidentStatus.RESOLVED and (
            not updated.resolution_classification
            or not updated.resolution_summary
            or not updated.resolution_summary.strip()
        ):
            raise IncidentError("resolution requires a classification and non-empty summary")
        if current.status == IncidentStatus.RESOLVED and updated.status == IncidentStatus.OPEN:
            values["resolution_classification"] = None
            values["resolution_summary"] = None
            updated = Incident.model_validate(values)
        cursor = connection.execute(
            """UPDATE incidents SET title=?, summary=?, status=?, severity=?, first_observed=?,
            last_observed=?, updated_at=?, alert_ids_json=?, entities_json=?, event_count=?, alert_count=?,
            assigned_analyst=?, resolution_classification=?, resolution_summary=?, version=?
            WHERE incident_id=? AND version=?""",
            (
                updated.title,
                updated.summary,
                updated.status.value,
                updated.severity.value,
                _stamp(updated.first_observed),
                _stamp(updated.last_observed),
                now,
                json.dumps(updated.alert_ids),
                json.dumps(updated.entities, sort_keys=True),
                updated.event_count,
                updated.alert_count,
                updated.assigned_analyst,
                updated.resolution_classification.value
                if updated.resolution_classification
                else None,
                updated.resolution_summary,
                updated.version,
                current.incident_id,
                expected_version,
            ),
        )
        if cursor.rowcount != 1:
            raise IncidentError("concurrent update conflict; reload the incident and retry")
        _audit(
            connection,
            current.incident_id,
            action,
            actor,
            {
                "before": {
                    "status": current.status.value,
                    "assigned_analyst": current.assigned_analyst,
                    "resolution_classification": current.resolution_classification.value
                    if current.resolution_classification
                    else None,
                    "resolution_summary": current.resolution_summary,
                },
                "after": {
                    "status": updated.status.value,
                    "assigned_analyst": updated.assigned_analyst,
                    "resolution_classification": updated.resolution_classification.value
                    if updated.resolution_classification
                    else None,
                    "resolution_summary": updated.resolution_summary,
                },
                "version": updated.version,
            },
            now,
        )
        connection.commit()
        return get_incident(database_path, current.incident_id)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def update_status(
    database_path: str | Path,
    incident_id: str,
    status: IncidentStatus,
    expected_version: int,
    *,
    actor: str = "analyst",
    classification: ResolutionClassification | None = None,
    summary: str | None = None,
) -> Incident:
    updates: dict[str, Any] = {"status": status}
    if status == IncidentStatus.RESOLVED:
        updates.update({"resolution_classification": classification, "resolution_summary": summary})
    return _change(database_path, incident_id, expected_version, actor, "status_changed", updates)


def assign_analyst(
    database_path: str | Path,
    incident_id: str,
    analyst: str | None,
    expected_version: int,
    *,
    actor: str = "analyst",
) -> Incident:
    if analyst is not None and not analyst.strip():
        raise IncidentError("analyst name cannot be blank")
    return _change(
        database_path,
        incident_id,
        expected_version,
        actor,
        "assignment_changed",
        {"assigned_analyst": analyst.strip() if analyst else None},
    )


def add_note(
    database_path: str | Path,
    incident_id: str,
    note: str,
    *,
    actor: str = "analyst",
    expected_version: int | None = None,
) -> dict[str, Any]:
    if not note.strip():
        raise IncidentError("note cannot be blank")
    connection = _connect(database_path)
    now = _stamp(_now())
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT incident_id, version FROM incidents WHERE incident_id=? OR reference=?",
            (incident_id, incident_id),
        ).fetchone()
        if row is None:
            raise IncidentError(f"incident not found: {incident_id}")
        if expected_version is not None and row["version"] != expected_version:
            raise IncidentError(
                f"stale incident version: expected {expected_version}, current version is {row['version']}"
            )
        connection.execute(
            "INSERT INTO incident_notes (incident_id, actor, note, created_at) VALUES (?, ?, ?, ?)",
            (row["incident_id"], actor, note.strip(), now),
        )
        connection.execute(
            "UPDATE incidents SET updated_at=?, version=version+1 WHERE incident_id=?",
            (now, row["incident_id"]),
        )
        _audit(connection, row["incident_id"], "note_added", actor, {"note": note.strip()}, now)
        connection.commit()
        return {
            "incident_id": row["incident_id"],
            "actor": actor,
            "note": note.strip(),
            "created_at": now,
        }
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def incident_timeline(database_path: str | Path, incident_id: str) -> list[dict[str, Any]]:
    connection = _connect(database_path)
    try:
        incident = get_incident(database_path, incident_id)
        items: list[dict[str, Any]] = []
        for row in connection.execute(
            """SELECT a.payload_json FROM incident_alerts ia JOIN alerts a USING(alert_id)
            WHERE ia.incident_id=? ORDER BY a.first_observed, a.alert_id""",
            (incident.incident_id,),
        ):
            alert = Alert.model_validate_json(row["payload_json"])
            items.append(
                {
                    "timestamp": _stamp(alert.first_observed),
                    "timestamp_type": "security_event",
                    "kind": "alert",
                    "provenance": "detection_rule",
                    "alert_id": alert.alert_id,
                    "rule_id": alert.rule_id,
                    "severity": alert.severity.value,
                    "evidence_event_ids": alert.evidence_event_ids,
                    "rationale": alert.rationale,
                }
            )
            for event_id in alert.evidence_event_ids:
                event_row = connection.execute(
                    "SELECT event_id, timestamp_utc, source_id FROM events WHERE event_id=?",
                    (event_id,),
                ).fetchone()
                items.append(
                    {
                        "timestamp": event_row["timestamp_utc"]
                        if event_row
                        else _stamp(alert.first_observed),
                        "timestamp_type": "security_event",
                        "kind": "evidence_reference",
                        "provenance": "source_telemetry"
                        if event_row
                        else "evidence_reference_only",
                        "event_id": event_id,
                        "source_id": event_row["source_id"] if event_row else None,
                        "source_available": event_row is not None,
                    }
                )
        for row in connection.execute(
            "SELECT * FROM correlation_explanations WHERE incident_id=?", (incident.incident_id,)
        ):
            items.append(
                {
                    "timestamp": row["created_at"],
                    "timestamp_type": "application_audit",
                    "kind": "correlation",
                    "provenance": "correlation_engine",
                    "alert_id": row["alert_id"],
                    "related_alert_id": row["related_alert_id"],
                    "strategy": row["strategy"],
                    "shared_values": json.loads(row["shared_values_json"]),
                    "explanation": row["explanation"],
                }
            )
        for row in connection.execute(
            "SELECT * FROM incident_audit WHERE incident_id=?", (incident.incident_id,)
        ):
            items.append(
                {
                    "timestamp": row["occurred_at"],
                    "timestamp_type": "application_audit",
                    "kind": row["action"],
                    "provenance": "analyst_or_application",
                    "actor": row["actor"],
                    "details": json.loads(row["details_json"]),
                    "audit_id": row["audit_id"],
                }
            )
        for row in connection.execute(
            "SELECT * FROM incident_notes WHERE incident_id=?", (incident.incident_id,)
        ):
            items.append(
                {
                    "timestamp": row["created_at"],
                    "timestamp_type": "application_audit",
                    "kind": "note",
                    "provenance": "analyst_input",
                    "actor": row["actor"],
                    "note": row["note"],
                    "note_id": row["note_id"],
                }
            )
        return sorted(
            items,
            key=lambda item: (
                item["timestamp"],
                item["kind"],
                str(item.get("event_id", item.get("audit_id", item.get("alert_id", "")))),
            ),
        )
    finally:
        connection.close()


def incident_audit_history(database_path: str | Path, incident_id: str) -> list[dict[str, Any]]:
    connection = _connect(database_path)
    try:
        incident = get_incident(database_path, incident_id)
        rows = connection.execute(
            "SELECT * FROM incident_audit WHERE incident_id=? ORDER BY occurred_at, audit_id",
            (incident.incident_id,),
        ).fetchall()
        return [
            {
                "audit_id": row["audit_id"],
                "action": row["action"],
                "actor": row["actor"],
                "details": json.loads(row["details_json"]),
                "occurred_at": row["occurred_at"],
            }
            for row in rows
        ]
    finally:
        connection.close()


def show_incident(database_path: str | Path, incident_id: str) -> dict[str, Any]:
    incident = get_incident(database_path, incident_id)
    connection = _connect(database_path)
    try:
        alerts = connection.execute(
            """SELECT a.payload_json FROM incident_alerts ia JOIN alerts a USING(alert_id)
            WHERE ia.incident_id=? ORDER BY a.first_observed, a.alert_id""",
            (incident.incident_id,),
        ).fetchall()
        explanations = connection.execute(
            "SELECT * FROM correlation_explanations WHERE incident_id=? ORDER BY created_at, explanation_id",
            (incident.incident_id,),
        ).fetchall()
        notes = connection.execute(
            "SELECT * FROM incident_notes WHERE incident_id=? ORDER BY created_at, note_id",
            (incident.incident_id,),
        ).fetchall()
        return {
            "incident": incident.model_dump(mode="json"),
            "alerts": [json.loads(row["payload_json"]) for row in alerts],
            "correlation_explanations": [
                {
                    "alert_id": row["alert_id"],
                    "related_alert_id": row["related_alert_id"],
                    "strategy": row["strategy"],
                    "shared_values": json.loads(row["shared_values_json"]),
                    "explanation": row["explanation"],
                    "time_gap_seconds": row["time_gap_seconds"],
                }
                for row in explanations
            ],
            "notes": [
                {"actor": row["actor"], "note": row["note"], "created_at": row["created_at"]}
                for row in notes
            ],
            "timeline": incident_timeline(database_path, incident.incident_id),
        }
    finally:
        connection.close()
