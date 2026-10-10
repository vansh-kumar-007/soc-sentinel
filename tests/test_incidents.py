"""Incident correlation, persistence, lifecycle, and migration tests."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from soc_sentinel.correlation import (
    CorrelationPolicy,
    CorrelationPolicyError,
    alert_entities,
    correlate_pair,
)
from soc_sentinel.db import initialize_database, insert_events
from soc_sentinel.detection.engine import Alert
from soc_sentinel.detection.rules import Severity
from soc_sentinel.incidents import (
    IncidentError,
    IncidentStatus,
    ResolutionClassification,
    add_note,
    assign_analyst,
    correlate_and_persist,
    get_incident,
    incident_audit_history,
    incident_timeline,
    show_incident,
    update_status,
)
from soc_sentinel.schemas import SecurityEvent


def event(
    event_id: str,
    second: int = 0,
    *,
    username: str | None = "alice",
    source_ip: str | None = "192.0.2.10",
    host_id: str = "host-a",
) -> SecurityEvent:
    return SecurityEvent.model_validate(
        {
            "event_id": event_id,
            "timestamp": (
                datetime(2026, 10, 10, tzinfo=UTC) + timedelta(seconds=second)
            ).isoformat(),
            "event_type": "authentication",
            "host_id": host_id,
            "username": username,
            "source_ip": source_ip,
            "action": "login",
            "outcome": "failure",
            "source_id": "synthetic-phase4-test",
        }
    )


def alert(
    alert_id: str,
    event_id: str,
    second: int = 0,
    *,
    username: str | None = "alice",
    source_ip: str | None = "192.0.2.10",
    host_id: str = "host-a",
    severity: Severity = Severity.HIGH,
) -> Alert:
    ts = datetime(2026, 10, 10, tzinfo=UTC) + timedelta(seconds=second)
    return Alert(
        alert_id=alert_id,
        rule_id="DET-001",
        rule_title="Synthetic authentication signal",
        severity=severity,
        first_observed=ts,
        last_observed=ts,
        event_count=1,
        evidence_event_ids=[event_id],
        grouping_context={
            k: v
            for k, v in {"username": username, "source_ip": source_ip, "host_id": host_id}.items()
            if v is not None
        },
        rationale="Synthetic test evidence matched configured rule.",
        mitre_attack=[],
    )


def policy(**overrides: object) -> CorrelationPolicy:
    return CorrelationPolicy.model_validate(
        {
            "policy_id": "test-policy",
            "window_seconds": 60,
            "strategies": ["same_username_and_source_ip", "shared_event", "same_host"],
            "allow_transitive": True,
            **overrides,
        }
    )


def seed_db(path: Path, events: list[SecurityEvent]) -> None:
    insert_events(path, events)


def test_policy_rejects_unknown_fields_duplicate_strategies_and_empty_strategies(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError):
        CorrelationPolicy.model_validate(
            {"policy_id": "x", "strategies": ["same_host", "same_host"]}
        )
    with pytest.raises(ValueError):
        CorrelationPolicy.model_validate({"policy_id": "x", "strategies": []})
    bad = tmp_path / "policy.yaml"
    bad.write_text(
        "policy_id: x\nstrategies: [same_host]\n"
        "run: !!python/object/apply:os.system ['echo bad']\n",
        encoding="utf-8",
    )
    with pytest.raises(CorrelationPolicyError):
        from_yaml(bad)


def from_yaml(path: Path) -> object:
    from soc_sentinel.correlation import load_correlation_policy

    return load_correlation_policy(path)


def test_pair_correlation_requires_matching_entity_and_time_window() -> None:
    ev1, ev2 = event("e1"), event("e2", 60)
    a = alert("a1", "e1")
    b = alert("a2", "e2", 60)
    ent_a, ent_b = alert_entities(a, {"e1": ev1}), alert_entities(b, {"e2": ev2})
    decision = correlate_pair(a, b, ent_a, ent_b, policy())
    assert decision is not None and decision.strategy == "same_username_and_source_ip"
    assert decision.shared_values == {"username": "alice", "source_ip": "192.0.2.10"}
    assert "within the 60s policy window" in decision.explanation
    far = alert("a3", "e2", 61)
    assert correlate_pair(a, far, ent_a, alert_entities(far, {"e2": ev2}), policy()) is None


def test_different_entities_and_missing_values_do_not_correlate() -> None:
    a, b = (
        alert("a", "e1"),
        alert("b", "e2", username="bob", source_ip="198.51.100.1", host_id="host-b"),
    )
    evs = {
        "e1": event("e1"),
        "e2": event("e2", username="bob", source_ip="198.51.100.1", host_id="host-b"),
    }
    p = policy(strategies=["same_username_and_source_ip", "same_host"])
    assert correlate_pair(a, b, alert_entities(a, evs), alert_entities(b, evs), p) is None
    missing = alert("c", "e3", username=None, source_ip=None, host_id="host-z")
    other = alert("d", "e4", username=None, source_ip=None, host_id="host-q")
    assert (
        correlate_pair(missing, other, alert_entities(missing, {}), alert_entities(other, {}), p)
        is None
    )


def test_shared_event_is_an_explicit_supported_relationship() -> None:
    a, b = alert("a", "shared"), alert("b", "shared", host_id="different")
    p = policy(strategies=["shared_event"])
    decision = correlate_pair(a, b, alert_entities(a, {}), alert_entities(b, {}), p)
    assert decision is not None and decision.shared_values == {"event_id": "shared"}


def test_three_alert_transitive_chain_and_idempotent_repeat(tmp_path: Path) -> None:
    db = tmp_path / "soc.sqlite3"
    events = [
        event("e1", 0, username="alice", source_ip="192.0.2.1", host_id="host-a"),
        event("e2", 10, username="bob", source_ip="192.0.2.2", host_id="host-a"),
        event("e3", 20, username="bob", source_ip="192.0.2.2", host_id="host-b"),
        event("e4", 30, username="carol", source_ip="192.0.2.3", host_id="host-b"),
    ]
    a1 = alert("a1", "e1", 0, username="alice", source_ip="192.0.2.1", host_id="host-a")
    a2 = alert("a2", "e2", 10, username="bob", source_ip="192.0.2.2", host_id="host-a")
    a2 = a2.model_copy(
        update={
            "evidence_event_ids": ["e2", "e3"],
            "event_count": 2,
            "last_observed": datetime(2026, 10, 10, tzinfo=UTC) + timedelta(seconds=20),
        }
    )
    a3 = alert("a3", "e4", 30, username="carol", source_ip="192.0.2.3", host_id="host-b")
    alerts = [a1, a2, a3]
    seed_db(db, events)
    p = policy(strategies=["same_host"], allow_transitive=True)
    first = correlate_and_persist(db, alerts, events, p)
    assert len(first) == 1 and first[0].alert_count == 3
    assert len(first[0].alert_ids) == 3
    second = correlate_and_persist(db, alerts, events, p)
    assert len(second) == 1 and second[0].incident_id == first[0].incident_id
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 3
        assert connection.execute("SELECT COUNT(*) FROM incident_alerts").fetchone()[0] == 3
        assert (
            connection.execute("SELECT COUNT(*) FROM correlation_explanations").fetchone()[0] >= 2
        )


def test_incident_lifecycle_notes_assignment_resolution_and_optimistic_version(
    tmp_path: Path,
) -> None:
    db = tmp_path / "lifecycle.sqlite3"
    ev = event("event-1")
    seed_db(db, [ev])
    incident = correlate_and_persist(db, [alert("alert-1", "event-1")], [ev], policy())[0]
    incident = assign_analyst(db, incident.incident_id, "analyst-1", incident.version)
    assert incident.assigned_analyst == "analyst-1"
    with pytest.raises(IncidentError, match="stale incident version"):
        assign_analyst(db, incident.incident_id, "analyst-2", incident.version - 1)
    add_note(
        db,
        incident.incident_id,
        "Reviewed synthetic authentication evidence.",
        expected_version=incident.version,
    )
    current = get_incident(db, incident.incident_id)
    with pytest.raises(IncidentError, match="resolution requires"):
        update_status(db, current.incident_id, IncidentStatus.RESOLVED, current.version)
    resolved = update_status(
        db,
        current.incident_id,
        IncidentStatus.RESOLVED,
        current.version,
        classification=ResolutionClassification.BENIGN_POSITIVE,
        summary="Synthetic benign validation case.",
    )
    assert resolved.status == IncidentStatus.RESOLVED
    reopened = update_status(db, resolved.incident_id, IncidentStatus.OPEN, resolved.version)
    assert reopened.status == IncidentStatus.OPEN and reopened.resolution_classification is None
    history = incident_audit_history(db, reopened.incident_id)
    assert any(item["action"] == "status_changed" for item in history)
    assert any(
        item["details"].get("before", {}).get("resolution_classification") == "benign_positive"
        for item in history
    )
    timeline = incident_timeline(db, reopened.incident_id)
    assert all("timestamp_type" in item and "provenance" in item for item in timeline)
    assert show_incident(db, reopened.incident_id)["alerts"][0]["alert_id"] == "alert-1"


def test_database_v2_migrates_without_losing_events_and_enables_foreign_keys(
    tmp_path: Path,
) -> None:
    db = tmp_path / "v2.sqlite3"
    with sqlite3.connect(db) as connection:
        connection.execute(
            "CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO schema_metadata VALUES ('schema_version','2')")
        connection.execute(
            "CREATE TABLE events (event_id TEXT PRIMARY KEY, timestamp_utc TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO events VALUES ('preserve-me','2026-10-10T00:00:00Z')")
    initialize_database(db)
    initialize_database(db)
    with sqlite3.connect(db) as connection:
        assert connection.execute(
            "SELECT value FROM schema_metadata WHERE key='schema_version'"
        ).fetchone() == ("3",)
        assert connection.execute("SELECT event_id FROM events").fetchone() == ("preserve-me",)
        connection.execute("PRAGMA foreign_keys=ON")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO incident_alerts "
                "VALUES ('missing-incident', 'missing-alert', '2026-10-10T00:00:00Z')"
            )
