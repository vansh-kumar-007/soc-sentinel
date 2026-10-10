"""Positive and negative tests for deterministic rule evaluation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from soc_sentinel.detection.engine import evaluate_events
from soc_sentinel.detection.rules import load_rules
from soc_sentinel.schemas import SecurityEvent


ROOT = Path(__file__).parents[1]
RULES = load_rules(ROOT / "rules")


def auth_event(
    event_id: str,
    second: int,
    *,
    username: str = "alice",
    source_ip: str | None = "192.0.2.10",
    outcome: str = "failure",
    scenario: dict[str, str] | None = None,
) -> SecurityEvent:
    timestamp = datetime(2026, 10, 10, tzinfo=UTC) + timedelta(seconds=second)
    payload: dict[str, Any] = {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "event_type": "authentication",
        "host_id": "lab-host",
        "username": username,
        "source_ip": source_ip,
        "action": "login",
        "outcome": outcome,
        "source_id": "synthetic-detection-test",
    }
    if scenario is not None:
        payload["scenario"] = scenario
    return SecurityEvent.model_validate(payload)


def process_event(
    event_id: str,
    *,
    name: str = "powershell.exe",
    command_line: str = "powershell.exe -EncodedCommand SQBFAFgA",
) -> SecurityEvent:
    return SecurityEvent.model_validate(
        {
            "event_id": event_id,
            "timestamp": "2026-10-10T06:30:00Z",
            "event_type": "process",
            "host_id": "endpoint-01",
            "action": "execute",
            "process": {"name": name, "command_line": command_line, "pid": 123},
            "source_id": "synthetic-process-test",
        }
    )


def alerts_for(rule_id: str, events: list[SecurityEvent]):
    return evaluate_events(events, [rule for rule in RULES if rule.rule_id == rule_id])


def test_failure_burst_below_threshold_does_not_alert() -> None:
    events = [auth_event(f"f-{i}", i, outcome="failure") for i in range(4)]
    assert alerts_for("DET-001", events) == []


def test_failure_burst_triggers_at_threshold_with_complete_evidence() -> None:
    events = [auth_event(f"f-{i}", i, outcome="failure") for i in range(5)]
    alerts = alerts_for("DET-001", events)
    assert len(alerts) == 1
    assert alerts[0].event_count == 5
    assert alerts[0].evidence_event_ids == [f"f-{i}" for i in range(5)]
    assert alerts[0].grouping_context == {
        "username": "alice",
        "source_ip": "192.0.2.10",
    }


def test_failure_burst_includes_exact_window_boundary() -> None:
    events = [
        auth_event("f-0", 0),
        auth_event("f-1", 150),
        auth_event("f-2", 300),
        auth_event("f-3", 450),
        auth_event("f-4", 600),
    ]
    assert len(alerts_for("DET-001", events)) == 1


def test_failure_burst_outside_window_does_not_alert() -> None:
    events = [
        auth_event("f-0", 0),
        auth_event("f-1", 1),
        auth_event("f-2", 2),
        auth_event("f-3", 3),
        auth_event("f-4", 601),
    ]
    assert alerts_for("DET-001", events) == []


def test_failure_burst_separates_users_and_source_ips() -> None:
    events = [
        auth_event(f"alice-{i}", i, username="alice", source_ip="192.0.2.10")
        for i in range(3)
    ] + [
        auth_event(f"bob-{i}", i, username="bob", source_ip="192.0.2.10")
        for i in range(2)
    ] + [
        auth_event(f"other-ip-{i}", i, username="alice", source_ip="198.51.100.20")
        for i in range(2)
    ]
    assert alerts_for("DET-001", events) == []


def test_failure_burst_skips_events_without_required_group_fields() -> None:
    events = [
        auth_event(f"no-ip-{i}", i, source_ip=None) for i in range(6)
    ]
    assert alerts_for("DET-001", events) == []


def test_failure_then_success_requires_three_prior_failures_same_group() -> None:
    events = [auth_event(f"fail-{i}", i) for i in range(3)]
    events.append(auth_event("success", 4, outcome="success"))
    alerts = alerts_for("DET-002", events)
    assert len(alerts) == 1
    assert alerts[0].evidence_event_ids == ["fail-0", "fail-1", "fail-2", "success"]
    assert alerts[0].first_observed < alerts[0].last_observed


def test_failure_then_success_rejects_success_before_failures() -> None:
    events = [auth_event("success", 0, outcome="success")]
    events.extend(auth_event(f"fail-{i}", i + 1) for i in range(3))
    assert alerts_for("DET-002", events) == []


def test_failure_then_success_does_not_cross_user_or_source() -> None:
    events = [auth_event(f"fail-{i}", i, username="alice") for i in range(3)]
    events.append(auth_event("success-other-user", 4, username="bob", outcome="success"))
    assert alerts_for("DET-002", events) == []
    events[-1] = auth_event(
        "success-other-ip", 4, username="alice", source_ip="198.51.100.22", outcome="success"
    )
    assert alerts_for("DET-002", events) == []


def test_failure_then_success_requires_strictly_earlier_failure_timestamp() -> None:
    events = [auth_event(f"fail-{i}", 10) for i in range(3)]
    events.append(auth_event("same-time-success", 10, outcome="success"))
    assert alerts_for("DET-002", events) == []


def test_process_encoded_command_triggers_but_benign_lookalikes_do_not() -> None:
    suspicious = process_event("encoded")
    benign_name_only = process_event("plain", command_line="powershell.exe -Command Get-Process")
    benign_flag_lookalike = process_event(
        "encoding", command_line="powershell.exe -Command Get-Content file.txt -Encoding UTF8"
    )
    alerts = alerts_for("DET-003", [suspicious, benign_name_only, benign_flag_lookalike])
    assert len(alerts) == 1
    assert alerts[0].evidence_event_ids == ["encoded"]


def test_process_rule_requires_both_process_name_and_command_line_indicator() -> None:
    benign_name = process_event("renamed", name="custom.exe")
    assert alerts_for("DET-003", [benign_name]) == []


def test_missing_optional_fields_do_not_match_conditions() -> None:
    event = process_event("missing-command", command_line="powershell.exe -NoProfile")
    assert alerts_for("DET-003", [event]) == []


def test_alert_ids_and_order_are_deterministic() -> None:
    events = [auth_event(f"f-{i}", i) for i in range(5)]
    first = alerts_for("DET-001", events)
    second = alerts_for("DET-001", list(reversed(events)))
    assert [item.model_dump(mode="json") for item in first] == [
        item.model_dump(mode="json") for item in second
    ]


def test_duplicate_event_ids_do_not_duplicate_evidence() -> None:
    events = [auth_event(f"f-{i}", i) for i in range(5)]
    alerts = alerts_for("DET-001", [*events, events[0], events[1]])
    assert len(alerts) == 1
    assert len(alerts[0].evidence_event_ids) == 5
    assert len(set(alerts[0].evidence_event_ids)) == 5


def test_overlapping_full_batches_return_same_alert_id() -> None:
    events = [auth_event(f"f-{i}", i) for i in range(6)]
    first = alerts_for("DET-001", events[:5])
    second = alerts_for("DET-001", events)
    assert len(first) == len(second) == 1
    assert first[0].alert_id == second[0].alert_id


def test_scenario_labels_never_change_detection_result() -> None:
    baseline = [auth_event(f"f-{i}", i) for i in range(5)]
    labeled = [
        auth_event(
            f"f-{i}",
            i,
            scenario={"scenario_id": "label-does-not-drive-detection", "label": "benign"},
        )
        for i in range(5)
    ]
    assert [a.alert_id for a in alerts_for("DET-001", baseline)] == [
        a.alert_id for a in alerts_for("DET-001", labeled)
    ]


def test_empty_batches_return_no_alerts() -> None:
    assert evaluate_events([], RULES) == []
