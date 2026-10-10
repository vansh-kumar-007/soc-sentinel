"""Normalized event model validation tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from soc_sentinel.schemas import EventType, SecurityEvent


def authentication_event(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "event_id": "auth-001",
        "timestamp": "2026-10-10T12:00:00+05:30",
        "event_type": "authentication",
        "host_id": "lab-host",
        "username": "analyst",
        "source_ip": "192.0.2.10",
        "action": "login",
        "outcome": "success",
        "source_id": "unit-test-fixture",
        "scenario": {"scenario_id": "sample-01", "label": "benign"},
    }
    payload.update(overrides)
    return payload


def test_valid_authentication_event_normalizes_timestamp_and_ip() -> None:
    event = SecurityEvent.model_validate(authentication_event())

    assert event.event_type == EventType.AUTHENTICATION
    assert event.timestamp == datetime(2026, 10, 10, 6, 30, tzinfo=UTC)
    assert event.source_ip == "192.0.2.10"
    assert event.scenario is not None and event.scenario.label == "benign"


def test_valid_process_event_requires_process_metadata() -> None:
    payload = {
        "event_id": "proc-001",
        "timestamp": "2026-10-10T06:30:00Z",
        "event_type": "process",
        "host_id": "lab-host",
        "action": "execute",
        "process": {"name": "demo", "pid": 42, "hash_sha256": "A" * 64},
        "source_id": "synthetic-process",
    }

    event = SecurityEvent.model_validate(payload)
    assert event.process is not None
    assert event.process.pid == 42
    assert event.process.hash_sha256 == "a" * 64


def test_valid_network_event_requires_at_least_one_ip() -> None:
    payload = {
        "event_id": "net-001",
        "timestamp": "2026-10-10T06:30:00Z",
        "event_type": "network",
        "host_id": "lab-host",
        "destination_ip": "2001:0db8::1",
        "action": "connect",
        "source_id": "synthetic-network",
    }

    event = SecurityEvent.model_validate(payload)
    assert event.destination_ip == "2001:db8::1"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"username": None}, "authentication events require username"),
        ({"timestamp": "2026-10-10T12:00:00"}, "timezone offset"),
        ({"source_ip": "999.1.1.1"}, "valid IPv4 or IPv6"),
        ({"event_type": "unknown"}, "Input should be"),
    ],
)
def test_invalid_event_records_are_rejected(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        SecurityEvent.model_validate(authentication_event(**overrides))


def test_unrecognized_top_level_fields_are_rejected() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SecurityEvent.model_validate(authentication_event(malware=True))
