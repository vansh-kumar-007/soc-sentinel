"""Coverage for the complete allow-listed rule operator set."""

from __future__ import annotations

from typing import Any

from soc_sentinel.detection.engine import evaluate_events
from soc_sentinel.detection.rules import DetectionRule
from soc_sentinel.schemas import SecurityEvent


def process_event() -> SecurityEvent:
    return SecurityEvent.model_validate(
        {
            "event_id": "operator-test",
            "timestamp": "2026-10-10T06:30:00Z",
            "event_type": "process",
            "host_id": "endpoint-01",
            "action": "execute",
            "process": {
                "name": "powershell.exe",
                "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
                "pid": 123,
            },
            "source_id": "synthetic-operator-test",
        }
    )


def make_rule(field: str, operator: str, value: Any) -> DetectionRule:
    return DetectionRule.model_validate(
        {
            "rule_id": "DET-990",
            "title": "Operator test",
            "description": "Test one supported operator on normalized process data.",
            "severity": "low",
            "event_types": ["process"],
            "detection": {
                "type": "match",
                "conditions": [{"field": field, "operator": operator, "value": value}],
            },
        }
    )


def test_allowlisted_operators_match_typed_fields() -> None:
    event = process_event()
    cases = [
        ("process.name", "eq", "powershell.exe"),
        ("process.name", "ne", "cmd.exe"),
        ("process.name", "in", ["powershell.exe", "pwsh.exe"]),
        ("process.name", "not_in", ["cmd.exe"]),
        ("process.command_line", "contains", "-EncodedCommand"),
        ("process.command_line", "icontains", "-encodedcommand"),
        ("process.command_line", "starts_with", "powershell.exe"),
        ("process.command_line", "ends_with", "SQBFAFgA"),
        ("process.pid", "gt", 122),
        ("process.pid", "gte", 123),
        ("process.pid", "lt", 124),
        ("process.pid", "lte", 123),
    ]
    for field, operator, value in cases:
        assert len(evaluate_events([event], [make_rule(field, operator, value)])) == 1, (
            field,
            operator,
            value,
        )


def test_missing_optional_field_never_matches_inequality() -> None:
    event = SecurityEvent.model_validate(
        {
            "event_id": "no-command-line",
            "timestamp": "2026-10-10T06:30:00Z",
            "event_type": "process",
            "host_id": "endpoint-01",
            "action": "execute",
            "process": {"name": "powershell.exe"},
            "source_id": "synthetic-process-test",
        }
    )
    rule = make_rule("process.command_line", "ne", "benign")
    assert evaluate_events([event], [rule]) == []
