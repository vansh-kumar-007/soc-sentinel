"""Deterministic evaluation of validated rules against normalized events."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict

from soc_sentinel.detection.rules import Condition, DetectionRule, Severity
from soc_sentinel.schemas import SecurityEvent


class Alert(BaseModel):
    """Evidence-linked alert emitted by a deterministic rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: str
    rule_id: str
    rule_title: str
    severity: Severity
    first_observed: datetime
    last_observed: datetime
    event_count: int
    evidence_event_ids: list[str]
    grouping_context: dict[str, str | int | float | bool]
    rationale: str
    mitre_attack: list[str]


def evaluate_events(events: list[SecurityEvent], rules: list[DetectionRule]) -> list[Alert]:
    """Evaluate rules and return stable, ordered alerts.

    Input is de-duplicated by event_id (first occurrence wins), then ordered by
    timestamp and event ID. Scenario/evaluation metadata is never read by this engine.
    Re-evaluating identical events and rules yields identical alerts. Alert IDs hash
    rule ID, grouping context, and evidence event IDs.
    """
    unique: dict[str, SecurityEvent] = {}
    for event in events:
        unique.setdefault(event.event_id, event)
    ordered = sorted(unique.values(), key=lambda item: (item.timestamp, item.event_id))
    alerts: dict[str, Alert] = {}
    for rule in sorted(rules, key=lambda item: item.rule_id):
        if not rule.enabled:
            continue
        if rule.detection.type == "match":
            generated = _match_alerts(rule, ordered)
        elif rule.detection.type == "threshold":
            generated = _threshold_alerts(rule, ordered)
        else:
            generated = _sequence_alerts(rule, ordered)
        for alert in generated:
            alerts.setdefault(alert.alert_id, alert)
    return sorted(
        alerts.values(),
        key=lambda item: (
            item.first_observed,
            item.rule_id,
            item.last_observed,
            item.alert_id,
        ),
    )


def _match_alerts(rule: DetectionRule, events: list[SecurityEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if event.event_type not in rule.event_types:
            continue
        if _matches_all(event, rule.detection.conditions):
            context = _group_context(rule, [event])
            alerts.append(
                _make_alert(
                    rule,
                    [event],
                    context,
                    f"One {event.event_type.value} event matched all configured conditions.",
                )
            )
    return alerts


def _threshold_alerts(rule: DetectionRule, events: list[SecurityEvent]) -> list[Alert]:
    grouped: dict[tuple[Any, ...], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.event_type not in rule.event_types or not _matches_all(
            event, rule.detection.conditions
        ):
            continue
        key = _group_key(rule, event)
        if key is not None:
            grouped[key].append(event)

    alerts: list[Alert] = []
    assert rule.window is not None and rule.threshold is not None
    window = timedelta(seconds=rule.window)
    for key in sorted(grouped, key=lambda item: json.dumps(item, sort_keys=True, default=str)):
        group_events = grouped[key]
        last_alert_time: datetime | None = None
        for index, endpoint in enumerate(group_events):
            if last_alert_time is not None and endpoint.timestamp <= last_alert_time + window:
                continue
            start = endpoint.timestamp - window
            candidates = [
                item
                for item in group_events[: index + 1]
                if start <= item.timestamp <= endpoint.timestamp
            ]
            if len(candidates) < rule.threshold:
                continue
            evidence = candidates[: rule.threshold]
            context = _group_context(rule, evidence)
            alerts.append(
                _make_alert(
                    rule,
                    evidence,
                    context,
                    f"{len(evidence)} matching events for this group occurred within "
                    f"{rule.window} seconds (configured threshold: {rule.threshold}).",
                )
            )
            last_alert_time = endpoint.timestamp
    return alerts


def _sequence_alerts(rule: DetectionRule, events: list[SecurityEvent]) -> list[Alert]:
    assert rule.window is not None and rule.threshold is not None
    first_stage, second_stage = rule.detection.stages
    grouped_first: dict[tuple[Any, ...], list[SecurityEvent]] = defaultdict(list)
    grouped_second: dict[tuple[Any, ...], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.event_type not in rule.event_types:
            continue
        key = _group_key(rule, event)
        if key is None:
            continue
        if event.event_type == first_stage.event_type and _matches_all(
            event, first_stage.conditions
        ):
            grouped_first[key].append(event)
        if event.event_type == second_stage.event_type and _matches_all(
            event, second_stage.conditions
        ):
            grouped_second[key].append(event)

    alerts: list[Alert] = []
    window = timedelta(seconds=rule.window)
    for key in sorted(
        grouped_second, key=lambda item: json.dumps(item, sort_keys=True, default=str)
    ):
        first_events = grouped_first.get(key, [])
        for success_event in grouped_second[key]:
            start = success_event.timestamp - window
            failures = [
                event
                for event in first_events
                if start <= event.timestamp < success_event.timestamp
            ]
            if len(failures) < rule.threshold:
                continue
            evidence = [*failures, success_event]
            context = _group_context(rule, evidence)
            alerts.append(
                _make_alert(
                    rule,
                    evidence,
                    context,
                    f"{len(failures)} first-stage events preceded a second-stage event "
                    f"for the same group within {rule.window} seconds "
                    f"(minimum: {rule.threshold}).",
                )
            )
    return alerts


def _make_alert(
    rule: DetectionRule,
    evidence: list[SecurityEvent],
    grouping_context: dict[str, str | int | float | bool],
    rationale: str,
) -> Alert:
    ordered = sorted(evidence, key=lambda item: (item.timestamp, item.event_id))
    evidence_ids = [event.event_id for event in ordered]
    identity = {
        "rule_id": rule.rule_id,
        "grouping_context": grouping_context,
        "evidence_event_ids": evidence_ids,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:24]
    return Alert(
        alert_id=f"alert_{digest}",
        rule_id=rule.rule_id,
        rule_title=rule.title,
        severity=rule.severity,
        first_observed=ordered[0].timestamp,
        last_observed=ordered[-1].timestamp,
        event_count=len(ordered),
        evidence_event_ids=evidence_ids,
        grouping_context=grouping_context,
        rationale=rationale,
        mitre_attack=list(rule.mitre_attack),
    )


def _group_key(rule: DetectionRule, event: SecurityEvent) -> tuple[Any, ...] | None:
    values = tuple(_field_value(event, field) for field in rule.group_by)
    if not values or any(value is None for value in values):
        return None
    return values


def _group_context(
    rule: DetectionRule, evidence: list[SecurityEvent]
) -> dict[str, str | int | float | bool]:
    if not rule.group_by:
        return {}
    event = evidence[0]
    return {
        field: value
        for field in rule.group_by
        if (value := _field_value(event, field)) is not None
        and isinstance(value, (str, int, float, bool))
    }


def _matches_all(event: SecurityEvent, conditions: list[Condition]) -> bool:
    return all(_matches_condition(event, condition) for condition in conditions)


def _matches_condition(event: SecurityEvent, condition: Condition) -> bool:
    actual = _field_value(event, condition.field)
    if actual is None:
        return False
    expected = condition.value
    operator = condition.operator
    if operator == "eq":
        return actual == expected
    if operator == "ne":
        return actual != expected
    if operator == "in":
        return actual in expected
    if operator == "not_in":
        return actual not in expected
    if operator == "contains":
        return isinstance(actual, str) and expected in actual
    if operator == "icontains":
        return isinstance(actual, str) and expected.casefold() in actual.casefold()
    if operator == "starts_with":
        return isinstance(actual, str) and actual.startswith(expected)
    if operator == "ends_with":
        return isinstance(actual, str) and actual.endswith(expected)
    if operator == "gt":
        return actual > expected
    if operator == "gte":
        return actual >= expected
    if operator == "lt":
        return actual < expected
    if operator == "lte":
        return actual <= expected
    return False


def _field_value(event: SecurityEvent, field: str) -> Any:
    if field == "event_type":
        return event.event_type.value
    if field == "timestamp":
        return event.timestamp
    if field in {
        "event_id",
        "host_id",
        "username",
        "source_ip",
        "destination_ip",
        "action",
        "outcome",
    }:
        value = getattr(event, field)
        return value.value if hasattr(value, "value") else value
    if field.startswith("process."):
        if event.process is None:
            return None
        return getattr(event.process, field.split(".", maxsplit=1)[1])
    return None
