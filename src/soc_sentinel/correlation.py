"""Validated, explainable alert-to-alert correlation policies."""

from __future__ import annotations
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from soc_sentinel.detection.engine import Alert
from soc_sentinel.schemas import SecurityEvent

StrategyName = Literal[
    "same_host", "same_username", "same_source_ip", "same_username_and_source_ip", "shared_event"
]


class CorrelationPolicyError(ValueError):
    """Raised when a correlation policy cannot be safely loaded."""


class CorrelationPolicy(BaseModel):
    """Small data-only correlation grammar; no expressions or executable content."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    policy_id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,80}$")
    window_seconds: int = Field(default=1800, ge=1, le=604800)
    strategies: list[StrategyName] = Field(min_length=1)
    allow_transitive: bool = True

    @model_validator(mode="after")
    def unique_strategies(self) -> CorrelationPolicy:
        if len(set(self.strategies)) != len(self.strategies):
            raise ValueError("strategies must not contain duplicates")
        return self


class CorrelationDecision(BaseModel):
    """Auditable explanation for one accepted alert relationship."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    alert_id: str
    related_alert_id: str
    strategy: StrategyName
    shared_values: dict[str, str]
    time_gap_seconds: float
    explanation: str


def load_correlation_policy(path: str | Path) -> CorrelationPolicy:
    """Load one safe YAML correlation policy."""
    policy_path = Path(path)
    try:
        with policy_path.open("r", encoding="utf-8") as stream:
            raw: Any = yaml.safe_load(stream)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise CorrelationPolicyError(f"{policy_path}: cannot parse policy: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise CorrelationPolicyError(f"{policy_path}: policy must be a YAML mapping")
    try:
        return CorrelationPolicy.model_validate(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
            for item in exc.errors(include_url=False)
        )
        raise CorrelationPolicyError(f"{policy_path}: invalid policy: {details}") from exc


def alert_entities(alert: Alert, events_by_id: Mapping[str, SecurityEvent]) -> dict[str, set[str]]:
    """Return only concrete entities supported by alert context or source events."""
    entities: dict[str, set[str]] = {
        key: set() for key in ("host_id", "username", "source_ip", "destination_ip")
    }
    for field in entities:
        value = alert.grouping_context.get(field)
        if isinstance(value, str) and value.strip():
            entities[field].add(value)
    for event_id in alert.evidence_event_ids:
        event = events_by_id.get(event_id)
        if event is None:
            continue
        for field in entities:
            value = getattr(event, field)
            if isinstance(value, str) and value.strip():
                entities[field].add(value)
    return entities


def _interval_gap_seconds(left: Alert, right: Alert) -> float:
    if left.last_observed < right.first_observed:
        return (right.first_observed - left.last_observed).total_seconds()
    if right.last_observed < left.first_observed:
        return (left.first_observed - right.last_observed).total_seconds()
    return 0.0


def correlate_pair(
    left: Alert,
    right: Alert,
    left_entities: dict[str, set[str]],
    right_entities: dict[str, set[str]],
    policy: CorrelationPolicy,
) -> CorrelationDecision | None:
    """Return the first policy-ordered, explainable relationship between two alerts."""
    if left.alert_id == right.alert_id:
        return None
    gap = _interval_gap_seconds(left, right)
    if gap > policy.window_seconds:
        return None
    for strategy in policy.strategies:
        shared: dict[str, str] = {}
        if strategy == "shared_event":
            common = sorted(set(left.evidence_event_ids) & set(right.evidence_event_ids))
            if common:
                shared = {"event_id": common[0]}
        elif strategy == "same_username_and_source_ip":
            usernames = left_entities["username"] & right_entities["username"]
            addresses = left_entities["source_ip"] & right_entities["source_ip"]
            if usernames and addresses:
                shared = {"username": sorted(usernames)[0], "source_ip": sorted(addresses)[0]}
        else:
            field = {
                "same_host": "host_id",
                "same_username": "username",
                "same_source_ip": "source_ip",
            }[strategy]
            values = left_entities[field] & right_entities[field]
            if values:
                shared = {field: sorted(values)[0]}
        if shared:
            details = ", ".join(f"{key}={value}" for key, value in sorted(shared.items()))
            return CorrelationDecision(
                alert_id=left.alert_id,
                related_alert_id=right.alert_id,
                strategy=strategy,
                shared_values=shared,
                time_gap_seconds=gap,
                explanation=(
                    f"Matched {strategy} ({details}); observed-interval gap {gap:g}s "
                    f"is within the {policy.window_seconds}s policy window."
                ),
            )
    return None
