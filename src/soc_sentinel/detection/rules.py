"""Safe, typed detection-rule contract and YAML loading.

Rules are declarative data only. This module never evaluates code or executes commands.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from soc_sentinel.schemas import EventType


class Severity(StrEnum):
    """Configured severity; not a confidence score or incident verdict."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


FIELD_TYPES: dict[str, str] = {
    "event_id": "string",
    "timestamp": "timestamp",
    "event_type": "string",
    "host_id": "string",
    "username": "string",
    "source_ip": "string",
    "destination_ip": "string",
    "action": "string",
    "outcome": "string",
    "process.name": "string",
    "process.executable": "string",
    "process.pid": "number",
    "process.parent_pid": "number",
    "process.command_line": "string",
    "process.hash_sha256": "string",
}
PROCESS_FIELDS = {
    "process.name",
    "process.executable",
    "process.pid",
    "process.parent_pid",
    "process.command_line",
    "process.hash_sha256",
}
GROUP_FIELDS = {"host_id", "username", "source_ip", "destination_ip", "process.name"}
STRING_OPERATORS = {"contains", "icontains", "icontains_token", "starts_with", "ends_with"}
NUMERIC_OPERATORS = {"gt", "gte", "lt", "lte"}
ALLOWED_OPERATORS = {"eq", "ne", "in", "not_in", *STRING_OPERATORS, *NUMERIC_OPERATORS}
EVENT_TYPES_BY_FIELD: dict[str, set[EventType]] = {
    field: ({EventType.PROCESS} if field in PROCESS_FIELDS else set(EventType))
    for field in FIELD_TYPES
}


class RuleValidationError(ValueError):
    """Raised when a rule file cannot be safely loaded or validated."""


class RuleModel(BaseModel):
    """Base class that rejects unrecognized rule grammar."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Condition(RuleModel):
    """A single allow-listed field/operator/value comparison."""

    field: str
    operator: str
    value: Any

    @model_validator(mode="after")
    def validate_condition(self) -> Condition:
        if self.field not in FIELD_TYPES:
            raise ValueError(f"unsupported field '{self.field}'")
        if self.operator not in ALLOWED_OPERATORS:
            raise ValueError(f"unsupported operator '{self.operator}'")
        field_type = FIELD_TYPES[self.field]
        if self.operator in STRING_OPERATORS and field_type != "string":
            raise ValueError(f"operator '{self.operator}' requires a string field")
        if self.operator in NUMERIC_OPERATORS:
            if field_type != "number":
                raise ValueError(f"operator '{self.operator}' requires a numeric field")
            if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
                raise ValueError(f"operator '{self.operator}' requires a numeric value")
        elif self.operator in {"in", "not_in"}:
            if not isinstance(self.value, list) or not self.value:
                raise ValueError(f"operator '{self.operator}' requires a non-empty list")
            if any(isinstance(item, (dict, list)) for item in self.value):
                raise ValueError("membership values must be scalar")
        elif self.operator in STRING_OPERATORS:
            if not isinstance(self.value, str) or not self.value:
                raise ValueError(f"operator '{self.operator}' requires a non-empty string")
        elif isinstance(self.value, (dict, list)):
            raise ValueError("comparison values must be scalar")

        if field_type == "string":
            values = self.value if self.operator in {"in", "not_in"} else [self.value]
            if any(not isinstance(item, str) for item in values):
                raise ValueError(f"field '{self.field}' requires string comparison values")
        elif field_type == "number":
            values = self.value if self.operator in {"in", "not_in"} else [self.value]
            if any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in values):
                raise ValueError(f"field '{self.field}' requires numeric comparison values")
        elif field_type == "timestamp":
            if self.operator not in {"eq", "ne"}:
                raise ValueError("timestamp fields support only eq and ne")
            if isinstance(self.value, str):
                try:
                    self.value = datetime.fromisoformat(self.value.replace("Z", "+00:00"))
                except ValueError as exc:
                    raise ValueError("timestamp comparison value must be ISO-8601") from exc
            if not isinstance(self.value, datetime):
                raise ValueError("timestamp comparison value must be ISO-8601")
            if self.value.tzinfo is None or self.value.utcoffset() is None:
                raise ValueError("timestamp comparison value must include a timezone")
        return self


class SequenceStage(RuleModel):
    """One ordered stage in a two-stage event sequence."""

    event_type: EventType
    conditions: list[Condition] = Field(min_length=1)


class DetectionSpec(RuleModel):
    """Detection strategy; strategy-specific combinations are validated by the rule."""

    type: Literal["match", "threshold", "sequence"]
    conditions: list[Condition] = Field(default_factory=list)
    stages: list[SequenceStage] = Field(default_factory=list)


class DetectionRule(RuleModel):
    """Complete, validated, data-only detection rule."""

    rule_id: str = Field(pattern=r"^DET-[0-9]{3,}$")
    title: str = Field(min_length=3, max_length=160)
    description: str = Field(min_length=10, max_length=2000)
    enabled: bool = True
    severity: Severity
    event_types: list[EventType] = Field(min_length=1)
    detection: DetectionSpec
    window: int | None = Field(default=None, ge=1, le=86_400)
    threshold: int | None = Field(default=None, ge=1, le=100_000)
    group_by: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_rule(self) -> DetectionRule:
        if len(set(self.event_types)) != len(self.event_types):
            raise ValueError("event_types must not contain duplicates")
        if len(set(self.group_by)) != len(self.group_by):
            raise ValueError("group_by must not contain duplicates")
        for field in self.group_by:
            if field not in GROUP_FIELDS:
                raise ValueError(f"unsupported grouping field '{field}'")
            if not set(self.event_types).issubset(EVENT_TYPES_BY_FIELD[field]):
                raise ValueError(
                    f"grouping field '{field}' is not available for every event type in event_types"
                )
        for technique in self.mitre_attack:
            if (
                not isinstance(technique, str)
                or re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", technique) is None
            ):
                raise ValueError(f"invalid MITRE ATT&CK technique ID '{technique}'")
        if any(not tag.strip() for tag in self.tags):
            raise ValueError("tags must be non-empty strings")

        spec = self.detection
        if spec.type == "match":
            if not spec.conditions:
                raise ValueError("match detections require at least one condition")
            if spec.stages or self.threshold is not None or self.window is not None:
                raise ValueError("match detections do not accept stages, threshold, or window")
            self._validate_condition_fields(spec.conditions, set(self.event_types))
        elif spec.type == "threshold":
            if not spec.conditions:
                raise ValueError("threshold detections require at least one condition")
            if spec.stages:
                raise ValueError("threshold detections do not accept stages")
            if self.threshold is None or self.threshold < 2:
                raise ValueError("threshold detections require threshold >= 2")
            if self.window is None:
                raise ValueError("threshold detections require window in seconds")
            if not self.group_by:
                raise ValueError("threshold detections require at least one group_by field")
            self._validate_condition_fields(spec.conditions, set(self.event_types))
        elif spec.type == "sequence":
            if spec.conditions:
                raise ValueError(
                    "sequence detections use stage conditions, not detection.conditions"
                )
            if len(spec.stages) != 2:
                raise ValueError("sequence detections require exactly two ordered stages")
            if self.threshold is None or self.threshold < 1:
                raise ValueError("sequence detections require threshold >= 1")
            if self.window is None:
                raise ValueError("sequence detections require window in seconds")
            if not self.group_by:
                raise ValueError("sequence detections require at least one group_by field")
            for stage in spec.stages:
                if stage.event_type not in self.event_types:
                    raise ValueError(
                        "each sequence stage event_type must appear in rule event_types"
                    )
                self._validate_condition_fields(stage.conditions, {stage.event_type})
        return self

    @staticmethod
    def _validate_condition_fields(
        conditions: list[Condition], event_types: set[EventType]
    ) -> None:
        for condition in conditions:
            supported = EVENT_TYPES_BY_FIELD[condition.field]
            if not event_types.issubset(supported):
                raise ValueError(
                    f"field '{condition.field}' is not available for every configured event type"
                )


def load_rules(path: str | Path) -> list[DetectionRule]:
    """Load one YAML rule file or all YAML files in a directory using safe parsing.

    Directory files are read in lexical order. Duplicate rule IDs, empty directories,
    non-mapping documents, and invalid schemas raise RuleValidationError.
    """
    rule_path = Path(path)
    if rule_path.is_dir():
        files = sorted([*rule_path.glob("*.yaml"), *rule_path.glob("*.yml")])
        if not files:
            raise RuleValidationError(f"no .yaml or .yml rule files found in '{rule_path}'")
    elif rule_path.is_file():
        files = [rule_path]
    else:
        raise RuleValidationError(f"rules path does not exist: '{rule_path}'")

    rules: list[DetectionRule] = []
    seen_ids: set[str] = set()
    for file_path in files:
        try:
            with file_path.open("r", encoding="utf-8") as stream:
                raw: Any = yaml.safe_load(stream)
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise RuleValidationError(f"{file_path}: cannot parse YAML: {exc}") from exc
        if not isinstance(raw, Mapping):
            raise RuleValidationError(f"{file_path}: rule document must be a YAML mapping")
        try:
            rule = DetectionRule.model_validate(raw)
        except ValidationError as exc:
            details = "; ".join(
                f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
                for item in exc.errors(include_url=False)
            )
            raise RuleValidationError(f"{file_path}: invalid rule: {details}") from exc
        if rule.rule_id in seen_ids:
            raise RuleValidationError(f"{file_path}: duplicate rule_id '{rule.rule_id}'")
        seen_ids.add(rule.rule_id)
        rules.append(rule)
    return rules
