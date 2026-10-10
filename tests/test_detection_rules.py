"""Detection rule schema and safe YAML loading tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from soc_sentinel.detection.rules import RuleValidationError, load_rules

ROOT = Path(__file__).parents[1]
SHIPPED_RULES = ROOT / "rules"


def write_rule(tmp_path: Path, payload: dict[str, Any]) -> Path:
    path = tmp_path / "rule.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_shipped_rules_load_and_have_unique_stable_ids() -> None:
    rules = load_rules(SHIPPED_RULES)
    assert [rule.rule_id for rule in rules] == ["DET-001", "DET-002", "DET-003"]


def test_unknown_field_is_rejected(tmp_path: Path) -> None:
    path = write_rule(
        tmp_path,
        {
            "rule_id": "DET-900",
            "title": "Unknown field test",
            "description": "A sufficiently long description for this test.",
            "severity": "low",
            "event_types": ["authentication"],
            "detection": {
                "type": "match",
                "conditions": [{"field": "process.magic", "operator": "eq", "value": "x"}],
            },
        },
    )
    with pytest.raises(RuleValidationError, match="unsupported field"):
        load_rules(path)


def test_unsupported_operator_is_rejected(tmp_path: Path) -> None:
    path = write_rule(
        tmp_path,
        {
            "rule_id": "DET-900",
            "title": "Unsupported operator",
            "description": "A sufficiently long description for this test.",
            "severity": "low",
            "event_types": ["authentication"],
            "detection": {
                "type": "match",
                "conditions": [{"field": "outcome", "operator": "regex", "value": "fail.*"}],
            },
        },
    )
    with pytest.raises(RuleValidationError, match="unsupported operator"):
        load_rules(path)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"severity": "urgent"}, "severity"),
        ({"threshold": 1, "window": 60, "group_by": ["username"]}, "threshold"),
        ({"window": -1}, "greater than or equal to 1"),
        ({"unknown_key": True}, "Extra inputs are not permitted"),
    ],
)
def test_invalid_rule_configuration_is_rejected(
    tmp_path: Path, changes: dict[str, Any], message: str
) -> None:
    payload: dict[str, Any] = {
        "rule_id": "DET-900",
        "title": "Rule validation",
        "description": "A sufficiently long description for this test.",
        "severity": "low",
        "event_types": ["authentication"],
        "detection": {
            "type": "match",
            "conditions": [{"field": "outcome", "operator": "eq", "value": "failure"}],
        },
    }
    payload.update(changes)
    path = write_rule(tmp_path, payload)
    with pytest.raises(RuleValidationError, match=message):
        load_rules(path)


def test_missing_required_properties_are_rejected(tmp_path: Path) -> None:
    path = write_rule(tmp_path, {"rule_id": "DET-900"})
    with pytest.raises(RuleValidationError, match="Field required"):
        load_rules(path)


def test_malformed_yaml_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("rule_id: [unterminated", encoding="utf-8")
    with pytest.raises(RuleValidationError, match="cannot parse YAML"):
        load_rules(path)


def test_unsafe_python_yaml_tag_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "unsafe.yaml"
    path.write_text("!!python/object/apply:os.system ['echo unsafe']", encoding="utf-8")
    with pytest.raises(RuleValidationError, match="cannot parse YAML"):
        load_rules(path)


def test_duplicate_rule_ids_are_rejected(tmp_path: Path) -> None:
    payload = {
        "rule_id": "DET-900",
        "title": "Duplicate rule",
        "description": "A sufficiently long description for this test.",
        "severity": "low",
        "event_types": ["authentication"],
        "detection": {
            "type": "match",
            "conditions": [{"field": "outcome", "operator": "eq", "value": "failure"}],
        },
    }
    write_rule(tmp_path, payload)
    second = tmp_path / "second.yaml"
    second.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(RuleValidationError, match="duplicate rule_id"):
        load_rules(tmp_path)



def test_field_value_type_mismatch_is_rejected(tmp_path: Path) -> None:
    path = write_rule(
        tmp_path,
        {
            "rule_id": "DET-900",
            "title": "Wrong value type",
            "description": "A sufficiently long description for this test.",
            "severity": "low",
            "event_types": ["process"],
            "detection": {
                "type": "match",
                "conditions": [
                    {"field": "process.pid", "operator": "eq", "value": "not-a-number"}
                ],
            },
        },
    )
    with pytest.raises(RuleValidationError, match="requires numeric comparison values"):
        load_rules(path)


def test_process_field_cannot_be_used_by_authentication_rule(tmp_path: Path) -> None:
    path = write_rule(
        tmp_path,
        {
            "rule_id": "DET-900",
            "title": "Incompatible event family",
            "description": "A sufficiently long description for this test.",
            "severity": "low",
            "event_types": ["authentication"],
            "detection": {
                "type": "match",
                "conditions": [
                    {"field": "process.name", "operator": "eq", "value": "powershell.exe"}
                ],
            },
        },
    )
    with pytest.raises(RuleValidationError, match="not available for every configured event type"):
        load_rules(path)
