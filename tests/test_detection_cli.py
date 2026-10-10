"""Integration tests for rule-validation and detection CLI commands."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from soc_sentinel.cli import main
from soc_sentinel.schemas import SecurityEvent


ROOT = Path(__file__).parents[1]
RULES = ROOT / "rules"


def auth_event(event_id: str, second: int) -> SecurityEvent:
    timestamp = datetime(2026, 10, 10, tzinfo=UTC) + timedelta(seconds=second)
    return SecurityEvent.model_validate(
        {
            "event_id": event_id,
            "timestamp": timestamp.isoformat(),
            "event_type": "authentication",
            "host_id": "cli-test-host",
            "username": "alice",
            "source_ip": "192.0.2.10",
            "action": "login",
            "outcome": "failure",
            "source_id": "synthetic-cli-test",
        }
    )


def test_validate_rules_cli_reports_shipped_rule_count(capsys: pytest.CaptureFixture[str]) -> None:
    status = main(["validate-rules", "--rules", str(RULES)])
    output = capsys.readouterr().out

    assert status == 0
    assert "Rules loaded: 3" in output
    assert "DET-001" in output and "DET-002" in output and "DET-003" in output


def test_validate_rules_cli_returns_two_for_invalid_yaml(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "invalid.yaml").write_text("not: [valid", encoding="utf-8")
    status = main(["validate-rules", "--rules", str(tmp_path)])
    assert status == 2
    assert "rule validation failed" in capsys.readouterr().err


def test_detect_cli_emits_machine_readable_alerts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "events.jsonl"
    events = [auth_event(f"cli-{i}", i) for i in range(5)]
    input_path.write_text(
        "\n".join(event.model_dump_json() for event in events),
        encoding="utf-8",
    )

    status = main(
        [
            "detect",
            "--input",
            str(input_path),
            "--rules",
            str(RULES),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert output["alerts_triggered"] == 1
    assert output["alerts"][0]["rule_id"] == "DET-001"
    assert output["alerts"][0]["evidence_event_ids"] == [f"cli-{i}" for i in range(5)]


def test_detect_cli_strict_mode_returns_three_for_bad_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "events.jsonl"
    input_path.write_text("{invalid-json}\n", encoding="utf-8")

    status = main(
        [
            "detect",
            "--input",
            str(input_path),
            "--rules",
            str(RULES),
            "--strict",
        ]
    )

    assert status == 3
    assert "strict detection rejected input" in capsys.readouterr().err
