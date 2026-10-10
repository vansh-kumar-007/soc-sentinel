"""End-to-end incident CLI tests using synthetic JSONL."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_sentinel.cli import main


def test_correlate_cli_is_repeatable_and_json_is_machine_readable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "cli.sqlite3"
    input_path = tmp_path / "auth.jsonl"
    records = [
        {
            "event_id": f"cli-failure-{index}",
            "timestamp": f"2026-10-10T00:00:{index:02d}Z",
            "event_type": "authentication",
            "host_id": "synthetic-host",
            "username": "alice",
            "source_ip": "192.0.2.55",
            "action": "login",
            "outcome": "failure",
            "source_id": "synthetic-cli-test",
        }
        for index in range(5)
    ]
    input_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )
    args = [
        "correlate",
        "--input",
        str(input_path),
        "--rules",
        str(Path(__file__).parents[1] / "rules"),
        "--db",
        str(db),
        "--policy",
        str(Path(__file__).parents[1] / "correlation.yaml"),
        "--json",
    ]
    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["alerts_generated"] >= 1
    assert first["incidents"]
    assert main(args) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["events_inserted"] == 0
    assert len(second["incidents"]) == len(first["incidents"])
    assert [item["incident_id"] for item in second["incidents"]] == [
        item["incident_id"] for item in first["incidents"]
    ]
