"""End-to-end incident CLI tests using the bundled synthetic JSONL fixture."""
from __future__ import annotations
import json
from pathlib import Path
import pytest
from soc_sentinel.cli import main

ROOT = Path(__file__).parents[1]

def test_correlate_cli_is_repeatable_and_json_is_machine_readable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "cli.sqlite3"
    args = ["correlate", "--input", str(ROOT / "data/samples/authentication.jsonl"),
            "--rules", str(ROOT / "rules"), "--db", str(db),
            "--policy", str(ROOT / "correlation.yaml"), "--json"]
    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert "alerts_generated" in first and "incidents" in first
    assert first["incidents"]
    assert main(args) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["events_inserted"] == 0
    assert len(second["incidents"]) == len(first["incidents"])
    assert [item["incident_id"] for item in second["incidents"]] == [
        item["incident_id"] for item in first["incidents"]]
