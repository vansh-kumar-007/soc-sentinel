"""CLI integration tests for JSONL ingestion."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from soc_sentinel.cli import main
from tests.test_schemas import authentication_event


def test_ingest_cli_reports_counts_and_persists_events(
    tmp_path: Path, capsys
) -> None:
    input_path = tmp_path / "events.jsonl"
    database_path = tmp_path / "events.sqlite3"
    invalid = {"event_id": "bad", "event_type": "authentication"}
    input_path.write_text(
        "\n".join([json.dumps(authentication_event()), "{bad json}", json.dumps(invalid)]),
        encoding="utf-8",
    )

    status = main(["ingest", "--input", str(input_path), "--db", str(database_path)])
    output = capsys.readouterr().out

    assert status == 0
    assert "Records read: 3" in output
    assert "Records accepted by schema: 1" in output
    assert "Records rejected: 2" in output
    assert "Events inserted: 1" in output
    assert "line 2:" in output and "line 3:" in output
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone() == (1,)


def test_strict_cli_does_not_create_database_after_invalid_input(
    tmp_path: Path, capsys
) -> None:
    input_path = tmp_path / "events.jsonl"
    database_path = tmp_path / "events.sqlite3"
    input_path.write_text("{invalid}\n", encoding="utf-8")

    status = main(
        ["ingest", "--input", str(input_path), "--db", str(database_path), "--strict"]
    )

    assert status == 2
    assert "line 1:" in capsys.readouterr().err
    assert not database_path.exists()


def test_repeated_cli_ingestion_skips_database_duplicates(
    tmp_path: Path, capsys
) -> None:
    input_path = tmp_path / "events.jsonl"
    database_path = tmp_path / "events.sqlite3"
    input_path.write_text(json.dumps(authentication_event()), encoding="utf-8")

    assert main(["ingest", "--input", str(input_path), "--db", str(database_path)]) == 0
    capsys.readouterr()
    assert main(["ingest", "--input", str(input_path), "--db", str(database_path)]) == 0
    output = capsys.readouterr().out

    assert "Duplicates already in database: 1" in output
    assert "Events inserted: 0" in output
