"""CLI integration tests for JSONL ingestion."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from soc_sentinel.cli import main
from tests.test_schemas import authentication_event


def test_ingest_cli_reports_counts_and_persists_events(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
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
    assert "Unique valid records accepted by schema: 1" in output
    assert "Records rejected: 2" in output
    assert "Events inserted: 1" in output
    assert "line 2:" in output and "line 3:" in output
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone() == (1,)


def test_strict_cli_does_not_create_database_after_invalid_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "events.jsonl"
    database_path = tmp_path / "events.sqlite3"
    input_path.write_text("{invalid}\n", encoding="utf-8")

    status = main(["ingest", "--input", str(input_path), "--db", str(database_path), "--strict"])

    assert status == 2
    assert "line 1:" in capsys.readouterr().err
    assert not database_path.exists()


def test_repeated_cli_ingestion_skips_database_duplicates(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "events.jsonl"
    database_path = tmp_path / "events.sqlite3"
    input_path.write_text(json.dumps(authentication_event()), encoding="utf-8")

    assert main(["ingest", "--input", str(input_path), "--db", str(database_path)]) == 0
    capsys.readouterr()
    assert main(["ingest", "--input", str(input_path), "--db", str(database_path)]) == 0
    output = capsys.readouterr().out

    assert "Duplicates already in database: 1" in output
    assert "Events inserted: 0"


def test_missing_input_file_returns_io_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing_path = tmp_path / "no-such-file.jsonl"
    status = main(["ingest", "--input", str(missing_path), "--db", str(tmp_path / "db.sqlite3")])
    assert status == 1
    assert "cannot read input" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("event_type", "action", "extra"),
    [
        ("process", "execute", {"process": {"name": "demo", "pid": 12}}),
        ("network", "connect", {"destination_ip": "203.0.113.8"}),
    ],
)
def test_cli_accepts_non_authentication_event_families(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    event_type: str,
    action: str,
    extra: dict[str, Any],
) -> None:
    input_path = tmp_path / f"{event_type}.jsonl"
    db_path = tmp_path / "db.sqlite3"
    payload: dict[str, Any] = {
        "event_id": f"{event_type}-cli",
        "timestamp": "2026-10-10T06:30:00Z",
        "event_type": event_type,
        "host_id": "host-test",
        "action": action,
        "source_id": "cli-family-test",
        **extra,
    }
    input_path.write_text(json.dumps(payload), encoding="utf-8")

    assert main(["ingest", "--input", str(input_path), "--db", str(db_path)]) == 0
    output = capsys.readouterr().out
    assert "Events inserted: 1" in output
    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT event_type FROM events").fetchone() == (event_type,)
