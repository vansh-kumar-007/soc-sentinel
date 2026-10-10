"""CLI behavior tests."""

from __future__ import annotations

from soc_sentinel.cli import main


def test_version_flag(capsys) -> None:
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "soc-sentinel 0.1.0"


def test_check_db_creates_database(tmp_path, capsys) -> None:
    database_path = tmp_path / "nested" / "soc.sqlite3"

    assert main(["check-db", str(database_path)]) == 0
    assert database_path.is_file()
    assert "SQLite database ready:" in capsys.readouterr().out


def test_check_db_invalid_parent_returns_error(tmp_path, capsys) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("file blocks directory creation", encoding="utf-8")

    assert main(["check-db", str(blocker / "soc.sqlite3")]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "database initialization failed:" in captured.err
