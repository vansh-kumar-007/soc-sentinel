"""Safe, reproducible synthetic demonstration database workflow."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from soc_sentinel.dashboard_services import PROJECT_ROOT, run_synthetic_investigation
from soc_sentinel.operating_mode import require_analyst_mode

DEFAULT_DEMO_DATABASE = PROJECT_ROOT / "data" / "soc-sentinel-demo.sqlite3"
PROTECTED_DATABASE = (PROJECT_ROOT / "data" / "soc-sentinel.sqlite3").resolve()


def seed_demo_database(
    database_path: str | Path = DEFAULT_DEMO_DATABASE, *, reset: bool = False
) -> dict[str, Any]:
    """Seed a demo database. Reset requires explicit intent and a demo-named target."""
    require_analyst_mode()
    path = Path(database_path).expanduser().resolve()
    if path == PROTECTED_DATABASE:
        raise ValueError("Refusing to use the default working database as a demo reset target.")
    if reset:
        if "demo" not in path.name.casefold():
            raise ValueError(
                "Refusing --reset: target filename must contain 'demo'. Use "
                "data/soc-sentinel-demo.sqlite3 to keep demo state separate."
            )
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
            try:
                candidate.unlink(missing_ok=True)
            except OSError as exc:
                raise OSError(f"Could not reset demo database {candidate}: {exc}") from exc
    result = run_synthetic_investigation(path, fixture_key="soc_demo", rule_profile="all")
    result["reset_performed"] = reset
    return result


def validate_demo_database(path: str | Path) -> bool:
    """Validate an existing schema-v3 file using a read-only connection."""
    candidate = Path(path).expanduser().resolve()
    if not candidate.is_file():
        return False
    try:
        connection = sqlite3.connect(f"{candidate.as_uri()}?mode=ro", uri=True, timeout=3)
        try:
            row = connection.execute(
                "SELECT value FROM schema_metadata WHERE key='schema_version'"
            ).fetchone()
            return row is not None and row[0] == "3"
        finally:
            connection.close()
    except sqlite3.Error:
        return False
