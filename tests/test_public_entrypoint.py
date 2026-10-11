"""Tests for the root public-host entry point's fail-safe configuration."""

from __future__ import annotations

import os
import runpy
import tempfile
from pathlib import Path

import soc_sentinel.dashboard as dashboard


def test_public_entrypoint_forces_read_only_mode_and_ignores_analyst_db(
    tmp_path: Path, monkeypatch
) -> None:
    captured: dict[str, str | None] = {}
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setenv("SOC_SENTINEL_MODE", "local-analyst")
    monkeypatch.setenv("SOC_SENTINEL_DB", str(tmp_path / "analyst.sqlite3"))
    monkeypatch.setattr(
        dashboard,
        "main",
        lambda: captured.update(
            mode=os.environ.get("SOC_SENTINEL_MODE"),
            database=os.environ.get("SOC_SENTINEL_DB"),
        ),
    )

    entrypoint = Path(__file__).parents[1] / "streamlit_app.py"
    runpy.run_path(str(entrypoint))

    assert captured["mode"] == "public-demo"
    assert captured["database"] == str(
        tmp_path / f"soc-sentinel-public-demo-{os.getpid()}.sqlite3"
    )
