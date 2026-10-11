"""Safe entry point for a public, synthetic-only SOC Sentinel demonstration.

Deploy this file on Streamlit Community Cloud. It forces read-only mode and a
disposable database path; local analysts should use docs/DASHBOARD.md instead.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def main() -> None:
    configured_mode = os.environ.get("SOC_SENTINEL_MODE")
    if configured_mode is None:
        os.environ["SOC_SENTINEL_MODE"] = "public-demo"
    elif configured_mode.strip().casefold() in {"local-analyst", "public-demo"}:
        # This entry point is for hosting only: never expose analyst writes publicly.
        os.environ["SOC_SENTINEL_MODE"] = "public-demo"
    os.environ["SOC_SENTINEL_DB"] = str(
        Path(tempfile.gettempdir()) / f"soc-sentinel-public-demo-{os.getpid()}.sqlite3"
    )
    from soc_sentinel.dashboard import main as run_dashboard

    run_dashboard()


main()
