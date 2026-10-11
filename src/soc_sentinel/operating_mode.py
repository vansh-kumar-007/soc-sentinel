"""Fail-safe operating modes for the Streamlit dashboard and its service layer."""

from __future__ import annotations

import os

LOCAL_ANALYST = "local-analyst"
PUBLIC_DEMO = "public-demo"
_VALID_MODES = {LOCAL_ANALYST, PUBLIC_DEMO}


class OperatingModeError(RuntimeError):
    """Raised when dashboard mode configuration is invalid or a write is forbidden."""


def operating_mode() -> str:
    """Return the explicit dashboard mode; local analyst mode preserves existing local use."""
    value = os.environ.get("SOC_SENTINEL_MODE", LOCAL_ANALYST).strip().casefold()
    if value not in _VALID_MODES:
        raise OperatingModeError(
            "SOC_SENTINEL_MODE must be 'local-analyst' or 'public-demo'; refusing access."
        )
    return value


def require_analyst_mode() -> None:
    """Reject every dashboard-service write when running as a public demonstration."""
    if operating_mode() != LOCAL_ANALYST:
        raise OperatingModeError(
            "This dashboard is read-only in public-demo mode; use local analyst mode for writes."
        )
