"""Command-line entry point for foundation-level operations."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections.abc import Sequence

from soc_sentinel import __version__
from soc_sentinel.db import initialize_database


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-sentinel",
        description="Local-first detection engineering and incident investigation lab.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_db = subparsers.add_parser(
        "check-db",
        help="Initialize the local SQLite database (creates a file if needed).",
    )
    check_db.add_argument("path", help="Path to a local SQLite database file.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit status."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "check-db":
        try:
            database_path = initialize_database(args.path)
        except (OSError, sqlite3.Error) as exc:
            print(f"soc-sentinel: database initialization failed: {exc}", file=sys.stderr)
            return 1
        print(f"SQLite database ready: {database_path}")
        return 0

    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
