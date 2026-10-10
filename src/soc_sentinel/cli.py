"""Command-line entry point for foundation and ingestion operations."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections.abc import Sequence
from soc_sentinel import __version__
from soc_sentinel.db import initialize_database, insert_events
from soc_sentinel.ingestion.jsonl import parse_jsonl_file


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-sentinel",
        description="Local-first detection engineering and incident investigation lab.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_db = subparsers.add_parser(
        "check-db",
        help="Initialize the local SQLite database (creates a file if needed).",
    )
    check_db.add_argument("path", help="Path to a local SQLite database file.")

    ingest = subparsers.add_parser(
        "ingest",
        help="Validate a JSONL file and store valid events in local SQLite.",
    )
    ingest.add_argument("--input", required=True, help="Path to a UTF-8 JSONL file.")
    ingest.add_argument("--db", required=True, help="Destination SQLite database path.")
    ingest.add_argument(
        "--strict",
        action="store_true",
        help="Reject the batch without writing any events if any record is invalid.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit status.

    Exit codes: 0 = ingestion completed (non-strict mode may reject individual lines),
    1 = I/O or database failure, 2 = strict validation failure.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "check-db":
        try:
            database_path = initialize_database(args.path)
        except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
            print(f"soc-sentinel: database initialization failed: {exc}", file=sys.stderr)
            return 1
        print(f"SQLite database ready: {database_path}")
        return 0

    if args.command == "ingest":
        try:
            batch = parse_jsonl_file(args.input, strict=args.strict)
        except (OSError, UnicodeError) as exc:
            print(f"soc-sentinel: cannot read input: {exc}", file=sys.stderr)
            return 1
        except ValueError as exc:
            print(f"soc-sentinel: strict ingestion rejected input: {exc}", file=sys.stderr)
            return 2

        try:
            database_path, inserted, duplicates = insert_events(args.db, batch.events)
        except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
            print(f"soc-sentinel: database ingestion failed: {exc}", file=sys.stderr)
            return 1

        print(f"Input: {args.input}")
        print(f"Database: {database_path}")
        print(f"Records read: {batch.records_read}")
        print(f"Unique valid records accepted by schema: {len(batch.events)}")
        print(f"Records rejected: {batch.records_rejected}")
        print(f"Duplicate records in input: {batch.duplicate_records}")
        print(f"Duplicates already in database: {duplicates}")
        print(f"Events inserted: {inserted}")
        if batch.issues:
            print("Validation issues:")
            for issue in batch.issues:
                print(f"  line {issue.line_number}: {issue.message}")
        return 0

    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
