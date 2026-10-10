"""Command-line entry point for ingestion, detection, and incident investigation."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Sequence
from typing import Any

from soc_sentinel import __version__
from soc_sentinel.db import initialize_database, insert_events
from soc_sentinel.detection.engine import evaluate_events
from soc_sentinel.detection.rules import RuleValidationError, load_rules
from soc_sentinel.incident_cli import add_incident_parsers, handle_incident_command
from soc_sentinel.ingestion.jsonl import parse_jsonl_file


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-sentinel",
        description="Local-first detection engineering and incident investigation lab.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_db = subparsers.add_parser(
        "check-db", help="Initialize the local SQLite database (creates a file if needed)."
    )
    check_db.add_argument("path", help="Path to a local SQLite database file.")
    ingest = subparsers.add_parser(
        "ingest", help="Validate a JSONL file and store valid events in local SQLite."
    )
    ingest.add_argument("--input", required=True, help="Path to a UTF-8 JSONL file.")
    ingest.add_argument("--db", required=True, help="Destination SQLite database path.")
    ingest.add_argument(
        "--strict",
        action="store_true",
        help="Reject the batch without writing any events if any record is invalid.",
    )
    validate = subparsers.add_parser(
        "validate-rules", help="Safely parse and validate YAML detection rules."
    )
    validate.add_argument("--rules", required=True, help="Rule YAML file or directory.")
    detect = subparsers.add_parser(
        "detect", help="Evaluate normalized JSONL events against validated YAML rules."
    )
    detect.add_argument("--input", required=True, help="Path to a UTF-8 JSONL file.")
    detect.add_argument("--rules", required=True, help="Rule YAML file or directory.")
    detect.add_argument(
        "--strict",
        action="store_true",
        help="Abort detection if any nonblank input record is invalid.",
    )
    detect.add_argument(
        "--json", action="store_true", dest="json_output", help="Emit machine-readable JSON."
    )
    demo = subparsers.add_parser(
        "demo-seed", help="Run the bundled synthetic scenario in a separate demo database."
    )
    demo.add_argument("--db", default="data/soc-sentinel-demo.sqlite3")
    demo.add_argument(
        "--reset", action="store_true", help="Explicitly recreate a demo-named database."
    )
    demo.add_argument("--json", action="store_true", dest="json_output")
    evaluate = subparsers.add_parser(
        "evaluate", help="Measure detection quality against an independent synthetic benchmark."
    )
    evaluate.add_argument("--dataset", default="data/evaluation/benchmark.json")
    evaluate.add_argument("--rules", default="rules/")
    evaluate.add_argument("--output", default="reports/evaluation/")
    evaluate.add_argument("--json", action="store_true", dest="json_output")
    evaluate.add_argument(
        "--fail-on-mismatch", action="store_true",
        help="Return exit code 3 when the benchmark contains false positives or false negatives."
    )
    add_incident_parsers(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI.

    Exit codes: 0 success; 1 I/O/storage; 2 configuration; 3 evaluation mismatch or strict input;
    4 incident operation error.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "evaluate":
        from soc_sentinel.evaluation import EvaluationError, evaluate_dataset, write_reports

        try:
            report = evaluate_dataset(args.dataset, args.rules)
            json_path, markdown_path = write_reports(report, args.output)
        except EvaluationError as exc:
            print(f"soc-sentinel: evaluation failed: {exc}", file=sys.stderr)
            return 2
        if args.json_output:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            aggregate = report["aggregate"]
            print(f"Dataset: {report['dataset']['title']}")
            print(f"Scenarios: {report['summary']['scenario_count']}")
            print(
                f"TP: {aggregate['tp']}  FP: {aggregate['fp']}  "
                f"FN: {aggregate['fn']}  TN*: {aggregate['tn']}"
            )
            print(
                f"Precision: {aggregate['precision']}  Recall: {aggregate['recall']}  "
                f"F1: {aggregate['f1']}"
            )
            print(f"Reports: {json_path} and {markdown_path}")
            print("* TN is a supplemental count of negative scenario-rule opportunities.")
        if args.fail_on_mismatch and (report["aggregate"]["fp"] or report["aggregate"]["fn"]):
            return 3
        return 0
    if args.command == "demo-seed":
        from soc_sentinel.demo import seed_demo_database

        try:
            result = seed_demo_database(args.db, reset=args.reset)
        except (OSError, sqlite3.Error, RuntimeError) as exc:
            print(f"soc-sentinel: demo seeding failed: {exc}", file=sys.stderr)
            return 1
        except ValueError as exc:
            print(f"soc-sentinel: unsafe demo operation rejected: {exc}", file=sys.stderr)
            return 2
        if args.json_output:
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
        else:
            print(f"Demo database: {result['database']}")
            print(f"Reset performed: {result['reset_performed']}")
            print(
                f"Fixture records: {result['records_read']}; "
                f"inserted: {result['events_inserted']}; "
                f"duplicates: {result['event_duplicates']}; "
                f"rejected: {result['records_rejected']}"
            )
            print(f"Alerts generated: {result['alerts_generated']}")
            print(f"Incidents available: {len(result['incidents'])}")
            for incident in result["incidents"]:
                print(
                    f"- {incident['reference']} [{incident['status']}] "
                    f"{incident['title']} ({incident['alert_count']} alert(s))"
                )
        return 0
    if args.command in {
        "correlate",
        "list-incidents",
        "show-incident",
        "update-incident",
        "assign-analyst",
        "add-note",
        "resolve-incident",
        "reopen-incident",
        "incident-timeline",
        "incident-audit",
    }:
        return handle_incident_command(args)
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
        for issue in batch.issues:
            print(f"  line {issue.line_number}: {issue.message}")
        return 0
    if args.command == "validate-rules":
        try:
            rules = load_rules(args.rules)
        except RuleValidationError as exc:
            print(f"soc-sentinel: rule validation failed: {exc}", file=sys.stderr)
            return 2
        print(f"Rules loaded: {len(rules)}")
        print(f"Rules enabled: {sum(rule.enabled for rule in rules)}")
        for rule in rules:
            print(f"  {rule.rule_id} [{rule.severity.value}] {rule.title}")
        return 0
    if args.command == "detect":
        try:
            rules = load_rules(args.rules)
        except RuleValidationError as exc:
            print(f"soc-sentinel: rule validation failed: {exc}", file=sys.stderr)
            return 2
        try:
            batch = parse_jsonl_file(args.input, strict=args.strict)
        except (OSError, UnicodeError) as exc:
            print(f"soc-sentinel: cannot read input: {exc}", file=sys.stderr)
            return 1
        except ValueError as exc:
            print(f"soc-sentinel: strict detection rejected input: {exc}", file=sys.stderr)
            return 3
        alerts = evaluate_events(batch.events, rules)
        if args.json_output:
            output: dict[str, Any] = {
                "input": args.input,
                "records_read": batch.records_read,
                "events_evaluated": len(batch.events),
                "records_rejected": batch.records_rejected,
                "duplicate_records": batch.duplicate_records,
                "alerts_triggered": len(alerts),
                "alerts": [alert.model_dump(mode="json") for alert in alerts],
                "issues": [
                    {"line_number": issue.line_number, "message": issue.message}
                    for issue in batch.issues
                ],
            }
            print(json.dumps(output, indent=2, sort_keys=True))
            return 0
        print(f"Input: {args.input}")
        print(f"Rules loaded: {len(rules)} ({sum(rule.enabled for rule in rules)} enabled)")
        print(f"Records read: {batch.records_read}")
        print(f"Events evaluated: {len(batch.events)}")
        print(f"Records rejected: {batch.records_rejected}")
        print(f"Duplicate records in input: {batch.duplicate_records}")
        print(f"Alerts triggered: {len(alerts)}")
        for alert in alerts:
            print(
                f"- {alert.rule_id} [{alert.severity.value}] {alert.rule_title} "
                f"(alert_id={alert.alert_id})"
            )
            print(f"  Group: {json.dumps(alert.grouping_context, sort_keys=True)}")
            print(f"  Events: {alert.event_count}; evidence: {', '.join(alert.evidence_event_ids)}")
            print(f"  Rationale: {alert.rationale}")
        for issue in batch.issues:
            print(f"  line {issue.line_number}: {issue.message}", file=sys.stderr)
        return 0
    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
