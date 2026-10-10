"""CLI adapters for local incident investigation operations."""

from __future__ import annotations
import argparse
import json
import sqlite3
import sys
from typing import Any
from soc_sentinel.correlation import CorrelationPolicyError, load_correlation_policy
from soc_sentinel.db import insert_events
from soc_sentinel.detection.engine import evaluate_events
from soc_sentinel.detection.rules import RuleValidationError, load_rules
from soc_sentinel.ingestion.jsonl import parse_jsonl_file
from soc_sentinel.incidents import (
    IncidentStatus,
    ResolutionClassification,
    add_note,
    assign_analyst,
    correlate_and_persist,
    incident_audit_history,
    incident_timeline,
    list_incidents,
    show_incident,
    update_status,
)


def add_incident_parsers(subparsers: Any) -> None:
    p = subparsers.add_parser("correlate", help="Detect, correlate, and persist incidents.")
    p.add_argument("--input", required=True)
    p.add_argument("--rules", required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--policy", default="correlation.yaml")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--json", action="store_true", dest="json_output")
    p.add_argument("--actor", default="system")
    p = subparsers.add_parser("list-incidents", help="List local incident cases.")
    p.add_argument("--db", required=True)
    p.add_argument("--status", choices=[x.value for x in IncidentStatus])
    p.add_argument("--json", action="store_true", dest="json_output")
    p = subparsers.add_parser(
        "show-incident", help="Inspect incident, alerts, explanations, notes, and timeline."
    )
    p.add_argument("--db", required=True)
    p.add_argument("--incident-id", required=True)
    p.add_argument("--json", action="store_true", dest="json_output")
    p = subparsers.add_parser(
        "update-incident", help="Change lifecycle status with optimistic concurrency."
    )
    p.add_argument("--db", required=True)
    p.add_argument("--incident-id", required=True)
    p.add_argument("--status", required=True, choices=[x.value for x in IncidentStatus])
    p.add_argument("--version", required=True, type=int)
    p.add_argument("--actor", default="analyst")
    p.add_argument("--classification", choices=[x.value for x in ResolutionClassification])
    p.add_argument("--summary")
    p = subparsers.add_parser("assign-analyst", help="Assign or unassign an analyst.")
    p.add_argument("--db", required=True)
    p.add_argument("--incident-id", required=True)
    p.add_argument("--analyst")
    p.add_argument("--version", required=True, type=int)
    p.add_argument("--actor", default="analyst")
    p = subparsers.add_parser("add-note", help="Append a timestamped investigation note.")
    p.add_argument("--db", required=True)
    p.add_argument("--incident-id", required=True)
    p.add_argument("--note", required=True)
    p.add_argument("--actor", default="analyst")
    p.add_argument("--version", type=int)
    p = subparsers.add_parser("resolve-incident", help="Resolve with a classification and summary.")
    p.add_argument("--db", required=True)
    p.add_argument("--incident-id", required=True)
    p.add_argument("--version", required=True, type=int)
    p.add_argument(
        "--classification", required=True, choices=[x.value for x in ResolutionClassification]
    )
    p.add_argument("--summary", required=True)
    p.add_argument("--actor", default="analyst")
    p = subparsers.add_parser(
        "reopen-incident", help="Reopen a resolved incident while preserving audit history."
    )
    p.add_argument("--db", required=True)
    p.add_argument("--incident-id", required=True)
    p.add_argument("--version", required=True, type=int)
    p.add_argument("--actor", default="analyst")
    for name, help_text in [
        ("incident-timeline", "Show chronological evidence and investigation timeline."),
        ("incident-audit", "Show lifecycle and investigation audit history."),
    ]:
        p = subparsers.add_parser(name, help=help_text)
        p.add_argument("--db", required=True)
        p.add_argument("--incident-id", required=True)
        p.add_argument("--json", action="store_true", dest="json_output")


def _emit(value: Any, json_output: bool) -> None:
    if json_output:
        print(json.dumps(value, indent=2, sort_keys=True, default=str))
        return
    if isinstance(value, list):
        if not value:
            print("No incidents found.")
        for item in value:
            if hasattr(item, "reference"):
                print(
                    f"{item.reference} [{item.status.value}] [{item.severity.value}] {item.title} — {item.alert_count} alert(s), {item.event_count} event(s)"
                )
                print(f"  ID: {item.incident_id}; version: {item.version}")
                if item.assigned_analyst:
                    print(f"  Analyst: {item.assigned_analyst}")
            else:
                print(json.dumps(item, sort_keys=True, default=str))
    else:
        print(json.dumps(value, indent=2, sort_keys=True, default=str))


def handle_incident_command(args: argparse.Namespace) -> int:
    """Run an incident command; 0 success, 1 I/O/storage, 2 config, 3 strict input, 4 operation error."""
    try:
        if args.command == "correlate":
            rules = load_rules(args.rules)
            policy = load_correlation_policy(args.policy)
            batch = parse_jsonl_file(args.input, strict=args.strict)
            database_path, inserted, duplicates = insert_events(args.db, batch.events)
            alerts = evaluate_events(batch.events, rules)
            incidents = correlate_and_persist(
                database_path, alerts, batch.events, policy, actor=args.actor
            )
            output = {
                "database": str(database_path),
                "events_inserted": inserted,
                "event_duplicates": duplicates,
                "records_rejected": batch.records_rejected,
                "alerts_generated": len(alerts),
                "incidents": [item.model_dump(mode="json") for item in incidents],
                "issues": [
                    {"line_number": issue.line_number, "message": issue.message}
                    for issue in batch.issues
                ],
            }
            if args.json_output:
                _emit(output, True)
            else:
                print(f"Database: {database_path}")
                print(f"Events inserted: {inserted}; existing event IDs skipped: {duplicates}")
                print(f"Alerts generated: {len(alerts)}; incidents stored: {len(incidents)}")
                _emit(incidents, False)
                for issue in batch.issues:
                    print(
                        f"Input issue at line {issue.line_number}: {issue.message}", file=sys.stderr
                    )
            return 0
        if args.command == "list-incidents":
            incidents = list_incidents(args.db, status=args.status)
            _emit(
                [item.model_dump(mode="json") for item in incidents]
                if args.json_output
                else incidents,
                args.json_output,
            )
            return 0
        if args.command == "show-incident":
            _emit(show_incident(args.db, args.incident_id), args.json_output)
            return 0
        if args.command in {"update-incident", "resolve-incident", "reopen-incident"}:
            if args.command == "reopen-incident":
                status, classification, summary = IncidentStatus.OPEN, None, None
            elif args.command == "resolve-incident":
                status, classification, summary = (
                    IncidentStatus.RESOLVED,
                    ResolutionClassification(args.classification),
                    args.summary,
                )
            else:
                status = IncidentStatus(args.status)
                classification = (
                    ResolutionClassification(args.classification) if args.classification else None
                )
                summary = args.summary
            incident = update_status(
                args.db,
                args.incident_id,
                status,
                args.version,
                actor=args.actor,
                classification=classification,
                summary=summary,
            )
            _emit(incident.model_dump(mode="json"), True)
            return 0
        if args.command == "assign-analyst":
            _emit(
                assign_analyst(
                    args.db, args.incident_id, args.analyst, args.version, actor=args.actor
                ).model_dump(mode="json"),
                True,
            )
            return 0
        if args.command == "add-note":
            _emit(
                add_note(
                    args.db,
                    args.incident_id,
                    args.note,
                    actor=args.actor,
                    expected_version=args.version,
                ),
                True,
            )
            return 0
        if args.command == "incident-timeline":
            _emit(incident_timeline(args.db, args.incident_id), args.json_output)
            return 0
        if args.command == "incident-audit":
            _emit(incident_audit_history(args.db, args.incident_id), args.json_output)
            return 0
    except (OSError, UnicodeError) as exc:
        print(f"soc-sentinel: incident command could not read input: {exc}", file=sys.stderr)
        return 1
    except sqlite3.Error as exc:
        print(f"soc-sentinel: incident database operation failed: {exc}", file=sys.stderr)
        return 1
    except (RuleValidationError, CorrelationPolicyError) as exc:
        print(f"soc-sentinel: configuration validation failed: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        if args.command == "correlate" and args.strict:
            print(f"soc-sentinel: strict incident input rejected: {exc}", file=sys.stderr)
            return 3
        print(f"soc-sentinel: incident operation failed: {exc}", file=sys.stderr)
        return 4
    return 4
