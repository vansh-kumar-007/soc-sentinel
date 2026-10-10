"""Local Streamlit SOC investigation workspace.

Run: streamlit run src/soc_sentinel/dashboard.py --server.address 127.0.0.1
"""

from __future__ import annotations

import importlib
import os
import sqlite3
from datetime import date
from pathlib import Path
from typing import Any

from soc_sentinel.correlation import CorrelationPolicyError
from soc_sentinel.dashboard_services import (
    PROJECT_ROOT,
    DashboardServiceError,
    add_investigation_note,
    assign_incident_to_analyst,
    change_incident_status,
    get_dashboard_summary,
    get_incident_details,
    list_dashboard_alerts,
    list_dashboard_incidents,
    reopen_incident,
    resolve_incident,
)
from soc_sentinel.incidents import IncidentError

st: Any = importlib.import_module("streamlit")

DB_PATH = Path(
    os.environ.get("SOC_SENTINEL_DB", str(PROJECT_ROOT / "data" / "soc-sentinel-demo.sqlite3"))
).expanduser()
SEVERITIES = ["critical", "high", "medium", "low", "informational"]
STATUSES = ["open", "in_progress", "resolved", "closed"]
RESOLUTIONS = ["true_positive", "benign_positive", "false_positive", "inconclusive"]
SEVERITY_DISPLAY = {
    "critical": "🟥 CRITICAL",
    "high": "🟧 HIGH",
    "medium": "🟨 MEDIUM",
    "low": "🟦 LOW",
    "informational": "⬜ INFORMATIONAL",
}


def severity_label(value: str) -> str:
    """Use consistent severity labels without rendering telemetry as HTML."""
    return SEVERITY_DISPLAY.get(value, "⬜ UNKNOWN")


PAGES = ["Operations overview", "Incident explorer", "Alerts & evidence", "Synthetic lab", "Detection evaluation"]
CSS = """
<style>
.block-container{padding-top:1.5rem;padding-bottom:2.5rem;max-width:1500px}
[data-testid="stSidebar"]{border-right:1px solid #27313d}
[data-testid="stMetric"]{background:#111821;border:1px solid #27313d;border-radius:10px;padding:13px 16px}
[data-testid="stMetricLabel"]{color:#9aa9ba;font-size:.82rem}
[data-testid="stMetricValue"]{color:#edf4fb}
h1,h2,h3{letter-spacing:-.025em}
.ss-kicker{color:#56c5b4;text-transform:uppercase;letter-spacing:.13em;font-size:.72rem;font-weight:700}
.ss-panel{border:1px solid #27313d;border-radius:10px;padding:16px;background:#111821}
.ss-muted{color:#9aa9ba;font-size:.88rem}
</style>
"""


def header(title: str, subtitle: str) -> None:
    st.markdown(
        '<div class="ss-kicker">SOC SENTINEL / LOCAL OPERATIONS</div>', unsafe_allow_html=True
    )
    st.title(title)
    st.caption(subtitle)


def empty(title: str, text: str) -> None:
    st.markdown(
        f'<div class="ss-panel"><h3>{title}</h3><p class="ss-muted">{text}</p></div>',
        unsafe_allow_html=True,
    )


def short(value: Any, limit: int = 110) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def incident_table(items: list[dict[str, Any]]) -> None:
    st.dataframe(
        [
            {
                "Reference": item["reference"],
                "Title": item["title"],
                "Severity": severity_label(item["severity"]),
                "Status": item["status"].replace("_", " ").title(),
                "First observed (UTC)": item["first_observed"],
                "Last observed (UTC)": item["last_observed"],
                "Alerts": item["alert_count"],
                "Events": item["event_count"],
                "Analyst": item.get("assigned_analyst") or "Unassigned",
                "Incident ID": item["incident_id"],
            }
            for item in items
        ],
        use_container_width=True,
        hide_index=True,
    )


def overview(db: Path) -> None:
    header(
        "Operations overview",
        "Database-backed situational awareness for the local investigation queue.",
    )
    summary = get_dashboard_summary(db)
    metrics = st.columns(5)
    for col, label, key in zip(
        metrics,
        ["Incidents", "Open", "In progress", "Alerts", "Resolved / closed"],
        ["total_incidents", "open_incidents", "in_progress_incidents", "total_alerts", None],
        strict=True,
    ):
        value = (
            (summary["resolved_incidents"] + summary["closed_incidents"])
            if key is None
            else summary[key]
        )
        col.metric(label, value)
    st.caption(
        "Counts reflect persisted records only. Workflow status is not a maliciousness verdict."
    )
    left, right = st.columns([1, 1.5])
    with left:
        st.subheader("Alerts by severity")
        if summary["total_alerts"]:
            st.bar_chart(
                {
                    "severity": [row["severity"] for row in summary["alerts_by_severity"]],
                    "count": [row["count"] for row in summary["alerts_by_severity"]],
                },
                x="severity",
                y="count",
                horizontal=True,
            )
        else:
            empty("No alerts yet", "Run the synthetic walkthrough to populate the severity chart.")
        st.subheader("Frequently involved entities")
        hosts, users = st.columns(2)
        with hosts:
            st.caption("Hosts")
            st.dataframe(summary["top_hosts"], hide_index=True, use_container_width=True)
        with users:
            st.caption("Users")
            st.dataframe(summary["top_users"], hide_index=True, use_container_width=True)
    with right:
        st.subheader("Incident creation activity")
        if summary["activity"]:
            st.line_chart(
                {
                    "date": [row["date"] for row in summary["activity"]],
                    "incidents": [row["incidents"] for row in summary["activity"]],
                },
                x="date",
                y="incidents",
            )
        else:
            empty(
                "No activity recorded", "Creation activity appears after incidents are persisted."
            )
        st.subheader("Recently updated")
        if summary["recent_incidents"]:
            incident_table(summary["recent_incidents"])
            choices = {
                f"{i['reference']} · {i['title']}": i["incident_id"]
                for i in summary["recent_incidents"]
            }
            chosen = st.selectbox("Open a recent incident", list(choices))
            if st.button("Investigate selected incident", type="primary"):
                st.session_state["selected_incident"] = choices[chosen]
                st.session_state["navigation"] = "Incident explorer"
                st.rerun()
        else:
            empty(
                "Your queue is clear", "Use Synthetic lab to generate fictional security activity."
            )
    with st.expander("Metric definitions"):
        st.json(summary["definitions"])


def workspace(db: Path, incident_id: str) -> None:
    data = get_incident_details(db, incident_id)
    inc = data["incident"]
    top, state = st.columns([3, 1])
    with top:
        st.markdown(f'<div class="ss-kicker">{inc["reference"]}</div>', unsafe_allow_html=True)
        st.subheader(inc["title"])
        st.write(inc["summary"])
    with state:
        st.metric("Severity", severity_label(inc["severity"]))
        st.metric("Status", inc["status"].replace("_", " ").title())
        st.caption(f"Version {inc['version']} · optimistic concurrency")
    cols = st.columns(4)
    for col, label, value in zip(
        cols,
        ["Alerts", "Evidence events", "First observed", "Last observed"],
        [inc["alert_count"], inc["event_count"], inc["first_observed"], inc["last_observed"]],
        strict=True,
    ):
        col.metric(label, str(value)[:19].replace("T", " ") if isinstance(value, str) else value)
    st.caption(
        f"Incident ID: {inc['incident_id']} · Analyst: {inc.get('assigned_analyst') or 'Unassigned'}"
    )
    if inc.get("resolution_classification"):
        st.info(
            f"Resolution: {inc['resolution_classification']} — {inc.get('resolution_summary') or ''}"
        )
    entity_cols = st.columns(max(1, len(inc["entities"])))
    for col, (kind, values) in zip(entity_cols, sorted(inc["entities"].items()), strict=False):
        with col:
            st.caption(kind.replace("_", " ").title())
            st.write(", ".join(values) or "Not recorded")

    tabs = st.tabs(
        ["Overview", "Alerts & evidence", "Timeline", "Correlation", "Notes", "Audit", "Manage"]
    )
    with tabs[0]:
        st.markdown("#### Investigation context")
        st.write(inc["summary"])
        st.json(inc["entities"])
        st.caption(f"{len(data['evidence_events'])} source event record(s) available.")
        if data["missing_event_ids"]:
            st.warning("Source details unavailable for: " + ", ".join(data["missing_event_ids"]))
    with tabs[1]:
        if not data["alerts"]:
            st.info("No linked alerts are stored for this incident.")
        for alert in data["alerts"]:
            with st.expander(
                f"{alert['rule_id']} · {severity_label(alert['severity'])} · {alert['alert_id']}",
                expanded=len(data["alerts"]) == 1,
            ):
                st.markdown(f"**{alert['rule_title']}**")
                st.caption(
                    f"{alert['first_observed']} → {alert['last_observed']} · {alert['event_count']} event(s)"
                )
                st.markdown("**Detection rationale**")
                st.write(alert["rationale"])
                st.markdown("**Grouping context**")
                st.json(alert["grouping_context"])
                st.caption("ATT&CK: " + (", ".join(alert.get("mitre_attack", [])) or "Not mapped"))
                for event_id in alert["evidence_event_ids"]:
                    event = data["evidence_events"].get(event_id)
                    with st.container(border=True):
                        st.code(event_id)
                        if event:
                            st.caption(
                                f"{event['timestamp']} · {event['source_id']} · source telemetry"
                            )
                            st.json(
                                {
                                    key: event.get(key)
                                    for key in (
                                        "event_type",
                                        "host_id",
                                        "username",
                                        "source_ip",
                                        "destination_ip",
                                        "action",
                                        "outcome",
                                        "process",
                                        "attributes",
                                    )
                                }
                            )
                        else:
                            st.warning("Source event unavailable; evidence reference retained.")
    with tabs[2]:
        timeline = data["timeline"]
        kinds = sorted({item.get("kind", "entry") for item in timeline})
        selected = st.multiselect("Timeline entry types", kinds, default=kinds)
        visible = [item for item in timeline if item.get("kind", "entry") in selected]
        st.caption(
            "UTC order is deterministic. Security-event and application-audit clocks are distinguished."
        )
        st.dataframe(
            [
                {
                    "Timestamp": item["timestamp"],
                    "Clock": item["timestamp_type"],
                    "Entry": item["kind"],
                    "Provenance": item["provenance"],
                    "Actor": item.get("actor", ""),
                    "Alert": item.get("alert_id", ""),
                    "Event": item.get("event_id", ""),
                    "Details": short(
                        item.get("note")
                        or item.get("explanation")
                        or item.get("rationale")
                        or item.get("details")
                        or item.get("strategy")
                    ),
                }
                for item in visible
            ],
            use_container_width=True,
            hide_index=True,
        )
        if visible:
            idx = st.selectbox(
                "Inspect timeline entry",
                range(len(visible)),
                format_func=lambda n: (
                    f"{visible[n]['timestamp']} · {visible[n]['kind']} · "
                    f"{visible[n].get('event_id', visible[n].get('alert_id', ''))}"
                ),
            )
            st.json(visible[idx])
    with tabs[3]:
        if not data["correlation_explanations"]:
            st.info("No pairwise correlation explanation is stored.")
        for item in data["correlation_explanations"]:
            with st.container(border=True):
                st.markdown(f"**{item['strategy']}** · {item['time_gap_seconds']:g}s gap")
                st.write(item["explanation"])
                st.caption(f"{item['alert_id']} related to {item['related_alert_id']}")
                st.json(item["shared_values"])
        st.caption("Correlation provides an investigative lead, not proof of compromise.")
    with tabs[4]:
        if data["notes"]:
            st.dataframe(data["notes"], use_container_width=True, hide_index=True)
        else:
            st.info("No investigation notes yet.")
        with st.form("note_form", clear_on_submit=True):
            actor = st.text_input("Analyst label", value="analyst")
            note = st.text_area(
                "Investigation note", placeholder="Record evidence reviewed and next steps…"
            )
            add = st.form_submit_button("Add note", type="primary")
        if add:
            try:
                saved = add_investigation_note(
                    db,
                    inc["incident_id"],
                    note,
                    expected_version=inc["version"],
                    actor=actor.strip() or "analyst",
                )
                st.success(f"Note saved at {saved['created_at']}.")
                st.rerun()
            except (IncidentError, DashboardServiceError, sqlite3.Error, OSError) as exc:
                st.error(f"Note was not saved: {exc}")
                st.caption("Reload the incident if its version changed.")
    with tabs[5]:
        audit = data["timeline"]
        audit_rows = [item for item in audit if item.get("timestamp_type") == "application_audit"]
        st.dataframe(
            [
                {
                    "Timestamp": item["timestamp"],
                    "Action": item["kind"],
                    "Provenance": item["provenance"],
                    "Actor": item.get("actor", ""),
                    "Details": short(
                        item.get("details") or item.get("note") or item.get("explanation")
                    ),
                }
                for item in audit_rows
            ],
            use_container_width=True,
            hide_index=True,
        )
        history = [item for item in audit_rows if "audit_id" in item]
        if history:
            with st.expander("Inspect audit details"):
                idx = st.selectbox("Audit record", range(len(history)))
                st.json(history[idx])
    with tabs[6]:
        allowed = {
            "open": ["open", "in_progress", "resolved"],
            "in_progress": ["in_progress", "open", "resolved"],
            "resolved": ["resolved", "open", "closed"],
            "closed": ["closed"],
        }[inc["status"]]
        target = st.selectbox(
            "Target status",
            allowed,
            format_func=lambda item: item.replace("_", " ").title(),
            key=f"status_{inc['incident_id']}",
        )
        classification, summary = "inconclusive", ""
        if target == "resolved":
            classification = st.selectbox("Resolution classification", RESOLUTIONS)
            summary = st.text_area("Resolution summary")
        confirmed = True
        if target == "closed" and inc["status"] != "closed":
            confirmed = st.checkbox("Confirm terminal closure of this resolved incident.")
        if st.button("Apply status transition", type="primary", disabled=not confirmed):
            try:
                if target == "resolved":
                    updated = resolve_incident(
                        db, inc["incident_id"], classification, summary, inc["version"]
                    )
                elif target == "open" and inc["status"] == "resolved":
                    updated = reopen_incident(db, inc["incident_id"], inc["version"])
                else:
                    updated = change_incident_status(db, inc["incident_id"], target, inc["version"])
                st.success(f"Status saved: {updated.status.value} · version {updated.version}")
                st.rerun()
            except (IncidentError, DashboardServiceError, sqlite3.Error, OSError) as exc:
                st.error(f"Status was not changed: {exc}")
                st.caption("Reload the incident before retrying a stale update.")
        st.divider()
        with st.form("assignment_form"):
            analyst = st.text_input(
                "Assigned analyst (blank means unassign)", value=inc.get("assigned_analyst") or ""
            )
            assign = st.form_submit_button("Save assignment")
        if assign:
            try:
                updated = assign_incident_to_analyst(
                    db, inc["incident_id"], analyst.strip() or None, inc["version"]
                )
                st.success(
                    f"Assignment saved: {updated.assigned_analyst or 'unassigned'} · version {updated.version}"
                )
                st.rerun()
            except (IncidentError, DashboardServiceError, sqlite3.Error, OSError) as exc:
                st.error(f"Assignment was not changed: {exc}")


def incident_explorer(db: Path) -> None:
    header("Incident explorer", "Filter the case queue and open a persisted investigation.")
    with st.expander("Search and filters", expanded=True):
        a, b, c = st.columns(3)
        with a:
            query = st.text_input("Search", placeholder="Reference, ID, title or summary")
            statuses = st.multiselect("Lifecycle status", STATUSES)
        with b:
            severities = st.multiselect("Severity", SEVERITIES)
            analyst = st.text_input("Assigned analyst contains")
        with c:
            host = st.text_input("Host contains")
            username = st.text_input("Username contains")
        d, e, f, g = st.columns(4)
        with d:
            start = st.date_input("Observed from", value=None)
        with e:
            end = st.date_input("Observed through", value=None)
        with f:
            sort_by = st.selectbox(
                "Sort by",
                [
                    "last_observed",
                    "first_observed",
                    "updated_at",
                    "severity",
                    "reference",
                    "alert_count",
                ],
            )
            descending = st.checkbox("Descending", value=True)
        with g:
            size = st.selectbox("Page size", [10, 25, 50, 100], index=1)
    kwargs: dict[str, Any] = {
        "query": query,
        "statuses": set(statuses) or None,
        "severities": set(severities) or None,
        "assigned_analyst": analyst,
        "host": host,
        "username": username,
        "observed_from": start if isinstance(start, date) else None,
        "observed_to": end if isinstance(end, date) else None,
        "sort_by": sort_by,
        "descending": descending,
        "page_size": size,
    }
    result = list_dashboard_incidents(db, **kwargs, page=1)
    st.caption(f"{result['total']} incident(s) match these filters.")
    if not result["items"]:
        empty("No matching incidents", "Change the filters or run the synthetic walkthrough.")
        return
    page = st.number_input("Page", min_value=1, max_value=result["pages"], value=1, step=1)
    result = list_dashboard_incidents(db, **kwargs, page=int(page))
    incident_table(result["items"])
    options = {
        f"{item['reference']} · {item['title']}": item["incident_id"] for item in result["items"]
    }
    labels = list(options)
    previous = st.session_state.get("selected_incident")
    default = next((i for i, label in enumerate(labels) if options[label] == previous), 0)
    chosen = st.selectbox("Select an incident", labels, index=default)
    if st.button("Open investigation workspace", type="primary"):
        st.session_state["selected_incident"] = options[chosen]
    selected_id = st.session_state.get("selected_incident")
    if selected_id in options.values():
        workspace(db, selected_id)


def alerts_page(db: Path) -> None:
    header(
        "Alerts & evidence",
        "Inspect persisted detection output without conflating evidence with conclusions.",
    )
    a, b = st.columns([3, 1])
    with a:
        query = st.text_input("Search alerts", placeholder="Alert ID, rule, entity or rationale")
    with b:
        severities = st.multiselect("Severity", SEVERITIES)
    alerts = list_dashboard_alerts(db, query=query, severities=set(severities) or None)
    st.caption(f"{len(alerts)} alert(s) match this view; at most 1,000 are shown.")
    if not alerts:
        empty("No matching alerts", "Run the synthetic lab or adjust your search.")
        return
    st.dataframe(
        [
            {
                "Alert ID": item["alert_id"],
                "Rule": item["rule_id"],
                "Title": item["rule_title"],
                "Severity": severity_label(item["severity"]),
                "First observed": item["first_observed"],
                "Last observed": item["last_observed"],
                "Events": item["event_count"],
                "Incident": item.get("incident_reference") or "Unassigned",
            }
            for item in alerts
        ],
        use_container_width=True,
        hide_index=True,
    )
    by_id = {item["alert_id"]: item for item in alerts}
    chosen = st.selectbox("Inspect alert", list(by_id))
    alert = by_id[chosen]
    st.subheader(f"{alert['rule_id']} · {alert['rule_title']}")
    st.caption(f"{alert['alert_id']} · {severity_label(alert['severity'])}")
    st.write(alert["rationale"])
    st.markdown("**Grouping context**")
    st.json(alert["grouping_context"])
    st.caption("ATT&CK: " + (", ".join(alert.get("mitre_attack", [])) or "Not mapped"))
    if alert.get("incident_id"):
        detail = get_incident_details(db, alert["incident_id"])
        for event_id in alert["evidence_event_ids"]:
            event = detail["evidence_events"].get(event_id)
            with st.container(border=True):
                st.code(event_id)
                if event:
                    st.caption(f"{event['timestamp']} · {event['source_id']}")
                    st.json(event)
                else:
                    st.warning("Source event unavailable; reference retained.")
        st.caption(f"Incident: {alert.get('incident_reference')} · {alert['incident_id']}")
        if st.button("Open associated incident"):
            st.session_state["selected_incident"] = alert["incident_id"]
            st.session_state["navigation"] = "Incident explorer"
            st.rerun()
    else:
        st.warning("No incident assignment is stored for this alert.")


def synthetic_lab(db: Path) -> None:
    header(
        "Synthetic lab", "A reproducible demonstration workflow — not live enterprise monitoring."
    )
    st.warning(
        "Only bundled synthetic fixtures and shipped rules are used. No simulated command is executed."
    )
    with st.form("synthetic_run"):
        fixture_label = st.selectbox(
            "Synthetic fixture", ["SOC incident walkthrough", "Authentication sample"]
        )
        fixture_key = {
            "SOC incident walkthrough": "soc_demo",
            "Authentication sample": "authentication",
        }[fixture_label]
        profile_label = st.selectbox(
            "Detection profile", ["All shipped rules", "Authentication only", "Process only"]
        )
        profile = {
            "All shipped rules": "all",
            "Authentication only": "authentication",
            "Process only": "process",
        }[profile_label]
        st.selectbox("Correlation policy", ["Checked-in policy · correlation.yaml"])
        submitted = st.form_submit_button("Run detection + correlation", type="primary")
    if submitted:
        try:
            from soc_sentinel.dashboard_services import run_synthetic_investigation

            result = run_synthetic_investigation(db, fixture_key=fixture_key, rule_profile=profile)
            st.session_state["pipeline_result"] = result
            st.success("Pipeline completed; the backend returned persisted results.")
        except (
            DashboardServiceError,
            CorrelationPolicyError,
            IncidentError,
            sqlite3.Error,
            OSError,
            ValueError,
        ) as exc:
            st.error(f"Pipeline failed: {exc}")
    result = st.session_state.get("pipeline_result")
    if result:
        cols = st.columns(4)
        for col, label, key in zip(
            cols,
            ["Records read", "Events inserted", "Alerts generated", "Rejected records"],
            ["records_read", "events_inserted", "alerts_generated", "records_rejected"],
            strict=True,
        ):
            col.metric(label, result[key])
        st.caption(
            f"Fixture: {result['fixture']} · profile: {result['rule_profile']} · existing event IDs skipped: {result['event_duplicates']}"
        )
        if result["issues"]:
            st.warning("Fixture records were rejected.")
            st.dataframe(result["issues"], use_container_width=True, hide_index=True)
        st.subheader("Detection output")
        st.dataframe(
            [
                {
                    "Alert ID": item["alert_id"],
                    "Rule": item["rule_id"],
                    "Severity": severity_label(item["severity"]),
                    "Evidence events": item["event_count"],
                    "Rationale": short(item["rationale"]),
                }
                for item in result["alerts"]
            ],
            use_container_width=True,
            hide_index=True,
        )
        st.subheader("Persisted incidents")
        incident_table(result["incidents"])
        if result["incidents"]:
            choices = {
                f"{item['reference']} · {item['title']}": item["incident_id"]
                for item in result["incidents"]
            }
            selected = st.selectbox("Open a pipeline incident", list(choices))
            if st.button("Investigate pipeline result"):
                st.session_state["selected_incident"] = choices[selected]
                st.session_state["navigation"] = "Incident explorer"
                st.rerun()
        st.caption(
            "Repeated runs are idempotent for stable event/alert IDs and incident relationships."
        )


def evaluation_page() -> None:
    """Display canonical metrics from the framework-independent evaluation module."""
    header(
        "Detection evaluation",
        "Reproducible rule-quality measurements from the committed synthetic benchmark.",
    )
    from soc_sentinel.evaluation import EvaluationError, evaluate_dataset

    dataset_path = PROJECT_ROOT / "data" / "evaluation" / "benchmark.json"
    rules_path = PROJECT_ROOT / "rules"
    try:
        report = evaluate_dataset(dataset_path, rules_path)
    except (EvaluationError, OSError, ValueError) as exc:
        st.error(f"Evaluation could not complete: {exc}")
        return

    st.warning(
        "Synthetic benchmark only. These metrics demonstrate repeatable evaluation mechanics; "
        "they are not estimates of real-world SOC performance."
    )
    aggregate = report["aggregate"]
    cols = st.columns(3)
    cols[0].metric("Precision", "null" if aggregate["precision"] is None else f"{aggregate['precision']:.3f}")
    cols[1].metric("Recall", "null" if aggregate["recall"] is None else f"{aggregate['recall']:.3f}")
    cols[2].metric("F1 score", "null" if aggregate["f1"] is None else f"{aggregate['f1']:.3f}")
    cols = st.columns(4)
    for col, label, key in zip(
        cols,
        ["True positives", "False positives", "False negatives", "True negatives*"],
        ["tp", "fp", "fn", "tn"],
        strict=True,
    ):
        col.metric(label, aggregate[key])
    st.caption(
        f"{report['dataset']['scenario_count']} scenarios · "
        f"{report['dataset']['event_count']} source events · "
        f"{report['rules']['enabled_rule_count']} enabled rules"
    )
    st.subheader("Per-rule performance")
    st.dataframe(report["per_rule"], use_container_width=True, hide_index=True)
    st.subheader("Scenario outcomes")
    st.dataframe(
        [
            {
                "Scenario": item["scenario_id"],
                "Title": item["title"],
                "Category": item["category"],
                "Outcome": item["outcome"],
                "Expected": len(item["expected_detections"]),
                "Matched": len(item["matched_detections"]),
                "Missed": len(item["missed_detections"]),
                "Unexpected": len(item["unexpected_detections"]),
            }
            for item in report["scenario_results"]
        ],
        use_container_width=True,
        hide_index=True,
    )
    with st.expander("Unexpected alerts / false positives"):
        if report["false_positives"]:
            st.dataframe(report["false_positives"], use_container_width=True, hide_index=True)
        else:
            st.success("No unexpected alerts in this benchmark.")
    with st.expander("Missed expected detections / false negatives"):
        if report["false_negatives"]:
            st.dataframe(report["false_negatives"], use_container_width=True, hide_index=True)
        else:
            st.success("No missed expected detections in this benchmark.")
    st.caption(
        "* TN is a supplemental count of negative scenario-rule opportunities; it is not used "
        "in precision, recall, or F1. Full methodology and reproducible JSON/Markdown reports "
        "are documented in docs/EVALUATION.md."
    )
    st.code(
        "soc-sentinel evaluate --dataset data/evaluation/benchmark.json "
        "--rules rules/ --output reports/evaluation/",
        language="bash",
    )


def main() -> None:
    st.set_page_config(page_title="SOC Sentinel", page_icon="🛡️", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    with st.sidebar:
        st.markdown("## 🛡️ SOC Sentinel")
        st.caption("LOCAL INVESTIGATION WORKSPACE")
        st.divider()
        nav = st.radio("Workspace", PAGES, key="navigation", label_visibility="collapsed")
        st.divider()
        st.markdown("**Storage**")
        st.caption(str(DB_PATH))
        st.caption("Local SQLite · no external services")
        st.markdown('<span style="color:#56c5b4">●</span> Local-only mode', unsafe_allow_html=True)
    if nav == "Detection evaluation":
        evaluation_page()
        return
    if not DB_PATH.is_file():
        header("SOC Sentinel", "Evidence-led investigation on your local machine.")
        st.info("The configured database does not exist yet. Run this from the repository root:")
        st.code("soc-sentinel demo-seed --db data/soc-sentinel-demo.sqlite3", language="bash")
        st.caption(
            "Use --reset only for a separate demo-named file. The default working database is protected."
        )
        return
    try:
        if nav == "Operations overview":
            overview(DB_PATH)
        elif nav == "Incident explorer":
            incident_explorer(DB_PATH)
        elif nav == "Alerts & evidence":
            alerts_page(DB_PATH)
        elif nav == "Detection evaluation":
            evaluation_page()
        else:
            synthetic_lab(DB_PATH)
    except (
        DashboardServiceError,
        IncidentError,
        CorrelationPolicyError,
        sqlite3.Error,
        OSError,
    ) as exc:
        st.error(f"Dashboard operation could not complete: {exc}")
        st.caption("Check the SQLite path or reload after a concurrent update.")


if __name__ == "__main__":
    main()
