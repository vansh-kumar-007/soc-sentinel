"""Local Streamlit SOC investigation workspace.

Run: streamlit run src/soc_sentinel/dashboard.py --server.address 127.0.0.1
"""

from __future__ import annotations

import importlib
import os
import sqlite3
import tempfile
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from soc_sentinel.correlation import CorrelationPolicyError
from soc_sentinel.dashboard_services import (
    PROJECT_ROOT,
    DashboardServiceError,
    add_investigation_note,
    assign_incident_to_analyst,
    change_incident_status,
    ensure_public_demo_database,
    get_dashboard_summary,
    get_incident_details,
    list_dashboard_alerts,
    list_dashboard_incidents,
    reopen_incident,
    resolve_incident,
)
from soc_sentinel.incidents import IncidentError
from soc_sentinel.operating_mode import PUBLIC_DEMO, OperatingModeError, operating_mode

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


PAGES = [
    "Operations overview",
    "Incident explorer",
    "Alerts & evidence",
    "Synthetic lab",
    "Detection evaluation",
]
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
[data-testid="stAppViewContainer"]{background:linear-gradient(145deg,#0b1016 0%,#0e151e 52%,#0b1016 100%)}
[data-testid="stSidebar"]{background:#0d141c}
[data-testid="stSidebar"] [data-testid="stRadio"] label{padding:.25rem .35rem;border-radius:6px}
[data-testid="stButton"] button,[data-testid="stFormSubmitButton"] button{border-radius:8px;min-height:2.55rem;font-weight:600}
[data-testid="stDataFrame"]{border:1px solid #27313d;border-radius:10px;overflow:hidden}
hr{border-color:#27313d}
.ss-status{display:inline-block;border:1px solid #2d746c;border-radius:999px;padding:3px 9px;color:#8fe0d2;font-size:.72rem;font-weight:700;letter-spacing:.04em}
.ss-mode{border:1px solid #344454;border-radius:10px;padding:12px 14px;background:#101923;margin:8px 0 16px}
@media(max-width:800px){.block-container{padding:1rem .8rem 2rem}.ss-panel{padding:12px}}
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
        st.subheader("Detection rule breakdown")
        if summary["alerts_by_rule"]:
            st.dataframe(summary["alerts_by_rule"], hide_index=True, use_container_width=True)
        else:
            empty("No rule activity", "Rule counts appear when detections are persisted.")
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
        st.subheader("Recent detection activity")
        recent_alerts = list_dashboard_alerts(db, limit=8)
        if recent_alerts:
            st.dataframe(
                [
                    {
                        "Observed (UTC)": item["first_observed"],
                        "Rule": item["rule_id"],
                        "Severity": severity_label(item["severity"]),
                        "Evidence events": item["event_count"],
                        "Incident": item.get("incident_reference") or "Unassigned",
                    }
                    for item in recent_alerts
                ],
                hide_index=True,
                use_container_width=True,
            )
        else:
            empty("No recent detections", "New alert activity appears after a pipeline run.")
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
        if operating_mode() == PUBLIC_DEMO:
            st.info(
                "Public demonstration is read-only. Analyst notes are available in local analyst mode."
            )
        else:
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
        if operating_mode() == PUBLIC_DEMO:
            st.info(
                "Public demonstration is read-only. Assignment, lifecycle changes, resolution, "
                "and audit mutations are disabled. Use a local analyst-mode database to investigate."
            )
        else:
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
                        updated = change_incident_status(
                            db, inc["incident_id"], target, inc["version"]
                        )
                    st.success(f"Status saved: {updated.status.value} · version {updated.version}")
                    st.rerun()
                except (IncidentError, DashboardServiceError, sqlite3.Error, OSError) as exc:
                    st.error(f"Status was not changed: {exc}")
                    st.caption("Reload the incident before retrying a stale update.")
            st.divider()
            with st.form("assignment_form"):
                analyst = st.text_input(
                    "Assigned analyst (blank means unassign)",
                    value=inc.get("assigned_analyst") or "",
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
        "Search persisted detection output while keeping evidence distinct from analyst conclusions.",
    )
    all_alerts = list_dashboard_alerts(db, limit=1000)
    available_rules = sorted({item["rule_id"] for item in all_alerts})
    first, second, third, fourth = st.columns([2, 1, 1, 1])
    with first:
        query = st.text_input(
            "Search alerts", placeholder="Alert ID, rule, entity, timestamp, or rationale"
        )
    with second:
        severities = st.multiselect("Severity", SEVERITIES)
    with third:
        rule_id = st.selectbox("Detection rule", ["All rules", *available_rules])
    with fourth:
        association = st.selectbox("Incident link", ["All alerts", "Linked", "Unassigned"])
    host_col, user_col = st.columns(2)
    with host_col:
        host = st.text_input("Host contains", placeholder="Host identifier")
    with user_col:
        username = st.text_input("Username contains", placeholder="Account name")
    date_from, date_to = st.columns(2)
    with date_from:
        observed_from = st.date_input("Observed from", value=None, key="alert_observed_from")
    with date_to:
        observed_to = st.date_input("Observed through", value=None, key="alert_observed_to")
    alerts = list_dashboard_alerts(
        db,
        query=query,
        severities=set(severities) or None,
        rule_ids={rule_id} if rule_id != "All rules" else None,
        host=host,
        username=username,
        incident_association={
            "All alerts": "all",
            "Linked": "linked",
            "Unassigned": "unassigned",
        }[association],
        observed_from=observed_from if isinstance(observed_from, date) else None,
        observed_to=observed_to if isinstance(observed_to, date) else None,
        limit=1000,
    )
    st.caption(f"{len(alerts)} alert(s) match these filters; at most 1,000 are shown.")
    if not alerts:
        empty("No matching alerts", "Clear a filter or run the local synthetic lab.")
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
    if operating_mode() == PUBLIC_DEMO:
        st.info(
            "Read-only public demo: a lab run uses a separate temporary SQLite database, "
            "executes only bundled fixtures and shipped rules, and discards its results afterward. "
            "It never changes the public demo database or analyst records."
        )
        summary = get_dashboard_summary(db)
        cols = st.columns(3)
        cols[0].metric("Persisted synthetic incidents", summary["total_incidents"])
        cols[1].metric("Persisted synthetic alerts", summary["total_alerts"])
        cols[2].metric("Shipped rules observed", len(summary["alerts_by_rule"]))
        st.subheader("Detection rules represented in the demo database")
        st.dataframe(summary["alerts_by_rule"], use_container_width=True, hide_index=True)
        st.caption(
            "These persisted records are bundled synthetic fixtures, not incoming telemetry."
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
            from soc_sentinel.dashboard_services import (
                run_public_synthetic_preview,
                run_synthetic_investigation,
            )

            if operating_mode() == PUBLIC_DEMO:
                result = run_public_synthetic_preview(fixture_key=fixture_key, rule_profile=profile)
                st.session_state["pipeline_result"] = result
                st.success(
                    "Isolated synthetic preview completed. Its temporary database was discarded; "
                    "no public or analyst state was changed."
                )
            else:
                result = run_synthetic_investigation(
                    db, fixture_key=fixture_key, rule_profile=profile
                )
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
        st.subheader(
            "Correlated incidents generated"
            if operating_mode() == PUBLIC_DEMO
            else "Persisted incidents"
        )
        incident_table(result["incidents"])
        if result["incidents"] and operating_mode() != PUBLIC_DEMO:
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
            "Public previews are isolated and discarded after execution. Local repeated runs are idempotent for stable event/alert IDs and incident relationships."
        )


def evaluation_page() -> None:
    """Display canonical metrics from the framework-independent evaluation module."""
    header(
        "Detection evaluation",
        "Reproducible rule-quality measurements from the committed synthetic benchmark.",
    )
    from soc_sentinel.evaluation import PHASE_6_BASELINE, evaluate_dataset

    dataset_path = PROJECT_ROOT / "data" / "evaluation" / "benchmark.json"
    rules_path = PROJECT_ROOT / "rules"
    try:
        report = evaluate_dataset(dataset_path, rules_path)
    except (OSError, ValueError) as exc:
        st.error(f"Evaluation could not complete: {exc}")
        return

    st.warning(
        "Synthetic benchmark only. These metrics demonstrate repeatable evaluation mechanics; "
        "they are not estimates of real-world SOC performance."
    )
    aggregate = report["aggregate"]
    cols = st.columns(3)
    for col, label, key in zip(
        cols,
        ["Precision", "Recall", "F1 score"],
        ["precision", "recall", "f1"],
        strict=True,
    ):
        value = aggregate[key]
        col.metric(label, "null" if value is None else f"{value:.3f}")
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
    st.subheader("Phase 6 baseline comparison")
    baseline_source = PHASE_6_BASELINE["source"]
    st.caption(
        "Historical reference from verified CI run #252: "
        + baseline_source["commit_sha"]
        + ". Current values are recomputed by the canonical evaluator."
    )
    st.markdown("[Open the Phase 6 CI run](" + baseline_source["run_url"] + ")")
    baseline_aggregate = PHASE_6_BASELINE["aggregate"]
    current = {
        "TP": aggregate["tp"],
        "FP": aggregate["fp"],
        "FN": aggregate["fn"],
        "Supplemental TN*": aggregate["tn"],
        "Precision": aggregate["precision"],
        "Recall": aggregate["recall"],
        "F1": aggregate["f1"],
    }
    baseline_metrics = {
        "TP": baseline_aggregate["tp"],
        "FP": baseline_aggregate["fp"],
        "FN": baseline_aggregate["fn"],
        "Supplemental TN*": baseline_aggregate["tn"],
        "Precision": baseline_aggregate["precision"],
        "Recall": baseline_aggregate["recall"],
        "F1": baseline_aggregate["f1"],
    }
    comparison_rows = []
    for metric, baseline_value in baseline_metrics.items():
        current_value = current[metric]
        if current_value is None:
            delta = "n/a"
        elif isinstance(current_value, float):
            delta = f"{current_value - baseline_value:+.6f}"
        else:
            delta = f"{current_value - baseline_value:+d}"
        comparison_rows.append(
            {
                "Metric": metric,
                "Current": current_value,
                "Phase 6 baseline": baseline_value,
                "Change": delta,
            }
        )
    st.dataframe(comparison_rows, hide_index=True, use_container_width=True)
    baseline_by_rule = {item["rule_id"]: item for item in PHASE_6_BASELINE["per_rule"]}
    rule_comparison = []
    for item in report["per_rule"]:
        prior = baseline_by_rule.get(item["rule_id"])
        if prior is None:
            continue
        rule_comparison.append(
            {
                "Rule": item["rule_id"],
                "Current FP": item["fp"],
                "Phase 6 FP": prior["fp"],
                "Current F1": item["f1"],
                "Phase 6 F1": prior["f1"],
            }
        )
    st.dataframe(rule_comparison, hide_index=True, use_container_width=True)
    st.caption(
        "* Supplemental TN counts negative scenario-rule opportunities; it is not conventional "
        "confusion-matrix TN. Synthetic benchmark comparisons do not establish real-world efficacy."
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
    if "SOC_SENTINEL_MODE" not in os.environ:
        os.environ["SOC_SENTINEL_MODE"] = PUBLIC_DEMO
    try:
        mode = operating_mode()
    except OperatingModeError:
        st.error(
            "SOC Sentinel stopped safely because SOC_SENTINEL_MODE is invalid. "
            "Use 'local-analyst' for local operation or the hosted read-only entry point."
        )
        return
    is_public = mode == PUBLIC_DEMO
    database_path = DB_PATH
    if is_public:
        database_path = (
            Path(tempfile.gettempdir()) / f"soc-sentinel-public-demo-{os.getpid()}.sqlite3"
        )
        try:
            ensure_public_demo_database(database_path)
        except (DashboardServiceError, sqlite3.Error, OSError, ValueError):
            st.error(
                "The synthetic demonstration data could not be initialized safely. "
                "The application did not reset the existing database."
            )
            return
    st.session_state["last_rendered_at"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    with st.sidebar:
        st.markdown("## 🛡️ SOC Sentinel")
        st.caption("SECURITY OPERATIONS WORKSTATION")
        st.markdown(
            '<div class="ss-mode"><span class="ss-status">'
            + ("PUBLIC · READ ONLY" if is_public else "LOCAL · ANALYST MODE")
            + "</span><p class='ss-muted'>"
            + (
                "Bundled synthetic records · no external telemetry"
                if is_public
                else "Local SQLite · analyst workflow enabled"
            )
            + "</p></div>",
            unsafe_allow_html=True,
        )
        nav = st.radio("Workspace", PAGES, key="navigation", label_visibility="collapsed")
        st.divider()
        if is_public:
            st.caption("Data source: synthetic demonstration database")
            st.caption("Storage is ephemeral on free hosting; no persistence guarantee.")
        else:
            st.markdown("**Storage**")
            st.caption(str(DB_PATH))
            st.caption("Local SQLite · no external services")
        if st.button("Refresh current data", use_container_width=True):
            st.rerun()
        st.caption("View refreshed: " + st.session_state["last_rendered_at"])
    if is_public:
        st.markdown(
            '<div class="ss-panel"><span class="ss-kicker">DEMO ENVIRONMENT</span>'
            "<p>Read-only synthetic data. This dashboard refreshes application state; it does not "
            "receive telemetry from external systems.</p></div>",
            unsafe_allow_html=True,
        )
    if nav == "Detection evaluation":
        evaluation_page()
        return
    if not database_path.is_file():
        header("SOC Sentinel", "Evidence-led investigation on your local machine.")
        st.info("The configured database does not exist yet. Run this from the repository root:")
        st.code("soc-sentinel demo-seed --db data/soc-sentinel-demo.sqlite3", language="bash")
        st.caption(
            "Use --reset only for a separate demo-named file. The default working database is protected."
        )
        return
    try:
        if nav == "Operations overview":
            overview(database_path)
        elif nav == "Incident explorer":
            incident_explorer(database_path)
        elif nav == "Alerts & evidence":
            alerts_page(database_path)
        elif nav == "Synthetic lab":
            synthetic_lab(database_path)
    except (
        DashboardServiceError,
        IncidentError,
        CorrelationPolicyError,
        OperatingModeError,
        sqlite3.Error,
        OSError,
    ):
        st.error("Dashboard data could not be loaded or the requested operation was rejected.")
        st.caption("Refresh the view or verify the local SQLite database and operating mode.")


if __name__ == "__main__":
    main()
