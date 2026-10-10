# SQLite Database Schema

Schema migrations are transactional and idempotent. Version 1 creates schema metadata, version 2 adds normalized security events, and version 3 adds persistent alerts and incident investigation records. A database newer than the supported version is rejected rather than downgraded.

## Tables

### schema_metadata
- key TEXT PRIMARY KEY
- value TEXT NOT NULL
- schema_version is maintained by initialization.

### events (v2)
Normalized telemetry with stable event ID primary key, UTC ISO-8601 timestamp, event type, host/user/IP context, action/outcome, optional process and scenario JSON, source provenance, and attributes JSON. Existing records are preserved during v3 migration. Duplicate event IDs are skipped rather than overwritten.

### alerts (v3)
- alert_id TEXT PRIMARY KEY: deterministic Phase 3 alert ID.
- rule_id, severity, first/last observed UTC timestamps.
- payload_json: validated alert, rationale, grouping context, and evidence event IDs.

### incidents (v3)
- incident_id TEXT PRIMARY KEY: deterministic ID derived from the initial alert set.
- reference TEXT UNIQUE: human-readable INC reference.
- Title, summary, lifecycle status, severity, observed/created/updated timestamps.
- Alert IDs and entity summary JSON; derived event/alert counts.
- Optional analyst assignment and resolution classification/summary.
- Monotonically increasing version for optimistic concurrency.

### incident_alerts
Foreign keys to incident and alert; alert_id UNIQUE enforces at most one incident assignment per alert. A composite primary key prevents duplicate links.

### correlation_explanations
Stores the linked alert pair, policy strategy, concrete shared values, time gap, explanation text, and application timestamp. A uniqueness constraint prevents repeated copies of the same explanation edge.

### incident_notes and incident_audit
Append-only timestamped analyst notes and lifecycle/application audit events. Foreign keys use RESTRICT so investigation history cannot be silently orphaned by deletion.

## Transactions, migration, and timestamps

The v3 DDL and schema version update run in one explicit transaction. Any exception rolls back the migration. Incident/alert relationship creation, correlation explanations, derived incident updates, and audit events are persisted in one transaction. Status and assignment updates use BEGIN IMMEDIATE, compare the expected version, and append audit history before commit. Foreign keys are enabled for all incident-store connections. Timestamps are stored in UTC ISO-8601 with a Z suffix where created by the application.

The end-to-end command persists accepted events first using the established Phase 2 ingestion transaction, then persists alerts and incident state in a separate transaction. Therefore, if the incident transaction fails, event ingestion may remain committed; no partial alert/incident transaction is committed. This is deliberate and documented rather than claiming a cross-phase distributed transaction.

SQLite is local single-user storage, not a distributed multi-writer database.
