# SQLite Database Schema

Phase 1 created `schema_metadata` with schema version `1`. Phase 2's `initialize_database()` migrates a version-1 database to version `2` and creates event storage. Migrations run in the same SQLite connection transaction; a database advertising a future schema version is rejected rather than downgraded.

## Tables

### `schema_metadata`

- `key TEXT PRIMARY KEY`
- `value TEXT NOT NULL`
- `schema_version` is maintained by the initializer.

### `events` (schema version 2)

| Column | Description |
|---|---|
| `event_id` | Primary key; event deduplication boundary |
| `timestamp_utc` | UTC ISO-8601 timestamp, indexed |
| `event_type` | Event family constrained to supported values |
| `host_id`, `username` | Host and account context |
| `source_ip`, `destination_ip` | Optional validated addresses |
| `action`, `outcome` | Normalized action and result |
| `process_json` | Optional process metadata serialized as JSON |
| `source_id` | Source provenance supplied with the event |
| `scenario_json` | Optional evaluation-only metadata |
| `attributes_json` | Extra source-specific JSON properties |
| `ingested_at_utc` | Database insertion timestamp |

Indexes exist for event timestamp, event type plus timestamp, host, and username.

## Transactions and duplicate semantics

Events are inserted through parameterized SQL inside a single SQLite transaction. `event_id` uniqueness is enforced by the primary key. Existing IDs are skipped and counted as duplicates rather than overwritten. A database error propagates out of the transaction context and causes rollback of all inserts in that batch.

The current SQLite model is local, single-user-oriented storage; it is not a multi-writer distributed event store.
