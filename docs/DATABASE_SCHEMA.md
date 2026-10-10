# SQLite Database Schema

Phase 1 created `schema_metadata` at schema version 1. Phase 2 upgrades it to version 2 and creates the local `events` table. Both migration DDL and version updates run in one explicit SQLite transaction. If a migration fails, the transaction rolls back. A newer version is rejected rather than downgraded.

## Tables

### `schema_metadata`

- `key TEXT PRIMARY KEY`
- `value TEXT NOT NULL`
- `schema_version` is maintained by the initializer.

### `events` (schema version 2)

| Column | Description |
|---|---|
| `event_id` | Primary key and deduplication boundary |
| `timestamp_utc` | UTC ISO-8601 timestamp ending in `Z`, indexed |
| `event_type` | `authentication`, `process`, or `network` |
| `host_id`, `username` | Host and account context |
| `source_ip`, `destination_ip` | Optional validated IP addresses |
| `action`, `outcome` | Normalized action and result |
| `process_json` | Optional process metadata as JSON |
| `source_id` | Supplied source-provenance label |
| `scenario_json` | Optional evaluation-only metadata |
| `attributes_json` | Additional source-specific JSON object |
| `ingested_at_utc` | Database insertion timestamp |

Indexes support queries by timestamp, event type and timestamp, host, and username.

## Transactions and duplicates

Events use parameterized inserts inside one explicit transaction. `event_id` uniqueness is enforced by the primary key. IDs already in the database are skipped, counted, and never overwritten. An unexpected SQL failure rolls back all inserts from that ingestion batch.

Schema migration and event insertion are independent transactions: migration may succeed even if a later event insertion fails, while no partial events from a failed insert batch are committed.

SQLite is intended for local, single-user MVP storage, not a distributed multi-writer event store.
