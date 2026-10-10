# Detection Catalog

Status: **planned — no detection rules are implemented in Phase 1.**

The initial catalog is intended to demonstrate explainable defensive detections over synthetic event sequences.

| Planned detection | Intended signal | Evidence expectation |
|---|---|---|
| Authentication failure burst | Repeated failures for an account or source within a time window | Event IDs, count, source/account, time range |
| Failure followed by success | Failed logins followed by a successful login in the same account/source context | Ordered event references and timestamps |
| Suspicious process execution | Configurable process indicators in endpoint events | Source event and matched fields |
| Unusual outbound connection | Synthetic or authorized network telemetry matching explicit criteria | Source event, destination, matched fields |
| Multi-stage activity | Related alerts sharing entities in a bounded time window | Contributing alert IDs and correlation rationale |

These are candidates, not claims of real-world coverage. Thresholds, fields, windows, false-positive cases, and limitations must be documented and tested when implemented. No automatic blocking or active response is planned for the MVP.
