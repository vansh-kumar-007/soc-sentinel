# Detection Rule Format

SOC Sentinel rules are data-only YAML documents. The loader uses PyYAML safe parsing and validates each document with Pydantic. Rule files cannot contain executable Python, shell commands, dynamic expressions, or custom functions. Unknown keys are rejected.

## Rule file discovery

Pass either one YAML file or a directory. A directory is read in lexical order and includes only files ending in .yaml or .yml. Each file contains exactly one mapping representing one rule. Duplicate rule IDs are rejected.

## Common fields

| Field | Required | Meaning |
|---|---|---|
| rule_id | yes | Stable identifier matching DET- followed by at least three digits |
| title | yes | Human-readable rule name |
| description | yes | Detection intent and context |
| enabled | no | Defaults to true |
| severity | yes | low, medium, high, or critical; severity is not confidence |
| event_types | yes | Non-empty list of authentication, process, or network |
| detection | yes | Strategy-specific declarative conditions |
| window | strategy-dependent | Positive integer seconds, maximum 86,400 |
| threshold | strategy-dependent | Positive count; threshold rules require at least 2 |
| group_by | strategy-dependent | Allow-listed event entity fields |
| mitre_attack | no | Technique IDs such as T1110 or T1059.001 |
| tags | no | Descriptive labels only; never detection evidence |

## Condition grammar

A condition has exactly these fields:

- field: allow-listed normalized event field.
- operator: one of eq, ne, in, not_in, contains, icontains, icontains_token, starts_with, ends_with, gt, gte, lt, lte.
- value: scalar comparison value or a non-empty list for in/not_in.

Supported fields are event_id, timestamp, event_type, host_id, username, source_ip, destination_ip, action, outcome, process.name, process.executable, process.pid, process.parent_pid, process.command_line, and process.hash_sha256. Scenario metadata and arbitrary attributes are intentionally not queryable fields.

String equality, membership, contains, starts_with, and ends_with are case-sensitive. icontains is explicitly case-insensitive. icontains_token is case-insensitive and requires the compared string to be bounded by non-word characters; hyphens are not boundaries so longer switch names and double-hyphen lookalikes do not match. Numeric comparisons are limited to process.pid and process.parent_pid. Timestamp conditions support equality/inequality only and require timezone-aware ISO-8601 values. A missing optional field never matches, including ne/not_in.

All conditions in one conditions list are ANDed. There is no arbitrary expression language and no OR, regex, Python, or shell execution.

## Strategies

### match

Evaluates one event at a time. All configured conditions must match. It does not accept window or threshold. Each matching event creates an evidence-linked alert.

### threshold

Requires conditions, threshold >= 2, a positive window in seconds, and group_by. Matching events are grouped by all selected grouping values. Events missing any grouping value are skipped. When a group first reaches threshold within the trailing window, one alert is emitted with the first threshold contributing events; further alerts for that group are suppressed until the detection window has elapsed. This avoids a flood of nearly identical alerts from a single burst.

### sequence

Requires exactly two ordered stages, a positive window, threshold >= 1, and group_by. Each stage has an event_type and its own ANDed conditions. A qualifying second-stage event must occur strictly after at least threshold first-stage events, for the same group, within the window. Evidence includes all qualifying first-stage events in that window and the second-stage event. Events at the same timestamp do not satisfy ordering.

## Alert identity and evidence

Alert IDs are deterministic SHA-256-derived identifiers over rule ID, grouping context, and ordered evidence event IDs. Alert payloads include the contributing event IDs, observed time range, event count, configured severity, rationale, grouping context, and optional ATT&CK references. Re-evaluating the same events and rules yields the same alert IDs. Exact duplicate input event IDs are de-duplicated (first occurrence wins).

The engine is stateless: it does not persist alerts. Re-evaluating the same complete batch is idempotent by alert ID. Separate partial batches can have different evidence sets, so callers that later persist alerts must deduplicate by alert ID and preserve their evidence references.

## Security and limitations

- Scenario IDs/labels, filenames, test outcomes, and expected results are not available to conditions and never drive a detection.
- Severity is rule configuration, not an assertion that malicious activity is confirmed.
- A triggered rule is an investigative lead, not proof of compromise.
- Rule logic and telemetry limits are documented in DETECTION_CATALOG.md.
