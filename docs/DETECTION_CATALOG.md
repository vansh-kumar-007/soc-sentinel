# Detection Catalog

Status: **implemented Phase 3 rules; alerts are investigative leads, not proof of malicious activity.**

Rules ship as YAML under the rules directory. Their schema and operator grammar are documented in [RULE_FORMAT.md](RULE_FORMAT.md). Run `soc-sentinel validate-rules --rules rules/` to validate them.

## DET-001 — Authentication failure burst

- **Objective:** identify a burst of failed login events for one account and source.
- **Required telemetry:** authentication events with action=login, outcome=failure, username, and source_ip.
- **Logic:** at least 5 matching events in a 600-second trailing window.
- **Grouping:** exact pair of username and source_ip. Events missing either group value are skipped.
- **Severity / ATT&CK:** high; T1110 (Brute Force).
- **Evidence:** the first five contributing event IDs in event-time order, grouping context, and observed range.
- **False positives:** mistyped passwords, password managers retrying, automated health checks, shared NAT addresses, and legitimate users with stale credentials.
- **Limitations:** this is a simple failure-burst signal; it does not distinguish users from automation or prove an attack. The initial implementation emits one alert when a group first reaches the threshold and suppresses further alerts for that group until the window elapses.

## DET-002 — Failed logins followed by successful login

- **Objective:** flag a success following repeated failures for the same account/source context.
- **Required telemetry:** authentication events with username, source_ip, login action, and explicit success/failure outcomes.
- **Logic:** at least 3 failed login events followed strictly later by a successful login, all within 600 seconds.
- **Grouping and ordering:** username and source_ip must match exactly; failures must have timestamps strictly earlier than the success. Equal timestamps do not satisfy the ordering requirement.
- **Severity / ATT&CK:** high; T1110 (Brute Force) and T1078 (Valid Accounts) are contextual mappings, not proof of technique use.
- **Evidence:** all qualifying failures in the window plus the successful event, ordered by timestamp and event ID.
- **False positives:** a legitimate user recovering after mistyped passwords, authentication retries, or shared egress IPs.
- **Limitations:** a successful login after failures does not prove compromise. The rule does not correlate device identity, MFA results, geolocation, or session risk. Missing username/source IP prevents grouping.

## DET-003 — Encoded PowerShell command execution

- **Objective:** flag endpoint process telemetry indicating a PowerShell-family process launched with an encoded-command switch.
- **Required telemetry:** process event, process.name matching a configured PowerShell executable name, and process.command_line containing `-EncodedCommand` (case-insensitive).
- **Logic:** one process event must match both conditions.
- **Grouping:** host_id is included in alert context; this is a single-event match, not a process-chain correlation.
- **Severity / ATT&CK:** medium; T1059.001 (PowerShell).
- **Evidence:** the exact process event ID, host grouping, timestamp, and matched-rule rationale.
- **False positives:** legitimate administration scripts, software deployment tools, and security products may use encoded commands. Benign PowerShell invocations without the encoded-command switch should not trigger this rule.
- **Limitations:** the event schema supports parent PID, executable, command line, and SHA-256, but the initial rule does not require parent-process telemetry or a hash. Command-line logging may be absent or truncated. This signal is suspicious context, not a malware verdict.

## Evaluation discipline

Detection tests use synthetic events and test both suspicious cases and benign lookalikes. Scenario labels are not queried by the engine. Comprehensive labeled precision/recall evaluation belongs to Phase 6.
