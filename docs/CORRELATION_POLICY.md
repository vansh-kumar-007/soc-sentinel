# Correlation policy

The `correlation.yaml` file is data-only YAML loaded with PyYAML safe loading and a strict Pydantic model. Unknown keys and strategy names are rejected; there is no expression language, regex execution, Python evaluation, or shell execution.

## Policy fields

- `policy_id`: short identifier for the policy used during an investigation.
- `window_seconds`: maximum gap between alert observed intervals (1–604800 seconds). Overlapping intervals have a zero-second gap. The boundary is inclusive.
- `strategies`: ordered list of supported exact-match relationships. The first matching strategy becomes the primary explanation for that alert pair; all corroborating matches are also recorded.
- `minimum_shared_entities`: minimum count of distinct shared entity/evidence key-value pairs required (1–4). For example, a username+source-IP pair provides two distinct shared values, while a host-only match provides one.
- `allow_transitive`: when true, a connected component may include A–B and B–C even when A does not directly match C. When false, only direct relationships from the seed alert join a new incident.

Supported strategies:

- `same_username_and_source_ip`: both exact username and source IP must be present and shared.
- `shared_event`: at least one identical evidence event ID is present in both alerts.
- `same_host`: exact host ID is shared.
- `same_username`: exact username is shared.
- `same_source_ip`: exact source IP is shared.

Missing values never count as shared. Severity and temporal proximity alone never correlate alerts. Shared source IP can be a NAT/proxy, shared username can represent a service account, and host identifiers depend on source quality; these are explainable links, not proof of common malicious intent.

## Existing incidents and conflicts

A new alert is attached to at most one incident. Existing incidents are never automatically merged. If a new alert matches more than one incident, the engine deterministically chooses the candidate with the earliest configured strategy priority, then incident ID and related alert ID. This avoids silently merging investigations. A resolved incident reopens to `open` when a newly correlated alert arrives; its previous resolution remains in the audit history.
