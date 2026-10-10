# Threat Model

## Assets

- Local event data and investigation notes
- Detection-rule definitions
- SQLite database and derived alerts
- Developer environment and repository credentials

## Trust boundaries

Imported logs and JSONL are untrusted. YAML rule files are untrusted configuration and must be schema-validated. Repository and dependency changes can alter behavior. Future web components may expose event content and require additional controls.

## Threats and mitigations

| Threat | Initial mitigation / required design |
|---|---|
| Secret or private log accidentally committed | Git ignore rules and review before commit |
| Malformed input crashes parser or consumes excessive resources | Add bounded parsing and validation in Phase 2 |
| Rule content executes code | Allow-listed operators only; never use eval or shell execution for rules |
| False or misleading alert | Evidence-linked results and labeled evaluation |
| Database accidentally tracked | Ignore database extensions and generated files |
| Local data is exposed or tampered with | Filesystem permissions and explicit limitation documentation |
| Dependency or CI supply-chain risk | Minimal dependencies, pinned action major versions, review updates |
| Unauthorized security testing | Synthetic data and authorized systems only |

## Out of scope

- Attacking or responding to systems without authorization.
- Production-grade multi-tenant access control or forensic chain-of-custody certification.
- Guaranteeing a local laptop or database is uncompromised.

This preliminary model must be updated as ingestion, rule evaluation, persistence, and UI features are implemented.
