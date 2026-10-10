# Security Policy

## Scope

SOC Sentinel is a defensive learning and investigation project. Phase 1 is a local Python foundation; ingestion and detection capabilities are planned.

## Supported use

- Use synthetic examples or logs from systems you own or are explicitly authorized to investigate.
- Keep secrets, credentials, private logs, and personal data out of source control.
- Treat event fields and log contents as untrusted input.
- Never execute content found in events or detection rules.

## Reporting a vulnerability

Avoid publishing sensitive exploit details or real user data in a public issue. Contact the repository owner privately through GitHub's available private-contact mechanism. Include the affected commit, impact, minimal reproduction steps, and a mitigation proposal when possible.

Do not include tokens, credentials, or confidential logs in a report.

## Data handling

Phase 1 uses no network services and persists only when the user explicitly runs the local database command. Database files are ignored by Git. This does not replace appropriate access controls, encryption, retention, or authorization for sensitive real-world logs.
