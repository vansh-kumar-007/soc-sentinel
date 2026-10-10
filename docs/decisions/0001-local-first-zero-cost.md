# ADR 0001: Local-first, zero-cost foundation

- **Status:** Accepted
- **Date:** 2026-10-10

## Context

SOC Sentinel is a student portfolio project with a hard budget of ₹0. It must work locally without cloud services, payment details, paid tiers, API keys, or external services.

## Decision

Use Python, SQLite from the standard library, and a local CLI for Phase 1. Development tools are optional extras. Add the dashboard after the underlying pipeline works. Hosting is an optional later assessment, not a core dependency.

## Consequences

- The core can be demonstrated locally after dependencies are installed.
- SQLite is suitable for the initial single-user MVP; multi-user access is not a Phase 1 goal.
- GitHub and free CI are conveniences, not runtime dependencies.
- No hosted database or AI API is part of the core architecture.
