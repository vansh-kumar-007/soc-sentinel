# Contributing

Contributions should preserve SOC Sentinel's local-first, zero-cost, defensive, and evidence-driven goals.

## Development setup

Use Python 3.11 or newer:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Before submitting

Run these checks from the repository root:

```bash
pytest
ruff check .
ruff format --check .
mypy src tests
```

Tests should be deterministic, network-independent, and safe to run locally and in CI.

## Change expectations

- Keep changes small and focused on one milestone.
- Add tests for new behavior and regression fixes.
- Document security-sensitive decisions and update `docs/PROJECT_STATUS.md`.
- Never commit secrets, private logs, generated SQLite databases, or large datasets.
- Do not add paid services, mandatory API keys, telemetry, or network dependencies without explicit review.
- Detection logic must be explainable and tied to event evidence. Never dynamically execute rules.
- Use only data and systems you own or are authorized to assess.

Use short, imperative commit messages such as `test: cover timestamp validation` or `docs: document local event replay`.
