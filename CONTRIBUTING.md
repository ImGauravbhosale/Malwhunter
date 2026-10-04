# Contributing to MalwHunter

Issues and PRs are welcome. This project is early and under active
development — see the [README's Status section](README.md#status) for
what's built/live-verified vs. not started yet before proposing anything
large.

## Dev setup

```bash
uv sync
uv run pytest -q          # full test suite
uv run ruff check .       # lint
uv run bandit -r malwhunter -c pyproject.toml   # security static analysis
```

Detonation (the sandboxed dynamic-analysis pass) needs Docker Desktop
running locally; the rest of the test suite does not.

## Before proposing a change

- **Changes to the `Dossier` model, or the Recon/Detonation/Analyst
  passes** — read the [docs site](https://imgauravbhosale.github.io/Malwhunter/)
  for the full architecture writeup first. The core invariant ("no signal
  without evidence," deterministic verdict combination) is load-bearing —
  changes here should keep it intact, not work around it.
- **New Recon signal categories** — include the real-world incident or
  pattern it's modeled on, plus a fixture under `examples/npm-fixtures/`
  and a test exercising it.
- **Everything else** (bug fixes, docs, CLI UX) — normal PR flow, no
  special process.

## Pull requests

1. Fork, branch, make your change.
2. `uv run pytest -q` and `uv run ruff check .` should both pass.
3. Open a PR describing *why*, not just *what* — especially for anything
   touching detection logic, since a false positive or false negative
   there has real consequences for someone's CI pipeline.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md) — please don't open a public issue for
security reports.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
