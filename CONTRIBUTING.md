# Contributing to loginscan

Thanks for helping improve loginscan. This is a **defensive** self-audit tool; please keep
contributions aligned with that goal (detection and remediation, not offensive tooling).

## Development setup

```bash
git clone https://github.com/bayraktarulku/loginscan
cd loginscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" ruff mypy pre-commit
pre-commit install
```

## Before you push

The CI runs these; run them locally first:

```bash
ruff check loginscan tests     # lint
mypy loginscan                 # type-check
pytest                         # tests
```

## Adding a check

A check is a module exposing `CHECK` (str) and `run(client, cfg) -> list[Finding]`.
Built-in checks live in `loginscan/checks/`; register them in `loginscan/checks/__init__.py`
and add a CWE/OWASP entry in `loginscan/knowledge.py`. Third-party checks can ship as
plugins via the `loginscan.checks` entry-point group — see the README.

Please add a test (unit against a fake client, and/or an integration test using the demo
servers in `tests/conftest.py`), and keep checks **low-volume and non-destructive**.

## Safety rules

- Never add password cracking, high-volume brute-force, or destructive payloads.
- Every network action must respect the request budget and the authorization gate.
- User-facing strings and code stay in English.
