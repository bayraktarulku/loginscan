# loginscan

A lightweight, **dependency-free** defensive self-audit scanner for login endpoints. Point it
at your own login page or API and it runs a series of safe, low-volume checks, then reports
what is wrong, how serious it is (0–100 score + CWE/OWASP), and how to fix it.

!!! warning "Authorized use only"
    Only run loginscan against systems you own or have written permission to test. The tool
    refuses to run without an explicit `--i-own-this` confirmation.

## Install

```bash
pip install loginscan
```

## Scan

```bash
# by explicit URL
loginscan https://site/login --i-own-this --user alice --success "Welcome"

# by site link (login form auto-discovered, incl. CSRF)
loginscan --site https://site/login --i-own-this --user alice

# by OpenAPI/Swagger link
loginscan --swagger https://api.site/openapi.json --i-own-this --user alice

# every auth endpoint in the spec
loginscan --swagger https://api.site/openapi.json --all-endpoints --i-own-this
```

## Why it's safe

- **No password cracking** — no brute-force, no wordlists.
- **Low-volume** — a request budget caps every scan.
- **Non-destructive** — detection probes only.

See [Usage](usage.md) for all options, [Checks](checks.md) for what it looks for, and
[CI & config](ci.md) to gate your pipeline.
