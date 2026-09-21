# loginscan

A lightweight, dependency-free **defensive self-audit scanner** for login endpoints.
Point it at your own login page or API, and it runs a series of **safe, low-volume**
checks and reports what is wrong and **how to fix it**. You can scan by giving just a
**site link** or a **Swagger/OpenAPI link** — the login endpoint is auto-discovered.

> ⚠️ **Authorized use only.** Run this only against systems you **own** or have **written
> permission** to test. Unauthorized scanning is illegal. The tool refuses to run without
> an explicit confirmation (`--i-own-this` / `authorized=True`).

## Why it's safe

This is not an attack tool. By design it:

- **Does not crack passwords** — no brute-force, no wordlists. The "brute-force" check only
  sends 5–6 requests to see *whether rate limiting exists*.
- **Is low-volume** — a total request budget (default 25) caps every scan.
- **Is non-destructive** — only well-known detection probes; it never modifies data.

## Install

```bash
pip install .
# or, for development:
pip install -e .
```

## Usage

Scan by explicit URL:

```bash
loginscan https://site/login --i-own-this --user alice --success "Welcome"
```

Scan by **site link** (login form auto-discovered):

```bash
loginscan --site https://site/login-page --i-own-this --user alice
```

Scan by **Swagger/OpenAPI link** (JSON spec; endpoint + fields auto-discovered):

```bash
loginscan --swagger https://api.site/openapi.json --i-own-this --user alice
```

### Whole-app scan (all auth endpoints)

With an OpenAPI/Swagger spec, scan **every** auth endpoint (login, register, password reset,
token refresh, …) in one run and get an aggregated report + worst-case score:

```bash
loginscan --swagger https://api.site/openapi.json --all-endpoints --i-own-this --user alice
# App scan: 4 auth endpoints discovered
# >>> [login] .../login
# >>> [register] .../register  ...
```

### Real login forms (CSRF + cookies)

Many real forms set a CSRF cookie and require a matching hidden token. With `--site`,
loginscan **auto-detects** the CSRF field, keeps a cookie jar, and fetches a fresh token
before each login request — so scanning works through CSRF protection:

```bash
loginscan --site https://site/login --i-own-this --user alice
# Target: POST https://site/login  (fields: username/password, form, csrf=csrf_token)
```

Override detection when needed: `--csrf-field csrf_token --csrf-url https://site/login`.

Useful options:

| Option | Description |
|---|---|
| `--i-own-this` | **Required.** Asserts you are authorized to test the target. |
| `--user NAME` | A username that really exists (not the password). Strengthens the enumeration check. |
| `--success "text"` | Text that means "login succeeded". Repeatable. |
| `--json-body` | Send credentials as JSON instead of form-encoded. |
| `--username-field` / `--password-field` | Override field names. |
| `--field csrf=abc` | Constant field added to every request. |
| `--csrf-field NAME` | Hidden CSRF field name; enables cookie jar + auto token fetch. |
| `--max-requests 25` | Total request budget. |
| `--json report.json` | Also write the report as JSON. |
| `--html report.html` | Also write a shareable, styled HTML report. |
| `--sarif report.sarif` | Also write SARIF 2.1.0 for GitHub code scanning / CI. |
| `--insecure` | Disable TLS verification (for your own test server). |

Exit code: `1` if any vulnerability is found, `0` if clean, `2` if unauthorized/misused (handy for CI).

## Python API

```python
from loginscan import Scanner, ScanConfig

cfg = ScanConfig(url="https://site/login", known_username="alice",
                 success_indicators=["Welcome"])
report = Scanner(cfg, authorized=True).run()
print(report.to_text())
print(report.to_json())
```

## Checks

| Check | What it looks for |
|---|---|
| `sqli` | SQL-injection auth bypass + database error leakage |
| `enumeration` | Different responses for existing vs unknown users |
| `ratelimit` | Whether repeated failed logins get blocked — sequentially **and** in a concurrent burst (catches race-condition bypasses) |
| `cookies` | Session cookie HttpOnly / Secure / SameSite flags |
| `session` | Predictable session tokens (short / numeric / sequential / low-entropy) |
| `csrf` | CSRF token / cookie / SameSite defense on the login page |
| `open_redirect` | Unvalidated redirect via `?next=`, `?returnUrl=`, etc. |
| `jwt` | Passive JWT weaknesses (`alg=none`, missing `exp`) |
| `verb` | Auth accepted over GET (creds in URLs/logs), TRACE enabled |
| `cors` | Permissive CORS on the auth endpoint (reflected origin / `*` with credentials) |
| `cache` | Auth responses missing `Cache-Control: no-store` |
| `headers` | HTTPS, HSTS, nosniff, clickjacking, Referrer-Policy, version disclosure |

## Learning demo

This repo also ships an intentionally **vulnerable** and a **secure** server to try loginscan against:

```bash
python3 vulnerable_app.py     # terminal 1 -> port 8001
loginscan --site http://127.0.0.1:8001/ --i-own-this --user admin --success "Giriş başarılı"
#   -> 4 vulnerabilities found

python3 secure_app.py         # port 8002
loginscan --site http://127.0.0.1:8002/ --i-own-this --user admin --success "Giriş başarılı"
#   -> sqli / enumeration / rate-limit all OK
```

## Writing a plugin check

loginscan discovers extra checks from the `loginscan.checks` entry-point group. A check is
any object with a `CHECK` name and `run(client, cfg) -> list[Finding]` (a plain function
works too — its entry-point name becomes the check name):

```python
# mypkg/mycheck.py
from loginscan.models import Finding, Severity, Status
CHECK = "mycheck"
def run(client, cfg):
    resp = client.get(cfg.url)
    if "X-Powered-By" in resp.headers:
        return [Finding(CHECK, Status.WARNING, Severity.LOW, "Tech disclosed", "…")]
    return [Finding(CHECK, Status.OK, Severity.INFO, "OK", "")]
```

```toml
# mypkg/pyproject.toml
[project.entry-points."loginscan.checks"]
mycheck = "mypkg.mycheck"
```

After `pip install mypkg`, `loginscan --list-checks` shows it and scans run it automatically.
Use `--only a,b` / `--skip x,y` to control which checks run.

## Config profiles, baseline & CI gating

Save a reusable profile (JSON, or YAML with `pyyaml`) instead of long command lines:

```json
{ "site": "https://staging/login", "user": "alice", "success": ["Welcome"],
  "skip": ["cache"], "min_score": 80, "fail_on": "vulnerable" }
```

```bash
loginscan --config profile.json --i-own-this
```

CLI flags override the config. Gate CI with `--fail-on {vulnerable,warning,never}` and
`--min-score N` (exit `1` on failure). Accept existing findings with a **baseline** so only
NEW issues fail the build:

```bash
loginscan --site https://staging/login --i-own-this --write-baseline baseline.json
loginscan --site https://staging/login --i-own-this --baseline baseline.json   # passes until something new appears
```

## Security score

Every report includes a **0–100 score and a letter grade** (A–F) derived from the
findings' severities, plus a **CWE** and **OWASP Top 10** reference per finding (in the
text, JSON, HTML and SARIF output).

## GitHub Action / CI

Scan a staging deployment on every push and upload results to GitHub code scanning:

```yaml
# .github/workflows/loginscan.yml
name: loginscan
on: [push]
permissions:
  security-events: write   # to upload SARIF
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: bayraktarulku/loginscan@v1
        with:
          site: https://staging.example.com/login
          user: alice
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: loginscan.sarif
```

Using the action asserts you are authorized to test the target. It fails the job when a
vulnerability is found (`fail-on-vuln: false` to only report).

## Releasing to PyPI

The package builds cleanly (`python -m build`) and passes `twine check`. To publish:

1. Create the `loginscan` project on PyPI and add a Trusted Publisher for this repo's
   `Publish to PyPI` workflow (environment `pypi`).
2. Push a version tag: `git tag v0.1.0 && git push origin v0.1.0`.

The workflow then builds and uploads automatically — no API token stored in the repo.

## License

MIT. Authorized use only.
