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

Useful options:

| Option | Description |
|---|---|
| `--i-own-this` | **Required.** Asserts you are authorized to test the target. |
| `--user NAME` | A username that really exists (not the password). Strengthens the enumeration check. |
| `--success "text"` | Text that means "login succeeded". Repeatable. |
| `--json-body` | Send credentials as JSON instead of form-encoded. |
| `--username-field` / `--password-field` | Override field names. |
| `--field csrf=abc` | Constant field added to every request. |
| `--max-requests 25` | Total request budget. |
| `--json report.json` | Also write the report as JSON. |
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
| `ratelimit` | Whether repeated failed logins get blocked |
| `cookies` | Session cookie HttpOnly / Secure / SameSite flags |
| `session` | Predictable session tokens (short / numeric / sequential / low-entropy) |
| `headers` | HTTPS, HSTS, nosniff, clickjacking, Referrer-Policy, version disclosure |

## Roadmap (checks to add next, in order)

- [ ] `csrf` — login form / endpoint CSRF token presence and enforcement
- [ ] `open_redirect` — unvalidated post-login redirect (`?next=`, `?returnUrl=`)
- [ ] `verb` — HTTP method handling / verb tampering
- [ ] `jwt` — passive JWT weaknesses (`alg=none`, missing `exp`)
- [ ] `cors` — permissive CORS on the auth endpoint (`ACAO: *` with credentials)
- [ ] `cache` — sensitive responses missing `Cache-Control: no-store`

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

## License

MIT. Authorized use only.
