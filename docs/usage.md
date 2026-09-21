# Usage

## Targets

Give exactly one target:

- a login endpoint URL,
- `--site URL` — fetch the page and auto-discover the login form (fields **and** CSRF token),
- `--swagger URL|file` — parse an OpenAPI/Swagger spec (v2 or v3), or
- `--swagger ... --all-endpoints` — scan every auth endpoint (login/register/reset/…).

## Common options

| Option | Description |
|---|---|
| `--i-own-this` | **Required.** Asserts you are authorized to test the target. |
| `--user NAME` | A username that really exists (strengthens enumeration). |
| `--success "text"` | Text meaning "login succeeded" (repeatable). |
| `--json-body` | Send credentials as JSON instead of form-encoded. |
| `--csrf-field NAME` | Enable cookie jar + auto CSRF token fetch. |
| `--only a,b` / `--skip x,y` | Choose which checks run. |
| `--json / --html / --sarif FILE` | Extra report formats. |
| `--max-requests N` | Total request budget (default 60). |

## Real login forms (CSRF)

With `--site`, loginscan auto-detects the CSRF field, keeps a cookie jar, and fetches a fresh
token before each login request, so scanning works through double-submit CSRF protection.

## Output & exit codes

Every run prints a score (0–100 + grade) and findings. Exit code is `1` when the run fails its
gate (see [CI & config](ci.md)), `0` when clean, and `2` on misuse / missing authorization.
