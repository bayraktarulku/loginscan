# Checks

loginscan ships 13 built-in checks. Each finding carries a severity, a **CWE** and an
**OWASP Top 10 (2021)** reference, and a remediation.

| Check | What it looks for | CWE |
|---|---|---|
| `sqli` | SQL-injection auth bypass + database error leakage | CWE-89 |
| `enumeration` | Different responses for existing vs unknown users | CWE-204 |
| `ratelimit` | Blocking of repeated failed logins — sequential **and** concurrent burst (race) | CWE-307 |
| `cookies` | Session cookie HttpOnly / Secure / SameSite flags | CWE-1004 |
| `session` | Predictable session tokens (short / numeric / sequential / low-entropy) | CWE-330 |
| `session_fixation` | Session id not rotated on login (stateful; needs `--password`) | CWE-384 |
| `csrf` | CSRF token / cookie / SameSite defense on the login page | CWE-352 |
| `jwt` | Passive JWT weaknesses (`alg=none`, missing `exp`) | CWE-347 |
| `open_redirect` | Unvalidated redirect via `?next=`, `?returnUrl=`, … | CWE-601 |
| `verb` | Auth accepted over GET (creds in URLs/logs), TRACE enabled | CWE-650 |
| `cors` | Reflected origin / `*` with credentials on the auth endpoint | CWE-942 |
| `cache` | Auth responses missing `Cache-Control: no-store` | CWE-525 |
| `headers` | HTTPS, HSTS, nosniff, clickjacking, Referrer-Policy, version disclosure | CWE-693 |

List them (including installed plugins) with:

```bash
loginscan --list-checks
```

Run a subset with `--only sqli,cors` or `--skip cache`.

## The concurrent rate-limit probe

Beyond sending failed logins one after another, `ratelimit` fires a **synchronized burst** of
requests on a fresh account. A race-free limiter blocks the excess; a limiter with a
non-atomic counter lets them all through — a TOCTOU race that a sequential test never sees.
