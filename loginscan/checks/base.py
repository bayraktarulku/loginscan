"""Shared helpers: build login data, get a baseline failed login, guess success."""
from __future__ import annotations

import re
import secrets

from ..context import CheckContext
from ..http import Response
from ..models import ScanConfig

SQL_ERROR_SIGNS = [
    "sql syntax", "sqlite3.", "sqlite error", "psycopg2", "pg::",
    "mysql_fetch", "you have an error in your sql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "odbc", "ora-0", "syntax error", "sqlalchemy",
]

SESSION_COOKIE_HINT = re.compile(r"sess|token|auth|sid|jwt|login", re.I)
# JSON APIs signal success by returning a token in the body.
TOKEN_KEY_HINT = re.compile(r'"(access_token|id_token|refresh_token|token|jwt)"\s*:', re.I)

# Signals that a request was throttled/blocked (shared by rate-limit checks).
BLOCK_STATUSES = {429, 403, 503}
_BLOCK_HINTS = ["too many", "rate limit", "try again later", "captcha", "locked", "blocked"]


def is_blocked(resp) -> bool:
    low = resp.body.lower()
    return resp.status in BLOCK_STATUSES or any(h in low for h in _BLOCK_HINTS)


def random_username(prefix: str = "nouser") -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)


def build_data(cfg: ScanConfig, username: str, password: str) -> dict[str, str]:
    data = dict(cfg.extra_fields)
    data[cfg.username_field] = username
    data[cfg.password_field] = password
    return data


def _input_value(html: str, field: str) -> str | None:
    for tag in _INPUT_RE.findall(html):
        name = re.search(r'name=["\']?([^"\'\s>]+)', tag, re.I)
        if name and name.group(1) == field:
            val = re.search(r'value=["\']?([^"\'\s>]*)', tag, re.I)
            return val.group(1) if val else ""
    return None


def _fresh_csrf(ctx: CheckContext, cfg: ScanConfig) -> str | None:
    # Fetch the login page so the cookie jar gets a matching CSRF cookie, then
    # read the token from the hidden field. Done per POST to stay valid even for
    # per-request tokens.
    if not cfg.csrf_field:
        return None
    resp = ctx.get(cfg.csrf_url or cfg.login_page_url or cfg.url)
    token = _input_value(resp.body, cfg.csrf_field)
    return token


def submit_login(ctx: CheckContext, cfg: ScanConfig, username: str, password: str) -> Response:
    data = build_data(cfg, username, password)
    if cfg.csrf_field:
        token = _fresh_csrf(ctx, cfg)
        if token is not None:
            data[cfg.csrf_field] = token
    return ctx.request(cfg.method, cfg.url, data=data, content_type=cfg.content_type)


def cookie_names(resp: Response) -> list[str]:
    return [c.split("=", 1)[0].strip() for c in resp.set_cookies if c.split("=", 1)[0].strip()]


def session_cookies(resp: Response) -> list[str]:
    return [n for n in cookie_names(resp) if SESSION_COOKIE_HINT.search(n)]


def baseline_fail(ctx: CheckContext, cfg: ScanConfig) -> Response:
    return submit_login(ctx, cfg, random_username(), "wrong_" + secrets.token_hex(3))


def has_sql_error(body: str) -> str | None:
    low = body.lower()
    for sign in SQL_ERROR_SIGNS:
        if sign in low:
            return sign
    return None


def looks_like_success(resp: Response, baseline: Response, cfg: ScanConfig) -> str | None:
    """Return a reason string if resp looks like a successful login, else None.

    Conservative on purpose to limit false positives; evidence goes in the report.
    """
    for token in cfg.success_indicators:
        if token and token.lower() in resp.body.lower():
            return f"success text seen in response: '{token}'"

    if TOKEN_KEY_HINT.search(resp.body) and not TOKEN_KEY_HINT.search(baseline.body):
        return "auth token returned in response body"

    new_sess = set(session_cookies(resp)) - set(session_cookies(baseline))
    if new_sess:
        return f"session cookie set that the failed baseline did not get: {sorted(new_sess)}"

    if resp.status < 400 and baseline.status >= 400:
        return f"status upgraded vs failed baseline (HTTP {resp.status} vs {baseline.status})"

    if 300 <= resp.status < 400 and not (300 <= baseline.status < 400):
        loc = resp.header("location") or "?"
        return f"redirect not present in failed baseline (HTTP {resp.status} -> {loc})"

    return None
