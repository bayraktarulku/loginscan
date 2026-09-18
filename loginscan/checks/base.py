"""Shared helpers: build login data, get a baseline failed login, guess success."""
from __future__ import annotations

import re
import secrets
from typing import Dict, List, Optional

from ..http import HttpClient, Response
from ..models import ScanConfig

SQL_ERROR_SIGNS = [
    "sql syntax", "sqlite3.", "sqlite error", "psycopg2", "pg::",
    "mysql_fetch", "you have an error in your sql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "odbc", "ora-0", "syntax error", "sqlalchemy",
]

SESSION_COOKIE_HINT = re.compile(r"sess|token|auth|sid|jwt|login", re.I)


def random_username(prefix: str = "nouser") -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)


def build_data(cfg: ScanConfig, username: str, password: str) -> Dict[str, str]:
    data = dict(cfg.extra_fields)
    data[cfg.username_field] = username
    data[cfg.password_field] = password
    return data


def _input_value(html: str, field: str) -> Optional[str]:
    for tag in _INPUT_RE.findall(html):
        name = re.search(r'name=["\']?([^"\'\s>]+)', tag, re.I)
        if name and name.group(1) == field:
            val = re.search(r'value=["\']?([^"\'\s>]*)', tag, re.I)
            return val.group(1) if val else ""
    return None


def _fresh_csrf(client: HttpClient, cfg: ScanConfig) -> Optional[str]:
    # Fetch the login page so the cookie jar gets a matching CSRF cookie, then
    # read the token from the hidden field. Done per POST to stay valid even for
    # per-request tokens.
    resp = client.get(cfg.csrf_url or cfg.login_page_url or cfg.url)
    token = _input_value(resp.body, cfg.csrf_field)
    client.csrf_token = token
    return token


def submit_login(client: HttpClient, cfg: ScanConfig, username: str, password: str) -> Response:
    data = build_data(cfg, username, password)
    if cfg.csrf_field:
        token = _fresh_csrf(client, cfg)
        if token is not None:
            data[cfg.csrf_field] = token
    return client.request(cfg.method, cfg.url, data=data, content_type=cfg.content_type)


def cookie_names(resp: Response) -> List[str]:
    return [c.split("=", 1)[0].strip() for c in resp.set_cookies if c.split("=", 1)[0].strip()]


def session_cookies(resp: Response) -> List[str]:
    return [n for n in cookie_names(resp) if SESSION_COOKIE_HINT.search(n)]


def baseline_fail(client: HttpClient, cfg: ScanConfig) -> Response:
    return submit_login(client, cfg, random_username(), "wrong_" + secrets.token_hex(3))


def has_sql_error(body: str) -> Optional[str]:
    low = body.lower()
    for sign in SQL_ERROR_SIGNS:
        if sign in low:
            return sign
    return None


def looks_like_success(resp: Response, baseline: Response, cfg: ScanConfig) -> Optional[str]:
    """Return a reason string if resp looks like a successful login, else None.

    Conservative on purpose to limit false positives; evidence goes in the report.
    """
    for token in cfg.success_indicators:
        if token and token.lower() in resp.body.lower():
            return f"success text seen in response: '{token}'"

    new_sess = set(session_cookies(resp)) - set(session_cookies(baseline))
    if new_sess:
        return f"session cookie set that the failed baseline did not get: {sorted(new_sess)}"

    if resp.status < 400 and baseline.status >= 400:
        return f"status upgraded vs failed baseline (HTTP {resp.status} vs {baseline.status})"

    if 300 <= resp.status < 400 and not (300 <= baseline.status < 400):
        loc = resp.header("location") or "?"
        return f"redirect not present in failed baseline (HTTP {resp.status} -> {loc})"

    return None
