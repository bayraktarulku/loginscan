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


def build_data(cfg: ScanConfig, username: str, password: str) -> Dict[str, str]:
    data = dict(cfg.extra_fields)
    data[cfg.username_field] = username
    data[cfg.password_field] = password
    return data


def submit_login(client: HttpClient, cfg: ScanConfig, username: str, password: str) -> Response:
    return client.request(cfg.method, cfg.url, data=build_data(cfg, username, password),
                          content_type=cfg.content_type)


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
