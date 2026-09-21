"""CSRF protection check (passive).

Looks at the login page for a defense: a CSRF token field/meta, a CSRF cookie,
or a SameSite cookie. If none is present, CSRF is likely possible.
"""
from __future__ import annotations

import re

from ..context import CheckContext
from ..models import Finding, ScanConfig, Severity, Status

CHECK = "csrf"
ORDER = 20
CWE = "CWE-352"
OWASP = "A01:2021 Broken Access Control"

_TOKEN_INPUT = re.compile(
    r'<input[^>]*name=["\']?[^"\'>\s]*(?:csrf|xsrf|authenticity|_token)[^"\'>\s]*', re.I)
_META_TOKEN = re.compile(r'<meta[^>]+name=["\'](?:csrf|xsrf)[-_]?token["\']', re.I)
_CSRF_COOKIE = re.compile(r"csrf|xsrf", re.I)


def run(ctx: CheckContext, cfg: ScanConfig) -> list[Finding]:
    page = ctx.get(cfg.login_page_url or cfg.url)
    body = page.body

    has_token = bool(_TOKEN_INPUT.search(body) or _META_TOKEN.search(body))
    has_csrf_cookie = any(_CSRF_COOKIE.search(c.split("=", 1)[0]) for c in page.set_cookies)
    has_samesite = any("samesite" in c.lower() for c in page.set_cookies)

    if has_token or has_csrf_cookie or has_samesite:
        how = ("CSRF token" if has_token else
               "CSRF cookie" if has_csrf_cookie else "SameSite cookie")
        return [Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="CSRF defense present",
            detail=f"Found a CSRF defense on the login page ({how}).",
        )]

    return [Finding(
        check=CHECK, status=Status.WARNING, severity=Severity.MEDIUM,
        title="No CSRF protection detected on login",
        detail="No CSRF token, CSRF cookie, or SameSite cookie found; login may be forgeable.",
        remediation="Add a per-session CSRF token to the login form or set SameSite=Lax/Strict on cookies.",
    )]
