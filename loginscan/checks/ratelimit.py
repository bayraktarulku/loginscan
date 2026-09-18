"""Brute-force protection presence check.

Not a brute-forcer: it sends a few failed attempts with a fixed dummy password
and only checks whether the server starts blocking. It never tries to crack anything.
"""
from __future__ import annotations

from typing import List

from ..http import HttpClient, RequestBudgetExceeded
from ..models import Finding, ScanConfig, Severity, Status
from .base import random_username, submit_login

CHECK = "ratelimit"

BLOCK_STATUSES = {429, 403, 503}
BLOCK_HINTS = ["too many", "rate limit", "try again later", "captcha", "locked", "blocked"]


def run(client: HttpClient, cfg: ScanConfig, attempts: int = 6) -> List[Finding]:
    target_user = cfg.known_username or random_username("probe")
    wrong_pw = "definitely-wrong-pw"

    statuses = []
    blocked_at = None
    try:
        for i in range(1, attempts + 1):
            if client.remaining <= 0:
                break
            resp = submit_login(client, cfg, target_user, wrong_pw)
            statuses.append(resp.status)
            low = resp.body.lower()
            if resp.status in BLOCK_STATUSES or any(h in low for h in BLOCK_HINTS):
                blocked_at = i
                break
    except RequestBudgetExceeded:
        pass

    if blocked_at:
        return [Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="Brute-force protection active",
            detail=f"Server blocked at attempt {blocked_at} (rate limiting present).",
            evidence={"statuses": statuses},
        )]
    if not statuses:
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Rate-limit test could not run",
            detail="Request budget was exhausted.",
        )]
    return [Finding(
        check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
        title="No brute-force protection",
        detail=f"{len(statuses)} failed attempts in a row were accepted without blocking.",
        remediation="Add IP- and account-based rate limiting; use delays/CAPTCHA/temporary lockout.",
        evidence={"attempts": len(statuses), "statuses": statuses},
    )]
