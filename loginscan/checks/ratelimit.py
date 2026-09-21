"""Brute-force protection check: sequential AND concurrent (race) probing.

Not a brute-forcer: it sends a few wrong-password attempts and only checks whether
the server blocks. The concurrent burst reveals limiters that count sequentially but
let a simultaneous burst slip through (a TOCTOU race).
"""
from __future__ import annotations

from ..context import CheckContext
from ..http import RequestBudgetExceeded
from ..models import Finding, ScanConfig, Severity, Status
from .base import build_data, random_username, submit_login

CHECK = "ratelimit"
ORDER = 200
CWE = "CWE-307"
OWASP = "A07:2021 Identification and Authentication Failures"

BLOCK_STATUSES = {429, 403, 503}
BLOCK_HINTS = ["too many", "rate limit", "try again later", "captcha", "locked", "blocked"]


def _blocked(resp) -> bool:
    low = resp.body.lower()
    return resp.status in BLOCK_STATUSES or any(h in low for h in BLOCK_HINTS)


def run(ctx: CheckContext, cfg: ScanConfig, attempts: int = 6) -> list[Finding]:
    target_user = cfg.known_username or random_username("probe")
    wrong_pw = "definitely-wrong-pw"

    statuses = []
    blocked_at = None
    try:
        for i in range(1, attempts + 1):
            if ctx.remaining <= 0:
                break
            resp = submit_login(ctx, cfg, target_user, wrong_pw)
            statuses.append(resp.status)
            if _blocked(resp):
                blocked_at = i
                break
    except RequestBudgetExceeded:
        pass

    if not statuses:
        return [Finding(check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
                        title="Rate-limit test could not run", detail="Request budget was exhausted.")]

    if blocked_at is None:
        return [Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
            title="No brute-force protection",
            detail=f"{len(statuses)} failed attempts in a row were accepted without blocking.",
            remediation="Add IP- and account-based rate limiting; use delays/CAPTCHA/temporary lockout.",
            evidence={"attempts": len(statuses), "statuses": statuses},
        )]

    findings = [Finding(
        check=CHECK, status=Status.OK, severity=Severity.INFO,
        title="Brute-force protection active (sequential)",
        detail=f"Server blocked at attempt {blocked_at}.",
        evidence={"statuses": statuses},
    )]
    findings.append(_concurrent_probe(ctx, cfg, blocked_at, wrong_pw))
    return [f for f in findings if f is not None]


def _concurrent_probe(ctx: CheckContext, cfg: ScanConfig, limit: int, wrong_pw: str):
    # Fire more than the observed limit at once, on a fresh account. A race-free
    # limiter blocks the excess; a racy one lets them all through.
    n = min(limit + 3, ctx.remaining, 12)
    if n <= limit:
        return Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Concurrent rate-limit test skipped",
            detail="Not enough request budget for a meaningful burst.")
    fresh = random_username("burst")
    try:
        responses = ctx.burst(cfg.method, cfg.url, build_data(cfg, fresh, wrong_pw),
                                 n, cfg.content_type)
    except RequestBudgetExceeded:
        return None
    if not responses:
        return None

    codes = [r.status for r in responses]
    blocked = sum(1 for r in responses if _blocked(r))
    if blocked == 0:
        return Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
            title="Rate limiter bypassable via concurrent requests",
            detail=(f"{len(codes)} simultaneous attempts on a fresh account all passed the "
                    f"limiter (which blocks after {limit} sequential attempts) — a race condition."),
            remediation="Make the counter atomic (e.g. atomic INCR / DB constraint) so "
                        "concurrent requests can't slip past.",
            evidence={"burst": len(codes), "blocked": blocked, "statuses": codes},
        )
    return Finding(
        check=CHECK, status=Status.OK, severity=Severity.INFO,
        title="Rate limiter holds under concurrency",
        detail=f"A burst of {len(codes)} simultaneous attempts was partly blocked ({blocked}).",
        evidence={"burst": len(codes), "blocked": blocked},
    )
