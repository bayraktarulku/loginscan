"""Rate-limit bypass via spoofed client-IP headers.

Attacker view: once throttled, rotate X-Forwarded-For / X-Real-IP so a limiter that
trusts those headers resets its per-IP counter. This first trips the limiter, then
retries with spoofed IP headers; if the block clears, the limiter is bypassable.
"""
from __future__ import annotations

from ..context import CheckContext
from ..http import RequestBudgetExceeded
from ..models import Finding, ScanConfig, Severity, Status
from .base import is_blocked, random_username, submit_login

CHECK = "ratelimit_bypass"
ORDER = 210  # after ratelimit (needs a limiter to exist)
CWE = "CWE-290"
OWASP = "A07:2021 Identification and Authentication Failures"

_SPOOF_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP"]


def _fake_ip(i: int) -> str:
    return f"203.0.113.{10 + i}"  # TEST-NET-3, non-routable


def run(ctx: CheckContext, cfg: ScanConfig, trip: int = 8) -> list[Finding]:
    user = random_username("rlbypass")  # a throwaway account, never a real one
    wrong = "definitely-wrong-pw"

    blocked = False
    try:
        for _ in range(trip):
            if ctx.remaining <= 0:
                break
            if is_blocked(submit_login(ctx, cfg, user, wrong)):
                blocked = True
                break
    except RequestBudgetExceeded:
        pass

    if not blocked:
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Rate-limit bypass not applicable",
            detail="No rate limit was triggered, so there is nothing to bypass here.")]

    # Now retry with rotating spoofed IP headers; a header-trusting limiter resets.
    for i in range(3):
        if ctx.remaining <= 0:
            break
        ip = _fake_ip(i)
        headers = dict.fromkeys(_SPOOF_HEADERS, ip)
        try:
            resp = ctx.request(cfg.method, cfg.url, data={cfg.username_field: user,
                               cfg.password_field: wrong, **cfg.extra_fields},
                               headers=headers, content_type=cfg.content_type)
        except RequestBudgetExceeded:
            break
        if not is_blocked(resp):
            return [Finding(
                check=CHECK, status=Status.VULNERABLE, severity=Severity.HIGH,
                title="Rate limiter bypassable via spoofed IP header",
                detail=("After being throttled, a request with a forged client-IP header was "
                        "accepted again — the limiter trusts attacker-controlled headers."),
                remediation="Rate-limit on the real connection IP; only trust X-Forwarded-For "
                            "from known proxies.",
                evidence={"header_ip": ip, "status": resp.status})]

    return [Finding(
        check=CHECK, status=Status.OK, severity=Severity.INFO,
        title="Rate limiter ignores spoofed IP headers",
        detail="Forged client-IP headers did not clear the block.")]
