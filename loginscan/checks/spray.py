"""Password-spraying resilience: is there IP-level throttling across accounts?

Attacker view: try one common password against many usernames to stay under
per-account lockout. This sends a few failed logins with DIFFERENT usernames from
one IP and checks whether the server throttles by IP (not just per account).
"""
from __future__ import annotations

from ..context import CheckContext
from ..http import RequestBudgetExceeded
from ..models import Finding, ScanConfig, Severity, Status
from .base import is_blocked, random_username, submit_login

CHECK = "spray"
ORDER = 130
CWE = "CWE-307"
OWASP = "A07:2021 Identification and Authentication Failures"


def run(ctx: CheckContext, cfg: ScanConfig, attempts: int = 8) -> list[Finding]:
    common_pw = "Password1!"
    statuses = []
    try:
        for i in range(attempts):
            if ctx.remaining <= 0:
                break
            resp = submit_login(ctx, cfg, random_username(f"spray{i}"), common_pw)
            statuses.append(resp.status)
            if is_blocked(resp):
                return [Finding(
                    check=CHECK, status=Status.OK, severity=Severity.INFO,
                    title="IP-level throttling present",
                    detail=f"Blocked after {len(statuses)} attempts across different usernames.",
                    evidence={"statuses": statuses})]
    except RequestBudgetExceeded:
        pass

    if not statuses:
        return [Finding(check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
                        title="Spray test could not run", detail="Request budget was exhausted.")]

    return [Finding(
        check=CHECK, status=Status.WARNING, severity=Severity.MEDIUM,
        title="No IP-level throttling (password spraying feasible)",
        detail=(f"{len(statuses)} failed logins across different usernames from one IP were "
                "not throttled; per-account lockout alone does not stop spraying."),
        remediation="Throttle by source IP across accounts as well as per account.",
        evidence={"attempts": len(statuses), "statuses": statuses},
    )]
