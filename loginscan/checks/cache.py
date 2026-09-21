"""Cache-Control check: auth responses should not be cacheable."""
from __future__ import annotations

from ..context import CheckContext
from ..models import Finding, ScanConfig, Severity, Status
from .base import baseline_fail

CHECK = "cache"
ORDER = 40


def run(ctx: CheckContext, cfg: ScanConfig) -> list[Finding]:
    resp = baseline_fail(ctx, cfg)
    cc = (resp.header("cache-control") or "").lower()

    if "no-store" in cc:
        return [Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="Auth response is not cacheable",
            detail="Cache-Control: no-store is set on the login response.",
        )]
    return [Finding(
        check=CHECK, status=Status.WARNING, severity=Severity.LOW,
        title="Auth response may be cached",
        detail=f"Login response lacks Cache-Control: no-store (got '{cc or 'none'}').",
        remediation="Set Cache-Control: no-store on login and other authenticated responses.",
    )]
