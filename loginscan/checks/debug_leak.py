"""Verbose error / debug-mode leakage.

Attacker view: trigger an error and read stack traces, framework debug pages and
internal paths to map the app. This sends one malformed probe and scans the response
for debug/traceback signatures.
"""
from __future__ import annotations

from ..context import CheckContext
from ..models import Finding, ScanConfig, Severity, Status
from .base import submit_login

CHECK = "debug_leak"
ORDER = 85  # after sqli
CWE = "CWE-209"
OWASP = "A05:2021 Security Misconfiguration"

_SIGNS = [
    "traceback (most recent call last)", "werkzeug", "django.core", "djangoproject",
    "rails", "actiondispatch", "symfony", "whoops", "stack trace", "stacktrace",
    ".py\", line", ".rb:", ".java:", "at line", "debug = true", "exception in thread",
]


def run(ctx: CheckContext, cfg: ScanConfig) -> list[Finding]:
    # A quote often triggers a server-side error on fragile apps.
    resp = submit_login(ctx, cfg, "'\"<loginscan>", "x")
    low = resp.body.lower()
    hit = next((s for s in _SIGNS if s in low), None)
    if hit:
        return [Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
            title="Verbose error / debug output leaks",
            detail=f"An error response exposed internal detail (matched '{hit}').",
            remediation="Disable debug mode in production; return generic error pages and log "
                        "details server-side only.",
            evidence={"status": resp.status, "signature": hit})]

    return [Finding(
        check=CHECK, status=Status.OK, severity=Severity.INFO,
        title="No debug/stack-trace leakage",
        detail="Error responses did not expose stack traces or debug pages.")]
