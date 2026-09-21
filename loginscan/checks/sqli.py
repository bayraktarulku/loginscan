"""SQL injection detection (detection-only, non-destructive)."""
from __future__ import annotations

from ..http import HttpClient
from ..models import Finding, ScanConfig, Severity, Status
from .base import baseline_fail, has_sql_error, looks_like_success, submit_login

CHECK = "sqli"

AUTH_BYPASS_PAYLOADS = ["admin'--", "admin'#", "' OR '1'='1'--", "' OR 1=1--"]
ERROR_PROBE = "'"


def run(client: HttpClient, cfg: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = baseline_fail(client, cfg)

    probe = submit_login(client, cfg, ERROR_PROBE, "x")
    sign = has_sql_error(probe.body)
    if sign:
        findings.append(Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.HIGH,
            title="Database error leaks (possible SQL injection)",
            detail="A single quote in the input returned a raw SQL error, so input reaches the query.",
            remediation="Use parameterized queries and return a generic error to users.",
            evidence={"trigger": "username='", "error": sign},
        ))

    hit = None
    for payload in AUTH_BYPASS_PAYLOADS:
        resp = submit_login(client, cfg, payload, "irrelevant")
        why = looks_like_success(resp, base, cfg)
        if why:
            hit = (payload, why, resp.status)
            break

    if hit:
        payload, why, status = hit
        findings.append(Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.CRITICAL,
            title="SQL injection bypasses authentication",
            detail=f"Username '{payload}' produced a success-like response; login without a password.",
            remediation="Use parameterized queries; never build SQL by string-concatenating input.",
            evidence={"payload": payload, "signal": why, "http": status},
        ))
    elif not sign:
        findings.append(Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="No obvious SQL injection signal",
            detail="Classic payloads did not bypass login or leak SQL errors.",
        ))
    return findings
