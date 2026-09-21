"""Session cookie flag check: HttpOnly, Secure, SameSite."""
from __future__ import annotations

from urllib.parse import urlparse

from ..http import HttpClient
from ..models import Finding, ScanConfig, Severity, Status
from .base import baseline_fail

CHECK = "cookies"


def _parse_flags(raw: str) -> dict:
    name = raw.split("=", 1)[0].strip() if raw else "?"
    low = raw.lower()
    return {
        "name": name,
        "httponly": "httponly" in low,
        "secure": "secure" in low,
        "samesite": "samesite" in low,
    }


def run(client: HttpClient, cfg: ScanConfig) -> list[Finding]:
    resp = baseline_fail(client, cfg)
    is_https = urlparse(cfg.url).scheme == "https"

    if not resp.set_cookies:
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="No cookies to inspect",
            detail="No Set-Cookie on this request (session may be set only on successful login).",
        )]

    findings: list[Finding] = []
    for raw in resp.set_cookies:
        f = _parse_flags(raw)
        missing = []
        if not f["httponly"]:
            missing.append("HttpOnly")
        if is_https and not f["secure"]:
            missing.append("Secure")
        if not f["samesite"]:
            missing.append("SameSite")

        if missing:
            findings.append(Finding(
                check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
                title=f"Cookie missing security flags: {f['name']}",
                detail=f"Missing: {', '.join(missing)}.",
                remediation="Set HttpOnly, Secure and SameSite=Lax/Strict on session cookies.",
                evidence={"cookie": f["name"], "missing": missing},
            ))
        else:
            findings.append(Finding(
                check=CHECK, status=Status.OK, severity=Severity.INFO,
                title=f"Cookie flags complete: {f['name']}",
                detail="HttpOnly / Secure / SameSite present.",
            ))
    return findings
