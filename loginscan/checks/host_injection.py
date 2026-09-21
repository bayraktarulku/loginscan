"""Host header injection (password-reset poisoning).

Attacker view: send a forged Host / X-Forwarded-Host so the app builds absolute URLs
(e.g. a password-reset link) pointing at the attacker's domain. This sends a spoofed
host and checks whether it is reflected into the response body or a redirect Location.
"""
from __future__ import annotations

from ..context import CheckContext
from ..models import Finding, ScanConfig, Severity, Status

CHECK = "host_injection"
ORDER = 55
CWE = "CWE-644"
OWASP = "A05:2021 Security Misconfiguration"

_EVIL_HOST = "loginscan-evil.example"


def run(ctx: CheckContext, cfg: ScanConfig) -> list[Finding]:
    url = cfg.login_page_url or cfg.url
    headers = {"Host": _EVIL_HOST, "X-Forwarded-Host": _EVIL_HOST}
    resp = ctx.get(url, headers=headers)

    location = resp.header("location") or ""
    in_location = _EVIL_HOST in location
    in_body = _EVIL_HOST in resp.body
    if in_location or in_body:
        where = "redirect Location" if in_location else "response body"
        return [Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
            title="Host header reflected (reset-poisoning risk)",
            detail=f"A forged Host was reflected into the {where}; password-reset links may "
                   "point to an attacker domain.",
            remediation="Build absolute URLs from a fixed, configured base URL; validate Host "
                        "against an allowlist.",
            evidence={"forged_host": _EVIL_HOST, "where": where})]

    return [Finding(
        check=CHECK, status=Status.OK, severity=Severity.INFO,
        title="Host header not reflected",
        detail="A forged Host header was not echoed into the response.")]
