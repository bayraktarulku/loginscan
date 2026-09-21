"""Transport and security-header checks (HTTPS, HSTS, nosniff, clickjacking, etc.)."""
from __future__ import annotations

from urllib.parse import urlparse

from ..context import CheckContext
from ..models import Finding, ScanConfig, Severity, Status

CHECK = "headers"
ORDER = 10


def run(ctx: CheckContext, cfg: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(cfg.url)
    is_https = parsed.scheme == "https"

    if not is_https:
        findings.append(Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.HIGH,
            title="Login is not served over HTTPS",
            detail="Username and password travel unencrypted; anyone on the network can read them.",
            remediation="Serve the whole site over HTTPS and redirect HTTP to HTTPS.",
            evidence={"scheme": parsed.scheme},
        ))

    probe_url = cfg.login_page_url or cfg.url
    try:
        resp = ctx.get(probe_url)
    except Exception as e:  # noqa: BLE001
        findings.append(Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Could not read headers",
            detail=f"GET {probe_url} failed: {e}",
        ))
        return findings

    def missing(header: str) -> bool:
        return resp.header(header) is None

    csp = (resp.header("content-security-policy") or "").lower()

    if is_https and missing("strict-transport-security"):
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.LOW,
            title="Missing HSTS header",
            detail="No Strict-Transport-Security; a first request may be downgraded to HTTP.",
            remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        ))
    if missing("x-content-type-options"):
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.LOW,
            title="Missing X-Content-Type-Options",
            detail="No nosniff; the browser may MIME-sniff responses.",
            remediation="Add X-Content-Type-Options: nosniff.",
        ))
    if missing("x-frame-options") and "frame-ancestors" not in csp:
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.MEDIUM,
            title="No clickjacking protection",
            detail="No X-Frame-Options or CSP frame-ancestors; the login page can be framed.",
            remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
        ))
    if missing("referrer-policy"):
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.LOW,
            title="Missing Referrer-Policy",
            detail="No Referrer-Policy; sensitive URL data may leak to third parties.",
            remediation="Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
        ))

    leak = resp.header("server") or resp.header("x-powered-by")
    if leak and any(ch.isdigit() for ch in leak):
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.LOW,
            title="Server/tech version disclosed",
            detail=f"Response header reveals version info: '{leak}'.",
            remediation="Strip version details from Server / X-Powered-By headers.",
            evidence={"header": leak},
        ))

    if not any(f.check == CHECK and f.status != Status.VULNERABLE for f in findings):
        findings.append(Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="Core security headers present",
            detail="No gaps found in HSTS/nosniff/frame protection/Referrer-Policy.",
        ))
    return findings
