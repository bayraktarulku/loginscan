"""HTTP verb / method handling check.

Flags authentication that also works over GET (credentials end up in URLs, logs
and browser history) and TRACE being enabled (Cross-Site Tracing).
"""
from __future__ import annotations

from urllib.parse import urlencode, urlsplit, urlunsplit

from ..http import HttpClient
from ..models import Finding, ScanConfig, Severity, Status
from .base import looks_like_success, random_username

CHECK = "verb"

BYPASS_PAYLOAD = "admin'--"


def _url_with(cfg: ScanConfig, username: str, password: str) -> str:
    parts = urlsplit(cfg.url)
    q = urlencode({cfg.username_field: username, cfg.password_field: password})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, q, ""))


def run(client: HttpClient, cfg: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []

    base = client.get(_url_with(cfg, random_username(), "x"))
    probe = client.get(_url_with(cfg, BYPASS_PAYLOAD, "x"))
    why = looks_like_success(probe, base, cfg)
    if why:
        findings.append(Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
            title="Authentication accepted over GET",
            detail="The login endpoint processes credentials via GET; they leak into URLs, logs and history.",
            remediation="Accept login only via POST; reject GET for state-changing/auth actions.",
            evidence={"signal": why},
        ))

    try:
        trace = client.request("TRACE", cfg.url)
        if trace.status == 200:
            findings.append(Finding(
                check=CHECK, status=Status.WARNING, severity=Severity.LOW,
                title="TRACE method enabled",
                detail="TRACE is enabled, which can enable Cross-Site Tracing (XST).",
                remediation="Disable the TRACE method at the server/proxy.",
            ))
    except Exception:  # noqa: BLE001
        pass

    if not findings:
        findings.append(Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="Method handling looks fine",
            detail="Login is not accepted over GET and TRACE is not enabled.",
        ))
    return findings
