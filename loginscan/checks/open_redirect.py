"""Open redirect check.

Sends a benign external sentinel via common redirect parameters and checks
whether the server issues a redirect (3xx Location) to that external host.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlencode, urlparse, urlsplit, urlunsplit

from ..http import HttpClient
from ..models import Finding, ScanConfig, Severity, Status

CHECK = "open_redirect"

REDIRECT_PARAMS = ["next", "redirect", "redirect_uri", "returnUrl", "return_to",
                   "url", "dest", "continue"]
SENTINEL = "https://loginscan-external.example/"


def _with_query(base_url: str, param: str, value: str) -> str:
    parts = urlsplit(base_url)
    query = urlencode({param: value})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def run(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    base = cfg.login_page_url or cfg.url
    sentinel_host = urlparse(SENTINEL).netloc

    for param in REDIRECT_PARAMS:
        if client.remaining <= 0:
            break
        try:
            resp = client.get(_with_query(base, param, SENTINEL))
        except Exception:  # noqa: BLE001
            continue
        location = resp.header("location") or ""
        if 300 <= resp.status < 400 and sentinel_host in location:
            return [Finding(
                check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
                title="Open redirect via login parameter",
                detail=f"'{param}' is reflected into a redirect to an external host without validation.",
                remediation="Allow redirects only to a fixed allowlist of internal paths/hosts.",
                evidence={"param": param, "location": location},
            )]

    return [Finding(
        check=CHECK, status=Status.OK, severity=Severity.INFO,
        title="No open redirect via common parameters",
        detail="Common redirect parameters did not trigger an external redirect.",
    )]
