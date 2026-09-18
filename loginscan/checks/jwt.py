"""Passive JWT weakness check.

If the login flow exposes a JWT (in a cookie or the response body), inspect its
header/payload without cracking anything: unsigned tokens (alg=none) and missing
expiry are flagged.
"""
from __future__ import annotations

import base64
import json
import re
from typing import List, Optional

from ..http import HttpClient
from ..models import Finding, ScanConfig, Severity, Status
from .base import baseline_fail

CHECK = "jwt"

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _b64url_json(segment: str) -> Optional[dict]:
    pad = "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(segment + pad))
    except Exception:
        return None


def _find_jwt(client: HttpClient, cfg: ScanConfig) -> Optional[str]:
    for _, value in client.observed_session_tokens:
        if _JWT_RE.fullmatch(value):
            return value
    resp = baseline_fail(client, cfg)
    for cookie in resp.set_cookies:
        m = _JWT_RE.search(cookie)
        if m:
            return m.group(0)
    m = _JWT_RE.search(resp.body)
    return m.group(0) if m else None


def run(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    token = _find_jwt(client, cfg)
    if not token:
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="No JWT observed",
            detail="No JSON Web Token seen in cookies or responses; check skipped.",
        )]

    parts = token.split(".")
    header = _b64url_json(parts[0]) or {}
    payload = _b64url_json(parts[1]) if len(parts) > 1 else {}
    payload = payload or {}
    alg = str(header.get("alg", "")).lower()

    findings: List[Finding] = []
    if alg == "none" or (len(parts) >= 3 and parts[2] == ""):
        findings.append(Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.CRITICAL,
            title="JWT is unsigned (alg=none)",
            detail="The token has no signature, so anyone can forge one and impersonate any user.",
            remediation="Reject alg=none; verify a strong signature (e.g. RS256/ES256) server-side.",
            evidence={"alg": header.get("alg")},
        ))
    if "exp" not in payload:
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.MEDIUM,
            title="JWT has no expiry (exp)",
            detail="Without exp the token never expires; a leaked token stays valid forever.",
            remediation="Add a short exp claim and validate it on every request.",
        ))
    if not findings:
        findings.append(Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="JWT looks acceptable",
            detail=f"Signed token (alg={header.get('alg')}) with an exp claim.",
        ))
    return findings
