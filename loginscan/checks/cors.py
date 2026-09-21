"""CORS misconfiguration check on the auth endpoint."""
from __future__ import annotations

from ..context import CheckContext
from ..models import Finding, ScanConfig, Severity, Status

CHECK = "cors"

EVIL_ORIGIN = "https://loginscan-evil.example"


def run(ctx: CheckContext, cfg: ScanConfig) -> list[Finding]:
    resp = ctx.get(cfg.login_page_url or cfg.url, headers={"Origin": EVIL_ORIGIN})
    acao = resp.header("access-control-allow-origin")
    acac = (resp.header("access-control-allow-credentials") or "").lower() == "true"

    if acao == EVIL_ORIGIN and acac:
        return [Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.HIGH,
            title="CORS reflects any origin with credentials",
            detail="The server echoes an arbitrary Origin and allows credentials; "
                   "any site can read authenticated responses.",
            remediation="Reflect only an allowlist of trusted origins; never combine "
                        "credentials with a reflected/wildcard origin.",
            evidence={"allow_origin": acao, "allow_credentials": True},
        )]
    if acao == "*" and acac:
        return [Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
            title="CORS wildcard with credentials",
            detail="ACAO '*' together with credentials is invalid and dangerous.",
            remediation="Use a strict origin allowlist; do not use '*' with credentials.",
            evidence={"allow_origin": acao, "allow_credentials": True},
        )]
    if acao == EVIL_ORIGIN:
        return [Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.MEDIUM,
            title="CORS reflects arbitrary origin",
            detail="The server echoes any Origin in ACAO.",
            remediation="Reflect only trusted origins from an allowlist.",
            evidence={"allow_origin": acao},
        )]
    if acao == "*":
        return [Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.LOW,
            title="Wildcard CORS on auth endpoint",
            detail="ACAO '*' exposes responses to any origin (no credentials).",
            remediation="Restrict CORS to trusted origins for auth endpoints.",
            evidence={"allow_origin": acao},
        )]
    return [Finding(
        check=CHECK, status=Status.OK, severity=Severity.INFO,
        title="No permissive CORS detected",
        detail="The endpoint did not expose an unsafe Access-Control-Allow-Origin.",
    )]
