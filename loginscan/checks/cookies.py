"""
Oturum cookie'si güvenlik bayrakları kontrolü.

Bir login denemesinden dönen Set-Cookie başlıklarına bakar:
  * HttpOnly  → JavaScript cookie'yi okuyamasın (XSS ile çalınmasını zorlaştırır)
  * Secure    → cookie yalnızca HTTPS üzerinden gitsin
  * SameSite  → CSRF'i zorlaştırır
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from ..http import HttpClient, Response
from ..models import Finding, ScanConfig, Severity, Status
from .base import baseline_fail

CHECK = "cookies"


def _parse_flags(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else "?"
    low = raw.lower()
    return {
        "name": name,
        "httponly": "httponly" in low,
        "secure": "secure" in low,
        "samesite": "samesite" in low,
    }


def _collect_cookies(client: HttpClient, cfg: ScanConfig) -> Response:
    # Cookie görmek için bir istek yeterli; başarısız login bile genelde
    # bir oturum/csrf cookie'si set edebilir.
    return baseline_fail(client, cfg)


def run(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    resp = _collect_cookies(client, cfg)
    is_https = urlparse(cfg.url).scheme == "https"

    if not resp.set_cookies:
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="İncelenecek cookie bulunamadı",
            detail="Bu istekte sunucu Set-Cookie döndürmedi (oturum başarılı girişte set ediliyor olabilir).",
        )]

    findings: List[Finding] = []
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
                title=f"Cookie güvenlik bayrağı eksik: {f['name']}",
                detail=f"Eksik bayraklar: {', '.join(missing)}.",
                remediation=("Set-Cookie'ye HttpOnly, Secure ve SameSite=Lax/Strict ekleyin. "
                             "Secure yalnızca HTTPS'te anlamlıdır."),
                evidence={"cookie": f["name"], "eksik": missing},
            ))
        else:
            findings.append(Finding(
                check=CHECK, status=Status.OK, severity=Severity.INFO,
                title=f"Cookie bayrakları tam: {f['name']}",
                detail="HttpOnly / Secure / SameSite mevcut.",
            ))
    return findings
