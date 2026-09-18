"""
Taşıma güvenliği ve güvenlik başlıkları kontrolü ("birkaç önemli durum daha").

Bakar:
  * Login HTTP (şifresiz) üzerinden mi gidiyor? → kimlik bilgileri açık ağda.
  * HSTS (Strict-Transport-Security) var mı?
  * X-Content-Type-Options: nosniff
  * Clickjacking koruması: X-Frame-Options veya CSP frame-ancestors
  * Referrer-Policy
  * Sunucu/teknoloji sürümü sızıntısı (Server / X-Powered-By)
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from ..http import HttpClient
from ..models import Finding, ScanConfig, Severity, Status

CHECK = "headers"


def run(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(cfg.url)
    is_https = parsed.scheme == "https"

    # 1) Şifresiz HTTP → en önemli taşıma açığı
    if not is_https:
        findings.append(Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.HIGH,
            title="Login HTTPS kullanmıyor",
            detail="Kullanıcı adı ve şifre şifrelenmeden (HTTP) gönderiliyor; ağdaki biri okuyabilir.",
            remediation="Tüm siteyi HTTPS'e taşıyın ve HTTP'yi HTTPS'e yönlendirin.",
            evidence={"scheme": parsed.scheme},
        ))

    # Başlıkları görmek için login sayfasını (varsa) yoksa endpoint'i GET'le.
    probe_url = cfg.login_page_url or cfg.url
    try:
        resp = client.get(probe_url)
    except Exception as e:  # noqa: BLE001 - ağ hatasını bulguya çeviriyoruz
        findings.append(Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Başlıklar okunamadı",
            detail=f"{probe_url} GET edilemedi: {e}",
        ))
        return findings

    def missing(header: str) -> bool:
        return resp.header(header) is None

    if is_https and missing("strict-transport-security"):
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.LOW,
            title="HSTS başlığı yok",
            detail="Strict-Transport-Security yok; tarayıcı ilk isteği HTTP'ye düşürebilir.",
            remediation="Strict-Transport-Security: max-age=31536000; includeSubDomains ekleyin.",
        ))

    if missing("x-content-type-options"):
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.LOW,
            title="X-Content-Type-Options yok",
            detail="nosniff yok; tarayıcı içerik türünü yanlış tahmin edebilir.",
            remediation="X-Content-Type-Options: nosniff ekleyin.",
        ))

    if missing("x-frame-options") and "frame-ancestors" not in (resp.header("content-security-policy") or "").lower():
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.MEDIUM,
            title="Clickjacking koruması yok",
            detail="X-Frame-Options veya CSP frame-ancestors yok; login sayfası iframe'e alınabilir.",
            remediation="X-Frame-Options: DENY veya CSP frame-ancestors 'none' ekleyin.",
        ))

    if missing("referrer-policy"):
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.LOW,
            title="Referrer-Policy yok",
            detail="Referrer-Policy yok; URL'deki hassas bilgi dış sitelere sızabilir.",
            remediation="Referrer-Policy: no-referrer veya strict-origin-when-cross-origin ekleyin.",
        ))

    leak = resp.header("server") or resp.header("x-powered-by")
    if leak and any(ch.isdigit() for ch in leak):
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.LOW,
            title="Sunucu/teknoloji sürümü sızıyor",
            detail=f"Yanıt başlığı sürüm bilgisi veriyor: '{leak}'. Saldırgana hedef seçmede yardımcı olur.",
            remediation="Server / X-Powered-By başlıklarından sürüm bilgisini kaldırın.",
            evidence={"baslik": leak},
        ))

    # Hiç uyarı yoksa olumlu bir satır bırak.
    if not any(f for f in findings if f.check == CHECK and f.status != Status.VULNERABLE):
        findings.append(Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="Temel güvenlik başlıkları mevcut",
            detail="HSTS/nosniff/çerçeve koruması/Referrer-Policy kontrollerinde eksik görülmedi.",
        ))
    return findings
