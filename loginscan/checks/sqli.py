"""
SQL Injection tespiti (tespit odaklı, ZARARSIZ).

İki şeye bakar:
  1) Klasik kimlik-atlatma payload'ı 'giriş başarılı' gibi bir yanıt üretiyor mu?
  2) Payload veritabanı hata mesajı sızdırıyor mu? (enjekte edilebilir işareti)

Yalnızca okuma amaçlı, iyi bilinen payload'lar kullanılır; veri değiştirmez.
"""
from __future__ import annotations

from typing import List

from ..http import HttpClient
from ..models import Finding, ScanConfig, Severity, Status
from .base import baseline_fail, has_sql_error, looks_like_success, submit_login

CHECK = "sqli"

# Kimlik doğrulamayı atlatmayı hedefleyen, veri BOZMAYAN klasik girdiler.
AUTH_BYPASS_PAYLOADS = [
    "admin'--",
    "admin'#",
    "' OR '1'='1'--",
    "' OR 1=1--",
]

# Hata tabanlı tespit için tek tırnak yeter.
ERROR_PROBE = "'"


def run(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []
    base = baseline_fail(client, cfg)

    # --- Hata sızıntısı (error-based) ---
    probe = submit_login(client, cfg, ERROR_PROBE, "x")
    sign = has_sql_error(probe.body)
    if sign:
        findings.append(Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.HIGH,
            title="Veritabanı hata mesajı sızıyor (SQL injection olası)",
            detail=("Tek tırnak (') içeren girdi ham SQL hatası döndürdü. "
                    "Girdi doğrudan sorguya giriyor demektir."),
            remediation=("Parametreli sorgu (prepared statement) kullanın; hata "
                         "mesajlarını kullanıcıya göstermeyin (genel mesaj döndürün)."),
            evidence={"tetikleyen": "username='", "hata_izi": sign},
        ))

    # --- Kimlik atlatma (auth bypass) ---
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
            title="SQL injection ile kimlik doğrulama atlatıldı",
            detail=(f"Kullanıcı adı alanına '{payload}' yazıldığında giriş başarılı "
                    "gibi davrandı — yani şifre bilmeden oturum açılabiliyor."),
            remediation=("Parametreli sorgu kullanın: kullanıcı girdisi asla SQL "
                         "cümlesine string olarak eklenmemeli."),
            evidence={"payload": payload, "sinyal": why, "http": status},
        ))
    elif not sign:
        findings.append(Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="Belirgin SQL injection sinyali görülmedi",
            detail="Denenen klasik payload'lar giriş atlatmadı ve hata sızdırmadı.",
        ))
    return findings
