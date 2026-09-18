"""
Rate limiting / brute-force koruması VAR MI kontrolü.

Önemli: Bu bir brute-force aracı DEĞİLDİR. Amaç şifre kırmak değil,
"sunucu peş peşe başarısız denemeleri engelliyor mu?" sorusunu yanıtlamak.
Bu yüzden az sayıda (varsayılan 6) deneme yapar ve şifre olarak hep aynı
anlamsız değeri kullanır — hesap kırmaya çalışmaz.
"""
from __future__ import annotations

from typing import List

from ..http import HttpClient, RequestBudgetExceeded
from ..models import Finding, ScanConfig, Severity, Status
from .base import random_username, submit_login

CHECK = "ratelimit"

# Engellemenin işareti sayılan HTTP kodları.
BLOCK_STATUSES = {429, 403, 503}
BLOCK_HINTS = ["too many", "rate limit", "try again later", "captcha",
               "çok fazla", "engellendi", "daha sonra"]


def run(client: HttpClient, cfg: ScanConfig, attempts: int = 6) -> List[Finding]:
    # Bilinen bir hesabı hedeflemeyelim; sabit ama anlamsız bir kullanıcıya deneriz.
    target_user = cfg.known_username or random_username("probe")
    wrong_pw = "definitely-wrong-pw"

    statuses = []
    blocked_at = None
    try:
        for i in range(1, attempts + 1):
            if client.remaining <= 0:
                break
            resp = submit_login(client, cfg, target_user, wrong_pw)
            statuses.append(resp.status)
            low = resp.body.lower()
            if resp.status in BLOCK_STATUSES or any(h in low for h in BLOCK_HINTS):
                blocked_at = i
                break
    except RequestBudgetExceeded:
        pass

    if blocked_at:
        return [Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="Brute-force koruması çalışıyor",
            detail=f"{blocked_at}. denemede sunucu engelledi (rate limiting mevcut).",
            evidence={"http_kodlari": statuses},
        )]

    if not statuses:
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Rate limit testi çalıştırılamadı",
            detail="İstek bütçesi yetmedi.",
        )]

    return [Finding(
        check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
        title="Brute-force koruması yok",
        detail=(f"{len(statuses)} başarısız deneme peş peşe engellenmeden kabul edildi. "
                "Saldırgan sözlük/brute-force ile şifre deneyebilir."),
        remediation=("IP ve hesap bazlı rate limiting ekleyin; art arda başarısızlıkta "
                     "gecikme/CAPTCHA/geçici kilit uygulayın. (Test yalnızca koruma "
                     "varlığını ölçtü, şifre denemedi.)"),
        evidence={"deneme": len(statuses), "http_kodlari": statuses},
    )]
