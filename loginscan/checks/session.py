"""
Oturum (session) token güvenliği kontrolü.

Tarama boyunca görülen oturum token'larını inceler:
  * Tahmin edilebilir mi? (kısa, tamamen sayısal, sıralı artan → çok kötü)
  * Yeterince rastgele/uzun mu? (entropi kabası)

Not: Çoğu uygulama token'ı yalnızca BAŞARILI girişte verir; şifre denemediğimiz
için hiç örnek görmeyebiliriz. O durumda kontrol atlanır (bu bir kusur değildir).
"""
from __future__ import annotations

import math
from collections import Counter
from typing import List

from ..http import HttpClient
from ..models import Finding, ScanConfig, Severity, Status

CHECK = "session"

# Bu uzunluğun altındaki token'lar kaba-kuvvete açık sayılır.
MIN_TOKEN_LEN = 16


def _shannon_entropy_bits(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    per_char = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return per_char * n  # toplam yaklaşık entropi (bit)


def run(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    tokens = [v for _, v in client.observed_session_tokens]

    if not tokens:
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="İncelenecek oturum token'ı görülmedi",
            detail=("Sunucu bu isteklerde oturum token'ı vermedi (genelde yalnızca "
                    "başarılı girişte verilir). Bu kontrol atlandı."),
        )]

    findings: List[Finding] = []
    uniq = list(dict.fromkeys(tokens))  # sırayı koruyarak tekilleştir
    sample = uniq[0]

    # 1) Tamamen sayısal ve sıralı mı? (en tehlikelisi)
    numeric = [t for t in uniq if t.isdigit()]
    if len(numeric) >= 2:
        nums = sorted(int(t) for t in numeric)
        if all(b - a == 1 for a, b in zip(nums, nums[1:])):
            findings.append(Finding(
                check=CHECK, status=Status.VULNERABLE, severity=Severity.HIGH,
                title="Oturum token'ı ardışık ve tahmin edilebilir",
                detail=(f"Token'lar sıralı sayılar: {nums}. Saldırgan bir sonraki/önceki "
                        "token'ı tahmin edip başka kullanıcının oturumunu ele geçirebilir."),
                remediation=("Kriptografik rastgele token üretin (ör. secrets.token_urlsafe(32)); "
                             "asla sıralı id / sayaç kullanmayın."),
                evidence={"ornekler": nums[:5]},
            ))
            return findings

    # 2) Tek örnek üzerinden zayıflık göstergeleri
    reasons = []
    if len(sample) < MIN_TOKEN_LEN:
        reasons.append(f"çok kısa ({len(sample)} karakter)")
    if sample.isdigit():
        reasons.append("tamamen sayısal")
    entropy = _shannon_entropy_bits(sample)
    if entropy < 64:
        reasons.append(f"düşük entropi (~{entropy:.0f} bit)")

    if reasons:
        findings.append(Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.MEDIUM,
            title="Oturum token'ı zayıf görünüyor",
            detail="Token şu açılardan zayıf: " + ", ".join(reasons) + ".",
            remediation="En az 128 bit entropili kriptografik rastgele token kullanın.",
            evidence={"ornek_uzunluk": len(sample), "entropi_bit": round(entropy)},
        ))
    else:
        findings.append(Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="Oturum token'ı makul görünüyor",
            detail=f"Uzunluk {len(sample)}, ~{entropy:.0f} bit entropi.",
        ))
    return findings
