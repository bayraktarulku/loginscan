"""
Kullanıcı adı sızdırma (user enumeration) tespiti.

Fikir: Var olan bir kullanıcıya yanlış şifre vs. hiç olmayan bir kullanıcıya
yanlış şifre gönderdiğimizde sunucu FARKLI davranıyorsa (farklı mesaj, farklı
uzunluk, farklı süre), saldırgan hangi kullanıcı adlarının gerçek olduğunu
ayıklayabilir.

En iyi sonuç için cfg.known_username verilmelidir (sizde gerçekten var olan
bir kullanıcı adı — şifresi GEREKMEZ). Verilmezse iki rastgele-yok kullanıcıyla
sadece tutarlılık ölçülür ve uyarı verilir.
"""
from __future__ import annotations

from typing import List

from ..http import HttpClient
from ..models import Finding, ScanConfig, Severity, Status
from .base import random_username, submit_login

CHECK = "enumeration"

# Bu orandan fazla gövde uzunluğu farkı "anlamlı fark" sayılır.
LEN_DIFF_RATIO = 0.15
# Bu kadar saniyeden fazla süre farkı zamanlama sızıntısı sayılır.
TIME_DIFF_SECONDS = 0.5


def _norm_body(text: str) -> str:
    # Rastgele token/uzunluk gürültüsünü azaltmak için kabaca sadeleştir.
    return " ".join(text.split())[:400].lower()


def run(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []
    wrong_pw = "wrong-Password-123"

    absent_user = random_username("ghost")
    r_absent = submit_login(client, cfg, absent_user, wrong_pw)

    if cfg.known_username:
        present_user = cfg.known_username
        r_present = submit_login(client, cfg, present_user, wrong_pw)

        # Sunucunun kendi rate limiting'i devreye girdiyse (429), iki yanıtı
        # karşılaştırmak yanıltıcı olur — açık DEĞİL, tarama etkilenmiştir.
        if 429 in (r_present.status, r_absent.status):
            return [Finding(
                check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
                title="Enumeration testi rate limiting nedeniyle güvenilmez",
                detail=("İsteklerden biri HTTP 429 aldı; sunucunun hız sınırı yanıtları "
                        "değiştirdiği için karşılaştırma yapılamadı."),
                remediation=("Taramayı daha yüksek --delay ile veya rate-limit penceresi "
                             "boşaldıktan sonra tekrar çalıştırın."),
                evidence={"http": f"{r_present.status} vs {r_absent.status}"},
            )]

        body_diff = _norm_body(r_present.body) != _norm_body(r_absent.body)
        len_a, len_b = len(r_present.body), len(r_absent.body)
        big = max(len_a, len_b, 1)
        len_diff = abs(len_a - len_b) / big > LEN_DIFF_RATIO
        status_diff = r_present.status != r_absent.status
        time_diff = abs(r_present.elapsed - r_absent.elapsed) > TIME_DIFF_SECONDS

        if body_diff or len_diff or status_diff:
            findings.append(Finding(
                check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
                title="Kullanıcı adı sızdırma (enumeration) mümkün",
                detail=("Var olan ve olmayan kullanıcıya sunucu farklı yanıt veriyor; "
                        "saldırgan geçerli kullanıcı adlarını ayıklayabilir."),
                remediation=("Her iki durumda da AYNI genel mesajı ve aynı HTTP kodunu "
                             "döndürün (ör. 'Kullanıcı adı veya şifre hatalı')."),
                evidence={
                    "mesaj_farkli": body_diff,
                    "uzunluk": f"{len_a} vs {len_b}",
                    "http": f"{r_present.status} vs {r_absent.status}",
                },
            ))
        elif time_diff:
            findings.append(Finding(
                check=CHECK, status=Status.WARNING, severity=Severity.LOW,
                title="Zamanlama farkı (olası enumeration)",
                detail=("Yanıt metinleri aynı ama süreler belirgin farklı; şifre "
                        "hash'i yalnızca var olan kullanıcıda çalıştırılıyor olabilir."),
                remediation="Kullanıcı yoksa da sahte bir hash doğrulaması çalıştırıp süreyi eşitleyin.",
                evidence={"sure": f"{r_present.elapsed:.3f}s vs {r_absent.elapsed:.3f}s"},
            ))
        else:
            findings.append(Finding(
                check=CHECK, status=Status.OK, severity=Severity.INFO,
                title="Enumeration'a karşı yanıtlar tutarlı",
                detail="Var olan ve olmayan kullanıcı için yanıtlar ayırt edilemedi.",
            ))
    else:
        # Bilinen kullanıcı yok → tam test edemiyoruz.
        r_absent2 = submit_login(client, cfg, random_username("ghost2"), wrong_pw)
        consistent = _norm_body(r_absent.body) == _norm_body(r_absent2.body)
        findings.append(Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Enumeration testi sınırlı (known_username verilmedi)",
            detail=("Tam test için sizde GERÇEKTEN var olan bir kullanıcı adı gerekir "
                    "(şifresi değil). İki yok-kullanıcı yanıtı "
                    + ("tutarlıydı." if consistent else "tutarsızdı — bu da şüphelidir.")),
            remediation="Taramayı known_username / --user ile tekrar çalıştırın.",
        ))
    return findings
