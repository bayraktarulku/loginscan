"""
Ortak veri modelleri: tarama ayarları (ScanConfig), bulgular (Finding)
ve önem/durum sabitleri. Diğer tüm modüller buradan besleniyor.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Severity:
    """Bulgunun önem derecesi — rapor sıralaması bunu kullanır."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}


class Status:
    """Bir kontrolün sonucu."""
    VULNERABLE = "vulnerable"   # açık bulundu
    WARNING = "warning"         # şüpheli / iyileştirilebilir
    OK = "ok"                   # bu kontrolde sorun yok
    SKIPPED = "skipped"         # çalıştırılamadı (bütçe/eksik bilgi)
    ERROR = "error"             # kontrol sırasında hata


@dataclass
class Finding:
    """Tek bir kontrolün ürettiği tek bir sonuç satırı."""
    check: str
    status: str
    severity: str
    title: str
    detail: str
    remediation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "status": self.status,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


@dataclass
class ScanConfig:
    """
    Tek bir login endpoint'ini nasıl tarayacağımızı anlatan ayarlar.

    url                : Login isteğinin gittiği tam adres (ör. https://site/login)
    method             : Login isteği metodu (genelde POST)
    username_field     : Formdaki kullanıcı adı alanının 'name' değeri
    password_field     : Formdaki şifre alanının 'name' değeri
    known_username     : Sizin sisteminizde GERÇEKTEN var olan bir kullanıcı adı.
                         (enumeration testini güçlendirir; şifre gerekmez)
    success_indicators : Yanıtta görülürse "giriş başarılı" sayılacak metinler
    login_page_url     : Login formunun HTML sayfası (başlık/cookie kontrolü için)
    max_requests       : Toplam istek üst sınırı — aracı düşük hacimde tutar
    delay              : İstekler arası bekleme (saniye) — nazik davranır
    timeout            : İstek zaman aşımı (saniye)
    verify_tls         : HTTPS sertifikası doğrulansın mı
    extra_fields       : Her isteğe eklenecek sabit form alanları (ör. csrf gerekiyorsa)
    """
    url: str
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    known_username: Optional[str] = None
    success_indicators: List[str] = field(default_factory=list)
    login_page_url: Optional[str] = None
    max_requests: int = 25
    delay: float = 0.3
    timeout: float = 10.0
    verify_tls: bool = True
    extra_fields: Dict[str, str] = field(default_factory=dict)
