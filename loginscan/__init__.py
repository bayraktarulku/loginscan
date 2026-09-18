"""
loginscan — kendi login endpoint'inizi savunma amaçlı tarayan, hafif bir araç.

YALNIZCA size ait olan veya yazılı test izniniz olan sistemlerde kullanın.
Şifre kırmaz, düşük hacimde çalışır; amacı açığı tespit edip düzeltme önermektir.

Hızlı başlangıç:
    from loginscan import Scanner, ScanConfig
    cfg = ScanConfig(url="http://127.0.0.1:8001/", known_username="admin")
    print(Scanner(cfg, authorized=True).run().to_text())
"""
from .authorization import AUTHORIZATION_NOTICE, NotAuthorized
from .models import Finding, ScanConfig, Severity, Status
from .report import Report
from .scanner import Scanner

__version__ = "0.1.0"

__all__ = [
    "Scanner", "ScanConfig", "Report", "Finding",
    "Severity", "Status", "NotAuthorized", "AUTHORIZATION_NOTICE",
    "__version__",
]
