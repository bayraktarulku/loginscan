"""
Scanner — kontrolleri sırayla çalıştırıp tek bir Report üretir.

Kullanım (Python):
    from loginscan import Scanner, ScanConfig
    cfg = ScanConfig(url="http://127.0.0.1:8001/login", known_username="admin")
    report = Scanner(cfg, authorized=True).run()
    print(report.to_text())
"""
from __future__ import annotations

from typing import List, Optional

from .authorization import ensure_authorized
from .checks import ALL_CHECKS
from .http import HttpClient, RequestBudgetExceeded
from .models import Finding, ScanConfig, Severity, Status
from .report import Report


class Scanner:
    def __init__(self, config: ScanConfig, authorized: bool = False,
                 checks: Optional[list] = None):
        self.config = config
        self.authorized = authorized
        self.checks = checks if checks is not None else ALL_CHECKS

    def run(self) -> Report:
        # Yetki kapısı — onay yoksa buradan geçemez.
        ensure_authorized(self.authorized)

        cfg = self.config
        client = HttpClient(
            max_requests=cfg.max_requests,
            delay=cfg.delay,
            timeout=cfg.timeout,
            verify_tls=cfg.verify_tls,
        )
        report = Report(target=cfg.url)

        for module in self.checks:
            name = getattr(module, "CHECK", module.__name__)
            try:
                findings: List[Finding] = module.run(client, cfg)
                report.extend(findings)
            except RequestBudgetExceeded:
                report.add(Finding(
                    check=name, status=Status.SKIPPED, severity=Severity.INFO,
                    title=f"'{name}' atlandı — istek bütçesi doldu",
                    detail=f"Toplam istek sınırına ({cfg.max_requests}) ulaşıldı.",
                    remediation="Daha kapsamlı tarama için max_requests değerini artırın.",
                ))
            except Exception as e:  # noqa: BLE001 - tek kontrol hatası taramayı durdurmasın
                report.add(Finding(
                    check=name, status=Status.ERROR, severity=Severity.INFO,
                    title=f"'{name}' kontrolünde hata",
                    detail=str(e),
                ))
        return report
