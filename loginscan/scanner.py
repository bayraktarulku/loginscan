"""Scanner: runs checks in order and returns a single Report."""
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
        ensure_authorized(self.authorized)
        cfg = self.config
        client = HttpClient(cfg.max_requests, cfg.delay, cfg.timeout, cfg.verify_tls)
        report = Report(target=cfg.url)

        for module in self.checks:
            name = getattr(module, "CHECK", module.__name__)
            try:
                findings: List[Finding] = module.run(client, cfg)
                report.extend(findings)
            except RequestBudgetExceeded:
                report.add(Finding(
                    check=name, status=Status.SKIPPED, severity=Severity.INFO,
                    title=f"'{name}' skipped - request budget exhausted",
                    detail=f"Reached the total request limit ({cfg.max_requests}).",
                    remediation="Increase max_requests for a deeper scan.",
                ))
            except Exception as e:  # noqa: BLE001
                report.add(Finding(
                    check=name, status=Status.ERROR, severity=Severity.INFO,
                    title=f"'{name}' check errored",
                    detail=str(e),
                ))
        return report
