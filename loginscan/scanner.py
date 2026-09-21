"""Scanner: runs checks in order and returns a single Report."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from .authorization import ensure_authorized
from .http import HttpClient, RequestBudgetExceeded
from .models import Finding, ScanConfig, Severity, Status
from .registry import all_checks, select
from .report import Report

log = logging.getLogger("loginscan.scanner")


def _hosts(cfg: ScanConfig) -> set[str]:
    urls = [cfg.url, cfg.login_page_url, cfg.csrf_url]
    return {urlparse(u).netloc for u in urls if u}


class Scanner:
    def __init__(self, config: ScanConfig, authorized: bool = False,
                 checks: list | None = None,
                 only: list | None = None, skip: list | None = None):
        self.config = config
        self.authorized = authorized
        base = checks if checks is not None else all_checks()
        self.checks = select(base, only=only, skip=skip)

    def run(self) -> Report:
        ensure_authorized(self.authorized)
        cfg = self.config
        client = HttpClient(
            cfg.max_requests, cfg.delay, cfg.timeout, cfg.verify_tls,
            use_cookies=bool(cfg.csrf_field) or bool(cfg.password),
            default_headers=cfg.extra_headers,
            proxy=cfg.proxy, retries=cfg.retries,
            allowed_hosts=_hosts(cfg) if cfg.scope_guard else None,
        )
        report = Report(target=cfg.url)

        for module in self.checks:
            name = getattr(module, "CHECK", module.__name__)
            log.info("running check: %s", name)
            try:
                findings: list[Finding] = module.run(client, cfg)
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
