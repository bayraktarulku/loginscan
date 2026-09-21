"""Core data models: scan config, findings, severity/status constants."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}


class Status:
    VULNERABLE = "vulnerable"
    WARNING = "warning"
    OK = "ok"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class Finding:
    check: str
    status: str
    severity: str
    title: str
    detail: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
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
    """How to scan a single login endpoint.

    known_username is a username that really exists on your system (no password
    needed); it strengthens the enumeration check. success_indicators are strings
    that, if present in a response, mean the login succeeded.
    """
    url: str
    method: str = "POST"
    content_type: str = "form"  # "form" or "json"
    username_field: str = "username"
    password_field: str = "password"
    known_username: str | None = None
    success_indicators: list[str] = field(default_factory=list)
    login_page_url: str | None = None
    csrf_field: str | None = None   # hidden form field carrying a CSRF token
    csrf_url: str | None = None     # page to fetch a fresh token/cookie from
    max_requests: int = 60
    delay: float = 0.3
    timeout: float = 10.0
    verify_tls: bool = True
    extra_fields: dict[str, str] = field(default_factory=dict)
    extra_headers: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    retries: int = 2
    scope_guard: bool = True
