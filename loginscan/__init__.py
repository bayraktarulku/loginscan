"""loginscan - a lightweight, dependency-free self-audit scanner for login endpoints.

Only use it against systems you own or are authorized to test. It does not crack
passwords and runs low-volume; the goal is to detect issues and suggest fixes.
"""
from .authorization import AUTHORIZATION_NOTICE, NotAuthorized
from .models import Finding, ScanConfig, Severity, Status
from .report import Report
from .scanner import Scanner

__version__ = "1.1.0"

__all__ = [
    "Scanner", "ScanConfig", "Report", "Finding",
    "Severity", "Status", "NotAuthorized", "AUTHORIZATION_NOTICE",
    "__version__",
]
