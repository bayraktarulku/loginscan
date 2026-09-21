"""Turn a set of findings into a 0-100 security score and a letter grade."""
from __future__ import annotations

from typing import Dict, List

from .models import Finding, Severity, Status

_PENALTY = {Severity.CRITICAL: 45, Severity.HIGH: 30, Severity.MEDIUM: 15,
            Severity.LOW: 6, Severity.INFO: 0}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def score_findings(findings: List[Finding]) -> Dict[str, object]:
    penalty = 0.0
    for f in findings:
        base = _PENALTY.get(f.severity, 0)
        if f.status == Status.VULNERABLE:
            penalty += base
        elif f.status == Status.WARNING:
            penalty += base / 2
    value = max(0, round(100 - penalty))
    return {"score": value, "grade": _grade(value)}
