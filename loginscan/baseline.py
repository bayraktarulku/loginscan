"""Baseline support: accept known findings so CI only fails on NEW ones."""
from __future__ import annotations

import json

from .models import Finding, Status
from .report import Report

_ACCEPTED = (Status.VULNERABLE, Status.WARNING)


def fingerprint(f: Finding) -> str:
    return f"{f.check}:{f.title}"


def load_baseline(path: str) -> set[str]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return set(data.get("accepted", []))


def write_baseline(report: Report, path: str) -> int:
    fps = sorted({fingerprint(f) for f in report.findings if f.status in _ACCEPTED})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"accepted": fps}, fh, ensure_ascii=False, indent=2)
    return len(fps)


def new_findings(report: Report, baseline: set[str]) -> list[Finding]:
    return [f for f in report.findings
            if f.status in _ACCEPTED and fingerprint(f) not in baseline]
