"""Scan report: collects findings, sorts them, renders text/JSON."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .models import Finding, Severity, Status

_SEV_LABEL = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

_STATUS_MARK = {
    Status.VULNERABLE: "[!]",
    Status.WARNING: "[~]",
    Status.OK: "[OK]",
    Status.SKIPPED: "[--]",
    Status.ERROR: "[ERR]",
}


@dataclass
class Report:
    target: str
    findings: List[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def vulnerabilities(self) -> List[Finding]:
        return [f for f in self.findings if f.status == Status.VULNERABLE]

    @property
    def warnings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == Status.WARNING]

    def sorted_findings(self) -> List[Finding]:
        status_rank = {
            Status.VULNERABLE: 0, Status.WARNING: 1, Status.ERROR: 2,
            Status.SKIPPED: 3, Status.OK: 4,
        }
        return sorted(
            self.findings,
            key=lambda f: (status_rank.get(f.status, 9),
                           Severity.ORDER.get(f.severity, 9)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "summary": {
                "total": len(self.findings),
                "vulnerable": len(self.vulnerabilities),
                "warnings": len(self.warnings),
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def to_text(self) -> str:
        lines = []
        bar = "=" * 64
        lines.append(bar)
        lines.append(f" loginscan report - target: {self.target}")
        lines.append(bar)
        v, w = len(self.vulnerabilities), len(self.warnings)
        lines.append(f" Findings: {len(self.findings)} | Vulnerable: {v} | Warnings: {w}")
        lines.append("")
        for f in self.sorted_findings():
            mark = _STATUS_MARK.get(f.status, "[?]")
            sev = _SEV_LABEL.get(f.severity, f.severity)
            lines.append(f"{mark} {sev:4} · {f.title}   ({f.check})")
            if f.detail:
                lines.append(f"      {f.detail}")
            if f.status in (Status.VULNERABLE, Status.WARNING) and f.remediation:
                lines.append(f"      -> Fix: {f.remediation}")
            for k, val in f.evidence.items():
                lines.append(f"        - {k}: {val}")
            lines.append("")
        if v == 0 and w == 0:
            lines.append("No obvious issues found in these checks.")
            lines.append("(This does not prove the system is fully secure.)")
        return "\n".join(lines)
