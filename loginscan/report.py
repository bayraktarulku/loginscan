"""
Tarama raporu: bulguları toplar, önem sırasına dizer, metin/JSON üretir.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .models import Finding, Severity, Status


_SEV_LABEL = {
    Severity.CRITICAL: "KRİTİK",
    Severity.HIGH: "YÜKSEK",
    Severity.MEDIUM: "ORTA",
    Severity.LOW: "DÜŞÜK",
    Severity.INFO: "BİLGİ",
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
        # Önce açık bulunanlar, sonra önem derecesine göre.
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
        lines.append(f" loginscan raporu — hedef: {self.target}")
        lines.append(bar)
        v, w = len(self.vulnerabilities), len(self.warnings)
        lines.append(f" Bulgu: {len(self.findings)} | Açık: {v} | Uyarı: {w}")
        lines.append("")
        for f in self.sorted_findings():
            mark = _STATUS_MARK.get(f.status, "[?]")
            sev = _SEV_LABEL.get(f.severity, f.severity)
            lines.append(f"{mark} {sev:5} · {f.title}   ({f.check})")
            if f.detail:
                lines.append(f"      {f.detail}")
            if f.status in (Status.VULNERABLE, Status.WARNING) and f.remediation:
                lines.append(f"      → Çözüm: {f.remediation}")
            if f.evidence:
                for k, val in f.evidence.items():
                    lines.append(f"        - {k}: {val}")
            lines.append("")
        if v == 0 and w == 0:
            lines.append("Tebrikler: bu kontrollerde belirgin açık görülmedi.")
            lines.append("(Yine de bu, sistemin tümüyle güvenli olduğu anlamına gelmez.)")
        return "\n".join(lines)
