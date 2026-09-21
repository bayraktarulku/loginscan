"""Whole-app scan: run per-endpoint scans and aggregate them into one report."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .report import Report
from .scanner import Scanner


@dataclass
class AppReport:
    sections: list[dict[str, Any]] = field(default_factory=list)  # {label, kind, report}

    def add(self, label: str, kind: str, report: Report) -> None:
        self.sections.append({"label": label, "kind": kind, "report": report})

    @property
    def all_vulnerabilities(self):
        return [f for s in self.sections for f in s["report"].vulnerabilities]

    def worst_score(self) -> dict[str, Any]:
        if not self.sections:
            return {"score": 100, "grade": "A"}
        return min((s["report"].score() for s in self.sections), key=lambda x: x["score"])

    def to_text(self) -> str:
        bar = "#" * 64
        ws = self.worst_score()
        out = [bar, f" loginscan APP report - {len(self.sections)} endpoints",
               f" Overall (worst) score: {ws['score']}/100 ({ws['grade']}) | "
               f"total vulnerable: {len(self.all_vulnerabilities)}", bar, ""]
        for s in self.sections:
            out.append(f">>> [{s['kind']}] {s['label']}")
            out.append(s["report"].to_text())
            out.append("")
        return "\n".join(out)

    def to_dict(self) -> dict[str, Any]:
        ws = self.worst_score()
        return {
            "summary": {
                "endpoints": len(self.sections),
                "worst_score": ws["score"],
                "grade": ws["grade"],
                "total_vulnerable": len(self.all_vulnerabilities),
            },
            "endpoints": [
                {"label": s["label"], "kind": s["kind"], **s["report"].to_dict()}
                for s in self.sections
            ],
        }


def scan_app(endpoints, authorized: bool = False,
             only: list | None = None, skip: list | None = None) -> AppReport:
    app = AppReport()
    for ep in endpoints:
        report = Scanner(ep.config, authorized=authorized, only=only, skip=skip).run()
        app.add(label=ep.config.url, kind=ep.kind, report=report)
    return app
