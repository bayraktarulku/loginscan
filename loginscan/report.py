"""Scan report: collects findings, sorts them, renders text/JSON/HTML."""
from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from typing import Any

from .knowledge import meta_for
from .models import Finding, Severity, Status
from .score import score_findings

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
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def vulnerabilities(self) -> list[Finding]:
        return [f for f in self.findings if f.status == Status.VULNERABLE]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.status == Status.WARNING]

    def sorted_findings(self) -> list[Finding]:
        status_rank = {
            Status.VULNERABLE: 0, Status.WARNING: 1, Status.ERROR: 2,
            Status.SKIPPED: 3, Status.OK: 4,
        }
        return sorted(
            self.findings,
            key=lambda f: (status_rank.get(f.status, 9),
                           Severity.ORDER.get(f.severity, 9)),
        )

    def score(self) -> dict[str, Any]:
        return score_findings(self.findings)

    def to_dict(self) -> dict[str, Any]:
        findings = []
        for f in self.sorted_findings():
            d = f.to_dict()
            d.update(meta_for(f.check))
            findings.append(d)
        s = self.score()
        return {
            "target": self.target,
            "summary": {
                "score": s["score"],
                "grade": s["grade"],
                "total": len(self.findings),
                "vulnerable": len(self.vulnerabilities),
                "warnings": len(self.warnings),
            },
            "findings": findings,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def to_text(self) -> str:
        lines = []
        bar = "=" * 64
        lines.append(bar)
        lines.append(f" loginscan report - target: {self.target}")
        lines.append(bar)
        s = self.score()
        v, w = len(self.vulnerabilities), len(self.warnings)
        lines.append(f" Score: {s['score']}/100 ({s['grade']})   "
                     f"Findings: {len(self.findings)} | Vulnerable: {v} | Warnings: {w}")
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

    def to_html(self) -> str:
        colors = {Severity.CRITICAL: "#b3153b", Severity.HIGH: "#d1495b",
                  Severity.MEDIUM: "#e08d29", Severity.LOW: "#c9a227",
                  Severity.INFO: "#5a7d9a"}
        status_bg = {Status.VULNERABLE: "#fdecef", Status.WARNING: "#fdf6ec",
                     Status.OK: "#edf7ed", Status.SKIPPED: "#f2f2f2",
                     Status.ERROR: "#f2f2f2"}

        def esc(x: Any) -> str:
            return html.escape(str(x))

        cards = []
        for f in self.sorted_findings():
            ev = "".join(
                f"<li><code>{esc(k)}</code>: {esc(val)}</li>" for k, val in f.evidence.items())
            ev_html = f"<ul class='ev'>{ev}</ul>" if ev else ""
            fix = (f"<p class='fix'><b>Fix:</b> {esc(f.remediation)}</p>"
                   if f.status in (Status.VULNERABLE, Status.WARNING) and f.remediation else "")
            m = meta_for(f.check)
            ref = (f"<span class='ref'>{esc(m.get('cwe', ''))} · {esc(m.get('owasp', ''))}</span>"
                   if m else "")
            cards.append(f"""
      <div class="card" style="background:{status_bg.get(f.status, '#fff')}">
        <div class="row">
          <span class="badge" style="background:{colors.get(f.severity, '#666')}">{esc(f.severity.upper())}</span>
          <span class="title">{esc(f.title)}</span>
          <span class="check">{esc(f.check)}</span>
        </div>
        <p class="detail">{esc(f.detail)}</p>
        {fix}{ev_html}{ref}
      </div>""")

        s = self.score()
        v, w = len(self.vulnerabilities), len(self.warnings)
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>loginscan report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 -apple-system, Segoe UI, Roboto, sans-serif;
         max-width: 820px; margin: 2rem auto; padding: 0 1rem; color: #1c1c1e; }}
  h1 {{ margin: 0 0 .25rem; }}
  .target {{ color: #666; word-break: break-all; }}
  .summary {{ display: flex; gap: .75rem; margin: 1rem 0 1.5rem; flex-wrap: wrap; }}
  .pill {{ padding: .4rem .8rem; border-radius: 999px; font-weight: 600; }}
  .pill.v {{ background: #fdecef; color: #b3153b; }}
  .pill.w {{ background: #fdf6ec; color: #a25c00; }}
  .pill.t {{ background: #eef; color: #334; }}
  .card {{ border: 1px solid #0001; border-radius: 10px; padding: .8rem 1rem; margin: .6rem 0; }}
  .row {{ display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }}
  .badge {{ color: #fff; padding: .1rem .5rem; border-radius: 6px; font-size: 12px; font-weight: 700; }}
  .title {{ font-weight: 600; }}
  .check {{ margin-left: auto; color: #888; font-family: monospace; font-size: 13px; }}
  .detail {{ margin: .5rem 0 .25rem; }}
  .fix {{ margin: .25rem 0; }}
  .ev {{ margin: .25rem 0 0; color: #555; font-size: 13px; }}
  .ref {{ display: inline-block; margin-top: .4rem; color: #777; font-size: 12px; font-family: monospace; }}
  .score {{ font-size: 2rem; font-weight: 800; }}
  footer {{ margin-top: 2rem; color: #999; font-size: 13px; }}
</style></head>
<body>
  <h1>loginscan report</h1>
  <div class="target">{esc(self.target)}</div>
  <div class="summary">
    <span class="score">{s['score']}/100 · {s['grade']}</span>
    <span class="pill t">{len(self.findings)} findings</span>
    <span class="pill v">{v} vulnerable</span>
    <span class="pill w">{w} warnings</span>
  </div>
  {''.join(cards)}
  <footer>Generated by loginscan. Authorized self-audit only; not a proof of full security.</footer>
</body></html>"""
