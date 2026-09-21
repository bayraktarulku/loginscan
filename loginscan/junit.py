"""Export a report as JUnit XML (for CI test reporters)."""
from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

from .models import Status
from .report import Report

_FAIL = {Status.VULNERABLE, Status.WARNING}


def report_to_junit(report: Report) -> str:
    findings = report.sorted_findings()
    failures = sum(1 for f in findings if f.status in _FAIL)
    errors = sum(1 for f in findings if f.status == Status.ERROR)

    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(
        f'<testsuite name="loginscan" tests="{len(findings)}" '
        f'failures="{failures}" errors="{errors}" hostname={quoteattr(report.target)}>')
    for f in findings:
        name = quoteattr(f"{f.check}: {f.title}")
        classname = quoteattr(f"loginscan.{f.check}")
        lines.append(f'  <testcase name={name} classname={classname}>')
        msg = quoteattr(f.title)
        body = escape(f"{f.detail}\n{f.remediation}".strip())
        if f.status in _FAIL:
            lines.append(f'    <failure type={quoteattr(f.severity)} message={msg}>{body}</failure>')
        elif f.status == Status.ERROR:
            lines.append(f'    <error message={msg}>{body}</error>')
        elif f.status == Status.SKIPPED:
            lines.append('    <skipped/>')
        lines.append('  </testcase>')
    lines.append('</testsuite>')
    return "\n".join(lines)
