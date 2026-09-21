"""Export a report as SARIF 2.1.0 (for GitHub code scanning / CI tooling)."""
from __future__ import annotations

import json
from typing import Any

from .knowledge import meta_for
from .models import Severity, Status
from .report import Report

_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error",
          Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}

# Only actionable findings become SARIF results.
_REPORTABLE = {Status.VULNERABLE, Status.WARNING}


def report_to_sarif(report: Report, version: str = "0") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in report.sorted_findings():
        if f.status not in _REPORTABLE:
            continue
        meta = meta_for(f.check)
        if f.check not in rules:
            rule: dict[str, Any] = {
                "id": f.check,
                "name": f.check,
                "shortDescription": {"text": f.title},
                "properties": dict(meta.items()),
            }
            if meta.get("cwe"):
                rule["properties"]["tags"] = ["security", meta["cwe"]]
                num = meta["cwe"].split("-")[-1]
                rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{num}.html"
            rules[f.check] = rule
        props: dict[str, Any] = {"severity": f.severity, "status": f.status}
        props.update(meta)
        results.append({
            "ruleId": f.check,
            "level": _LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.title}. {f.detail}"
                        + (f" Fix: {f.remediation}" if f.remediation else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": report.target}}}],
            "properties": props,
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "loginscan",
                "version": version,
                "informationUri": "https://github.com/bayraktarulku/loginscan",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def report_to_sarif_json(report: Report, version: str = "0", indent: int = 2) -> str:
    return json.dumps(report_to_sarif(report, version), ensure_ascii=False, indent=indent)
