"""Write report artifacts (JSON/HTML/SARIF/JUnit) and compute the CI exit code."""
from __future__ import annotations

import json
import sys

from .authorization import NotAuthorized
from .discovery import DiscoveryError
from .http import HttpClient
from .models import Status


def write_reports(report, args, version: str) -> None:
    print(report.to_text())
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            fh.write(report.to_json())
        print(f"\nJSON report written: {args.json_path}")
    if args.html_path:
        with open(args.html_path, "w", encoding="utf-8") as fh:
            fh.write(report.to_html())
        print(f"HTML report written: {args.html_path}")
    if args.sarif_path:
        from .sarif import report_to_sarif_json
        with open(args.sarif_path, "w", encoding="utf-8") as fh:
            fh.write(report_to_sarif_json(report, version))
        print(f"SARIF report written: {args.sarif_path}")
    if args.junit_path:
        from .junit import report_to_junit
        with open(args.junit_path, "w", encoding="utf-8") as fh:
            fh.write(report_to_junit(report))
        print(f"JUnit report written: {args.junit_path}")


def exit_code(args, conf, report) -> int:
    from .baseline import load_baseline, new_findings

    baseline_path = args.baseline or conf.get("baseline")
    if baseline_path:
        offenders = new_findings(report, load_baseline(baseline_path))
    else:
        offenders = [f for f in report.findings
                     if f.status in (Status.VULNERABLE, Status.WARNING)]

    min_score = args.min_score if args.min_score is not None else conf.get("min_score")
    if min_score is not None and report.score()["score"] < min_score:
        print(f"\nFAIL: score {report.score()['score']} < min-score {min_score}", file=sys.stderr)
        return 1

    fail_on = args.fail_on or conf.get("fail_on", "vulnerable")
    if fail_on == "never":
        return 0
    if fail_on == "warning":
        bad = [f for f in offenders if f.status in (Status.VULNERABLE, Status.WARNING)]
    else:
        bad = [f for f in offenders if f.status == Status.VULNERABLE]
    return 1 if bad else 0


def run_app(args, conf, cfg, only, skip) -> int:
    swagger = args.swagger or conf.get("swagger")
    if not swagger:
        print("--all-endpoints requires --swagger.", file=sys.stderr)
        return 2

    from .app import scan_app
    from .discovery import discover_endpoints

    disco = HttpClient(max_requests=20, delay=0.0, timeout=cfg.timeout, verify_tls=cfg.verify_tls)
    try:
        endpoints = discover_endpoints(swagger, disco)
    except DiscoveryError as e:
        print(f"Discovery failed: {e}", file=sys.stderr)
        return 2

    for ep in endpoints:  # apply common tuning to every endpoint
        c = ep.config
        c.known_username = cfg.known_username
        c.success_indicators = cfg.success_indicators
        c.extra_fields = dict(cfg.extra_fields)
        c.delay, c.timeout = cfg.delay, cfg.timeout
        c.max_requests, c.verify_tls = cfg.max_requests, cfg.verify_tls

    print(f"App scan: {len(endpoints)} auth endpoints discovered\n")
    try:
        app = scan_app(endpoints, authorized=args.i_own_this, only=only, skip=skip)
    except NotAuthorized as e:
        print(str(e), file=sys.stderr)
        return 2

    print(app.to_text())
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(app.to_dict(), ensure_ascii=False, indent=2))
        print(f"JSON report written: {args.json_path}")

    min_score = args.min_score if args.min_score is not None else conf.get("min_score")
    if min_score is not None and app.worst_score()["score"] < min_score:
        return 1
    fail_on = args.fail_on or conf.get("fail_on", "vulnerable")
    if fail_on == "never":
        return 0
    offenders = app.all_vulnerabilities
    if fail_on == "warning":
        offenders = offenders + [f for s in app.sections for f in s["report"].warnings]
    return 1 if offenders else 0
