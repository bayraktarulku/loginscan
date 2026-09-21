"""loginscan command-line interface."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .authorization import AUTHORIZATION_NOTICE, NotAuthorized
from .discovery import DiscoveryError, from_site, from_swagger
from .http import HttpClient
from .models import ScanConfig, Status
from .scanner import Scanner


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="loginscan",
        description="Defensive self-audit scanner for login endpoints (authorized use only).",
        epilog=AUTHORIZATION_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_argument_group("target (give one)")
    src.add_argument("url", nargs="?", help="Login endpoint URL (e.g. https://site/login)")
    src.add_argument("--site", help="Web page URL; the login form is auto-discovered")
    src.add_argument("--swagger", help="OpenAPI/Swagger JSON URL or file; login endpoint is auto-discovered")
    src.add_argument("--all-endpoints", action="store_true",
                     help="With --swagger: scan EVERY auth endpoint (login/register/reset/...).")

    p.add_argument("--i-own-this", action="store_true",
                   help="Assert you are authorized to test the target (required).")
    p.add_argument("--user", dest="known_username", default=None,
                   help="A username that really exists on your system (not the password).")
    p.add_argument("--method", default=None, help="Login HTTP method (default POST).")
    p.add_argument("--json-body", action="store_true",
                   help="Send credentials as JSON instead of form-encoded.")
    p.add_argument("--username-field", default=None, help="Username form field name.")
    p.add_argument("--password-field", default=None, help="Password form field name.")
    p.add_argument("--login-page", dest="login_page_url", default=None,
                   help="HTML page of the login form (for header checks).")
    p.add_argument("--csrf-field", default=None,
                   help="Hidden CSRF field name; enables a cookie jar + auto token fetch.")
    p.add_argument("--csrf-url", default=None,
                   help="Page to fetch the CSRF token/cookie from (default: login page).")
    p.add_argument("--success", dest="success_indicators", action="append", default=[],
                   metavar="TEXT", help="Text meaning 'login succeeded' (repeatable).")
    p.add_argument("--field", dest="extra_fields", action="append", default=[],
                   metavar="NAME=VALUE", help="Constant field added to every request (repeatable).")
    p.add_argument("--only", default=None, metavar="a,b,c",
                   help="Run only these checks (comma-separated).")
    p.add_argument("--skip", default=None, metavar="x,y",
                   help="Skip these checks (comma-separated).")
    p.add_argument("--list-checks", action="store_true",
                   help="List all available checks (built-in + plugins) and exit.")
    p.add_argument("--max-requests", type=int, default=None, help="Total request budget (default 60).")
    p.add_argument("--delay", type=float, default=None, help="Delay between requests (s, default 0.3).")
    p.add_argument("--timeout", type=float, default=None, help="Request timeout (s, default 10).")
    p.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    p.add_argument("--config", default=None, metavar="FILE",
                   help="Load a scan profile (JSON, or YAML with pyyaml). CLI flags override it.")
    p.add_argument("--baseline", default=None, metavar="FILE",
                   help="Accept findings listed in this baseline; fail only on NEW ones.")
    p.add_argument("--write-baseline", default=None, metavar="FILE",
                   help="Write current findings to a baseline file and exit 0.")
    p.add_argument("--fail-on", choices=["vulnerable", "warning", "never"], default=None,
                   help="What makes the run fail (default vulnerable).")
    p.add_argument("--min-score", type=int, default=None, metavar="N",
                   help="Fail if the security score is below N.")
    p.add_argument("--json", dest="json_path", default=None, metavar="FILE",
                   help="Also write the report as JSON to this file.")
    p.add_argument("--html", dest="html_path", default=None, metavar="FILE",
                   help="Also write the report as a shareable HTML page.")
    p.add_argument("--sarif", dest="sarif_path", default=None, metavar="FILE",
                   help="Also write SARIF 2.1.0 (for GitHub code scanning / CI).")
    p.add_argument("--version", action="version", version=f"loginscan {__version__}")
    return p


def _parse_fields(pairs: List[str]) -> dict:
    out = {}
    for item in pairs:
        if "=" not in item:
            raise SystemExit(f"--field '{item}' invalid; expected NAME=VALUE.")
        k, v = item.split("=", 1)
        out[k.strip()] = v
    return out


def _build_config(args, conf) -> ScanConfig:
    def pick(cli_val, key, default=None):
        return cli_val if cli_val is not None else conf.get(key, default)

    timeout = pick(args.timeout, "timeout", 10.0)
    insecure = args.insecure or conf.get("insecure", False)
    target = args.url or conf.get("url")
    site = args.site or conf.get("site")
    swagger = args.swagger or conf.get("swagger")

    disco_client = HttpClient(max_requests=5, delay=0.0, timeout=timeout, verify_tls=not insecure)
    if swagger:
        cfg = from_swagger(swagger, disco_client)
    elif site:
        cfg = from_site(site, disco_client)
    else:
        cfg = ScanConfig(url=target)

    method = pick(args.method, "method")
    if method:
        cfg.method = method
    if args.json_body or conf.get("json_body"):
        cfg.content_type = "json"
    uf = pick(args.username_field, "username_field")
    if uf:
        cfg.username_field = uf
    pf = pick(args.password_field, "password_field")
    if pf:
        cfg.password_field = pf
    lp = pick(args.login_page_url, "login_page")
    if lp:
        cfg.login_page_url = lp
    csrf = pick(args.csrf_field, "csrf_field")
    if csrf:
        cfg.csrf_field = csrf
        cfg.csrf_url = pick(args.csrf_url, "csrf_url") or cfg.csrf_url or cfg.login_page_url or cfg.url

    cfg.known_username = pick(args.known_username, "user")
    cfg.success_indicators = args.success_indicators or conf.get("success", [])
    fields = _parse_fields(args.extra_fields) if args.extra_fields else conf.get("fields", {})
    cfg.extra_fields = dict(fields)
    cfg.max_requests = pick(args.max_requests, "max_requests", 60)
    cfg.delay = pick(args.delay, "delay", 0.3)
    cfg.timeout = timeout
    cfg.verify_tls = not insecure
    return cfg


def _split(value):
    return [x.strip() for x in value.split(",") if x.strip()] if value else None


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.list_checks:
        from .registry import check_names
        print("Available checks:")
        for name in check_names():
            print(f"  - {name}")
        return 0

    conf = {}
    if args.config:
        from .config import ConfigError, load_config
        try:
            conf = load_config(args.config)
        except (OSError, ConfigError, ValueError) as e:
            print(f"Config error: {e}", file=sys.stderr)
            return 2

    if not (args.url or args.site or args.swagger or conf.get("url")
            or conf.get("site") or conf.get("swagger")):
        print("Give a target: a URL, --site URL, --swagger URL/file, or a --config.", file=sys.stderr)
        return 2

    try:
        cfg = _build_config(args, conf)
    except DiscoveryError as e:
        print(f"Discovery failed: {e}", file=sys.stderr)
        return 2

    only = _split(args.only) or conf.get("only")
    skip = _split(args.skip) or conf.get("skip")

    if args.all_endpoints or conf.get("all_endpoints"):
        return _run_app(args, conf, cfg, only, skip)

    csrf_note = f", csrf={cfg.csrf_field}" if cfg.csrf_field else ""
    print(f"Target: {cfg.method} {cfg.url}  (fields: {cfg.username_field}/{cfg.password_field}, "
          f"{cfg.content_type}{csrf_note})\n")

    try:
        report = Scanner(cfg, authorized=args.i_own_this, only=only, skip=skip).run()
    except NotAuthorized as e:
        print(str(e), file=sys.stderr)
        return 2

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
            fh.write(report_to_sarif_json(report, __version__))
        print(f"SARIF report written: {args.sarif_path}")

    if args.write_baseline:
        from .baseline import write_baseline
        n = write_baseline(report, args.write_baseline)
        print(f"Baseline written ({n} findings): {args.write_baseline}")
        return 0

    return _exit_code(args, conf, report)


def _run_app(args, conf, cfg, only, skip) -> int:
    swagger = args.swagger or conf.get("swagger")
    if not swagger:
        print("--all-endpoints requires --swagger.", file=sys.stderr)
        return 2
    import json as _json

    from .app import scan_app
    from .discovery import discover_endpoints
    from .models import Status

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
            fh.write(_json.dumps(app.to_dict(), ensure_ascii=False, indent=2))
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


def _exit_code(args, conf, report) -> int:
    from .baseline import load_baseline, new_findings
    from .models import Status

    baseline_path = args.baseline or conf.get("baseline")
    if baseline_path:
        base = load_baseline(baseline_path)
        offenders = new_findings(report, base)
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


if __name__ == "__main__":
    raise SystemExit(main())
