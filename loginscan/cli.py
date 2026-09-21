"""loginscan command-line interface."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .authorization import AUTHORIZATION_NOTICE, NotAuthorized
from .discovery import DiscoveryError
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
    p.add_argument("--password", default=None,
                   help="YOUR OWN test-account password; enables stateful checks (session fixation).")
    p.add_argument("--logout-url", default=None, help="Logout endpoint (for the logout check).")
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
    p.add_argument("--header", dest="headers", action="append", default=[], metavar="K: V",
                   help="Custom request header (repeatable).")
    p.add_argument("--bearer", default=None, metavar="TOKEN",
                   help="Send Authorization: Bearer TOKEN on every request.")
    p.add_argument("--proxy", default=None, metavar="URL", help="HTTP(S) proxy URL.")
    p.add_argument("--retries", type=int, default=None, help="Transient-failure retries (default 2).")
    p.add_argument("--no-scope-guard", action="store_true",
                   help="Allow requests to hosts other than the target (off by default).")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="Increase log verbosity (-v info, -vv debug).")
    p.add_argument("--quiet", action="store_true", help="Only log errors.")
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
    p.add_argument("--junit", dest="junit_path", default=None, metavar="FILE",
                   help="Also write JUnit XML (for CI test reporters).")
    p.add_argument("--version", action="version", version=f"loginscan {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    from .logconf import configure_logging
    configure_logging(verbosity=args.verbose, quiet=args.quiet)

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

    from .report_io import exit_code, run_app, write_reports
    from .resolve import build_config, split_csv
    try:
        cfg = build_config(args, conf)
    except DiscoveryError as e:
        print(f"Discovery failed: {e}", file=sys.stderr)
        return 2

    only = split_csv(args.only) or conf.get("only")
    skip = split_csv(args.skip) or conf.get("skip")

    if args.all_endpoints or conf.get("all_endpoints"):
        return run_app(args, conf, cfg, only, skip)

    csrf_note = f", csrf={cfg.csrf_field}" if cfg.csrf_field else ""
    print(f"Target: {cfg.method} {cfg.url}  (fields: {cfg.username_field}/{cfg.password_field}, "
          f"{cfg.content_type}{csrf_note})\n")

    try:
        report = Scanner(cfg, authorized=args.i_own_this, only=only, skip=skip).run()
    except NotAuthorized as e:
        print(str(e), file=sys.stderr)
        return 2

    write_reports(report, args, __version__)

    if args.write_baseline:
        from .baseline import write_baseline
        n = write_baseline(report, args.write_baseline)
        print(f"Baseline written ({n} findings): {args.write_baseline}")
        return 0

    return exit_code(args, conf, report)


if __name__ == "__main__":
    raise SystemExit(main())
