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
    p.add_argument("--success", dest="success_indicators", action="append", default=[],
                   metavar="TEXT", help="Text meaning 'login succeeded' (repeatable).")
    p.add_argument("--field", dest="extra_fields", action="append", default=[],
                   metavar="NAME=VALUE", help="Constant field added to every request (repeatable).")
    p.add_argument("--max-requests", type=int, default=25, help="Total request budget (default 25).")
    p.add_argument("--delay", type=float, default=0.3, help="Delay between requests (s).")
    p.add_argument("--timeout", type=float, default=10.0, help="Request timeout (s).")
    p.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    p.add_argument("--json", dest="json_path", default=None, metavar="FILE",
                   help="Also write the report as JSON to this file.")
    p.add_argument("--html", dest="html_path", default=None, metavar="FILE",
                   help="Also write the report as a shareable HTML page.")
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


def _build_config(args) -> ScanConfig:
    disco_client = HttpClient(max_requests=5, delay=0.0, timeout=args.timeout,
                              verify_tls=not args.insecure)
    if args.swagger:
        cfg = from_swagger(args.swagger, disco_client)
    elif args.site:
        cfg = from_site(args.site, disco_client)
    else:
        cfg = ScanConfig(url=args.url)

    # Apply explicit overrides on top of discovery / defaults.
    if args.method:
        cfg.method = args.method
    if args.json_body:
        cfg.content_type = "json"
    if args.username_field:
        cfg.username_field = args.username_field
    if args.password_field:
        cfg.password_field = args.password_field
    if args.login_page_url:
        cfg.login_page_url = args.login_page_url
    cfg.known_username = args.known_username
    cfg.success_indicators = args.success_indicators
    cfg.extra_fields = _parse_fields(args.extra_fields)
    cfg.max_requests = args.max_requests
    cfg.delay = args.delay
    cfg.timeout = args.timeout
    cfg.verify_tls = not args.insecure
    return cfg


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    if not (args.url or args.site or args.swagger):
        print("Give a target: a URL, --site URL, or --swagger URL/file.", file=sys.stderr)
        return 2

    try:
        cfg = _build_config(args)
    except DiscoveryError as e:
        print(f"Discovery failed: {e}", file=sys.stderr)
        return 2

    print(f"Target: {cfg.method} {cfg.url}  (fields: {cfg.username_field}/{cfg.password_field}, "
          f"{cfg.content_type})\n")

    try:
        report = Scanner(cfg, authorized=args.i_own_this).run()
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

    return 1 if any(f.status == Status.VULNERABLE for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
