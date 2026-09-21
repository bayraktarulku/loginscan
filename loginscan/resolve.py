"""Turn parsed CLI args + an optional config profile into a ScanConfig.

Precedence: explicit CLI flags override the config file, which overrides defaults.
"""
from __future__ import annotations

from .discovery import from_site, from_swagger
from .http import HttpClient
from .models import ScanConfig


def parse_fields(pairs: list[str]) -> dict:
    out = {}
    for item in pairs:
        if "=" not in item:
            raise SystemExit(f"--field '{item}' invalid; expected NAME=VALUE.")
        k, v = item.split("=", 1)
        out[k.strip()] = v
    return out


def parse_headers(pairs: list[str]) -> dict:
    out = {}
    for item in pairs:
        if ":" not in item:
            raise SystemExit(f"--header '{item}' invalid; expected 'Key: Value'.")
        k, v = item.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def split_csv(value):
    return [x.strip() for x in value.split(",") if x.strip()] if value else None


def build_config(args, conf) -> ScanConfig:
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
    cfg.password = pick(args.password, "password")
    cfg.logout_url = pick(args.logout_url, "logout_url")
    cfg.success_indicators = args.success_indicators or conf.get("success", [])
    fields = parse_fields(args.extra_fields) if args.extra_fields else conf.get("fields", {})
    cfg.extra_fields = dict(fields)
    cfg.max_requests = pick(args.max_requests, "max_requests", 60)
    cfg.delay = pick(args.delay, "delay", 0.3)
    cfg.timeout = timeout
    cfg.verify_tls = not insecure

    headers = dict(conf.get("headers", {}))
    headers.update(parse_headers(args.headers))
    bearer = args.bearer or conf.get("bearer")
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    cfg.extra_headers = headers
    cfg.proxy = args.proxy or conf.get("proxy")
    cfg.retries = pick(args.retries, "retries", 2)
    cfg.scope_guard = not (args.no_scope_guard or conf.get("no_scope_guard", False))
    return cfg
