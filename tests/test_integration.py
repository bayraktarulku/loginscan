"""End-to-end scans against the vulnerable and secure demo servers."""
from loginscan import ScanConfig, Scanner, Status
from loginscan.discovery import from_site
from loginscan.http import HttpClient


def _scan(url, **kw):
    cfg = ScanConfig(url=url, success_indicators=["Giriş başarılı"],
                     delay=0.0, max_requests=40, **kw)
    return Scanner(cfg, authorized=True).run()


def test_vulnerable_server_flags_core_issues(vuln_url):
    report = _scan(vuln_url, known_username="admin")
    vuln = {f.check for f in report.vulnerabilities}
    assert {"sqli", "enumeration", "ratelimit", "cors", "verb"} <= vuln


def test_secure_server_passes_core_checks(secure_url):
    report = _scan(secure_url, known_username="admin")
    vuln = {f.check for f in report.vulnerabilities}
    for check in ("sqli", "enumeration", "ratelimit", "cors", "verb"):
        assert check not in vuln


def test_cache_header_split(vuln_url, secure_url):
    vuln = {f.check: f for f in _scan(vuln_url, known_username="admin").findings}
    secure = {f.check: f for f in _scan(secure_url, known_username="admin").findings}
    assert vuln["cache"].status == Status.WARNING
    assert secure["cache"].status == Status.OK


def test_vulnerable_server_open_redirect(vuln_url):
    report = _scan(vuln_url, known_username="admin")
    assert "open_redirect" in {f.check for f in report.vulnerabilities}


def test_csrf_protected_scan_via_discovery(secure_url):
    # --site discovery should auto-detect the CSRF field and scan through the
    # double-submit protection (login POSTs must succeed, not 403).
    cfg = from_site(secure_url, HttpClient(5, 0.0, 10, True))
    assert cfg.csrf_field == "csrf"
    cfg.known_username = "admin"
    cfg.success_indicators = ["Giriş başarılı"]
    cfg.delay = 0.0
    cfg.max_requests = 90
    report = Scanner(cfg, authorized=True).run()
    vuln = {f.check for f in report.vulnerabilities}
    assert "sqli" not in vuln
    csrf = [f for f in report.findings if f.check == "csrf"][0]
    assert csrf.status == Status.OK


def test_app_scan_multiple_endpoints(vuln_url, tmp_path):
    import json

    from loginscan.app import scan_app
    from loginscan.discovery import discover_endpoints

    schema = {"type": "object", "properties": {"username": {"type": "string"},
                                               "password": {"type": "string"}}}
    body = {"content": {"application/x-www-form-urlencoded": {"schema": schema}}}
    base = vuln_url.rstrip("/")
    spec = {"openapi": "3.0.0", "servers": [{"url": base}], "paths": {
        "/login": {"post": {"operationId": "login", "requestBody": body}},
        "/register": {"post": {"operationId": "signup", "requestBody": body}},
    }}
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec))
    endpoints = discover_endpoints(str(p), HttpClient(5, 0.0, 10, True))
    assert {"login", "register"} <= {e.kind for e in endpoints}
    for e in endpoints:
        e.config.success_indicators = ["Giriş başarılı"]
        e.config.delay = 0.0
        e.config.max_requests = 60
    app = scan_app(endpoints, authorized=True, only=["sqli"])
    assert len(app.sections) == 2
    assert app.all_vulnerabilities  # SQLi found on each endpoint


def test_secure_server_has_csrf_defense(secure_url):
    report = _scan(secure_url, known_username="admin")
    csrf = [f for f in report.findings if f.check == "csrf"]
    assert csrf and csrf[0].status == Status.OK
