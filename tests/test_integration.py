"""End-to-end scans against the vulnerable and secure demo servers."""
import http.server
import threading
import urllib.parse

from loginscan import ScanConfig, Scanner, Status
from loginscan.discovery import from_site
from loginscan.http import HttpClient


def _make_stateful_handler(rotate: bool):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Set-Cookie", "session=PRESET; Path=/")
            self.end_headers()
            self.wfile.write(b"<form>login</form>")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(length).decode())
            ok = data.get("username", [""])[0] == "admin" and data.get("password", [""])[0] == "pw"
            self.send_response(200 if ok else 401)
            if ok and rotate:
                self.send_header("Set-Cookie", "session=ROTATED; Path=/")
            self.end_headers()
            self.wfile.write(b"Welcome admin" if ok else b"nope")

    return Handler


def _serve_handler(handler):
    httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/"


def _fixation_report(rotate: bool):
    httpd, url = _serve_handler(_make_stateful_handler(rotate))
    try:
        cfg = ScanConfig(url=url, known_username="admin", password="pw",
                         success_indicators=["Welcome"], delay=0.0)
        return Scanner(cfg, authorized=True, only=["session_fixation"]).run()
    finally:
        httpd.shutdown()


def test_session_fixation_detected():
    report = _fixation_report(rotate=False)
    assert "session_fixation" in {f.check for f in report.vulnerabilities}


def test_session_rotation_passes():
    report = _fixation_report(rotate=True)
    sf = [f for f in report.findings if f.check == "session_fixation"][0]
    assert sf.status == Status.OK


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
