"""End-to-end scans against the vulnerable and secure demo servers."""
from loginscan import ScanConfig, Scanner, Status


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


def test_secure_server_has_csrf_defense(secure_url):
    report = _scan(secure_url, known_username="admin")
    csrf = [f for f in report.findings if f.check == "csrf"]
    assert csrf and csrf[0].status == Status.OK
