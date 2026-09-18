"""End-to-end scans against the vulnerable and secure demo servers."""
from loginscan import ScanConfig, Scanner, Status


def _scan(url, **kw):
    cfg = ScanConfig(url=url, success_indicators=["Giriş başarılı"],
                     delay=0.0, max_requests=40, **kw)
    return Scanner(cfg, authorized=True).run()


def test_vulnerable_server_flags_core_issues(vuln_url):
    report = _scan(vuln_url, known_username="admin")
    vuln = {f.check for f in report.vulnerabilities}
    assert "sqli" in vuln
    assert "enumeration" in vuln
    assert "ratelimit" in vuln


def test_secure_server_passes_core_checks(secure_url):
    report = _scan(secure_url, known_username="admin")
    vuln = {f.check for f in report.vulnerabilities}
    assert "sqli" not in vuln
    assert "enumeration" not in vuln
    assert "ratelimit" not in vuln


def test_secure_server_has_csrf_defense(secure_url):
    report = _scan(secure_url, known_username="admin")
    csrf = [f for f in report.findings if f.check == "csrf"]
    assert csrf and csrf[0].status == Status.OK
