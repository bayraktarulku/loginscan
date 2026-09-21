"""Smoke tests for the CLI entry point (exit-code contract)."""
from loginscan.cli import main


def test_list_checks_exits_zero(capsys):
    assert main(["--list-checks"]) == 0
    assert "sqli" in capsys.readouterr().out


def test_no_target_exits_two():
    assert main([]) == 2


def test_unauthorized_exits_two():
    # No --i-own-this: refused before any request.
    assert main(["http://127.0.0.1:9/login"]) == 2


def test_bad_config_exits_two(tmp_path):
    bad = tmp_path / "c.json"
    bad.write_text("{not json")
    assert main(["--config", str(bad), "--i-own-this"]) == 2


def test_scan_vulnerable_exits_one(vuln_url):
    code = main(["--site", vuln_url, "--i-own-this", "--only", "sqli",
                 "--success", "Giriş başarılı", "--delay", "0"])
    assert code == 1  # a vulnerability was found
