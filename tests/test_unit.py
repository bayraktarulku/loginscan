"""Unit tests for pure logic (no network)."""
import base64
import json

import pytest

from loginscan.authorization import NotAuthorized, ensure_authorized
from loginscan.checks import jwt as jwt_check
from loginscan.checks import session as session_check
from loginscan.discovery import DiscoveryError, from_site, from_swagger
from loginscan.http import HttpClient, Response
from loginscan.models import Finding, ScanConfig, Severity, Status
from loginscan.report import Report


class FakeClient:
    def __init__(self, body="", cookies=None):
        self.body = body
        self.cookies = cookies or []
        self.observed_session_tokens = []

    def get(self, url, headers=None):
        return Response(200, {}, self.cookies, self.body, 0.0, url)


def test_registry_select_and_function_check():
    from loginscan.checks import headers, sqli
    from loginscan.registry import _FunctionCheck, check_names, select

    fc = _FunctionCheck("custom", lambda client, cfg: [])
    assert fc.CHECK == "custom" and fc.run(None, None) == []

    names = check_names()
    assert "sqli" in names and "csrf" in names

    assert [c.CHECK for c in select([sqli, headers], only=["sqli"])] == ["sqli"]
    assert [c.CHECK for c in select([sqli, headers], skip=["sqli"])] == ["headers"]


def test_plugin_checks_merged(monkeypatch):
    from loginscan import registry
    plugin = registry._FunctionCheck("myplugin", lambda client, cfg: [])
    monkeypatch.setattr(registry, "plugin_checks", lambda: [plugin])
    assert "myplugin" in registry.check_names(registry.all_checks())


class _FakeBurstClient:
    def __init__(self, responses):
        self._responses = responses
        self.remaining = 20

    def burst(self, method, url, data, n, content_type="form"):
        return self._responses[:n]


def test_concurrent_ratelimit_race_detected():
    from loginscan.checks.ratelimit import _concurrent_probe
    from loginscan.http import Response
    from loginscan.models import ScanConfig

    cfg = ScanConfig(url="http://x/")
    all_pass = [Response(401, {}, [], "", 0.0, "u") for _ in range(8)]
    race = _concurrent_probe(_FakeBurstClient(all_pass), cfg, limit=5, wrong_pw="x")
    assert race.status == Status.VULNERABLE and "concurrent" in race.title.lower()

    some_blocked = [Response(429, {}, [], "", 0.0, "u")] + \
        [Response(401, {}, [], "", 0.0, "u") for _ in range(7)]
    ok = _concurrent_probe(_FakeBurstClient(some_blocked), cfg, limit=5, wrong_pw="x")
    assert ok.status == Status.OK


def test_input_value_extraction():
    from loginscan.checks.base import _input_value
    html = '<input type="hidden" name="csrf" value="abc123"><input name="username">'
    assert _input_value(html, "csrf") == "abc123"
    assert _input_value(html, "missing") is None


def test_config_load_json(tmp_path):
    from loginscan.config import load_config
    p = tmp_path / "c.json"
    p.write_text('{"site": "http://x/", "user": "alice", "only": ["sqli"]}')
    conf = load_config(str(p))
    assert conf["user"] == "alice" and conf["only"] == ["sqli"]


def test_baseline_roundtrip_and_new_findings():
    from loginscan.baseline import fingerprint, new_findings
    rep = Report("t")
    known = Finding("sqli", Status.VULNERABLE, Severity.CRITICAL, "SQLi", "d")
    fresh = Finding("cors", Status.VULNERABLE, Severity.HIGH, "CORS", "d")
    rep.add(known)
    rep.add(fresh)
    baseline = {fingerprint(known)}
    offenders = new_findings(rep, baseline)
    assert [f.check for f in offenders] == ["cors"]


def test_success_detection_json_token():
    from loginscan.checks.base import looks_like_success
    from loginscan.http import Response
    from loginscan.models import ScanConfig
    cfg = ScanConfig(url="http://x/")
    baseline = Response(401, {}, [], '{"error":"bad"}', 0.0, "u")
    ok = Response(200, {}, [], '{"access_token":"abc"}', 0.0, "u")
    assert looks_like_success(ok, baseline, cfg)
    assert looks_like_success(baseline, baseline, cfg) is None


def test_scope_guard_blocks_other_host():
    import pytest as _pytest

    from loginscan.http import HttpClient, ScopeError
    client = HttpClient(10, 0.0, 5, True, allowed_hosts={"good.example"})
    with _pytest.raises(ScopeError):
        client.request("GET", "http://evil.example/x")


def test_junit_export():
    from loginscan.junit import report_to_junit
    rep = Report("http://x/login")
    rep.add(Finding("sqli", Status.VULNERABLE, Severity.CRITICAL, "SQLi", "d & <bad>"))
    rep.add(Finding("headers", Status.OK, Severity.INFO, "ok", "d"))
    xml = report_to_junit(rep)
    assert '<testsuite name="loginscan"' in xml
    assert 'failures="1"' in xml
    assert "&lt;bad&gt;" in xml  # escaped


def test_authorization_gate():
    with pytest.raises(NotAuthorized):
        ensure_authorized(False)
    ensure_authorized(True)


def _ctx_with_tokens(tokens=()):
    from loginscan.context import CheckContext, SessionObserver
    obs = SessionObserver()
    obs.tokens = list(tokens)
    return CheckContext(HttpClient(10, 0, 5, True), obs)


def test_session_sequential_is_vulnerable():
    ctx = _ctx_with_tokens([("session", "1006"), ("session", "1007")])
    findings = session_check.run(ctx, ScanConfig(url="http://x/"))
    assert findings[0].status == Status.VULNERABLE


def test_session_none_is_skipped():
    findings = session_check.run(_ctx_with_tokens(), ScanConfig(url="http://x/"))
    assert findings[0].status == Status.SKIPPED


def test_report_tracks_vulnerabilities():
    rep = Report("t")
    rep.add(Finding("a", Status.VULNERABLE, Severity.HIGH, "t", "d"))
    rep.add(Finding("b", Status.OK, Severity.INFO, "t", "d"))
    assert len(rep.vulnerabilities) == 1
    assert json.loads(rep.to_json())["summary"]["vulnerable"] == 1


def test_score_and_grade():
    from loginscan.score import score_findings
    clean = score_findings([Finding("a", Status.OK, Severity.INFO, "t", "d")])
    assert clean["score"] == 100 and clean["grade"] == "A"
    bad = score_findings([Finding("sqli", Status.VULNERABLE, Severity.CRITICAL, "t", "d")])
    assert bad["score"] == 55 and bad["grade"] == "D"
    worst = score_findings([Finding(c, Status.VULNERABLE, Severity.CRITICAL, "t", "d")
                            for c in ("a", "b", "c")])
    assert worst["score"] == 0 and worst["grade"] == "F"


def test_sarif_export():
    from loginscan.sarif import report_to_sarif
    rep = Report("http://x/login")
    rep.add(Finding("sqli", Status.VULNERABLE, Severity.CRITICAL, "SQLi", "d"))
    rep.add(Finding("headers", Status.OK, Severity.INFO, "ok", "d"))
    doc = report_to_sarif(rep, "0.2.0")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "loginscan"
    assert len(run["results"]) == 1  # only the vulnerable one
    assert run["results"][0]["ruleId"] == "sqli"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["properties"]["cwe"] == "CWE-89"


def test_report_html_escapes_and_renders():
    rep = Report("http://x/")
    rep.add(Finding("a", Status.VULNERABLE, Severity.HIGH, "<script>", "d & d"))
    out = rep.to_html()
    assert out.startswith("<!doctype html>")
    assert "<script>" not in out  # escaped
    assert "1 vulnerable" in out


def test_from_site_discovers_fields():
    html = ('<form action="/login" method="post">'
            '<input name="email" type="text">'
            '<input name="pw" type="password"></form>')
    cfg = from_site("http://site/page", FakeClient(html))
    assert cfg.url == "http://site/login"
    assert cfg.username_field == "email"
    assert cfg.password_field == "pw"


def test_from_site_without_password_raises():
    with pytest.raises(DiscoveryError):
        from_site("http://site/page", FakeClient("<form></form>"))


def test_discover_endpoints_classifies(tmp_path):
    from loginscan.discovery import discover_endpoints
    schema = {"type": "object", "properties": {"username": {"type": "string"},
                                               "password": {"type": "string"}}}
    body = {"content": {"application/json": {"schema": schema}}}
    spec = {"openapi": "3.0.0", "servers": [{"url": "http://api.example"}], "paths": {
        "/login": {"post": {"operationId": "login", "requestBody": body}},
        "/register": {"post": {"operationId": "signup", "requestBody": body}},
        "/password-reset": {"post": {"operationId": "reset", "requestBody": body}},
    }}
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec))
    eps = discover_endpoints(str(p), FakeClient())
    assert {"login", "register", "reset"} <= {e.kind for e in eps}


def _b64url(obj):
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_jwt_alg_none_is_vulnerable():
    token = f"{_b64url({'alg': 'none'})}.{_b64url({'sub': 'admin'})}."
    ctx = _ctx_with_tokens([("token", token)])
    findings = jwt_check.run(ctx, ScanConfig(url="http://x/"))
    assert any(f.status == Status.VULNERABLE for f in findings)
    assert any("exp" in f.title for f in findings)


def test_from_swagger_v3(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "http://api.example"}],
        "paths": {
            "/health": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {
                "type": "object",
                "properties": {"username": {"type": "string"}, "password": {"type": "string"}},
            }}}}}},
        },
    }
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec))
    cfg = from_swagger(str(path), FakeClient())
    assert cfg.url == "http://api.example/login"
    assert cfg.content_type == "json"
    assert cfg.password_field == "password"
