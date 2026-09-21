"""Discover a login endpoint from a site URL or an OpenAPI/Swagger spec,
so users can scan by giving just a link.
"""
from __future__ import annotations

import json
import re
import urllib.request
from html.parser import HTMLParser
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from dataclasses import dataclass

from .http import HttpClient
from .models import ScanConfig

_USER_HINT = re.compile(r"user|email|login|account|phone|uname", re.I)
_PASS_HINT = re.compile(r"pass|pwd|secret", re.I)
_CSRF_HINT = re.compile(r"csrf|xsrf|authenticity|_token", re.I)
_LOGIN_PATH_HINT = re.compile(r"log[\-_]?in|sign[\-_]?in|authenticate|auth|session|token|oauth", re.I)


class DiscoveryError(Exception):
    pass


# --------------------------- site (HTML form) ---------------------------

class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: List[dict] = []
        self._cur: Optional[dict] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": a.get("method", "post"),
                         "inputs": []}
        elif tag == "input" and self._cur is not None:
            self._cur["inputs"].append({"name": a.get("name", ""),
                                        "type": (a.get("type", "text") or "text").lower()})

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def from_site(page_url: str, client: HttpClient, **overrides) -> ScanConfig:
    """Fetch an HTML page, find the login form, and build a ScanConfig."""
    resp = client.get(page_url)
    parser = _FormParser()
    parser.feed(resp.body)

    login_form = None
    for form in parser.forms:
        if any(i["type"] == "password" for i in form["inputs"]):
            login_form = form
            break
    if login_form is None:
        raise DiscoveryError(f"No form with a password field found at {page_url}")

    pw = next(i for i in login_form["inputs"] if i["type"] == "password")
    candidates = [i for i in login_form["inputs"]
                  if i["type"] in ("text", "email", "tel", "") and i["name"]]
    user = next((i for i in candidates if _USER_HINT.search(i["name"])),
                candidates[0] if candidates else {"name": "username"})

    csrf = next((i["name"] for i in login_form["inputs"]
                 if i["name"] and _CSRF_HINT.search(i["name"])), None)

    action = urljoin(page_url, login_form["action"]) if login_form["action"] else page_url
    cfg = ScanConfig(
        url=action,
        method=(login_form["method"] or "post").upper(),
        content_type="form",
        username_field=user["name"] or "username",
        password_field=pw["name"] or "password",
        login_page_url=page_url,
        csrf_field=csrf,
        csrf_url=page_url if csrf else None,
    )
    _apply_overrides(cfg, overrides)
    return cfg


# --------------------------- swagger / openapi ---------------------------

def _load_spec(location: str) -> dict:
    if location.startswith(("http://", "https://")):
        with urllib.request.urlopen(location, timeout=15) as r:
            raw = r.read().decode("utf-8", errors="replace")
    else:
        with open(location, "r", encoding="utf-8") as fh:
            raw = fh.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise DiscoveryError("Only JSON OpenAPI/Swagger specs are supported (not YAML).") from e


def _resolve_ref(spec: dict, node: dict) -> dict:
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 10:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            break
        cur = spec
        for part in ref[2:].split("/"):
            cur = cur.get(part, {})
        node = cur
        seen += 1
    return node if isinstance(node, dict) else {}


def _base_url(spec: dict, spec_location: str) -> str:
    servers = spec.get("servers")
    if servers:
        url = servers[0].get("url", "")
        if url.startswith(("http://", "https://")):
            return url.rstrip("/")
        return urljoin(spec_location, url).rstrip("/")
    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        return f"{scheme}://{host}{spec.get('basePath', '')}".rstrip("/")
    parsed = urlparse(spec_location)
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _score_path(path: str, op: dict) -> int:
    text = " ".join([path, op.get("operationId", "") or "", op.get("summary", "") or "",
                     " ".join(op.get("tags", []) or [])])
    return len(_LOGIN_PATH_HINT.findall(text))


def _fields_from_operation(spec: dict, op: dict):
    """Return (content_type, username_field, password_field) or None."""
    # OpenAPI v3 requestBody
    body = op.get("requestBody")
    if body:
        content = _resolve_ref(spec, body).get("content", {})
        for ctype in ("application/json", "application/x-www-form-urlencoded"):
            if ctype in content:
                schema = _resolve_ref(spec, content[ctype].get("schema", {}))
                props = schema.get("properties", {})
                u, p = _match_fields(props.keys())
                if p:
                    return ("json" if "json" in ctype else "form", u, p)
    # Swagger v2 parameters
    params = op.get("parameters", [])
    form_names = [pr.get("name") for pr in params if pr.get("in") == "formData"]
    if form_names:
        u, p = _match_fields(form_names)
        if p:
            return ("form", u, p)
    for pr in params:
        if pr.get("in") == "body":
            schema = _resolve_ref(spec, pr.get("schema", {}))
            u, p = _match_fields(schema.get("properties", {}).keys())
            if p:
                return ("json", u, p)
    return None


def _match_fields(names):
    names = [n for n in names if n]
    user = next((n for n in names if _USER_HINT.search(n)), None)
    pw = next((n for n in names if _PASS_HINT.search(n)), None)
    return user, pw


_KIND_HINTS = [
    ("logout", re.compile(r"log[\-_]?out|sign[\-_]?out", re.I)),
    ("register", re.compile(r"regist|sign[\-_]?up|create[\-_]?account", re.I)),
    ("reset", re.compile(r"reset|forgot|recover|change[\-_]?password", re.I)),
    ("refresh", re.compile(r"refresh", re.I)),
    ("login", re.compile(r"log[\-_]?in|sign[\-_]?in|authenticate|token|session|oauth", re.I)),
]


@dataclass
class Endpoint:
    kind: str
    config: ScanConfig


def _classify(path: str, op: dict) -> str:
    text = " ".join([path, op.get("operationId", "") or "", op.get("summary", "") or ""])
    for kind, rx in _KIND_HINTS:
        if rx.search(text):
            return kind
    return "auth"


def _credential_endpoints(spec: dict, base: str):
    """Yield (score, path, method, op, fields) for every credential-taking operation."""
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("post", "put") or not isinstance(op, dict):
                continue
            fields = _fields_from_operation(spec, op)
            if not fields:
                continue
            yield _score_path(path, op) + 1, path, method, op, fields


def from_swagger(location: str, client: HttpClient, **overrides) -> ScanConfig:
    """Parse an OpenAPI/Swagger JSON spec and build a ScanConfig for its login endpoint."""
    spec = _load_spec(location)
    base = _base_url(spec, location)
    best = None
    for score, path, method, _op, fields in _credential_endpoints(spec, base):
        if best is None or score > best[0]:
            best = (score, path, method, fields)
    if best is None:
        raise DiscoveryError("No login-like endpoint with username/password fields found in the spec.")
    _, path, method, (ctype, user, pw) = best
    cfg = ScanConfig(url=base + path, method=method.upper(), content_type=ctype,
                     username_field=user or "username", password_field=pw)
    _apply_overrides(cfg, overrides)
    return cfg


def discover_endpoints(location: str, client: HttpClient) -> List[Endpoint]:
    """Return every credential-taking auth endpoint in an OpenAPI/Swagger spec."""
    spec = _load_spec(location)
    base = _base_url(spec, location)
    endpoints = []
    for _score, path, method, op, (ctype, user, pw) in _credential_endpoints(spec, base):
        cfg = ScanConfig(url=base + path, method=method.upper(), content_type=ctype,
                         username_field=user or "username", password_field=pw)
        endpoints.append(Endpoint(kind=_classify(path, op), config=cfg))
    if not endpoints:
        raise DiscoveryError("No auth endpoints with credential fields found in the spec.")
    return endpoints


def _apply_overrides(cfg: ScanConfig, overrides: dict) -> None:
    for k, v in overrides.items():
        if v is not None and hasattr(cfg, k):
            setattr(cfg, k, v)
