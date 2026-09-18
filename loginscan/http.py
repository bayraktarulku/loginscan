"""Dependency-free HTTP client with a request budget and inter-request delay.

The request budget (max_requests) keeps the tool low-volume so it stays a
self-audit scanner rather than a brute-force weapon.
"""
from __future__ import annotations

import http.cookiejar
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

_SESSION_COOKIE_HINT = re.compile(r"sess|token|auth|sid|jwt|login", re.I)


class RequestBudgetExceeded(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A scanner must see 3xx responses, not silently follow them.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    set_cookies: list
    body: str
    elapsed: float
    url: str

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())


class HttpClient:
    def __init__(self, max_requests: int, delay: float, timeout: float, verify_tls: bool,
                 use_cookies: bool = False):
        self.max_requests = max_requests
        self.delay = delay
        self.timeout = timeout
        self.count = 0
        self.observed_session_tokens: List[Tuple[str, str]] = []
        self.csrf_token: Optional[str] = None  # cached per scan when CSRF mode is on
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        handlers = [_NoRedirect, urllib.request.HTTPSHandler(context=self._ctx)]
        if use_cookies:
            # A shared cookie jar lets multi-step flows work (e.g. fetch a CSRF
            # cookie, then submit the matching token).
            handlers.append(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self._opener = urllib.request.build_opener(*handlers)

    @property
    def remaining(self) -> int:
        return self.max_requests - self.count

    def _spend(self) -> None:
        if self.count >= self.max_requests:
            raise RequestBudgetExceeded(
                f"Request budget exhausted ({self.max_requests}). "
                "Increase max_requests for a deeper scan."
            )
        self.count += 1

    def request(self, method: str, url: str, data: Optional[Dict[str, str]] = None,
                headers: Optional[Dict[str, str]] = None,
                content_type: str = "form") -> Response:
        self._spend()
        if self.delay and self.count > 1:
            time.sleep(self.delay)

        req_headers = {"User-Agent": "loginscan (self-audit)"}
        body_bytes = None
        if data is not None:
            if content_type == "json":
                body_bytes = json.dumps(data).encode()
                req_headers["Content-Type"] = "application/json"
            else:
                body_bytes = urllib.parse.urlencode(data).encode()
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=body_bytes, method=method.upper(),
                                     headers=req_headers)
        start = time.time()
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return self._to_response(resp, start, url)
        except urllib.error.HTTPError as e:
            return self._to_response(e, start, url)

    def _to_response(self, resp, start: float, url: str) -> Response:
        raw = resp.read() if hasattr(resp, "read") else b""
        text = raw.decode("utf-8", errors="replace")
        headers = {}
        set_cookies = []
        for k, v in resp.headers.items():
            lk = k.lower()
            if lk == "set-cookie":
                set_cookies.append(v)
            headers[lk] = v
        try:
            all_cookies = resp.headers.get_all("Set-Cookie")
            if all_cookies:
                set_cookies = list(all_cookies)
        except Exception:
            pass

        for cookie in set_cookies:
            nv = cookie.split(";", 1)[0]
            if "=" in nv:
                name, value = (p.strip() for p in nv.split("=", 1))
                if value and _SESSION_COOKIE_HINT.search(name):
                    self.observed_session_tokens.append((name, value))

        return Response(
            status=getattr(resp, "status", getattr(resp, "code", 0)) or 0,
            headers=headers,
            set_cookies=set_cookies,
            body=text,
            elapsed=time.time() - start,
            url=url,
        )

    def post(self, url: str, data: Dict[str, str], headers: Optional[Dict[str, str]] = None,
             content_type: str = "form") -> Response:
        return self.request("POST", url, data=data, headers=headers, content_type=content_type)

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> Response:
        return self.request("GET", url, data=None, headers=headers)
