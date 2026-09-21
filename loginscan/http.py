"""Dependency-free HTTP client with a request budget and inter-request delay.

The request budget (max_requests) keeps the tool low-volume so it stays a
self-audit scanner rather than a brute-force weapon.
"""
from __future__ import annotations

import http.cookiejar
import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("loginscan.http")


class RequestBudgetExceeded(Exception):
    pass


class ScopeError(Exception):
    """Raised when a request would leave the authorized target host."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A scanner must see 3xx responses, not silently follow them.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    set_cookies: list
    body: str
    elapsed: float
    url: str

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class HttpClient:
    def __init__(self, max_requests: int, delay: float, timeout: float, verify_tls: bool,
                 use_cookies: bool = False, default_headers: dict[str, str] | None = None,
                 proxy: str | None = None, retries: int = 2,
                 allowed_hosts: set[str] | None = None):
        self.max_requests = max_requests
        self.delay = delay
        self.timeout = timeout
        self.retries = retries
        self.count = 0
        self.default_headers = default_headers or {}
        self.allowed_hosts = allowed_hosts or set()
        self._lock = threading.Lock()
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy}) if proxy \
            else urllib.request.ProxyHandler({})
        handlers: list[Any] = [_NoRedirect, urllib.request.HTTPSHandler(context=self._ctx),
                               proxy_handler]
        if use_cookies:
            # A shared cookie jar lets multi-step flows work (e.g. fetch a CSRF
            # cookie, then submit the matching token).
            handlers.append(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self._opener = urllib.request.build_opener(*handlers)
        # A cookie-less opener for concurrent bursts (CookieJar is not thread-safe).
        self._burst_opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=self._ctx), proxy_handler)

    def _check_scope(self, url: str) -> None:
        if self.allowed_hosts:
            host = urllib.parse.urlparse(url).netloc
            if host and host not in self.allowed_hosts:
                raise ScopeError(f"Refusing to leave target scope: {host} not in {sorted(self.allowed_hosts)}")

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

    def request(self, method: str, url: str, data: dict[str, str] | None = None,
                headers: dict[str, str] | None = None,
                content_type: str = "form") -> Response:
        self._check_scope(url)
        self._spend()
        if self.delay and self.count > 1:
            time.sleep(self.delay)

        req_headers = {"User-Agent": "loginscan (self-audit)"}
        req_headers.update(self.default_headers)
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

        start = time.time()
        last_err: Exception | None = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=body_bytes, method=method.upper(),
                                         headers=req_headers)
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    r = self._to_response(resp, start, url)
                    log.debug("%s %s -> %s (%.0fms)", method, url, r.status, r.elapsed * 1000)
                    return r
            except urllib.error.HTTPError as e:
                r = self._to_response(e, start, url)
                log.debug("%s %s -> %s (%.0fms)", method, url, r.status, r.elapsed * 1000)
                return r  # 4xx/5xx is a valid response, not a transport error
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_err = e
                if attempt < self.retries:
                    backoff = 0.3 * (2 ** attempt)
                    log.warning("%s %s failed (%s); retry %d/%d in %.1fs",
                                method, url, e, attempt + 1, self.retries, backoff)
                    time.sleep(backoff)
        raise urllib.error.URLError(f"request failed after {self.retries} retries: {last_err}")

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

        return Response(
            status=getattr(resp, "status", getattr(resp, "code", 0)) or 0,
            headers=headers,
            set_cookies=set_cookies,
            body=text,
            elapsed=time.time() - start,
            url=url,
        )

    def post(self, url: str, data: dict[str, str], headers: dict[str, str] | None = None,
             content_type: str = "form") -> Response:
        return self.request("POST", url, data=data, headers=headers, content_type=content_type)

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        return self.request("GET", url, data=None, headers=headers)

    def burst(self, method: str, url: str, data: dict[str, str], n: int,
              content_type: str = "form") -> list[Response]:
        """Fire n identical requests concurrently (no delay) to probe race-y limits.

        Costs n from the request budget. Uses a cookie-less opener and does not
        record session tokens, so it is safe to run across threads.
        """
        with self._lock:
            if self.count + n > self.max_requests:
                raise RequestBudgetExceeded(
                    f"Request budget too low for a burst of {n} ({self.remaining} left)."
                )
            self.count += n

        if content_type == "json":
            body = json.dumps(data).encode()
            ctype = "application/json"
        else:
            body = urllib.parse.urlencode(data).encode()
            ctype = "application/x-www-form-urlencoded"
        headers = {"User-Agent": "loginscan (self-audit)", "Content-Type": ctype}

        results: list[Response] = []
        barrier = threading.Barrier(n)

        def worker():
            req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
            barrier.wait()  # release all threads at the same instant
            start = time.time()
            try:
                with self._burst_opener.open(req, timeout=self.timeout) as resp:
                    r = self._to_response(resp, start, url)
            except urllib.error.HTTPError as e:
                r = self._to_response(e, start, url)
            except Exception:  # noqa: BLE001 - a failed thread just yields no result
                return
            results.append(r)  # list.append is atomic under CPython's GIL

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return results
