"""CheckContext: the surface a check is given.

Checks never touch the transport client directly. They get a CheckContext that
exposes HTTP-with-a-budget plus explicit, scan-scoped session observation. This
keeps the transport layer (HttpClient) pure and removes the hidden, order-dependent
shared state that used to live on the client.
"""
from __future__ import annotations

import re
from typing import Protocol

from .http import HttpClient, Response

_SESSION_COOKIE_HINT = re.compile(r"sess|token|auth|sid|jwt|login", re.I)


class SessionObserver:
    """Records session-like cookies seen during a scan."""

    def __init__(self) -> None:
        self.tokens: list[tuple[str, str]] = []

    def record(self, resp: Response) -> None:
        for cookie in resp.set_cookies:
            nv = cookie.split(";", 1)[0]
            if "=" in nv:
                name, value = (p.strip() for p in nv.split("=", 1))
                if value and _SESSION_COOKIE_HINT.search(name):
                    self.tokens.append((name, value))


class CheckContext:
    """HTTP access for a check, with a request budget and session observation."""

    def __init__(self, http: HttpClient, observer: SessionObserver | None = None) -> None:
        self._http = http
        self._obs = observer or SessionObserver()

    @property
    def remaining(self) -> int:
        return self._http.remaining

    def request(self, method: str, url: str, data: dict[str, str] | None = None,
                headers: dict[str, str] | None = None, content_type: str = "form") -> Response:
        resp = self._http.request(method, url, data=data, headers=headers,
                                  content_type=content_type)
        self._obs.record(resp)
        return resp

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        resp = self._http.get(url, headers=headers)
        self._obs.record(resp)
        return resp

    def post(self, url: str, data: dict[str, str], headers: dict[str, str] | None = None,
             content_type: str = "form") -> Response:
        resp = self._http.post(url, data, headers=headers, content_type=content_type)
        self._obs.record(resp)
        return resp

    def burst(self, method: str, url: str, data: dict[str, str], n: int,
              content_type: str = "form") -> list[Response]:
        # Concurrent burst is intentionally not observed (thread-safety).
        return self._http.burst(method, url, data, n, content_type=content_type)

    def session_tokens(self) -> list[tuple[str, str]]:
        return list(self._obs.tokens)


class Check(Protocol):
    """The contract every check satisfies (built-in modules and plugins)."""

    CHECK: str

    def run(self, ctx: CheckContext, cfg: object) -> list: ...
